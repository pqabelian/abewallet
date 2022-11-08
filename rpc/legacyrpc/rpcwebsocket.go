package legacyrpc

import (
	"container/list"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/abesuite/abec/abejson"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abewallet/wallet"
	"github.com/abesuite/abewallet/wtxmgr"
	"github.com/gorilla/websocket"
	"io"
	"sync"
	"time"
)

const (
	// websocketSendBufferSize is the number of elements the send channel
	// can queue before blocking.  Note that this only applies to requests
	// handled directly in the websocket client input handler or the async
	// handler since notifications have their own queuing mechanism
	// independent of the send channel buffer.
	websocketSendBufferSize = 50
)

type semaphore chan struct{}

func makeSemaphore(n int) semaphore {
	return make(chan struct{}, n)
}

func (s semaphore) acquire() { s <- struct{}{} }
func (s semaphore) release() { <-s }

// timeZeroVal is simply the zero value for a time.Time and is used to avoid
// creating multiple instances.
var timeZeroVal time.Time

// wsCommandHandler describes a callback function used to handle a specific
// command.
type wsCommandHandler func(*wsClient, interface{}) (interface{}, error)

// wsHandlers maps RPC command strings to appropriate websocket handler
// functions.  This is set by init because help references wsHandlers and thus
// causes a dependency loop.
var wsHandlers map[string]wsCommandHandler
var wsHandlersBeforeInit = map[string]wsCommandHandler{
	"help":              handleWebsocketHelp,
	"notifytransaction": handleNotifyTransaction,
}

// WebsocketHandler handles a new websocket client by creating a new wsClient,
// starting it, and blocking until the connection closes.  Since it blocks, it
// must be run in a separate goroutine.  It should be invoked from the websocket
// server handler which runs each new connection in a new goroutine thereby
// satisfying the requirement.
func (s *Server) WebsocketHandler(conn *websocket.Conn, remoteAddr string,
	authenticated bool) {

	// Clear the read deadline that was set before the websocket hijacked
	// the connection.
	conn.SetReadDeadline(timeZeroVal)

	// Limit max number of websocket clients.
	log.Infof("New websocket client %s", remoteAddr)
	if s.ntfnMgr.NumClients()+1 > int(s.maxWebsocketClients) {
		log.Infof("Max websocket clients exceeded [%d] - "+
			"disconnecting client %s", s.maxWebsocketClients,
			remoteAddr)
		conn.Close()
		return
	}

	// Create a new websocket client to handle the new websocket connection
	// and wait for it to shutdown.  Once it has shutdown (and hence
	// disconnected), remove it and any notifications it registered for.
	client, err := newWebsocketClient(s, conn, remoteAddr, authenticated)
	if err != nil {
		log.Errorf("Failed to serve client %s: %v", remoteAddr, err)
		conn.Close()
		return
	}
	s.ntfnMgr.AddClient(client)
	client.Start()
	client.WaitForShutdown()
	s.ntfnMgr.RemoveClient(client)
	log.Infof("Disconnected websocket client %s", remoteAddr)
}

// Start begins processing input and output messages.
func (c *wsClient) Start() {
	log.Tracef("Starting websocket client %s", c.addr)

	// Start processing input and output.
	c.wg.Add(3)
	go c.inHandler()
	go c.notificationQueueHandler()
	go c.outHandler()
}

// WaitForShutdown blocks until the websocket client goroutines are stopped
// and the connection is closed.
func (c *wsClient) WaitForShutdown() {
	c.wg.Wait()
}

// Start starts the goroutines required for the manager to queue and process
// websocket client notifications.
func (m *wsNotificationManager) Start() {
	m.wg.Add(2)
	go m.queueHandler()
	go m.notificationHandler()
}

// wsNotificationManager is a connection and notification manager used for
// websockets.  It allows websocket clients to register for notifications they
// are interested in.  When an event happens elsewhere in the code such as
// transactions being added to the memory pool or block connects/disconnects,
// the notification manager is provided with the relevant details needed to
// figure out which websocket clients need to be notified based on what they
// have registered for and notifies them accordingly.  It is also used to keep
// track of all connected websocket clients.
type wsNotificationManager struct {
	// server is the RPC server the notification manager is associated with.
	server *Server

	// queueNotification queues a notification for handling.
	queueNotification chan interface{}

	// notificationMsgs feeds notificationHandler with notifications
	// and client (un)registeration requests from a queue as well as
	// registeration and unregisteration requests from clients.
	notificationMsgs chan interface{}

	// Access channel for current number of connected clients.
	numClients chan int

	// Shutdown handling
	wg   sync.WaitGroup
	quit chan struct{}
}

// queueHandler manages a queue of empty interfaces, reading from in and
// sending the oldest unsent to out.  This handler stops when either of the
// in or quit channels are closed, and closes out before returning, without
// waiting to send any variables still remaining in the queue.
func queueHandler(in <-chan interface{}, out chan<- interface{}, quit <-chan struct{}) {
	var q []interface{}
	var dequeue chan<- interface{}
	skipQueue := out
	var next interface{}
out:
	for {
		select {
		case n, ok := <-in: // take a notification
			if !ok { // it means that finished
				// Sender closed input channel.
				break out
			}

			// Either send to out immediately if skipQueue is
			// non-nil (queue is empty) and reader is ready,
			// or append to the queue and send later.
			select {
			case skipQueue <- n:
			default:
				q = append(q, n) // wait
				dequeue = out
				skipQueue = nil
				next = q[0]
			}

		case dequeue <- next:
			copy(q, q[1:])
			q[len(q)-1] = nil // avoid leak
			q = q[:len(q)-1]
			if len(q) == 0 {
				dequeue = nil
				skipQueue = out
			} else {
				next = q[0]
			}

		case <-quit:
			break out
		}
	}
	close(out)
}

// queueHandler maintains a queue of notifications and notification handler
// control messages.
func (m *wsNotificationManager) queueHandler() {
	queueHandler(m.queueNotification, m.notificationMsgs, m.quit)
	m.wg.Done()
}

func handleNotifyTransaction(wsc *wsClient, icmd interface{}) (interface{}, error) {
	_, ok := icmd.(*abejson.NotifyTransactionCmd)
	if !ok {
		return nil, abejson.ErrRPCInternal
	}

	wsc.server.ntfnMgr.RegisteTransactionNotification(wsc)
	return nil, nil
}

// HandleMinerManagerNotification handles notifications from miner manager. It does
// things such as notify share difficulty changed and so on.
func (m *wsNotificationManager) HandleMinerManagerNotification(notification *wallet.Notification) {
	switch notification.Type {
	case wallet.NTTransactionAccepted:
		txInfo, ok := notification.Data.(*wtxmgr.TransactionInfo)
		if !ok {
			break
		}
		n := &notificationTxAccepted{tx: txInfo.TxHash, Height: txInfo.Height}

		select {
		case m.queueNotification <- n:
		case <-m.quit:
		}
	case wallet.NTTransactionRollback:
		txInfo, ok := notification.Data.(*wtxmgr.TransactionInfo)
		if !ok {
			break
		}
		n := &notificationTxRollback{tx: txInfo.TxHash, Height: txInfo.Height}

		select {
		case m.queueNotification <- n:
		case <-m.quit:
		}
	case wallet.NTTransactionInvalid:
		txInfo, ok := notification.Data.(*wtxmgr.TransactionInfo)
		if !ok {
			break
		}
		n := &notificationTxInvalid{tx: txInfo.TxHash, Height: txInfo.Height}

		select {
		case m.queueNotification <- n:
		case <-m.quit:
		}
	}

}

// todo (ABE):
type notificationTxAccepted struct {
	tx     *chainhash.Hash
	Height int32
}
type notificationTxRollback struct {
	tx     *chainhash.Hash
	Height int32
}
type notificationTxInvalid struct {
	tx     *chainhash.Hash
	Height int32
}

// Notification control requests
type notificationRegisterClient wsClient
type notificationUnregisterClient wsClient
type notificationRegistedTransaction wsClient
type notificationUnregisterTransaction wsClient

//	todo(ABE): ABE does not support watchedOutPoints or watchedAddrs.
//type notificationRegisterSpent struct {
//	wsc *wsClient
//	ops []*wire.OutPoint
//}
//type notificationUnregisterSpent struct {
//	wsc *wsClient
//	op  *wire.OutPoint
//}
//type notificationRegisterAddr struct {
//	wsc   *wsClient
//	addrs []string
//}
//type notificationUnregisterAddr struct {
//	wsc  *wsClient
//	addr string
//}

// notificationHandler reads notifications and control messages from the queue
// handler and processes one at a time.
//
//	TODO(ABE, MUST):
func (m *wsNotificationManager) notificationHandler() {
	// clients is a map of all currently connected websocket clients.
	clients := make(map[chan struct{}]*wsClient)

	// Maps used to hold lists of websocket clients to be notified on
	// certain events.  Each websocket client also keeps maps for the events
	// which have multiple triggers to make removal from these lists on
	// connection close less horrendously expensive.
	//
	// Where possible, the quit channel is used as the unique id for a client
	// since it is quite a bit more efficient than using the entire struct.
	//blockNotifications := make(map[chan struct{}]*wsClient)
	txNotifications := make(map[chan struct{}]*wsClient)

	//	todo(ABE): ABE does not support watchedOutPoints or watchedAddrs.
	//watchedOutPoints := make(map[wire.OutPoint]map[chan struct{}]*wsClient)
	//watchedAddrs := make(map[string]map[chan struct{}]*wsClient)

out:
	for {
		select {
		case n, ok := <-m.notificationMsgs:
			if !ok {
				// queueHandler quit.
				break out
			}
			switch n := n.(type) {
			case *notificationTxAccepted:
				if len(txNotifications) != 0 {
					m.notifyTransactionAccepted(txNotifications, *n.tx, n.Height)
				}
			case *notificationTxRollback:
				if len(txNotifications) != 0 {
					m.notifyTransactionRollback(txNotifications, *n.tx, n.Height)
				}
			case *notificationTxInvalid:
				if len(txNotifications) != 0 {
					m.notifyTransactionInvalid(txNotifications, *n.tx, n.Height)
				}

			case *notificationRegisterClient:
				wsc := (*wsClient)(n)
				clients[wsc.quit] = wsc

			case *notificationUnregisterClient:
				wsc := (*wsClient)(n)
				// Remove any requests made by the client as well as
				// the client itself.
				//delete(blockNotifications, wsc.quit)
				delete(txNotifications, wsc.quit)
				delete(clients, wsc.quit)

			case *notificationRegistedTransaction:
				wsc := (*wsClient)(n)
				txNotifications[wsc.quit] = wsc

			case *notificationUnregisterTransaction:
				wsc := (*wsClient)(n)
				delete(txNotifications, wsc.quit)

			default:
				log.Warn("Unhandled notification type")
			}

		case m.numClients <- len(clients):

		case <-m.quit:
			// RPC server shutting down.
			break out
		}
	}

	for _, c := range clients {
		c.Disconnect()
	}
	m.wg.Done()
}

// NumClients returns the number of clients actively being served.
func (m *wsNotificationManager) NumClients() (n int) {
	select {
	case n = <-m.numClients:
	case <-m.quit: // Use default n (0) if server has shut down.
	}
	return
}

func (m *wsNotificationManager) RegisteTransactionNotification(wsc *wsClient) {
	m.queueNotification <- (*notificationRegistedTransaction)(wsc)
}

func (m *wsNotificationManager) UnregisterTransactionAccepted(wsc *wsClient) {
	m.queueNotification <- (*notificationUnregisterTransaction)(wsc)
}

// notifyTransactionAccepted notifies websocket clients that have registered for updates
// when a new transaction is added to the memory pool.
//
//	todo(ABE.MUST):
func (m *wsNotificationManager) notifyTransactionAccepted(clients map[chan struct{}]*wsClient, txHash chainhash.Hash, height int32) {
	txHashStr := txHash.String()
	ntfn := abejson.NewTxAcceptedNtfn(txHashStr, height)
	marshalledJSON, err := abejson.MarshalCmd(nil, ntfn)
	if err != nil {
		log.Errorf("Failed to marshal tx notification: %s", err.Error())
		return
	}
	for _, wsc := range clients {
		err = wsc.QueueNotification(marshalledJSON)
		if err != nil {
			log.Errorf("Failed to send tx notification: %s", err.Error())
			return
		}
	}
}
func (m *wsNotificationManager) notifyTransactionRollback(clients map[chan struct{}]*wsClient, txHash chainhash.Hash, height int32) {
	txHashStr := txHash.String()
	ntfn := abejson.NewTxRollbackNtfn(txHashStr, height)
	marshalledJSON, err := abejson.MarshalCmd(nil, ntfn)
	if err != nil {
		log.Errorf("Failed to marshal tx notification: %s", err.Error())
		return
	}
	for _, wsc := range clients {
		err = wsc.QueueNotification(marshalledJSON)
		if err != nil {
			log.Errorf("Failed to send tx notification: %s", err.Error())
			return
		}
	}
}
func (m *wsNotificationManager) notifyTransactionInvalid(clients map[chan struct{}]*wsClient, txHash chainhash.Hash, height int32) {
	txHashStr := txHash.String()
	ntfn := abejson.NewTxInvalidNtfn(txHashStr, height)
	marshalledJSON, err := abejson.MarshalCmd(nil, ntfn)
	if err != nil {
		log.Errorf("Failed to marshal tx notification: %s", err.Error())
		return
	}
	for _, wsc := range clients {
		err = wsc.QueueNotification(marshalledJSON)
		if err != nil {
			log.Errorf("Failed to send tx notification: %s", err.Error())
			return
		}
	}
}

// AddClient adds the passed websocket client to the notification manager.
func (m *wsNotificationManager) AddClient(wsc *wsClient) {
	m.queueNotification <- (*notificationRegisterClient)(wsc)
}

// RemoveClient removes the passed websocket client and all notifications
// registered for it.
func (m *wsNotificationManager) RemoveClient(wsc *wsClient) {
	select {
	case m.queueNotification <- (*notificationUnregisterClient)(wsc):
	case <-m.quit:
	}
}

// WaitForShutdown blocks until all notification manager goroutines have
// finished.
func (m *wsNotificationManager) WaitForShutdown() {
	m.wg.Wait()
}

// Shutdown shuts down the manager, stopping the notification queue and
// notification handler goroutines.
func (m *wsNotificationManager) Shutdown() {
	close(m.quit)
}

// newWsNotificationManager returns a new notification manager ready for use.
// See wsNotificationManager for more details.
func newWsNotificationManager(server *Server) *wsNotificationManager {
	return &wsNotificationManager{
		server:            server,
		queueNotification: make(chan interface{}),
		notificationMsgs:  make(chan interface{}),
		numClients:        make(chan int),
		quit:              make(chan struct{}),
	}
}

// wsResponse houses a message to send to a connected websocket client as
// well as a channel to reply on when the message is sent.
type wsResponse struct {
	msg      []byte
	doneChan chan bool
}

// wsClient provides an abstraction for handling a websocket client.  The
// overall data flow is split into 3 main goroutines, a possible 4th goroutine
// for long-running operations (only started if request is made), and a
// websocket manager which is used to allow things such as broadcasting
// requested notifications to all connected websocket clients.   Inbound
// messages are read via the inHandler goroutine and generally dispatched to
// their own handler.  However, certain potentially long-running operations such
// as rescans, are sent to the asyncHander goroutine and are limited to one at a
// time.  There are two outbound message types - one for responding to client
// requests and another for async notifications.  Responses to client requests
// use SendMessage which employs a buffered channel thereby limiting the number
// of outstanding requests that can be made.  Notifications are sent via
// QueueNotification which implements a queue via notificationQueueHandler to
// ensure sending notifications from other subsystems can't block.  Ultimately,
// all messages are sent via the outHandler.
type wsClient struct {
	sync.Mutex

	// server is the RPC server that is servicing the client.
	server *Server

	// conn is the underlying websocket connection.
	conn *websocket.Conn

	// disconnected indicated whether or not the websocket client is
	// disconnected.
	disconnected bool

	// addr is the remote address of the client.
	addr string

	// authenticated specifies whether a client has been authenticated
	// and therefore is allowed to communicated over the websocket.
	authenticated bool

	// isAdmin specifies whether a client may change the state of the server;
	// false means its access is only to the limited set of RPC calls.
	isAdmin bool

	// sessionID is a random ID generated for each client when connected.
	// These IDs may be queried by a client using the session RPC.  A change
	// to the session ID indicates that the client reconnected.
	sessionID uint64

	// verboseTxUpdates specifies whether a client has requested verbose
	// information about all new transactions.
	//verboseTxUpdates bool

	// Networking infrastructure.
	serviceRequestSem semaphore
	ntfnChan          chan []byte
	sendChan          chan wsResponse
	quit              chan struct{}
	wg                sync.WaitGroup
}

// inHandler handles all incoming messages for the websocket connection.  It
// must be run as a goroutine.
func (c *wsClient) inHandler() {
out:
	for {
		// Break out of the loop once the quit channel has been closed.
		// Use a non-blocking select here so we fall through otherwise.
		select {
		case <-c.quit:
			break out
		default:
		}

		_, msg, err := c.conn.ReadMessage()
		if err != nil {
			// Log the error if it's not due to disconnecting.
			if err != io.EOF {
				log.Errorf("Websocket receive error from "+
					"%s: %v", c.addr, err)
			}
			break out
		}

		var request abejson.Request
		err = json.Unmarshal(msg, &request)
		if err != nil {
			if !c.authenticated {
				break out
			}

			jsonErr := &abejson.RPCError{
				Code:    abejson.ErrRPCParse.Code,
				Message: "Failed to parse request: " + err.Error(),
			}
			reply, err := createMarshalledReply(nil, nil, jsonErr)
			if err != nil {
				log.Errorf("Failed to marshal parse failure "+
					"reply: %v", err)
				continue
			}
			c.SendMessage(reply, nil)
			continue
		}

		// The JSON-RPC 1.0 spec defines that notifications must have their "id"
		// set to null and states that notifications do not have a response.
		//
		// A JSON-RPC 2.0 notification is a request with "json-rpc":"2.0", and
		// without an "id" member. The specification states that notifications
		// must not be responded to. JSON-RPC 2.0 permits the null value as a
		// valid request id, therefore such requests are not notifications.
		//
		// Bitcoin Core serves requests with "id":null or even an absent "id",
		// and responds to such requests with "id":null in the response.
		//
		// Btcd does not respond to any request without and "id" or "id":null,
		// regardless the indicated JSON-RPC protocol version unless RPC quirks
		// are enabled. With RPC quirks enabled, such requests will be responded
		// to if the reqeust does not indicate JSON-RPC version.
		//
		// RPC quirks can be enabled by the user to avoid compatibility issues
		// with software relying on Core's behavior.
		if request.ID == nil && request.Jsonrpc != "" {
			if !c.authenticated {
				break out
			}
			continue
		}

		cmd := parseCmd(&request)
		if cmd.err != nil {
			if !c.authenticated {
				break out
			}

			reply, err := createMarshalledReply(cmd.id, nil, cmd.err)
			if err != nil {
				log.Errorf("Failed to marshal parse failure "+
					"reply: %v", err)
				continue
			}
			c.SendMessage(reply, nil)
			continue
		}
		log.Debugf("Received command <%s> from %s", cmd.method, c.addr)

		// Check auth.  The client is immediately disconnected if the
		// first request of an unauthentiated websocket client is not
		// the authenticate request, an authenticate request is received
		// when the client is already authenticated, or incorrect
		// authentication credentials are provided in the request.
		switch authCmd, ok := cmd.cmd.(*abejson.AuthenticateCmd); {
		case c.authenticated && ok:
			log.Warnf("Websocket client %s is already authenticated",
				c.addr)
			break out
		case !c.authenticated && !ok:
			log.Warnf("Unauthenticated websocket message " +
				"received")
			break out
		case !c.authenticated:
			// Check credentials.
			login := authCmd.Username + ":" + authCmd.Passphrase
			auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(login))
			authSha := sha256.Sum256([]byte(auth))
			cmp := subtle.ConstantTimeCompare(authSha[:], c.server.authsha[:])
			limitcmp := subtle.ConstantTimeCompare(authSha[:], c.server.authsha[:]) // TODO split limit user and admin user
			if cmp != 1 && limitcmp != 1 {
				log.Warnf("Auth failure.")
				break out
			}
			c.authenticated = true
			c.isAdmin = cmp == 1

			// Marshal and send response.
			reply, err := createMarshalledReply(cmd.id, nil, nil)
			if err != nil {
				log.Errorf("Failed to marshal authenticate reply: "+
					"%v", err.Error())
				continue
			}
			c.SendMessage(reply, nil)
			continue
		}

		if _, ok := rpcHandlers[request.Method]; !ok {
			jsonErr := &abejson.RPCError{
				Code:    abejson.ErrRPCInvalidParams.Code,
				Message: "limited user not authorized for this method",
			}
			// Marshal and send response.
			reply, err := createMarshalledReply(request.ID, nil, jsonErr)
			if err != nil {
				log.Errorf("Failed to marshal parse failure "+
					"reply: %v", err)
				continue
			}
			c.SendMessage(reply, nil)
			continue
		}

		// Asynchronously handle the request.  A semaphore is used to
		// limit the number of concurrent requests currently being
		// serviced.  If the semaphore can not be acquired, simply wait
		// until a request finished before reading the next RPC request
		// from the websocket client.
		//
		// This could be a little fancier by timing out and erroring
		// when it takes too long to service the request, but if that is
		// done, the read of the next request should not be blocked by
		// this semaphore, otherwise the next request will be read and
		// will probably sit here for another few seconds before timing
		// out as well.  This will cause the total timeout duration for
		// later requests to be much longer than the check here would
		// imply.
		//
		// If a timeout is added, the semaphore acquiring should be
		// moved inside of the new goroutine with a select statement
		// that also reads a time.After channel.  This will unblock the
		// read of the next request from the websocket client and allow
		// many requests to be waited on concurrently.
		c.serviceRequestSem.acquire()
		go func() {
			c.serviceRequest(cmd)
			c.serviceRequestSem.release()
		}()
	}

	// Ensure the connection is closed.
	c.Disconnect()
	c.wg.Done()
	log.Tracef("Websocket client input handler done for %s", c.addr)
}

// serviceRequest services a parsed RPC request by looking up and executing the
// appropriate RPC handler.  The response is marshalled and sent to the
// websocket client.
func (c *wsClient) serviceRequest(r *parsedRPCCmd) {
	var (
		result interface{}
		err    error
	)

	// Lookup the websocket extension for the command and if it doesn't
	// exist fallback to handling the command as a standard command.
	wsHandler, ok := wsHandlers[r.method]
	if ok {
		result, err = wsHandler(c, r.cmd)
	} else {
		result, err = c.server.standardCmdResult(r, nil)
	}
	reply, err := createMarshalledReply(r.id, result, err)
	if err != nil {
		log.Errorf("Failed to marshal reply for <%s> "+
			"command: %v", r.method, err)
		return
	}
	c.SendMessage(reply, nil)
}

// notificationQueueHandler handles the queuing of outgoing notifications for
// the websocket client.  This runs as a muxer for various sources of input to
// ensure that queuing up notifications to be sent will not block.  Otherwise,
// slow clients could bog down the other systems (such as the mempool or block
// manager) which are queuing the data.  The data is passed on to outHandler to
// actually be written.  It must be run as a goroutine.
func (c *wsClient) notificationQueueHandler() {
	ntfnSentChan := make(chan bool, 1) // nonblocking sync

	// pendingNtfns is used as a queue for notifications that are ready to
	// be sent once there are no outstanding notifications currently being
	// sent.  The waiting flag is used over simply checking for items in the
	// pending list to ensure cleanup knows what has and hasn't been sent
	// to the outHandler.  Currently no special cleanup is needed, however
	// if something like a done channel is added to notifications in the
	// future, not knowing what has and hasn't been sent to the outHandler
	// (and thus who should respond to the done channel) would be
	// problematic without using this approach.
	pendingNtfns := list.New()
	waiting := false
out:
	for {
		select {
		// This channel is notified when a message is being queued to
		// be sent across the network socket.  It will either send the
		// message immediately if a send is not already in progress, or
		// queue the message to be sent once the other pending messages
		// are sent.
		case msg := <-c.ntfnChan:
			if !waiting {
				c.SendMessage(msg, ntfnSentChan)
			} else {
				pendingNtfns.PushBack(msg)
			}
			waiting = true

		// This channel is notified when a notification has been sent
		// across the network socket.
		case <-ntfnSentChan:
			// No longer waiting if there are no more messages in
			// the pending messages queue.
			next := pendingNtfns.Front()
			if next == nil {
				waiting = false
				continue
			}

			// Notify the outHandler about the next item to
			// asynchronously send.
			msg := pendingNtfns.Remove(next).([]byte)
			c.SendMessage(msg, ntfnSentChan)

		case <-c.quit:
			break out
		}
	}

	// Drain any wait channels before exiting so nothing is left waiting
	// around to send.
cleanup:
	for {
		select {
		case <-c.ntfnChan:
		case <-ntfnSentChan:
		default:
			break cleanup
		}
	}
	c.wg.Done()
	log.Tracef("Websocket client notification queue handler done "+
		"for %s", c.addr)
}

// outHandler handles all outgoing messages for the websocket connection.  It
// must be run as a goroutine.  It uses a buffered channel to serialize output
// messages while allowing the sender to continue running asynchronously.  It
// must be run as a goroutine.
func (c *wsClient) outHandler() {
out:
	for {
		// Send any messages ready for send until the quit channel is
		// closed.
		select {
		case r := <-c.sendChan:
			err := c.conn.WriteMessage(websocket.TextMessage, r.msg)
			if err != nil {
				c.Disconnect()
				break out
			}
			if r.doneChan != nil {
				r.doneChan <- true
			}

		case <-c.quit:
			break out
		}
	}

	// Drain any wait channels before exiting so nothing is left waiting
	// around to send.
cleanup:
	for {
		select {
		case r := <-c.sendChan:
			if r.doneChan != nil {
				r.doneChan <- false
			}
		default:
			break cleanup
		}
	}
	c.wg.Done()
	log.Tracef("Websocket client output handler done for %s", c.addr)
}

// SendMessage sends the passed json to the websocket client.  It is backed
// by a buffered channel, so it will not block until the send channel is full.
// Note however that QueueNotification must be used for sending async
// notifications instead of the this function.  This approach allows a limit to
// the number of outstanding requests a client can make without preventing or
// blocking on async notifications.
func (c *wsClient) SendMessage(marshalledJSON []byte, doneChan chan bool) {
	// Don't send the message if disconnected.
	if c.Disconnected() {
		if doneChan != nil {
			doneChan <- false
		}
		return
	}

	c.sendChan <- wsResponse{msg: marshalledJSON, doneChan: doneChan}
}

// ErrClientQuit describes the error where a client send is not processed due
// to the client having already been disconnected or dropped.
var ErrClientQuit = errors.New("client quit")

// QueueNotification queues the passed notification to be sent to the websocket
// client.  This function, as the name implies, is only intended for
// notifications since it has additional logic to prevent other subsystems, such
// as the memory pool and block manager, from blocking even when the send
// channel is full.
//
// If the client is in the process of shutting down, this function returns
// ErrClientQuit.  This is intended to be checked by long-running notification
// handlers to stop processing if there is no more work needed to be done.
func (c *wsClient) QueueNotification(marshalledJSON []byte) error {
	// Don't queue the message if disconnected.
	if c.Disconnected() {
		return ErrClientQuit
	}

	c.ntfnChan <- marshalledJSON
	return nil
}

// Disconnected returns whether or not the websocket client is disconnected.
func (c *wsClient) Disconnected() bool {
	c.Lock()
	isDisconnected := c.disconnected
	c.Unlock()

	return isDisconnected
}

// Disconnect disconnects the websocket client.
func (c *wsClient) Disconnect() {
	c.Lock()
	defer c.Unlock()

	// Nothing to do if already disconnected.
	if c.disconnected {
		return
	}

	log.Tracef("Disconnecting websocket client %s", c.addr)
	close(c.quit)
	c.conn.Close()
	c.disconnected = true
}

// newWebsocketClient returns a new websocket client given the notification
// manager, websocket connection, remote address, and whether or not the client
// has already been authenticated (via HTTP Basic access authentication).  The
// returned client is ready to start.  Once started, the client will process
// incoming and outgoing messages in separate goroutines complete with queuing
// and asynchrous handling for long-running operations.
func newWebsocketClient(server *Server, conn *websocket.Conn,
	remoteAddr string, authenticated bool) (*wsClient, error) {

	sessionID, err := wire.RandomUint64()
	if err != nil {
		return nil, err
	}

	client := &wsClient{
		conn:              conn,
		addr:              remoteAddr,
		authenticated:     authenticated,
		sessionID:         sessionID,
		server:            server,
		serviceRequestSem: makeSemaphore(server.maxConcurrentReqs),
		ntfnChan:          make(chan []byte, 1), // nonblocking sync
		sendChan:          make(chan wsResponse, websocketSendBufferSize),
		quit:              make(chan struct{}),
	}
	return client, nil
}

// handleWebsocketHelp implements the help command for websocket connections.
func handleWebsocketHelp(wsc *wsClient, icmd interface{}) (interface{}, error) {
	cmd, ok := icmd.(*abejson.HelpCmd)
	if !ok {
		return nil, abejson.ErrRPCInternal
	}

	// Provide a usage overview of all commands when no specific command
	// was specified.
	var command string
	if cmd.Command != nil {
		command = *cmd.Command
	}
	if command == "" {
		return requestUsages, nil
	}

	// Check that the command asked for is supported and implemented.
	// Search the list of websocket handlers as well as the main list of
	// handlers since help should only be provided for those cases.
	valid := true
	if _, ok := rpcHandlers[command]; !ok {
		if _, ok := wsHandlers[command]; !ok {
			valid = false
		}
	}
	if !valid {
		return nil, &abejson.RPCError{
			Code:    abejson.ErrRPCInvalidParameter,
			Message: "Unknown command: " + command,
		}
	}
	return help, nil
}

// parsedRPCCmd represents a JSON-RPC request object that has been parsed into
// a known concrete command along with any error that might have happened while
// parsing it.
type parsedRPCCmd struct {
	id     interface{}
	method string
	cmd    interface{}
	err    *abejson.RPCError
}

func parseCmd(request *abejson.Request) *parsedRPCCmd {
	var parsedCmd parsedRPCCmd
	parsedCmd.id = request.ID
	parsedCmd.method = request.Method

	cmd, err := abejson.UnmarshalCmd(request)
	if err != nil {
		// When the error is because the method is not registered,
		// produce a method not found RPC error.
		if jerr, ok := err.(abejson.Error); ok &&
			jerr.ErrorCode == abejson.ErrUnregisteredMethod {

			parsedCmd.err = abejson.ErrRPCMethodNotFound
			return &parsedCmd
		}

		// Otherwise, some type of invalid parameters is the
		// cause, so produce the equivalent RPC error.
		parsedCmd.err = abejson.NewRPCError(
			abejson.ErrRPCInvalidParams.Code, err.Error())
		return &parsedCmd
	}

	parsedCmd.cmd = cmd
	return &parsedCmd
}

func init() {
	wsHandlers = wsHandlersBeforeInit
}
