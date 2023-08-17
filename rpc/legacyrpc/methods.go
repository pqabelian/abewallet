package legacyrpc

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abejson"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abewallet/wallet/txrules"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/abesuite/abec/btcec"
	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/rpcclient"
	"github.com/abesuite/abec/txscript"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abewallet/chain"
	"github.com/abesuite/abewallet/waddrmgr"
	"github.com/abesuite/abewallet/wallet"
)

// confirmed checks whether a transaction at height txHeight has met minconf
// confirmations for a blockchain at height curHeight.
func confirmed(minconf, txHeight, curHeight int32) bool {
	return confirms(txHeight, curHeight) >= minconf
}

// confirms returns the number of confirmations for a transaction in a block at
// height txHeight (or -1 for an unconfirmed tx) given the chain height
// curHeight.
func confirms(txHeight, curHeight int32) int32 {
	switch {
	case txHeight == -1, txHeight > curHeight:
		return 0
	default:
		return curHeight - txHeight + 1
	}
}

// requestHandler is a handler function to handle an unmarshaled and parsed
// request into a marshalable response.  If the error is a *btcjson.RPCError
// or any of the above special error classes, the server will respond with
// the JSON-RPC appropiate error code.  All other errors use the wallet
// catch-all error code, btcjson.ErrRPCWallet.
type requestHandler func(interface{}, *wallet.Wallet) (interface{}, error)

// requestHandlerChain is a requestHandler that also takes a parameter for
type requestHandlerChainRequired func(interface{}, *wallet.Wallet, *chain.RPCClient) (interface{}, error)

var rpcHandlers = map[string]struct {
	handler          requestHandler
	handlerWithChain requestHandlerChainRequired

	// Function variables cannot be compared against anything but nil, so
	// use a boolean to record whether help generation is necessary.  This
	// is used by the tests to ensure that help can be generated for every
	// implemented method.
	//
	// A single map and this bool is here is used rather than several maps
	// for the unimplemented handlers so every method has exactly one
	// handler function.
	noHelp bool
}{
	//	todo(ABE): The supported RPC requests are here. We need to remove some that are not supported any more.
	// Reference implementation wallet methods (implemented)
	//"addmultisigaddress": {handler: addMultiSigAddress},
	//"addpayee":              {handler: addPayee},
	//"createmultisig":        {handler: createMultiSig},
	//"dumpprivkey":           {handler: dumpPrivKey},
	//"getaccount":            {handler: getAccount},
	//"getaccountaddress":     {handler: getAccountAddress},
	//"getaddressesbyaccount": {handler: getAddressesByAccount},
	//"getbalance":            {handler: getBalance},
	"getbalancesabe":   {handler: getBalances},
	"getdetailedutxos": {handler: getDetailedUtxos},
	"getbestblockhash": {handler: getBestBlockHash},
	"getblockcount":    {handler: getBlockCount},
	"getinfo":          {handlerWithChain: getInfo},
	//"getnewaddress":        {handler: getNewAddress},
	//"getrawchangeaddress":  {handler: getRawChangeAddress},
	//"getreceivedbyaccount": {handler: getReceivedByAccount},
	//"getreceivedbyaddress": {handler: getReceivedByAddress},
	//"gettransaction": {handler: getTransaction},
	"help": {handler: helpNoChainRPC, handlerWithChain: helpWithChainRPC},
	//"importprivkey":  {handler: importPrivKey},
	"keypoolrefill": {handler: keypoolRefill}, // TODO
	//"listaccounts":           {handler: listAccounts},
	"listlockunspent": {handler: listLockUnspent},
	//"listreceivedbyaccount":  {handler: listReceivedByAccount},
	//"listreceivedbyaddress":  {handler: listReceivedByAddress},
	//"listsinceblock": {handlerWithChain: listSinceBlock},
	//"listtransactions":       {handler: listTransactions},
	//"listunspent":            {handler: listUnspent},
	"listallutxoabe":           {handler: listAllUTXOAbe},
	"listimmaturetxoabe":       {handler: listUnmaturedUTXOAbe},
	"listmaturetxoabe":         {handler: listUnspentAbe},
	"listmaturecoinbasetxoabe": {handler: listUnspentCoinbaseAbe},
	"listunconfirmedtxoabe":    {handler: listSpentButUnminedAbe},
	"listconfirmedtxoabe":      {handler: listSpentAndMinedAbe},

	"listunconfirmedtxs": {handler: listUnconfirmedTxs},
	"listconfirmedtxs":   {handler: listConfirmedTxs},
	"listinvalidtxs":     {handler: listInvalidTxs},
	"transactionstatus":  {handler: txStatus},

	"lockunspent": {handler: lockUnspent},
	//"sendfrom":               {handlerWithChain: sendFrom},
	//"sendmany":               {handler: sendMany},
	"gettxhashfromreqeust": {handler: getTxHashFromRequest},

	"sendtoaddressesabe":       {handler: sendToAddressesAbe},
	"generateaddressabe":       {handler: generateAddressAbe},
	"addressmaxsequencenumber": {handler: addressMaxSequenceNumber},
	"addressrange":             {handler: addressRange},
	"listfreeaddresses":        {handler: listFreeAddress},
	//"sendtoaddress":          {handler: sendToAddress},
	//"sendtopayee":            {handler: sendToPayees},
	"settxfee": {handler: setTxFee}, // TODO
	//"signmessage":            {handler: signMessage},
	"signrawtransaction": {handlerWithChain: signRawTransaction},
	"validateaddress":    {handler: validateAddress}, // just support for address in database
	//"verifymessage":          {handler: verifyMessage},
	"walletlock": {handler: walletLock},
	//"freshen":                {handler: freshen},
	"walletunlock":           {handler: walletPassphrase},
	"walletpassphrasechange": {handler: walletPassphraseChange},

	// Reference implementation methods (still unimplemented)
	"backupwallet":         {handler: unimplemented, noHelp: true},
	"dumpwallet":           {handler: unimplemented, noHelp: true},
	"getwalletinfo":        {handler: unimplemented, noHelp: true},
	"importwallet":         {handler: unimplemented, noHelp: true},
	"listaddressgroupings": {handler: unimplemented, noHelp: true},

	// Reference methods which can't be implemented by btcwallet due to
	// design decision differences
	"encryptwallet": {handler: unsupported, noHelp: true},
	"move":          {handler: unsupported, noHelp: true},
	"setaccount":    {handler: unsupported, noHelp: true},

	// Extensions to the reference client JSON-RPC API
	//"createnewaccount": {handler: createNewAccount},
	"getbestblock": {handler: getBestBlock},
	// This was an extension but the reference implementation added it as
	// well, but with a different API (no account parameter).  It's listed
	// here because it hasn't been update to use the reference
	// implemenation's API.
	//"getunconfirmedbalance":   {handler: getUnconfirmedBalance},
	//"listaddresstransactions": {handler: listAddressTransactions},
	//"listalltransactions":     {handler: listAllTransactions},
	//"renameaccount":           {handler: renameAccount},
	"walletislocked":    {handler: walletIsLocked},
	"notifytransaction": {}, /*handleNotifyTransactionAccepted*/
}

// unimplemented handles an unimplemented RPC request with the
// appropiate error.
func unimplemented(interface{}, *wallet.Wallet) (interface{}, error) {
	return nil, &abejson.RPCError{
		Code:    abejson.ErrRPCUnimplemented,
		Message: "Method unimplemented",
	}
}

// unsupported handles a standard bitcoind RPC request which is
// unsupported by btcwallet due to design differences.
func unsupported(interface{}, *wallet.Wallet) (interface{}, error) {
	return nil, &abejson.RPCError{
		Code:    -1,
		Message: "Request unsupported by abewallet",
	}
}

// lazyHandler is a closure over a requestHandler or passthrough request with
// the RPC server's wallet and chain server variables as part of the closure
// context.
type lazyHandler func() (interface{}, *abejson.RPCError)

// lazyApplyHandler looks up the best request handler func for the method,
// returning a closure that will execute it with the (required) wallet and
// (optional) consensus RPC server.  If no handlers are found and the
// chainClient is not nil, the returned handler performs RPC passthrough.
func lazyApplyHandler(request *abejson.Request, w *wallet.Wallet, chainClient chain.Interface) lazyHandler {
	handlerData, ok := rpcHandlers[request.Method]
	if ok && handlerData.handlerWithChain != nil && w != nil && chainClient != nil { // if this handle need helps of chain
		return func() (interface{}, *abejson.RPCError) {
			cmd, err := abejson.UnmarshalCmd(request)
			if err != nil {
				return nil, abejson.ErrRPCInvalidRequest
			}
			switch client := chainClient.(type) {
			case *chain.RPCClient:
				resp, err := handlerData.handlerWithChain(cmd,
					w, client)
				if err != nil {
					return nil, jsonError(err)
				}
				return resp, nil
			default:
				return nil, &abejson.RPCError{
					Code:    -1,
					Message: "Chain RPC is inactive",
				}
			}
		}
	}
	if ok && handlerData.handler != nil && w != nil { //just wallet can handle with this request
		return func() (interface{}, *abejson.RPCError) {
			cmd, err := abejson.UnmarshalCmd(request)
			if err != nil {
				return nil, abejson.ErrRPCInvalidRequest
			}
			resp, err := handlerData.handler(cmd, w)
			if err != nil {
				return nil, jsonError(err)
			}
			return resp, nil
		}
	}

	// Fallback to RPC passthrough
	return func() (interface{}, *abejson.RPCError) {
		if chainClient == nil {
			return nil, &abejson.RPCError{
				Code:    -1,
				Message: "Chain RPC is inactive",
			}
		}
		switch client := chainClient.(type) {
		case *chain.RPCClient:
			resp, err := client.RawRequest(request.Method,
				request.Params)
			if err != nil {
				return nil, jsonError(err)
			}
			return &resp, nil
		default:
			return nil, &abejson.RPCError{
				Code:    -1,
				Message: "Chain RPC is inactive",
			}
		}
	}
}

// makeResponse makes the JSON-RPC response struct for the result and error
// returned by a requestHandler.  The returned response is not ready for
// marshaling and sending off to a client, but must be
func makeResponse(id, result interface{}, err error) abejson.Response {
	idPtr := idPointer(id)
	if err != nil {
		return abejson.Response{
			ID:    idPtr,
			Error: jsonError(err),
		}
	}
	resultBytes, err := json.Marshal(result)
	if err != nil {
		return abejson.Response{
			ID: idPtr,
			Error: &abejson.RPCError{
				Code:    abejson.ErrRPCInternal.Code,
				Message: "Unexpected error marshalling result",
			},
		}
	}
	return abejson.Response{
		ID:     idPtr,
		Result: json.RawMessage(resultBytes),
	}
}

// jsonError creates a JSON-RPC error from the Go error.
func jsonError(err error) *abejson.RPCError {
	if err == nil {
		return nil
	}

	code := abejson.ErrRPCWallet
	switch e := err.(type) {
	case abejson.RPCError:
		return &e
	case *abejson.RPCError:
		return e
	case DeserializationError:
		code = abejson.ErrRPCDeserialization
	case InvalidParameterError:
		code = abejson.ErrRPCInvalidParameter
	case ParseError:
		code = abejson.ErrRPCParse.Code
	case waddrmgr.ManagerError:
		switch e.ErrorCode {
		case waddrmgr.ErrWrongPassphrase:
			code = abejson.ErrRPCWalletPassphraseIncorrect
		}
	}
	return &abejson.RPCError{
		Code:    code,
		Message: err.Error(),
	}
}

// makeMultiSigScript is a helper function to combine common logic for
// AddMultiSig and CreateMultiSig.

// addMultiSigAddress handles an addmultisigaddress request by adding a
// multisig address to the given wallet.

// createMultiSig handles an createmultisig request by returning a
// multisig address for the given inputs.

// dumpPrivKey handles a dumpprivkey request with the private key
// for a single address, or an appropiate error if the wallet
// is locked.

// dumpWallet handles a dumpwallet request by returning  all private
// keys in a wallet, or an appropiate error if the wallet is locked.

// getAddressesByAccount handles a getaddressesbyaccount request by returning
// all addresses for an account, or an error if the requested account does
// not exist.

// getBalance handles a getbalance request by returning the balance for an
// account (wallet), or an error if the requested account does not
// exist.
func getBalances(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.GetBalancesAbeCmd)

	currentTime := time.Now().String()
	bs := w.Manager.SyncedTo()
	var balances []abeutil.Amount
	//var needUpdateNum int
	var err error
	balances, err = w.CalculateBalance(int32(*cmd.Minconf))
	if err != nil {
		return nil, err
	}
	type tt struct {
		CurrentTime        string  `json:"current_time,omitempty"`
		CurrentHeight      int32   `json:"current_height,omitempty"`
		CurrentBlockHash   string  `json:"current_block_hash,omitempty"`
		TotalBalance       float64 `json:"total_balance"`
		SpendableBalance   float64 `json:"spendable_balance"`
		ImmatureCBBalance  float64 `json:"immature_cb_balance"`
		ImmatureTRBalance  float64 `json:"immature_tr_balance"`
		UnconfirmedBalance float64 `json:"unconfirmed_balance"`
	}
	res := &tt{
		CurrentTime:        currentTime,
		CurrentHeight:      bs.Height,
		CurrentBlockHash:   bs.Hash.String(),
		TotalBalance:       balances[0].ToABE(),
		SpendableBalance:   balances[1].ToABE(),
		ImmatureCBBalance:  balances[2].ToABE(),
		ImmatureTRBalance:  balances[3].ToABE(),
		UnconfirmedBalance: balances[4].ToABE(),
	}
	marshal, err := json.Marshal(res)
	if err != nil {
		return nil, err
	}
	return string(marshal), nil
}

// getDetailedUtxos is a temporary command for convenience of test.
// TODO(abe) this function would be modified
func getDetailedUtxos(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.GetDetailedUtxosCmd)
	res, err := w.FetchDetailedUtxos(int32(*cmd.Minconf))
	if err != nil {
		return nil, err
	}
	return res, nil
}

// getBestBlock handles a getbestblock request by returning a JSON object
// with the height and hash of the most recently processed block.
func getBestBlock(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	blk := w.Manager.SyncedTo()
	result := &abejson.GetBestBlockResult{
		Hash:   blk.Hash.String(),
		Height: blk.Height,
	}
	return result, nil
}

// getBestBlockHash handles a getbestblockhash request by returning the hash
// of the most recently processed block.
// TODO(abe): this function can be reused for abelian
func getBestBlockHash(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	//blk := w.Manager.SyncedTo()
	blk := w.Manager.SyncedTo()
	return blk.Hash.String(), nil
}

// getBlockCount handles a getblockcount request by returning the chain height
// of the most recently processed block.
// TODO(abe): this function can be reused for abelian
func getBlockCount(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	//blk := w.Manager.SyncedTo()
	blk := w.Manager.SyncedTo()
	return blk.Height, nil
}

// getInfo handles a getinfo request by returning the a structure containing
// information about the current state of btcwallet.
// exist.
// TODO(abe): this function needs to be redesigned for abelian
func getInfo(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	// Call down to btcd for all of the information in this command known
	// by them.
	info, err := chainClient.GetInfo()
	if err != nil {
		return nil, err
	}
	// TODO(abe):need add the update number into result struct
	//bal, err := w.CalculateBalance(1)  // switch to calculateBalanceAbe
	bal, err := w.CalculateBalance(1)
	if err != nil {
		return nil, err
	}

	// TODO(davec): This should probably have a database version as opposed
	// to using the manager version.
	info.WalletVersion = int32(waddrmgr.LatestMgrVersion)
	info.Balance = bal[1].ToABE()
	info.PaytxFee = float64(txrules.DefaultRelayFeePerKb)
	// We don't set the following since they don't make much sense in the
	// wallet architecture:
	//  - unlocked_until
	//  - errors

	return info, nil
}

func decodeAddress(s string, params *chaincfg.Params) (abeutil.Address, error) {
	addr, err := abeutil.DecodeAddress(s, params)
	if err != nil {
		msg := fmt.Sprintf("Invalid address %q: decode failed with %#q", s, err)
		return nil, &abejson.RPCError{
			Code:    abejson.ErrRPCInvalidAddressOrKey,
			Message: msg,
		}
	}
	if !addr.IsForNet(params) {
		msg := fmt.Sprintf("Invalid address %q: not intended for use on %s",
			addr, params.Name)
		return nil, &abejson.RPCError{
			Code:    abejson.ErrRPCInvalidAddressOrKey,
			Message: msg,
		}
	}
	return addr, nil
}

// getAccount handles a getaccount request by returning the account name
// associated with a single address.

// getAccountAddress handles a getaccountaddress by returning the most
// recently-created chained address that has not yet been used (does not yet
// appear in the blockchain, or any tx that has arrived in the btcd mempool).
// If the most recently-requested address has been used, a new address (the
// next chained address in the keypool) is used.  This can fail if the keypool
// runs out (and will return abejson.ErrRPCWalletKeypoolRanOut if that happens).

// getUnconfirmedBalance handles a getunconfirmedbalance extension request
// by returning the current unconfirmed balance of an account.

// importPrivKey handles an importprivkey request by parsing
// a WIF-encoded private key and adding it to an account.

// keypoolRefill handles the keypoolrefill command. Since we handle the keypool
// automatically this does nothing since refilling is never manually required.
func keypoolRefill(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	return nil, nil
}

// createNewAccount handles a createnewaccount request by creating and
// returning a new account. If the last account has no transaction history
// as per BIP 0044 a new account cannot be created so an error will be returned.

// renameAccount handles a renameaccount request by renaming an account.
// If the account does not exist an appropiate error will be returned.

// getNewAddress handles a getnewaddress request by returning a new
// address for an account.  If the account does not exist an appropiate
// error is returned.
// TODO: Follow BIP 0044 and warn if number of unused addresses exceeds
// the gap limit.

// getRawChangeAddress handles a getrawchangeaddress request by creating
// and returning a new change address for an account.
//
// Note: bitcoind allows specifying the account as an optional parameter,
// but ignores the parameter.

// getReceivedByAccount handles a getreceivedbyaccount request by returning
// the total amount received by addresses of an account.

// getReceivedByAddress handles a getreceivedbyaddress request by returning
// the total amount received by a single address.

// getTransaction handles a gettransaction request by returning details about
// a single transaction saved by wallet.

// These generators create the following global variables in this package:
//
//   var localeHelpDescs map[string]func() map[string]string
//   var requestUsages string
//
// localeHelpDescs maps from locale strings (e.g. "en_US") to a function that
// builds a map of help texts for each RPC server method.  This prevents help
// text maps for every locale map from being rooted and created during init.
// Instead, the appropiate function is looked up when help text is first needed
// using the current locale and saved to the global below for futher reuse.
//
// requestUsages contains single line usages for every supported request,
// separated by newlines.  It is set during init.  These usages are used for all
// locales.
//
//go:generate go run ../../internal/rpchelp/genrpcserverhelp.go legacyrpc
//go:generate gofmt -w rpcserverhelp.go

var helpDescs map[string]string
var helpDescsMu sync.Mutex // Help may execute concurrently, so synchronize access.

// helpWithChainRPC handles the help request when the RPC server has been
// associated with a consensus RPC client.  The additional RPC client is used to
// include help messages for methods implemented by the consensus server via RPC
// passthrough.
func helpWithChainRPC(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	return help(icmd, w, chainClient)
}

// helpNoChainRPC handles the help request when the RPC server has not been
// associated with a consensus RPC client.  No help messages are included for
// passthrough requests.
func helpNoChainRPC(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	return help(icmd, w, nil)
}

// help handles the help request by returning one line usage of all available
// methods, or full help for a specific method.  The chainClient is optional,
// and this is simply a helper function for the HelpNoChainRPC and
// HelpWithChainRPC handlers.
func help(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	cmd := icmd.(*abejson.HelpCmd)

	// btcd returns different help messages depending on the kind of
	// connection the client is using.  Only methods availble to HTTP POST
	// clients are available to be used by wallet clients, even though
	// wallet itself is a websocket client to btcd.  Therefore, create a
	// POST client as needed.
	//
	// Returns nil if chainClient is currently nil or there is an error
	// creating the client.
	//
	// This is hacky and is probably better handled by exposing help usage
	// texts in a non-internal btcd package.
	postClient := func() *rpcclient.Client {
		if chainClient == nil {
			return nil
		}
		c, err := chainClient.POSTClient()
		if err != nil {
			return nil
		}
		return c
	}
	if cmd.Command == nil || *cmd.Command == "" {
		// Prepend chain server usage if it is available.
		usages := requestUsages
		client := postClient()
		if client != nil {
			rawChainUsage, err := client.RawRequest("help", nil)
			var chainUsage string
			if err == nil {
				_ = json.Unmarshal([]byte(rawChainUsage), &chainUsage)
			}
			if chainUsage != "" {
				usages = "Chain server usage:\n\n" + chainUsage + "\n\n" +
					"Wallet server usage (overrides chain requests):\n\n" +
					requestUsages
			}
		}
		return usages, nil
	}

	defer helpDescsMu.Unlock()
	helpDescsMu.Lock()

	if helpDescs == nil {
		// TODO: Allow other locales to be set via config or detemine
		// this from environment variables.  For now, hardcode US
		// English.
		helpDescs = localeHelpDescs["en_US"]()
	}

	helpText, ok := helpDescs[*cmd.Command]
	if ok {
		return helpText, nil
	}

	// Return the chain server's detailed help if possible.
	var chainHelp string
	client := postClient()
	if client != nil {
		param := make([]byte, len(*cmd.Command)+2)
		param[0] = '"'
		copy(param[1:], *cmd.Command)
		param[len(param)-1] = '"'
		rawChainHelp, err := client.RawRequest("help", []json.RawMessage{param})
		if err == nil {
			_ = json.Unmarshal([]byte(rawChainHelp), &chainHelp)
		}
	}
	if chainHelp != "" {
		return chainHelp, nil
	}
	return nil, &abejson.RPCError{
		Code:    abejson.ErrRPCInvalidParameter,
		Message: fmt.Sprintf("No help for method '%s'", *cmd.Command),
	}
}

// listAccounts handles a listaccounts request by returning a map of account
// names to their balances.

// listLockUnspent handles a listlockunspent request by returning an slice of
// all locked outpoints.
func listLockUnspent(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	return w.LockedOutpoints(), nil
}

// listReceivedByAccount handles a listreceivedbyaccount request by returning
// a slice of objects, each one containing:
//  "account": the receiving account;
//  "amount": total amount received by the account;
//  "confirmations": number of confirmations of the most recent transaction.
// It takes two parameters:
//  "minconf": minimum number of confirmations to consider a transaction -
//             default: one;
//  "includeempty": whether or not to include addresses that have no transactions -
//                  default: false.

// listReceivedByAddress handles a listreceivedbyaddress request by returning
// a slice of objects, each one containing:
//  "account": the account of the receiving address;
//  "address": the receiving address;
//  "amount": total amount received by the address;
//  "confirmations": number of confirmations of the most recent transaction.
// It takes two parameters:
//  "minconf": minimum number of confirmations to consider a transaction -
//             default: one;
//  "includeempty": whether or not to include addresses that have no transactions -
//                  default: false.

// listSinceBlock handles a listsinceblock request by returning an array of maps
// with details of sent and received wallet transactions since the given block.

// listTransactions handles a listtransactions request by returning an
// array of maps with details of sent and recevied wallet transactions.

// listAddressTransactions handles a listaddresstransactions request by
// returning an array of maps with details of spent and received wallet
// transactions.  The form of the reply is identical to listtransactions,
// but the array elements are limited to transaction details which are
// about the addresess included in the request.

// listAllTransactions handles a listalltransactions request by returning
// a map with details of sent and recevied wallet transactions.  This is
// similar to ListTransactions, except it takes only a single optional
// argument for the account name and replies with all transactions.

// listUnspent handles the listunspent command.

// For test
type utxo struct {
	RingHash         string
	TxHash           string
	Index            uint8
	FromCoinbase     bool
	Amount           uint64
	Height           int32
	UTXOHash         chainhash.Hash `json:"-"`
	UTXOHashStr      string
	SpentByTxHash    chainhash.Hash `json:"-"`
	SpentByTxHashStr string         `json:"spentByTxHashStr,omitempty"`
	SpentTime        string         `json:"spentTime,omitempty"`
	ConfirmTime      string         `json:"confirmTime,omitempty"`
}
type utxoset []utxo

func (u *utxoset) Len() int {
	return len(*u)
}

func (u *utxoset) Less(i, j int) bool {
	return (*u)[i].Height < (*u)[j].Height
}

func (u *utxoset) Swap(i, j int) {
	(*u)[i], (*u)[j] = (*u)[j], (*u)[i]
}
func listAllUTXOAbe(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.ListAllUnspentAbeCmd)
	segment := false
	if *cmd.Max != 0 && *cmd.Min != 0 && *cmd.Max >= *cmd.Min {
		segment = true
	}
	utxos, err := w.FetchUnspentUTXOSet()
	if err != nil {
		return nil, err
	}
	unmatureds, err := w.FetchUnmatruedUTXOSet()
	if err != nil {
		return nil, err
	}
	res := make([]utxo, 0, len(utxos)+len(unmatureds))
	for i := 0; i < len(utxos); i++ {
		res = append(res, utxo{
			RingHash:     utxos[i].RingHash.String(),
			TxHash:       utxos[i].TxOutput.TxHash.String(),
			Index:        utxos[i].TxOutput.Index,
			FromCoinbase: utxos[i].FromCoinBase,
			Amount:       utxos[i].Amount,
			Height:       utxos[i].Height,
			UTXOHash:     utxos[i].Hash(),
			UTXOHashStr:  utxos[i].Hash().String(),
		})
	}
	for i := 0; i < len(unmatureds); i++ {
		res = append(res, utxo{
			RingHash:     unmatureds[i].RingHash.String(),
			TxHash:       unmatureds[i].TxOutput.TxHash.String(),
			Index:        unmatureds[i].TxOutput.Index,
			FromCoinbase: unmatureds[i].FromCoinBase,
			Amount:       unmatureds[i].Amount,
			Height:       unmatureds[i].Height,
			UTXOHash:     unmatureds[i].Hash(),
			UTXOHashStr:  utxos[i].Hash().String(),
		})
	}
	if !segment {
		t := utxoset(res)
		sort.Sort(&t)
		return res, nil
	}
	return segmentationTXOSet(res, *cmd.Min, *cmd.Max), nil
}
func listUnmaturedUTXOAbe(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.ListUnmaturedAbeCmd)
	segment := false
	if *cmd.Max != 0 && *cmd.Min != 0 && *cmd.Max >= *cmd.Min {
		segment = true
	}
	unmatureds, err := w.FetchUnmatruedUTXOSet()
	if err != nil {
		return nil, err
	}
	res := make([]utxo, 0, len(unmatureds))
	for i := 0; i < len(unmatureds); i++ {
		res = append(res, utxo{
			RingHash:     unmatureds[i].RingHash.String(),
			TxHash:       unmatureds[i].TxOutput.TxHash.String(),
			Index:        unmatureds[i].TxOutput.Index,
			FromCoinbase: unmatureds[i].FromCoinBase,
			Amount:       unmatureds[i].Amount,
			Height:       unmatureds[i].Height,
			UTXOHash:     unmatureds[i].Hash(),
			UTXOHashStr:  unmatureds[i].Hash().String(),
		})
	}
	if !segment {
		t := utxoset(res)
		sort.Sort(&t)
		return res, nil
	}
	return segmentationTXOSet(res, *cmd.Min, *cmd.Max), nil
}

func listUnspentAbe(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.ListUnspentAbeCmd)
	segment := false
	if *cmd.Max != 0 && *cmd.Min != 0 && *cmd.Max >= *cmd.Min {
		segment = true
	}
	utxos, err := w.FetchUnspentUTXOSet()
	if err != nil {
		return nil, err
	}
	res := make([]utxo, 0, len(utxos))
	for i := 0; i < len(utxos); i++ {
		res = append(res, utxo{
			RingHash:     utxos[i].RingHash.String(),
			TxHash:       utxos[i].TxOutput.TxHash.String(),
			Index:        utxos[i].TxOutput.Index,
			FromCoinbase: utxos[i].FromCoinBase,
			Amount:       utxos[i].Amount,
			Height:       utxos[i].Height,
			UTXOHash:     utxos[i].Hash(),
			UTXOHashStr:  utxos[i].Hash().String(),
		})
	}
	if !segment {
		t := utxoset(res)
		sort.Sort(&t)
		return res, nil
	}
	return segmentationTXOSet(res, *cmd.Min, *cmd.Max), nil
}

func listUnspentCoinbaseAbe(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	_ = icmd.(*abejson.ListUnspentCoinbaseAbeCmd)
	utxos, err := w.FetchUnspentUTXOSet()
	if err != nil {
		return nil, err
	}
	res := make([]utxo, 0, len(utxos))
	for i := 0; i < len(utxos); i++ {
		if utxos[i].FromCoinBase {
			res = append(res, utxo{
				RingHash:     utxos[i].RingHash.String(),
				TxHash:       utxos[i].TxOutput.TxHash.String(),
				Index:        utxos[i].TxOutput.Index,
				FromCoinbase: utxos[i].FromCoinBase,
				Amount:       utxos[i].Amount,
				Height:       utxos[i].Height,
				UTXOHash:     utxos[i].Hash(),
				UTXOHashStr:  utxos[i].Hash().String(),
			})
		}

	}
	t := utxoset(res)
	sort.Sort(&t)
	return res, nil
}

func listSpentButUnminedAbe(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.ListSpentButUnminedAbeCmd)
	segment := false
	if *cmd.Max != 0 && *cmd.Min != 0 && *cmd.Max >= *cmd.Min {
		segment = true
	}
	sbutxos, err := w.FetchSpentButUnminedTXOSet()
	if err != nil {
		return nil, err
	}
	res := make([]utxo, 0, len(sbutxos))
	for i := 0; i < len(sbutxos); i++ {
		res = append(res, utxo{
			RingHash:         sbutxos[i].RingHash.String(),
			TxHash:           sbutxos[i].TxOutput.TxHash.String(),
			Index:            sbutxos[i].TxOutput.Index,
			FromCoinbase:     sbutxos[i].FromCoinBase,
			Amount:           sbutxos[i].Amount,
			Height:           sbutxos[i].Height,
			UTXOHash:         sbutxos[i].Hash(),
			UTXOHashStr:      sbutxos[i].Hash().String(),
			SpentByTxHash:    sbutxos[i].SpentByHash,
			SpentByTxHashStr: sbutxos[i].SpentByHash.String(),
			SpentTime:        sbutxos[i].SpentTime.Format("2006-01-02 15:04:05"),
		})
	}
	if !segment {
		t := utxoset(res)
		sort.Sort(&t)
		return res, nil
	}
	return segmentationTXOSet(res, *cmd.Min, *cmd.Max), nil
}
func listSpentAndMinedAbe(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.ListSpentAndMinedAbeCmd)
	segment := false
	if *cmd.Max != 0 && *cmd.Min != 0 && *cmd.Max >= *cmd.Min {
		segment = true
	}
	sctxos, err := w.FetchSpentAndConfirmedTXOSet()
	if err != nil {
		return nil, err
	}
	res := make([]utxo, 0, len(sctxos))
	for i := 0; i < len(sctxos); i++ {
		res = append(res, utxo{
			RingHash:         sctxos[i].RingHash.String(),
			TxHash:           sctxos[i].TxOutput.TxHash.String(),
			Index:            sctxos[i].TxOutput.Index,
			FromCoinbase:     sctxos[i].FromCoinBase,
			Amount:           sctxos[i].Amount,
			Height:           sctxos[i].Height,
			UTXOHash:         sctxos[i].Hash(),
			UTXOHashStr:      sctxos[i].Hash().String(),
			SpentByTxHash:    sctxos[i].SpentByHash,
			SpentByTxHashStr: sctxos[i].SpentByHash.String(),
			SpentTime:        sctxos[i].SpentTime.Format("2006-01-02 15:04:05"),
			ConfirmTime:      sctxos[i].ConfirmTime.Format("2006-01-02 15:04:05"),
		})
	}
	if !segment {
		t := utxoset(res)
		sort.Sort(&t)
		return res, nil
	}
	return segmentationTXOSet(res, *cmd.Min, *cmd.Max), nil
}
func listConfirmedTxs(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.ListConfirmedTxsCmd)
	if *cmd.Verbose == 0 {
		confirmedTxHashs, err := w.FetchConfirmedTxHashs()
		if err != nil {
			return nil, err
		}
		res := make([]string, len(confirmedTxHashs))
		for i := 0; i < len(confirmedTxHashs); i++ {
			res[i] = confirmedTxHashs[i].String()
		}
		return res, nil
	}

	confirmedTxs, err := w.FetchConfirmedTransactions()
	if err != nil {
		return nil, err
	}

	txReplies := make([]*abejson.TxRawResultAbe, 0, len(confirmedTxs))
	for i := 0; i < len(confirmedTxs); i++ {
		reply, _ := createTxRawResultAbe(
			nil,
			&confirmedTxs[i].MsgTx,
			confirmedTxs[i].MsgTx.TxHash().String(),
			nil,
			"",
			0,
			0,
			*cmd.Verbose)
		txReplies = append(txReplies, reply)
	}

	return txReplies, nil
}
func listUnconfirmedTxs(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.ListUnconfirmedTxsCmd)
	if *cmd.Verbose == 0 {
		unconfirmedTxHashs, err := w.FetchUnconfirmedTxHashs()
		if err != nil {
			return nil, err
		}
		res := make([]string, len(unconfirmedTxHashs))
		for i := 0; i < len(unconfirmedTxHashs); i++ {
			res[i] = unconfirmedTxHashs[i].String()
		}
		return res, nil
	}
	unconfirmedTxs, err := w.FetchUnconfirmedTransactions()
	if err != nil {
		return nil, err
	}

	txReplies := make([]*abejson.TxRawResultAbe, 0, len(unconfirmedTxs))
	for i := 0; i < len(unconfirmedTxs); i++ {
		reply, _ := createTxRawResultAbe(
			nil,
			&unconfirmedTxs[i].MsgTx,
			unconfirmedTxs[i].MsgTx.TxHash().String(),
			nil,
			"",
			0,
			0,
			*cmd.Verbose)
		txReplies = append(txReplies, reply)
	}
	return txReplies, nil
}

func listInvalidTxs(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.ListInvalidTxsCmd)
	if *cmd.Verbose == 0 {
		invalidTxHashs, err := w.FetchInvalidTxHashs()
		if err != nil {
			return nil, err
		}
		res := make([]string, len(invalidTxHashs))
		for i := 0; i < len(invalidTxHashs); i++ {
			res[i] = invalidTxHashs[i].String()
		}
		return res, nil
	}
	invalidTxs, err := w.FetchInvalidTransactions()
	if err != nil {
		return nil, err
	}
	txReplies := make([]*abejson.TxRawResultAbe, 0, len(invalidTxs))
	for i := 0; i < len(invalidTxs); i++ {
		reply, _ := createTxRawResultAbe(
			nil,
			&invalidTxs[i].MsgTx,
			invalidTxs[i].MsgTx.TxHash().String(),
			nil,
			"",
			0,
			0,
			*cmd.Verbose)
		txReplies = append(txReplies, reply)
	}
	return txReplies, nil
}

func txStatus(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.TxStatusCmd)
	txHash, err := chainhash.NewHashFromStr(cmd.TxHash)
	if err != nil {
		return -1, err
	}
	status, err := w.TransactionStatus(txHash)
	if err != nil {
		return nil, err
	}
	return status, nil
}

// lockUnspent handles the lockunspent command.
func lockUnspent(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.LockUnspentCmd)

	switch {
	case cmd.Unlock && len(cmd.Transactions) == 0:
		w.ResetLockedOutpoints()
	default:
		for _, input := range cmd.Transactions {
			txHash, err := chainhash.NewHashFromStr(input.Txid)
			if err != nil {
				return nil, ParseError{err}
			}
			op := wire.OutPoint{Hash: *txHash, Index: input.Vout}
			if cmd.Unlock {
				w.UnlockOutpoint(op)
			} else {
				w.LockOutpoint(op)
			}
		}
	}
	return true, nil
}
func getTxHashFromRequest(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.GetTxHashFromReqeustCmd)

	if !w.RecordRequestFlag {
		return nil, errors.New("please enable the record request flag for wallet first")
	}

	return w.GetTxHashRequestHash(cmd.RequestHashStr)
}

// makeOutputs creates a slice of transaction outputs from a pair of address
// strings to amounts.  This is used to create the outputs to include in newly
// created transactions from a JSON object describing the output destinations
// and amounts.
// TODO(abe): we must use payee to send some coin
func makeOutputs(pairs map[string]abeutil.Amount, chainParams *chaincfg.Params) ([]*wire.TxOut, error) {
	outputs := make([]*wire.TxOut, 0, len(pairs))
	for addrStr, amt := range pairs {
		addr, err := abeutil.DecodeAddress(addrStr, chainParams)
		if err != nil {
			return nil, fmt.Errorf("cannot decode address: %s", err)
		}

		pkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, fmt.Errorf("cannot create txout script: %s", err)
		}

		outputs = append(outputs, wire.NewTxOut(int64(amt), pkScript))
	}
	return outputs, nil
}

// checkValidAddress checks whether the given address meets the requirement,
// including netID and verification hash
func checkValidAddress(addr []byte, chainParams *chaincfg.Params) error {
	if len(addr) < 33 {
		return errors.New("the length of address is incorrect")
	}

	// Check netID
	netID := addr[0]
	if netID != chainParams.PQRingCTID {
		return errors.New("address verification fails: the netID of address does not match the active net")
	}

	// Check verification hash
	verifyBytes := addr[:len(addr)-32]
	dstHash0 := addr[len(addr)-32:]
	dstHash, _ := chainhash.NewHash(dstHash0)
	realHash := chainhash.DoubleHashH(verifyBytes)
	if !dstHash.IsEqual(&realHash) {
		return errors.New("address verification fails: verification hash does not match")
	}
	return nil
}

func makeOutputDescsForPairs(w *wallet.Wallet, pairs []abejson.Pair, chainParams *chaincfg.Params) ([]*abecrypto.AbeTxOutputDesc, error) {
	outputDescs := make([]*abecrypto.AbeTxOutputDesc, 0, len(pairs))
	for i := 0; i < len(pairs); i++ {
		addr, err := hex.DecodeString(pairs[i].Address)
		if err != nil {
			return nil, err
		}
		err = checkValidAddress(addr, chainParams)
		if err != nil {
			return nil, err
		}
		targetAmount := uint64(pairs[i].Amount)
		addr = addr[1 : len(addr)-32]
		outputDesc := abecrypto.NewAbeTxOutDesc(addr, targetAmount)

		outputDescs = append(outputDescs, outputDesc)
	}
	return outputDescs, nil
}

func makeOutputDescs(w *wallet.Wallet, pairs map[string]abeutil.Amount, chainParams *chaincfg.Params) ([]*abecrypto.AbeTxOutputDesc, error) {
	outputDescs := make([]*abecrypto.AbeTxOutputDesc, 0, len(pairs))
	for addrStr, amt := range pairs {
		//payeeManager, err := w.FetchPayeeManager(name)
		//if payeeManager == nil {
		//	return nil, err
		//}
		//addr, err := payeeManager.ChooseMAddr()
		//if err != nil {
		//	return nil, fmt.Errorf("cannot get an address from given payee: %s", err)
		//}
		addr, err := hex.DecodeString(addrStr)
		if err != nil {
			return nil, err
		}
		targetAmount := uint64(amt)
		// TODO: check the net ID and the check hash
		// discard the heading net ID and tailing hash in address
		addr = addr[1 : len(addr)-32]
		outputDesc := abecrypto.NewAbeTxOutDesc(addr, targetAmount)

		outputDescs = append(outputDescs, outputDesc)
	}
	return outputDescs, nil
}

// sendPairs creates and sends payment transactions.
// It returns the transaction hash in string format upon success
// All errors are returned in abejson.RPCError format

func isNilOrEmpty(s *string) bool {
	return s == nil || *s == ""
}

func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for _, ch := range s {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return false
		}
	}
	return true
}

//	todo: to confirm : modified by AliceBob on 15 June
/*func sendPairsAbe(w *wallet.Wallet, amounts map[string]abeutil.Amount,
	minconf int32, feeSatPerKb abeutil.Amount) (string, error) {

	//outputs, err := makeOutputsAbe(w, amounts, w.ChainParams())
	outputDescs, err := makeOutputDescs(w, amounts, w.ChainParams())
	if err != nil {
		return "", err
	}
	tx, err := w.SendOutputsAbe(outputDescs, minconf, feeSatPerKb, "") // TODO(abe): what's label?
	if err != nil {
		if err == txrules.ErrAmountNegative {
			return "", ErrNeedPositiveAmount
		}
		if waddrmgr.IsError(err, waddrmgr.ErrLocked) {
			return "", &ErrWalletUnlockNeeded
		}
		switch err.(type) {
		case abejson.RPCError:
			return "", err
		}

		return "", &abejson.RPCError{
			Code:    abejson.ErrRPCInternal.Code,
			Message: err.Error(),
		}
	}

	txHashStr := tx.TxHash().String()
	log.Infof("Successfully sent transaction %v", txHashStr)
	return txHashStr, nil
}*/

func sendAddressAbe(w *wallet.Wallet, amounts []abejson.Pair,
	minconf int32, feePerKbSpecified abeutil.Amount, feeSpecified abeutil.Amount, utxoSpecified []string) (string, error) {

	outputDescs, err := makeOutputDescsForPairs(w, amounts, w.ChainParams())
	if err != nil {
		return "", err
	}
	var requestHash *chainhash.Hash
	if w.RecordRequestFlag {
		requestContentBuff := &bytes.Buffer{}
		for i := 0; i < len(outputDescs); i++ {
			requestContentBuff.WriteString(amounts[i].Address)
			wire.WriteVarInt(requestContentBuff, 0, uint64(amounts[i].Amount))
		}
		for i := 0; i < len(utxoSpecified); i++ {
			requestContentBuff.WriteString(utxoSpecified[i])
		}
		wire.WriteVarInt(requestContentBuff, 0, uint64(feeSpecified))
		tmp := chainhash.HashH(requestContentBuff.Bytes())
		requestHash = &tmp
		log.Infof("generate request hash:%s", requestHash)
		// if the record request flag is enabled, then query the database
		requestMap, err := w.GetTxHashRequestHash(requestHash.String())
		if err == nil {
			txHashStr, ok := requestMap["txHash"].(string)
			if ok {
				return txHashStr, nil
			}
		}
	}
	tx, err := w.SendOutputs(outputDescs, minconf, feePerKbSpecified, feeSpecified, utxoSpecified, "", requestHash) // TODO(abe): what's label?
	if err != nil {
		if err == txrules.ErrAmountNegative {
			return "", ErrNeedPositiveAmount
		}
		if waddrmgr.IsError(err, waddrmgr.ErrLocked) {
			return "", &ErrWalletUnlockNeeded
		}
		switch err.(type) {
		case abejson.RPCError:
			return "", err
		}

		return "", &abejson.RPCError{
			Code:    abejson.ErrRPCInternal.Code,
			Message: err.Error(),
		}
	}
	txHashStr := tx.Tx.TxHash().String()
	log.Infof("Successfully sent transaction %v", txHashStr)
	return txHashStr + fmt.Sprintf("\nCurrent max No. of address is %d", tx.ChangeAddressNo), nil
}

func sendPairsAbe(w *wallet.Wallet, amounts map[string]abeutil.Amount,
	minconf int32, feePerKbSpecified abeutil.Amount, feeSpecified abeutil.Amount, utxoSpecified []string) (string, error) {

	//outputs, err := makeOutputsAbe(w, amounts, w.ChainParams())
	outputDescs, err := makeOutputDescs(w, amounts, w.ChainParams())
	if err != nil {
		return "", err
	}
	tx, err := w.SendOutputs(outputDescs, minconf, feePerKbSpecified, feeSpecified, utxoSpecified, "", nil) // TODO(abe): what's label?
	if err != nil {
		if err == txrules.ErrAmountNegative {
			return "", ErrNeedPositiveAmount
		}
		if waddrmgr.IsError(err, waddrmgr.ErrLocked) {
			return "", &ErrWalletUnlockNeeded
		}
		switch err.(type) {
		case abejson.RPCError:
			return "", err
		}

		return "", &abejson.RPCError{
			Code:    abejson.ErrRPCInternal.Code,
			Message: err.Error(),
		}
	}

	txHashStr := tx.Tx.TxHash().String()
	log.Infof("Successfully sent transaction %v", txHashStr)
	return txHashStr, nil
}

func sendToPayees(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.SendToPayeesCmd)

	// Transaction comments are not yet supported.  Error instead of
	// pretending to save them.
	if !isNilOrEmpty(cmd.Comment) {
		return nil, &abejson.RPCError{
			Code:    abejson.ErrRPCUnimplemented,
			Message: "Transaction comments are not yet supported",
		}
	}

	// Check that minconf is positive.
	minConf := int32(*cmd.MinConf)
	if minConf < 0 {
		return nil, ErrNeedPositiveMinconf
	}

	// Recreate address/amount pairs, using abeutil.Amount.
	pairs := make(map[string]abeutil.Amount, len(cmd.Amounts))
	for k, v := range cmd.Amounts {
		amt, err := abeutil.NewAmountAbe(v)
		if err != nil {
			return nil, err
		}
		pairs[k] = amt
	}

	//	todo: the fee policy
	feeSatPerKb := txrules.DefaultRelayFeePerKb // todo: AliceBobScorpio, should use the feeSatPerKb received from abec
	scaleToFeeSatPerKb := *cmd.ScaleToFeeSatPerKb
	feeSpecified, err := abeutil.NewAmountAbe(*cmd.FeeSpecified)
	if err != nil {
		return nil, err
	}

	if scaleToFeeSatPerKb != 1 {
		// set the scaleToFeeSatPerKb
		feeSatPerKb = feeSatPerKb.MulF64(scaleToFeeSatPerKb)
		feeSpecified = abeutil.Amount(0)
	} else if feeSpecified != 0 && scaleToFeeSatPerKb == 1 {
		//	if neither scaleToFeeSatPerKb or feeSpecified is specified, the use scaleToFeeSatPerKb = 1
		//	feeSatPerKb = feeSatPerKb
		//	feeSpecified = 0
		//	i.e. nothing to do
	}

	var utxoSpecified []string = nil
	if cmd.UTXOSpecified != nil {
		utxoSpecified = strings.Split(*cmd.UTXOSpecified, ",")
		utxoNum := len(utxoSpecified)
		for i := 0; i < utxoNum; i++ {
			utxoSpecified[i] = strings.TrimSpace(utxoSpecified[i])
			if !isHexString(utxoSpecified[i]) {
				return nil, ErrSpeicifiedUTXOWrong
			}
		}
	}

	// return sendPairsAbe(w, pairs, minConf, txrules.DefaultRelayFeePerKb)
	//	todo: AliceBobScorpio, should use the feeSatPerKb received from abec
	return sendPairsAbe(w, pairs, minConf, feeSatPerKb, feeSpecified, utxoSpecified)
}

// sendFrom handles a sendfrom RPC request by creating a new transaction
// spending unspent transaction outputs for a wallet to another payment
// address.  Leftover inputs not sent to the payment address or a fee for
// the miner are sent back to a new address in the wallet.  Upon success,
// the TxID for the created transaction is returned.

// sendMany handles a sendmany RPC request by creating a new transaction
// spending unspent transaction outputs for a wallet to any number of
// payment addresses.  Leftover inputs not sent to the payment address
// or a fee for the miner are sent back to a new address in the wallet.
// Upon success, the TxID for the created transaction is returned.

func addressMaxSequenceNumber(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	_ = icmd.(*abejson.AddressMaxSequenceNumberCmd)
	addressMaxSN, err := w.AddressMaxSequenceNumber()
	if err != nil {
		return -1, err
	}
	return addressMaxSN, nil
}

func addressRange(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.AddressRangeCmd)
	res, err := w.AddressRange(cmd.Start, cmd.End)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func generateAddressAbe(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.GenerateAddressCmd)
	number := *cmd.Num

	var err error
	numberOrder := make([]uint64, number)
	addresses := make([][]byte, number)

	for i := 0; i < number; i++ {
		var address []byte
		var netID []byte
		netID, numberOrder[i], address, err = w.NewAddressKey()
		if err != nil {
			return nil, err
		}
		addresses[i] = make([]byte, len(netID)+len(address)+32)
		// TODO: How to know the active net?
		copy(addresses[i][:len(netID)], netID)
		copy(addresses[i][len(netID):], address)
		// generate the hash of (abecrypto.CryptoSchemePQRINGCT || serialized address)
		hash := chainhash.DoubleHashB(addresses[i][:len(address)+len(netID)])
		copy(addresses[i][len(address)+len(netID):], hash[:])
	}
	type tt struct {
		No_  uint64 `json:"No,omitempty"`
		Addr string `json:"addr,omitempty"`
	}
	res := make([]*tt, number)
	for i := 0; i < number; i++ {
		res[i] = &tt{
			No_:  numberOrder[i],
			Addr: hex.EncodeToString(addresses[i]),
		}
	}
	return res, nil
}
func listFreeAddress(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	_ = icmd.(*abejson.ListFreeAddressesCmd)

	addressBytes, err := w.ListFreeAddresses()
	if err != nil {
		return nil, err
	}
	type tt struct {
		No_  uint64 `json:"No,omitempty"`
		Addr string `json:"addr,omitempty"`
	}
	res := make([]*tt, 0, len(addressBytes))
	for idx, addressByte := range addressBytes {
		res = append(res, &tt{
			No_:  idx,
			Addr: hex.EncodeToString(addressByte),
		})
	}
	return res, nil
}
func sendToAddressesAbe(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.SendToAddressAbeCmd)

	// Transaction comments are not yet supported.  Error instead of
	// pretending to save them.
	if !isNilOrEmpty(cmd.Comment) {
		return nil, &abejson.RPCError{
			Code:    abejson.ErrRPCUnimplemented,
			Message: "Transaction comments are not yet supported",
		}
	}

	// Check that minconf is positive.
	minConf := int32(*cmd.MinConf)
	if minConf < 0 {
		return nil, ErrNeedPositiveMinconf
	}

	//	todo: the fee policy
	// TODO: abec use perhkb to replace perkb to allow users to use smaller tx fee
	// but here it seems to keep a larger one
	// TODO 20230323 use perhkb to replace the perkb
	feeSatPerKb := txrules.DefaultRelayFeePerKb //default
	scaleToFeeSatPerKb := *cmd.ScaleToFeeSatPerKb
	feeSpecified, err := abeutil.NewAmountAbe(*cmd.FeeSpecified)
	if err != nil {
		return nil, err
	}

	if scaleToFeeSatPerKb != 1 {
		// set the scaleToFeeSatPerKb
		feeSatPerKb = feeSatPerKb.MulF64(scaleToFeeSatPerKb)
		feeSpecified = abeutil.Amount(0)
	} else if feeSpecified != 0 && scaleToFeeSatPerKb == 1 {
		//	if neither scaleToFeeSatPerKb nor feeSpecified is specified, the use scaleToFeeSatPerKb = 1
		//	feeSatPerKb = feeSatPerKb
		//	feeSpecified = 0
		//	i.e. nothing to do
	}

	var utxoSpecified []string = nil
	if cmd.UTXOSpecified != nil {
		utxoSpecified = strings.Split(*cmd.UTXOSpecified, ",")
		utxoNum := len(utxoSpecified)
		for i := 0; i < utxoNum; i++ {
			utxoSpecified[i] = strings.TrimSpace(utxoSpecified[i])
			if !isHexString(utxoSpecified[i]) {
				return nil, ErrSpeicifiedUTXOWrong
			}
		}
	}

	return sendAddressAbe(w, cmd.Amounts, minConf, feeSatPerKb, feeSpecified, utxoSpecified)
}

// sendToAddress handles a sendtoaddress RPC request by creating a new
// transaction spending unspent transaction outputs for a wallet to another
// payment address.  Leftover inputs not sent to the payment address or a fee
// for the miner are sent back to a new address in the wallet.  Upon success,
// the TxID for the created transaction is returned.

// setTxFee sets the transaction fee per kilobyte added to transactions.
func setTxFee(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.SetTxFeeCmd)

	// Check that amount is not negative.
	if cmd.Amount < 0 {
		return nil, ErrNeedPositiveAmount
	}

	// A boolean true result is returned upon success.
	return true, nil
}

// signMessage signs the given message with the private key for the given
// address

// signRawTransaction handles the signrawtransaction command.
func signRawTransaction(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	_ = icmd.(*abejson.SignRawTransactionCmd)

	return nil, fmt.Errorf("unsupport")
	//serializedTx, err := decodeHexStr(cmd.RawTx)
	//if err != nil {
	//	return nil, err
	//}
	//var tx wire.MsgTx
	//err = tx.Deserialize(bytes.NewBuffer(serializedTx))
	//if err != nil {
	//	e := errors.New("TX decode failed")
	//	return nil, DeserializationError{e}
	//}
	//
	//var hashType txscript.SigHashType
	//switch *cmd.Flags {
	//case "ALL":
	//	hashType = txscript.SigHashAll
	//case "NONE":
	//	hashType = txscript.SigHashNone
	//case "SINGLE":
	//	hashType = txscript.SigHashSingle
	//case "ALL|ANYONECANPAY":
	//	hashType = txscript.SigHashAll | txscript.SigHashAnyOneCanPay
	//case "NONE|ANYONECANPAY":
	//	hashType = txscript.SigHashNone | txscript.SigHashAnyOneCanPay
	//case "SINGLE|ANYONECANPAY":
	//	hashType = txscript.SigHashSingle | txscript.SigHashAnyOneCanPay
	//default:
	//	e := errors.New("Invalid sighash parameter")
	//	return nil, InvalidParameterError{e}
	//}
	//
	//// TODO: really we probably should look these up with btcd anyway to
	//// make sure that they match the blockchain if present.
	//inputs := make(map[wire.OutPoint][]byte)
	//scripts := make(map[string][]byte)
	//var cmdInputs []abejson.RawTxInput
	//if cmd.Inputs != nil {
	//	cmdInputs = *cmd.Inputs
	//}
	//for _, rti := range cmdInputs {
	//	inputHash, err := chainhash.NewHashFromStr(rti.Txid)
	//	if err != nil {
	//		return nil, DeserializationError{err}
	//	}
	//
	//	script, err := decodeHexStr(rti.ScriptPubKey)
	//	if err != nil {
	//		return nil, err
	//	}
	//
	//	// redeemScript is only actually used iff the user provided
	//	// private keys. In which case, it is used to get the scripts
	//	// for signing. If the user did not provide keys then we always
	//	// get scripts from the wallet.
	//	// Empty strings are ok for this one and hex.DecodeString will
	//	// DTRT.
	//	if cmd.PrivKeys != nil && len(*cmd.PrivKeys) != 0 {
	//		redeemScript, err := decodeHexStr(rti.RedeemScript)
	//		if err != nil {
	//			return nil, err
	//		}
	//
	//		addr, err := abeutil.NewAddressScriptHash(redeemScript,
	//			w.ChainParams())
	//		if err != nil {
	//			return nil, DeserializationError{err}
	//		}
	//		scripts[addr.String()] = redeemScript
	//	}
	//	inputs[wire.OutPoint{
	//		Hash:  *inputHash,
	//		Index: rti.Vout,
	//	}] = script
	//}
	//
	//// Now we go and look for any inputs that we were not provided by
	//// querying btcd with getrawtransaction. We queue up a bunch of async
	//// requests and will wait for replies after we have checked the rest of
	//// the arguments.
	//requested := make(map[wire.OutPoint]rpcclient.FutureGetTxOutResult)
	//for _, txIn := range tx.TxIn {
	//	// Did we get this outpoint from the arguments?
	//	if _, ok := inputs[txIn.PreviousOutPoint]; ok {
	//		continue
	//	}
	//
	//	// Asynchronously request the output script.
	//	requested[txIn.PreviousOutPoint] = chainClient.GetTxOutAsync(
	//		&txIn.PreviousOutPoint.Hash, txIn.PreviousOutPoint.Index,
	//		true)
	//}
	//
	//// Parse list of private keys, if present. If there are any keys here
	//// they are the keys that we may use for signing. If empty we will
	//// use any keys known to us already.
	//var keys map[string]*abeutil.WIF
	//if cmd.PrivKeys != nil {
	//	keys = make(map[string]*abeutil.WIF)
	//
	//	for _, key := range *cmd.PrivKeys {
	//		wif, err := abeutil.DecodeWIF(key)
	//		if err != nil {
	//			return nil, DeserializationError{err}
	//		}
	//
	//		if !wif.IsForNet(w.ChainParams()) {
	//			s := "key network doesn't match wallet's"
	//			return nil, DeserializationError{errors.New(s)}
	//		}
	//
	//		addr, err := abeutil.NewAddressPubKey(wif.SerializePubKey(),
	//			w.ChainParams())
	//		if err != nil {
	//			return nil, DeserializationError{err}
	//		}
	//		keys[addr.EncodeAddress()] = wif
	//	}
	//}
	//
	//// We have checked the rest of the args. now we can collect the async
	//// txs. TODO: If we don't mind the possibility of wasting work we could
	//// move waiting to the following loop and be slightly more asynchronous.
	//for outPoint, resp := range requested {
	//	result, err := resp.Receive()
	//	if err != nil {
	//		return nil, err
	//	}
	//	script, err := hex.DecodeString(result.ScriptPubKey.Hex)
	//	if err != nil {
	//		return nil, err
	//	}
	//	inputs[outPoint] = script
	//}
	//
	//// All args collected. Now we can sign all the inputs that we can.
	//// `complete' denotes that we successfully signed all outputs and that
	//// all scripts will run to completion. This is returned as part of the
	//// reply.
	//signErrs, err := w.SignTransaction(&tx, hashType, inputs, keys, scripts)
	//if err != nil {
	//	return nil, err
	//}
	//
	//var buf bytes.Buffer
	//buf.Grow(tx.SerializeSize())
	//
	//// All returned errors (not OOM, which panics) encounted during
	//// bytes.Buffer writes are unexpected.
	//if err = tx.Serialize(&buf); err != nil {
	//	panic(err)
	//}
	//
	//signErrors := make([]abejson.SignRawTransactionError, 0, len(signErrs))
	//for _, e := range signErrs {
	//	input := tx.TxIn[e.InputIndex]
	//	signErrors = append(signErrors, abejson.SignRawTransactionError{
	//		TxID:      input.PreviousOutPoint.Hash.String(),
	//		Vout:      input.PreviousOutPoint.Index,
	//		ScriptSig: hex.EncodeToString(input.SignatureScript),
	//		Sequence:  input.Sequence,
	//		Error:     e.Error.Error(),
	//	})
	//}
	//
	//return abejson.SignRawTransactionResult{
	//	Hex:      hex.EncodeToString(buf.Bytes()),
	//	Complete: len(signErrors) == 0,
	//	Errors:   signErrors,
	//}, nil
}

// validateAddress handles the validateaddress command.
func validateAddress(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	_ = icmd.(*abejson.ValidateAddressCmd)

	result := abejson.ValidateAddressWalletResult{}
	// TODO(abe)
	return result, nil
	//	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	//	if err != nil {
	//		// Use result zero value (IsValid=false).
	//		return result, nil
	//	}
	//
	//	// We could put whether or not the address is a script here,
	//	// by checking the type of "addr", however, the reference
	//	// implementation only puts that information if the script is
	//	// "ismine", and we follow that behaviour.
	//	result.Address = addr.EncodeAddress()
	//	result.IsValid = true
	//
	//	ainfo, err := w.AddressInfo(addr)
	//	if err != nil {
	//		if waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
	//			// No additional information available about the address.
	//			return result, nil
	//		}
	//		return nil, err
	//	}
	//
	//	// The address lookup was successful which means there is further
	//	// information about it available and it is "mine".
	//	result.IsMine = true
	//	acctName, err := w.AccountName(waddrmgr.KeyScopeBIP0044, ainfo.Account())
	//	if err != nil {
	//		return nil, &ErrAccountNameNotFound
	//	}
	//	result.Account = acctName
	//
	//	switch ma := ainfo.(type) {
	//	case waddrmgr.ManagedPubKeyAddress:
	//		result.IsCompressed = ma.Compressed()
	//		result.PubKey = ma.ExportPubKey()
	//
	//	case waddrmgr.ManagedScriptAddress:
	//		result.IsScript = true
	//
	//		// The script is only available if the manager is unlocked, so
	//		// just break out now if there is an error.
	//		script, err := ma.Script()
	//		if err != nil {
	//			break
	//		}
	//		result.Hex = hex.EncodeToString(script)
	//
	//		// This typically shouldn't fail unless an invalid script was
	//		// imported.  However, if it fails for any reason, there is no
	//		// further information available, so just set the script type
	//		// a non-standard and break out now.
	//		class, addrs, reqSigs, err := txscript.ExtractPkScriptAddrs(
	//			script, w.ChainParams())
	//		if err != nil {
	//			result.Script = txscript.NonStandardTy.String()
	//			break
	//		}
	//
	//		addrStrings := make([]string, len(addrs))
	//		for i, a := range addrs {
	//			addrStrings[i] = a.EncodeAddress()
	//		}
	//		result.Addresses = addrStrings
	//
	//		// Multi-signature scripts also provide the number of required
	//		// signatures.
	//		result.Script = class.String()
	//		if class == txscript.MultiSigTy {
	//			result.SigsRequired = int32(reqSigs)
	//		}
	//	}
	//
	//	return result, nil
}

// verifyMessage handles the verifymessage command by verifying the provided
// compact signature for the given address and message.
func verifyMessage(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.VerifyMessageCmd)

	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		return nil, err
	}

	// decode base64 signature
	sig, err := base64.StdEncoding.DecodeString(cmd.Signature)
	if err != nil {
		return nil, err
	}

	// Validate the signature - this just shows that it was valid at all.
	// we will compare it with the key next.
	var buf bytes.Buffer
	wire.WriteVarString(&buf, 0, "Bitcoin Signed Message:\n")
	wire.WriteVarString(&buf, 0, cmd.Message)
	expectedMessageHash := chainhash.DoubleHashB(buf.Bytes())
	pk, wasCompressed, err := btcec.RecoverCompact(btcec.S256(), sig,
		expectedMessageHash)
	if err != nil {
		return nil, err
	}

	var serializedPubKey []byte
	if wasCompressed {
		serializedPubKey = pk.SerializeCompressed()
	} else {
		serializedPubKey = pk.SerializeUncompressed()
	}
	// Verify that the signed-by address matches the given address
	switch checkAddr := addr.(type) {
	case *abeutil.AddressPubKeyHash: // ok
		return bytes.Equal(abeutil.Hash160(serializedPubKey), checkAddr.Hash160()[:]), nil
	case *abeutil.AddressPubKey: // ok
		return string(serializedPubKey) == checkAddr.String(), nil
	default:
		return nil, errors.New("address type not supported")
	}
}

// walletIsLocked handles the walletislocked extension request by
// returning the current lock state (false for unlocked, true for locked)
// of an account.
func walletIsLocked(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	return w.Locked(), nil
}

// walletLock handles a walletlock request by locking the all account
// wallets, returning an error if any wallet is not encrypted (for example,
// a watching-only wallet).
func walletLock(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	w.Lock()
	return nil, nil
}

// walletPassphrase responds to the walletpassphrase request by unlocking
// the wallet.  The decryption key is saved in the wallet until timeout
// seconds expires, after which the wallet is locked.
func walletPassphrase(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.WalletPassphraseCmd)

	timeout := time.Second * time.Duration(cmd.Timeout)
	var unlockAfter <-chan time.Time
	if timeout != 0 {
		unlockAfter = time.After(timeout)
	}
	err := w.Unlock([]byte(cmd.Passphrase), unlockAfter)
	return nil, err
}

// walletPassphraseChange responds to the walletpassphrasechange request
// by unlocking all accounts with the provided old passphrase, and
// re-encrypting each private key with an AES key derived from the new
// passphrase.
//
// If the old passphrase is correct and the passphrase is changed, all
// wallets will be immediately locked.
func walletPassphraseChange(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.WalletPassphraseChangeCmd)

	err := w.ChangePrivatePassphrase([]byte(cmd.OldPassphrase),
		[]byte(cmd.NewPassphrase))
	if waddrmgr.IsError(err, waddrmgr.ErrWrongPassphrase) {
		return nil, &abejson.RPCError{
			Code:    abejson.ErrRPCWalletPassphraseIncorrect,
			Message: "Incorrect passphrase",
		}
	}
	return nil, err
}

// decodeHexStr decodes the hex encoding of a string, possibly prepending a
// leading '0' character if there is an odd number of bytes in the hex string.
// This is to prevent an error for an invalid hex string when using an odd
// number of bytes when calling hex.Decode.
func decodeHexStr(hexStr string) ([]byte, error) {
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, &abejson.RPCError{
			Code:    abejson.ErrRPCDecodeHexString,
			Message: "Hex string decode failed: " + err.Error(),
		}
	}
	return decoded, nil
}

func createTxRawResultAbe(chainParams *chaincfg.Params, mtx *wire.MsgTxAbe,
	txHash string, blkHeader *wire.BlockHeader, blkHash string,
	blkHeight int32, chainHeight int32, verbose int) (*abejson.TxRawResultAbe, error) {

	txReply := &abejson.TxRawResultAbe{
		Txid:     txHash,
		Hash:     mtx.TxHash().String(),
		Size:     int32(mtx.SerializeSize()),
		Fullsize: int32(mtx.SerializeSizeFull()),
		Vin:      createVinListAbe(mtx),
		Vout:     createVoutListAbe(mtx, chainParams, verbose),
		Fee:      abeutil.Amount(mtx.TxFee).ToABE(),
		Version:  mtx.Version,
	}

	if mtx.HasWitness() && verbose == 2 {
		txReply.Witness = hex.EncodeToString(mtx.TxWitness)
	}

	if blkHeader != nil {
		// This is not a typo, they are identical in bitcoind as well.
		txReply.Time = blkHeader.Timestamp.Unix()
		txReply.Blocktime = blkHeader.Timestamp.Unix()
		txReply.BlockHash = blkHash
		txReply.Confirmations = uint64(1 + chainHeight - blkHeight)
	}

	return txReply, nil
}

func createVinListAbe(mtx *wire.MsgTxAbe) []abejson.TxIn {
	// Coinbase transactions only have a single txin by definition.
	vinList := make([]abejson.TxIn, len(mtx.TxIns))

	for i, txIn := range mtx.TxIns {
		vinEntry := &vinList[i]
		vinEntry.SerialNumber = hex.EncodeToString(txIn.SerialNumber)

		blockHashNum := len(txIn.PreviousOutPointRing.BlockHashs)
		blockHashs := make([]string, blockHashNum)
		for i := 0; i < blockHashNum; i++ {
			blockHashs[i] = txIn.PreviousOutPointRing.BlockHashs[i].String()
		}

		ringSize := len(txIn.PreviousOutPointRing.OutPoints)
		outPoints := make([]abejson.OutPointAbe, ringSize)
		for i := 0; i < ringSize; i++ {
			outPoint := &outPoints[i]
			outPoint.Txid = txIn.PreviousOutPointRing.OutPoints[i].TxHash.String()
			outPoint.Index = txIn.PreviousOutPointRing.OutPoints[i].Index
		}

		vinEntry.PreviousOutPointRing = &abejson.OutPointRing{
			BlockHashs: blockHashs,
			OutPoints:  outPoints}
	}

	return vinList
}

func createVoutListAbe(mtx *wire.MsgTxAbe, chainParams *chaincfg.Params, verbose int) []abejson.TxOutAbe {
	voutList := make([]abejson.TxOutAbe, 0, len(mtx.TxOuts))
	for i, txOut := range mtx.TxOuts {

		var voutEntry abejson.TxOutAbe
		voutEntry.N = uint8(i)
		if verbose == 2 {
			buffer := bytes.NewBuffer(make([]byte, 0, txOut.SerializeSize()))
			_ = wire.WriteTxOutAbe(buffer, 0, mtx.Version, txOut)
			voutEntry.TxoScript = hex.EncodeToString(buffer.Bytes())
		}

		voutList = append(voutList, voutEntry)
	}

	return voutList
}
func segmentationTXOSet(txo []utxo, min float64, max float64) [][]utxo {
	if max < min {
		return nil
	}
	interval := (max - min) / 10
	segmentations := make([][]utxo, 10)
	for i := 0; i < 10; i++ {
		segmentations[i] = make([]utxo, 0, len(txo))
	}
	for i := 0; i < len(txo); i++ {
		if min <= float64(txo[i].Amount) && float64(txo[i].Amount) < max {
			seg := 0
			if interval != 0 {
				seg = int((float64(txo[i].Amount)-min+interval)/interval) - 1
			}
			segmentations[seg] = append(segmentations[seg], txo[i])
		} else if float64(txo[i].Amount) == max {
			segmentations[len(segmentations)-1] = append(segmentations[len(segmentations)-1], txo[i])
		}

	}
	for i := 0; i < len(segmentations); i++ {
		t := utxoset(segmentations[i])
		sort.Sort(&t)
	}
	return segmentations
}
