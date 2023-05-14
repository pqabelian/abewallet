package wallet

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abecrypto/abecryptoparam"
	"github.com/abesuite/abec/abejson"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abewallet/chain"
	"github.com/abesuite/abewallet/internal/prompt"
	"github.com/abesuite/abewallet/waddrmgr"
	"github.com/abesuite/abewallet/wallet/txauthor"
	"github.com/abesuite/abewallet/wallet/txrules"
	"github.com/abesuite/abewallet/walletdb"
	"github.com/abesuite/abewallet/walletdb/migration"
	"github.com/abesuite/abewallet/wtxmgr"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// InsecurePubPassphrase is the default outer encryption passphrase used
	// for public data (everything but private keys).  Using a non-default
	// public passphrase can prevent an attacker without the public
	// passphrase from discovering all past and future wallet addresses if
	// they gain access to the wallet database.
	//
	// NOTE: at time of writing, public encryption only applies to public
	// data in the waddrmgr namespace.  Transactions are not yet encrypted.
	// TODO 20220612 Would be delete
	InsecurePubPassphrase = "public"

	walletDbWatchingOnlyName = "wowallet.db"

	// recoveryBatchSize is the default number of blocks that will be
	// scanned successively by the recovery manager, in the event that the
	// wallet is started in recovery mode.
	recoveryBatchSize = 2000
)

const (
	NTTransactionAccepted NotificationType = iota
	NTTransactionRollback
	NTTransactionInvalid
)

// NotificationType represents the type of a notification message.
type NotificationType int

// NotificationCallback is used for a caller to provide a callback for
// notifications about various events.
type NotificationCallback func(*Notification)

// Notification defines notification that is sent to the caller via the callback
// function provided during the call to New and consists of a notification type
// as well as associated data.
type Notification struct {
	Type NotificationType
	Data interface{}
}

var (
	// ErrNotSynced describes an error where an operation cannot complete
	// due wallet being out of sync (and perhaps currently syncing with)
	// the remote chain server.
	ErrNotSynced = errors.New("wallet is not synchronized with the chain server")

	// ErrWalletShuttingDown is an error returned when we attempt to make a
	// request to the wallet but it is in the process of or has already shut
	// down.
	ErrWalletShuttingDown = errors.New("wallet shutting down")

	// ErrUnknownTransaction is returned when an attempt is made to label
	// a transaction that is not known to the wallet.
	ErrUnknownTransaction = errors.New("cannot label transaction not " +
		"known to wallet")

	// ErrTxLabelExists is returned when a transaction already has a label
	// and an attempt has been made to label it without setting overwrite
	// to true.
	ErrTxLabelExists = errors.New("transaction already labelled")

	// Namespace bucket keys.
	waddrmgrNamespaceKey = []byte("waddrmgr") // used for restore the master key
	wtxmgrNamespaceKey   = []byte("wtxmgr")
)

// Wallet is a structure containing all the components for a
// complete wallet.  It contains the Armory-style key store
// addresses and keys),
type Wallet struct {
	publicPassphrase []byte

	// Data stores
	db walletdb.DB
	//Manager    *waddrmgr.Manager
	Manager *waddrmgr.Manager
	TxStore *wtxmgr.Store

	chainClient        chain.Interface
	chainClientLock    sync.Mutex
	chainClientSynced  bool
	chainClientSyncMtx sync.Mutex

	lockedOutpoints map[wire.OutPoint]struct{}

	resendUnminedTxFlag atomic.Value

	RecordRequestFlag bool

	recoveryWindow uint32

	// Channels for rescan processing.  Requests are added and merged with
	// any waiting requests, before being sent to another goroutine to
	// call the rescan RPC.

	// Channel for transaction creation requests.
	createTxRequests chan createTxRequest

	// Channels for the manager locker.
	unlockRequests     chan unlockRequest
	lockRequests       chan struct{}
	holdUnlockRequests chan chan heldUnlock
	lockState          chan bool
	changePassphrase   chan changePassphraseRequest
	changePassphrases  chan changePassphrasesRequest

	// Information for reorganization handling.
	// TODO 20220610 use this field to control something?
	reorganizingLock sync.Mutex
	reorganizeToHash chainhash.Hash
	reorganizing     bool

	// TODO 20220610 notification server to notify the client that something
	// like a hook?
	NtfnServer *NotificationServer

	notificationsLock sync.RWMutex
	notifications     []NotificationCallback

	chainParams *chaincfg.Params
	wg          sync.WaitGroup

	started bool
	quit    chan struct{}
	quitMu  sync.Mutex

	// Information for syncing.
	SyncFrom int32
}

// Start starts the goroutines necessary to manage a wallet.
func (w *Wallet) Start() {
	w.quitMu.Lock()
	select {
	case <-w.quit:
		// Restart the wallet goroutines after shutdown finishes.
		w.WaitForShutdown()
		w.quit = make(chan struct{})
	default:
		// Ignore when the wallet is still running.
		if w.started {
			w.quitMu.Unlock()
			return
		}
		w.started = true
	}
	w.quitMu.Unlock()

	w.wg.Add(2)
	go w.txCreator()
	go w.walletLocker()
}
func (w *Wallet) Subscribe(callback NotificationCallback) {
	w.notificationsLock.Lock()
	w.notifications = append(w.notifications, callback)
	w.notificationsLock.Unlock()
}
func (w *Wallet) sendNotification(typ NotificationType, data interface{}) {
	// Generate and send the notification.
	n := Notification{Type: typ, Data: data}
	w.notificationsLock.RLock()
	for _, callback := range w.notifications {
		callback(&n)
	}
	w.notificationsLock.RUnlock()
}

// SynchronizeRPC associates the wallet with the consensus RPC client,
// synchronizes the wallet with the latest changes to the blockchain, and
// continuously updates the wallet through RPC notifications.
//
// This method is unstable and will be removed when all syncing logic is moved
// outside of the wallet package.
func (w *Wallet) SynchronizeRPC(chainClient chain.Interface) {
	w.quitMu.Lock()
	select {
	case <-w.quit:
		w.quitMu.Unlock()
		return
	default:
	}
	w.quitMu.Unlock()

	// TODO: Ignoring the new client when one is already set breaks callers
	// who are replacing the client, perhaps after a disconnect.
	w.chainClientLock.Lock()

	if w.chainClient != nil {
		w.chainClientLock.Unlock()
		return
	}
	w.chainClient = chainClient

	w.chainClientLock.Unlock()

	// TODO: It would be preferable to either run these goroutines
	// separately from the wallet (use wallet mutator functions to
	// make changes from the RPC client) and not have to stop and
	// restart them each time the client disconnects and reconnects.
	w.wg.Add(1)
	go w.handleChainNotifications()
}

// requireChainClient marks that a wallet method can only be completed when the
// consensus RPC server is set.  This function and all functions that call it
// are unstable and will need to be moved when the syncing code is moved out of
// the wallet.
func (w *Wallet) requireChainClient() (chain.Interface, error) {
	w.chainClientLock.Lock()
	chainClient := w.chainClient
	w.chainClientLock.Unlock()
	if chainClient == nil {
		return nil, errors.New("blockchain RPC is inactive")
	}
	return chainClient, nil
}

// ChainClient returns the optional consensus RPC client associated with the
// wallet.
//
// This function is unstable and will be removed once sync logic is moved out of
// the wallet.
func (w *Wallet) ChainClient() chain.Interface {
	w.chainClientLock.Lock()
	chainClient := w.chainClient
	w.chainClientLock.Unlock()
	return chainClient
}

// quitChan atomically reads the quit channel.
func (w *Wallet) quitChan() <-chan struct{} {
	w.quitMu.Lock()
	c := w.quit
	w.quitMu.Unlock()
	return c
}

// Stop signals all wallet goroutines to shutdown.
func (w *Wallet) Stop() {
	w.quitMu.Lock()
	quit := w.quit
	w.quitMu.Unlock()

	select {
	case <-quit:
	default:
		close(quit)
		w.chainClientLock.Lock()
		if w.chainClient != nil {
			w.chainClient.Stop()
			w.chainClient = nil
		}
		w.chainClientLock.Unlock()
	}
}

// ShuttingDown returns whether the wallet is currently in the process of
// shutting down or not.
func (w *Wallet) ShuttingDown() bool {
	select {
	case <-w.quitChan():
		return true
	default:
		return false
	}
}

// WaitForShutdown blocks until all wallet goroutines have finished executing.
func (w *Wallet) WaitForShutdown() {
	w.chainClientLock.Lock()
	if w.chainClient != nil {
		w.chainClient.WaitForShutdown()
	}
	w.chainClientLock.Unlock()
	w.wg.Wait()
}

// SynchronizingToNetwork returns whether the wallet is currently synchronizing
// with the Abelian network.
func (w *Wallet) SynchronizingToNetwork() bool {
	// At the moment, RPC is the only synchronization method.  In the
	// future, when SPV is added, a separate check will also be needed, or
	// SPV could always be enabled if RPC was not explicitly specified when
	// creating the wallet.
	w.chainClientSyncMtx.Lock()
	syncing := w.chainClient != nil
	w.chainClientSyncMtx.Unlock()
	return syncing
}

// ChainSynced returns whether the wallet has been attached to a chain server
// and synced up to the best block on the main chain.
func (w *Wallet) ChainSynced() bool {
	w.chainClientSyncMtx.Lock()
	synced := w.chainClientSynced
	w.chainClientSyncMtx.Unlock()
	return synced
}

// SetChainSynced marks whether the wallet is connected to and currently in sync
// with the latest block notified by the chain server.
//
// NOTE: Due to an API limitation with rpcclient, this may return true after
// the client disconnected (and is attempting a reconnect).  This will be unknown
// until the reconnect notification is received, at which point the wallet can be
// marked out of sync again until after the next rescan completes.
func (w *Wallet) SetChainSynced(synced bool) {
	w.chainClientSyncMtx.Lock()
	w.chainClientSynced = synced
	w.chainClientSyncMtx.Unlock()
}

// activeData returns the currently-active receiving addresses and all unspent
// outputs.  This is primarely intended to provide the parameters for a
// rescan request.

// syncWithChain brings the wallet up to date with the current chain server
// connection. It creates a rescan request and blocks until the rescan has
// finished. The birthday block can be passed in, if set, to ensure we can
// properly detect if it gets rolled back.
func (w *Wallet) syncWithChain(birthdayStamp *waddrmgr.BlockStamp) error {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return err
	}

	// We'll wait until the backend is synced to ensure we get the latest
	// MaxReorgDepth blocks to store. We don't do this for development
	// environments as we can't guarantee a lively chain, except for
	// Neutrino, where the cfheader server tells us what it believes the
	// chain tip is.
	if !w.isDevEnv() {
		log.Debug("Waiting for chain backend to sync to tip")
		if err := w.waitUntilBackendSynced(chainClient); err != nil {
			return err
		}
		log.Debug("Chain backend synced to tip!")
	}

	// If we've yet to find our birthday block, we'll do so now.
	if birthdayStamp == nil {
		var err error
		birthdayStamp, err = locateBirthdayBlock(
			chainClient, w.Manager.Birthday(),
		)
		if err != nil {
			return fmt.Errorf("unable to locate birthday block: %v",
				err)
		}

		// We'll also determine our initial sync starting height. This
		// is needed as the wallet can now begin storing blocks from an
		// arbitrary height, rather than all the blocks from genesis, so
		// we persist this height to ensure we don't store any blocks
		// before it.
		//startHeight := birthdayStamp.Height

		// With the starting height obtained, get the remaining block
		// details required by the wallet.
		//startHash, err := chainClient.GetBlockHash(int64(startHeight))
		//if err != nil {
		//	return err
		//}
		////startHeader, err := chainClient.GetBlockHeader(startHash)
		//if err != nil {
		//	return err
		//}

		err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
			ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
			return w.Manager.SetBirthdayBlock(ns, *birthdayStamp, true)
		})
		if err != nil {
			return fmt.Errorf("unable to persist initial sync "+
				"data: %v", err)
		}
	}

	// Compare previously-seen blocks against the current chain. If any of
	// these blocks no longer exist, rollback all of the missing blocks
	// before catching up with the rescan.
	rollback := false
	rollbackStamp := w.Manager.SyncedTo()

	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)

		// compare the block with the backend chain, and rollback the sync
		// height if necessary
		for height := rollbackStamp.Height; true; height-- {
			hash, err := w.Manager.BlockHash(addrmgrNs, height)
			if err != nil {
				return err
			}
			chainHash, err := chainClient.GetBlockHash(int64(height))
			if err != nil {
				return err
			}
			header, err := chainClient.GetBlockHeader(chainHash)
			if err != nil {
				return err
			}

			rollbackStamp.Hash = *chainHash
			rollbackStamp.Height = height
			rollbackStamp.Timestamp = header.Timestamp

			if bytes.Equal(hash[:], chainHash[:]) {
				break
			}
			rollback = true
		}

		// If a rollback did not happen, we can proceed safely.
		if !rollback {
			return nil
		}

		// Otherwise, we'll mark this as our new synced height.
		err := w.Manager.SetSyncedTo(addrmgrNs, &rollbackStamp)
		if err != nil {
			return err
		}
		log.Infof("Rollbacking to block with height %d, hash %s", rollbackStamp.Height, rollbackStamp.Hash)

		// If the rollback happened to go beyond our birthday stamp,
		// we'll need to find a new one by syncing with the chain again
		// until finding one.
		if rollbackStamp.Height <= birthdayStamp.Height && !bytes.Equal(rollbackStamp.Hash[:], birthdayStamp.Hash[:]) {
			err := w.Manager.SetBirthdayBlock(addrmgrNs, rollbackStamp, true)
			if err != nil {
				return err
			}
		}

		// Finally, we'll roll back our transaction store to reflect the
		// stale state. `Rollback` unconfirms transactions at and beyond
		// the passed height, so add one to the new synced-to height to
		// prevent unconfirming transactions in the synced-to block.
		return w.TxStore.Rollback(w.Manager, addrmgrNs, txmgrNs, rollbackStamp.Height)
	})
	if err != nil {
		return err
	}

	// Request notifications for connected and disconnected blocks.
	//
	// TODO(jrick): Either request this notification only once, or when
	// rpcclient is modified to allow some notification request to not
	// automatically resent on reconnect, include the notifyblocks request
	// as well.  I am leaning towards allowing off all rpcclient
	// notification re-registrations, in which case the code here should be
	// left as is.
	if err := chainClient.NotifyBlocks(); err != nil {
		return err
	}

	// Finally, we'll trigger a wallet rescan and request notifications for
	// transactions sending to all wallet addresses and spending all wallet
	// UTXOs.
	return w.rescanWithTarget(nil)
}

// isDevEnv determines whether the wallet is currently under a local developer
// environment, e.g. simnet or regtest.
func (w *Wallet) isDevEnv() bool {
	switch uint32(w.ChainParams().Net) {
	case uint32(chaincfg.RegressionNetParams.Net):
	case uint32(chaincfg.SimNetParams.Net):
	default:
		return false
	}
	return true
}

// waitUntilBackendSynced blocks until the chain backend considers itself
// "current".
func (w *Wallet) waitUntilBackendSynced(chainClient chain.Interface) error {
	// We'll poll every second to determine if our chain considers itself
	// "current".
	t := time.NewTicker(time.Second)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			if chainClient.IsCurrent() {
				return nil
			}
		case <-w.quitChan():
			return ErrWalletShuttingDown
		}
	}
}

// locateBirthdayBlock returns a block that meets the given birthday timestamp
// by a margin of +/-2 hours. This is safe to do as the timestamp is already 2
// days in the past of the actual timestamp.
func locateBirthdayBlock(chainClient chainConn,
	birthday time.Time) (*waddrmgr.BlockStamp, error) {

	// Retrieve the lookup range for our block.
	startHeight := int32(0)
	_, bestHeight, err := chainClient.GetBestBlock()
	if err != nil {
		return nil, err
	}

	log.Debugf("Locating suitable block for birthday %v between blocks "+
		"%v-%v", birthday, startHeight, bestHeight)

	var (
		birthdayBlock *waddrmgr.BlockStamp
		left, right   = startHeight, bestHeight
	)

	// Binary search for a block that meets the birthday timestamp by a
	// margin of +/-2 hours.
	for {
		// Retrieve the timestamp for the block halfway through our
		// range.
		mid := left + (right-left)/2
		hash, err := chainClient.GetBlockHash(int64(mid))
		if err != nil {
			return nil, err
		}
		header, err := chainClient.GetBlockHeader(hash)
		if err != nil {
			return nil, err
		}

		log.Debugf("Checking candidate block: height=%v, hash=%v, "+
			"timestamp=%v", mid, hash, header.Timestamp)

		// If the search happened to reach either of our range extremes,
		// then we'll just use that as there's nothing left to search.
		if mid == startHeight || mid == bestHeight || mid == left {
			birthdayBlock = &waddrmgr.BlockStamp{
				Hash:      *hash,
				Height:    mid,
				Timestamp: header.Timestamp,
			}
			break
		}

		// The block's timestamp is more than 2 hours after the
		// birthday, so look for a lower block.
		if header.Timestamp.Sub(birthday) > birthdayBlockDelta {
			right = mid
			continue
		}

		// The birthday is more than 2 hours before the block's
		// timestamp, so look for a higher block.
		if header.Timestamp.Sub(birthday) < -birthdayBlockDelta {
			left = mid
			continue
		}

		birthdayBlock = &waddrmgr.BlockStamp{
			Hash:      *hash,
			Height:    mid,
			Timestamp: header.Timestamp,
		}
		break
	}

	log.Debugf("Found birthday block: height=%d, hash=%v, timestamp=%v",
		birthdayBlock.Height, birthdayBlock.Hash,
		birthdayBlock.Timestamp)

	return birthdayBlock, nil
}

// recovery attempts to recover any unspent outputs that pay to any of our
// addresses starting from our birthday, or the wallet's tip (if higher), which
// would indicate resuming a recovery after a restart.
// In abelian, when create a wallet, the user would input the address number to recover

// recoverScopedAddresses scans a range of blocks in attempts to recover any
// previously used addresses for a particular account derivation path. At a high
// level, the algorithm works as follows:
//
//  1) Ensure internal and external branch horizons are fully expanded.
//  2) Filter the entire range of blocks, stopping if a non-zero number of
//       address are contained in a particular block.
//  3) Record all internal and external addresses found in the block.
//  4) Record any outpoints found in the block that should be watched for spends
//  5) Trim the range of blocks up to and including the one reporting the addrs.
//  6) Repeat from (1) if there are still more blocks in the range.
//

// expandScopeHorizons ensures that the ScopeRecoveryState has an adequately
// sized look ahead for both its internal and external branches. The keys
// derived here are added to the scope's recovery state, but do not affect the
// persistent state of the wallet. If any invalid child keys are detected, the
// horizon will be properly extended such that our lookahead always includes the
// proper number of valid child keys.

// externalKeyPath returns the relative external derivation path /0/0/index.

// internalKeyPath returns the relative internal derivation path /0/1/index.

// extendFoundAddresses accepts a filter blocks response that contains addresses
// found on chain, and advances the state of all relevant derivation paths to
// match the highest found child index for each branch.

// logFilterBlocksResp provides useful logging information when filtering
// succeeded in finding relevant transactions.

type (
	createTxRequest struct {
		txOutDescs        []*abecrypto.AbeTxOutputDesc
		minconf           int32
		feePerKbSpecified abeutil.Amount
		feeSpecified      abeutil.Amount
		utxoSpecified     []string
		dryRun            bool
		resp              chan createTxResponse
	}
	createTxResponse struct {
		tx  *txauthor.AuthoredTxAbe
		err error
	}
)

// txCreator is responsible for the input selection and creation of
// transactions. These functions are the responsibility of this method
// (designed to be run as its own goroutine) since input selection must be
// serialized, or else it is possible to create double spends by choosing the
// same inputs for multiple transactions. Along with input selection, this
// method is also responsible for the signing of transactions, since we don't
// want to end up in a situation where we run out of inputs as multiple
// transactions are being created.  In this situation, it would then be possible
// for both requests, rather than just one, to fail due to not enough available
// inputs.
func (w *Wallet) txCreator() {
	quit := w.quitChan()
out:
	for {
		select {
		case txr := <-w.createTxRequests:
			heldUnlock, err := w.holdUnlock()
			if err != nil {
				txr.resp <- createTxResponse{nil, err}
				continue
			}
			tx, err := w.txPqringCTToOutputs(txr.txOutDescs, txr.minconf, txr.feePerKbSpecified, txr.feeSpecified, txr.utxoSpecified, txr.dryRun)
			heldUnlock.release()
			txr.resp <- createTxResponse{tx, err}
		case <-quit:
			break out
		}
	}
	w.wg.Done()
}

// CreateSimpleTx creates a new signed transaction spending unspent P2PKH
// outputs with at least minconf confirmations spending to any number of
// address/amount pairs.  Change and an appropriate transaction fee are
// automatically included, if necessary.  All transaction creation through this
// function is serialized to prevent the creation of many transactions which
// spend the same outputs.
//
// NOTE: The dryRun argument can be set true to create a tx that doesn't alter
// the database. A tx created with this set to true SHOULD NOT be broadcasted.
func (w *Wallet) CreateSimpleTx(outputDescs []*abecrypto.AbeTxOutputDesc, minconf int32,
	feePerKbSpecified abeutil.Amount, feeSpecified abeutil.Amount, utxoSpecified []string, dryRun bool) (*txauthor.AuthoredTxAbe, error) {

	req := createTxRequest{
		txOutDescs:        outputDescs,
		minconf:           minconf,
		feePerKbSpecified: feePerKbSpecified,
		feeSpecified:      feeSpecified,
		utxoSpecified:     utxoSpecified,
		dryRun:            dryRun,
		resp:              make(chan createTxResponse),
	}
	w.createTxRequests <- req
	resp := <-req.resp
	return resp.tx, resp.err
}

type (
	unlockRequest struct {
		passphrase []byte
		lockAfter  <-chan time.Time // nil prevents the timeout.
		err        chan error
	}

	changePassphraseRequest struct {
		old, new []byte
		private  bool
		err      chan error
	}

	changePassphrasesRequest struct {
		publicOld, publicNew   []byte
		privateOld, privateNew []byte
		err                    chan error
	}

	// heldUnlock is a tool to prevent the wallet from automatically
	// locking after some timeout before an operation which needed
	// the unlocked wallet has finished.  Any aquired heldUnlock
	// *must* be released (preferably with a defer) or the wallet
	// will forever remain unlocked.
	heldUnlock chan struct{}
)

// walletLocker manages the locked/unlocked state of a wallet.
func (w *Wallet) walletLocker() {
	var timeout <-chan time.Time
	holdChan := make(heldUnlock)
	quit := w.quitChan()
out:
	for {
		select {
		case req := <-w.unlockRequests:
			err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
				addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
				//return w.Manager.Unlock(addrmgrNs, req.passphrase)
				return w.Manager.Unlock(addrmgrNs, req.passphrase)
			})
			if err != nil {
				req.err <- err
				continue
			}
			timeout = req.lockAfter
			if timeout == nil {
				log.Info("The wallet has been unlocked without a time limit")
			} else {
				log.Info("The wallet has been temporarily unlocked")
			}
			req.err <- nil
			continue

		case req := <-w.changePassphrase:
			err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
				addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
				return w.Manager.ChangePassphrase(
					addrmgrNs, req.old, req.new, req.private,
					&waddrmgr.DefaultScryptOptions,
				)
			})
			req.err <- err
			continue

		case req := <-w.changePassphrases:
			err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
				addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
				err := w.Manager.ChangePassphrase(
					addrmgrNs, req.publicOld, req.publicNew,
					false, &waddrmgr.DefaultScryptOptions,
				)
				if err != nil {
					return err
				}

				return w.Manager.ChangePassphrase(
					addrmgrNs, req.privateOld, req.privateNew,
					true, &waddrmgr.DefaultScryptOptions,
				)
			})
			req.err <- err
			continue

		case req := <-w.holdUnlockRequests:
			if w.Manager.IsLocked() {
				close(req)
				continue
			}

			req <- holdChan
			<-holdChan // Block until the lock is released.

			// If, after holding onto the unlocked wallet for some
			// time, the timeout has expired, lock it now instead
			// of hoping it gets unlocked next time the top level
			// select runs.
			select {
			case <-timeout:
			// Let the top level select fallthrough so the
			// wallet is locked.
			default:
				continue
			}
		case w.lockState <- w.Manager.IsLocked():
			continue

		case <-quit:
			break out

		case <-w.lockRequests:
		case <-timeout:
		}

		// Select statement fell through by an explicit lock or the
		// timer expiring.  Lock the manager here.
		timeout = nil
		err := w.Manager.Lock()
		if err != nil && !waddrmgr.IsError(err, waddrmgr.ErrLocked) {
			log.Errorf("Could not lock wallet: %v", err)
		} else {
			log.Info("The wallet has been locked")
		}
	}
	w.wg.Done()
}

// Unlock unlocks the wallet's address manager and relocks it after timeout has
// expired.  If the wallet is already unlocked and the new passphrase is
// correct, the current timeout is replaced with the new one.  The wallet will
// be locked if the passphrase is incorrect or any other error occurs during the
// unlock.
func (w *Wallet) Unlock(passphrase []byte, lock <-chan time.Time) error {
	err := make(chan error, 1)
	w.unlockRequests <- unlockRequest{
		passphrase: passphrase,
		lockAfter:  lock,
		err:        err,
	}
	return <-err
}

// Lock locks the wallet's address manager.
func (w *Wallet) Lock() {
	w.lockRequests <- struct{}{}
}

// Locked returns whether the account manager for a wallet is locked.
func (w *Wallet) Locked() bool {
	return <-w.lockState
}

// holdUnlock prevents the wallet from being locked.  The heldUnlock object
// *must* be released, or the wallet will forever remain unlocked.
//
// TODO: To prevent the above scenario, perhaps closures should be passed
// to the walletLocker goroutine and disallow callers from explicitly
// handling the locking mechanism.
func (w *Wallet) holdUnlock() (heldUnlock, error) {
	req := make(chan heldUnlock)
	w.holdUnlockRequests <- req
	hl, ok := <-req
	if !ok {
		// TODO(davec): This should be defined and exported from
		// waddrmgr.
		return nil, waddrmgr.ManagerError{
			ErrorCode:   waddrmgr.ErrLocked,
			Description: "address manager is locked",
		}
	}
	return hl, nil
}

// release releases the hold on the unlocked-state of the wallet and allows the
// wallet to be locked again.  If a lock timeout has already expired, the
// wallet is locked again as soon as release is called.
func (c heldUnlock) release() {
	c <- struct{}{}
}

// ChangePrivatePassphrase attempts to change the passphrase for a wallet from
// old to new.  Changing the passphrase is synchronized with all other address
// manager locking and unlocking.  The lock state will be the same as it was
// before the password change.
func (w *Wallet) ChangePrivatePassphrase(old, new []byte) error {
	err := make(chan error, 1)
	w.changePassphrase <- changePassphraseRequest{
		old:     old,
		new:     new,
		private: true,
		err:     err,
	}
	return <-err
}

// ChangePublicPassphrase modifies the public passphrase of the wallet.
func (w *Wallet) ChangePublicPassphrase(old, new []byte) error {
	err := make(chan error, 1)
	w.changePassphrase <- changePassphraseRequest{
		old:     old,
		new:     new,
		private: false,
		err:     err,
	}
	return <-err
}

// ChangePassphrases modifies the public and private passphrase of the wallet
// atomically.
// TODO :This function is never used yet until the gRPC is supported.
func (w *Wallet) ChangePassphrases(publicOld, publicNew, privateOld,
	privateNew []byte) error {

	err := make(chan error, 1)
	w.changePassphrases <- changePassphrasesRequest{
		publicOld:  publicOld,
		publicNew:  publicNew,
		privateOld: privateOld,
		privateNew: privateNew,
		err:        err,
	}
	return <-err
}

// accountUsed returns whether there are any recorded transactions spending to
// a given account. It returns true if atleast one address in the account was
// used and false if no address in the account was used.

// AccountAddresses returns the addresses for every created address for an
// account.

// CalculateBalance sums the amounts of all unspent transaction
// outputs to addresses of a wallet and returns the balance.
//
// If confirmations is 0, all UTXOs, even those not present in a
// block (height -1), will be used to get the balance.  Otherwise,
// a UTXO must be in a block.  If confirmations is 1 or greater,
// the balance will be calculated based on how many how many blocks
// include a UTXO.

func (w *Wallet) CalculateBalance(confirms int32) ([]abeutil.Amount, error) {
	var balances []abeutil.Amount
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		var err error
		blk := w.Manager.SyncedTo()
		balances, err = w.TxStore.Balance(txmgrNs, confirms, blk.Height)
		return err
	})
	return balances, err
}

func (w *Wallet) FetchUnmatruedUTXOSet() ([]wtxmgr.UnspentUTXO, error) {
	var utxos []wtxmgr.UnspentUTXO
	var err error
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		utxos, err = w.TxStore.UnmaturedOutputs(txmgrNs)
		return err
	})
	return utxos, err
}

func (w *Wallet) FetchUnspentUTXOSet() ([]wtxmgr.UnspentUTXO, error) {
	var utxos []wtxmgr.UnspentUTXO
	var err error
	bs := w.Manager.SyncedTo()
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		utxos, err = w.findEligibleTxosAbe(txmgrNs, 1, &bs)
		return err
	})
	return utxos, err
}

func (w *Wallet) FetchSpentButUnminedTXOSet() ([]wtxmgr.SpentButUnminedTXO, error) {
	var utxos []wtxmgr.SpentButUnminedTXO
	var err error
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		utxos, err = w.TxStore.SpentButUnminedOutputs(txmgrNs)
		return err
	})
	return utxos, err
}

func (w *Wallet) FetchSpentAndConfirmedTXOSet() ([]wtxmgr.SpentConfirmedTXO, error) {
	var utxos []wtxmgr.SpentConfirmedTXO
	var err error
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		utxos, err = w.TxStore.SpentAndMinedOutputs(txmgrNs)
		return err
	})
	return utxos, err
}
func (w *Wallet) FetchConfirmedTxHashs() ([]*chainhash.Hash, error) {
	var txHashs []*chainhash.Hash
	var err error
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		txHashs, err = w.TxStore.ConfirmedTxHashes(txmgrNs)
		return err
	})
	return txHashs, err
}

func (w *Wallet) FetchUnconfirmedTxHashs() ([]*chainhash.Hash, error) {
	var txHashs []*chainhash.Hash
	var err error
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		txHashs, err = w.TxStore.UnminedTxHashes(txmgrNs)
		return err
	})
	return txHashs, err
}

func (w *Wallet) FetchInvalidTxHashs() ([]*chainhash.Hash, error) {
	var txHashs []*chainhash.Hash
	var err error
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		txHashs, err = w.TxStore.InvalidTxHashes(txmgrNs)
		return err
	})
	return txHashs, err
}

func (w *Wallet) TransactionStatus(hash *chainhash.Hash) (int, error) {
	if hash == nil {
		return -2, errors.New("invalid transaction hash")
	}
	var status int
	var err error
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		status, err = w.TxStore.TxStatus(txmgrNs, hash)
		return err
	})
	return status, err
}

func (w *Wallet) FetchDetailedUtxos(confirms int32) (string, error) {
	var details []string
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		chainClient, err := w.requireChainClient()
		if err != nil {
			return err
		}
		bs, err := chainClient.BlockStamp()
		if err != nil {
			return err
		}
		eligible, err := w.findEligibleTxosAbe(txmgrNs, confirms, bs)
		if err != nil {
			return err
		}
		details = make([]string, len(eligible))
		for idx, utxo := range eligible {
			details[idx] = fmt.Sprintf("%s %d %v", utxo.Hash().String(), utxo.Height, float64(utxo.Amount)/math.Pow10(7))
		}
		return err
	})
	return strings.Join(details, "\n"), err
}

// Balances records total, spendable (by policy), and immature coinbase
// reward balance amounts.
type Balances struct {
	Total          abeutil.Amount
	Spendable      abeutil.Amount
	ImmatureReward abeutil.Amount
}

// CalculateAccountBalances sums the amounts of all unspent transaction
// outputs to the given account of a wallet and returns the balance.
//
// This function is much slower than it needs to be since transactions outputs
// are not indexed by the accounts they credit to, and all unspent transaction
// outputs must be iterated.

// PubKeyForAddress looks up the associated public key for a P2PKH address.

// LabelTransaction adds a label to the transaction with the hash provided. The
// call will fail if the label is too long, or if the transaction already has
// a label and the overwrite boolean is not set.

// PrivKeyForAddress looks up the associated private key for a P2PKH or P2PK
// address.

// HaveAddress returns whether the wallet is the owner of the address a.

// AccountOfAddress finds the account that an address is associated with.

// AddressInfo returns detailed information regarding a wallet address.

// AccountNumber returns the account number for an account name under a
// particular key scope.

// AccountName returns the name of an account.

// AccountProperties returns the properties of an account, including address
// indexes and name. It first fetches the desynced information from the address
// manager, then updates the indexes based on the address pools.

// RenameAccount sets the name for an account number to newName.

// NextAccount creates the next account and returns its account number.  The
// name must be unique to the account.  In order to support automatic seed
// restoring, new accounts may not be created when all of the previous 100
// accounts have no transaction history (this is a deviation from the BIP0044
// spec, which allows no unused account gaps).

// CreditCategory describes the type of wallet transaction output.  The category
// of "sent transactions" (debits) is always "send", and is not expressed by
// this type.
//
// RecvCategory returns the category of received credit outputs from a
// transaction record.  The passed block chain height is used to distinguish
// immature from mature coinbase outputs.
//
// TODO: This is intended for use by the RPC server and should be moved out of
// this package at a later time.

// listTransactions creates a object that may be marshalled to a response result
// for a listtransactions RPC.
//

// ListSinceBlock returns a slice of objects with details about transactions
// since the given block. If the block is -1 then all transactions are included.
// This is intended to be used for listsinceblock RPC replies.

// ListTransactions returns a slice of objects with details about a recorded
// transaction.  This is intended to be used for listtransactions RPC
// replies.

// ListAddressTransactions returns a slice of objects with details about
// recorded transactions to or from any address belonging to a set.  This is
// intended to be used for listaddresstransactions RPC replies.

// ListAllTransactions returns a slice of objects with details about a recorded
// transaction.  This is intended to be used for listalltransactions RPC
// replies.

// BlockIdentifier identifies a block by either a height or a hash.
type BlockIdentifier struct {
	height int32
	hash   *chainhash.Hash
}

// NewBlockIdentifierFromHeight constructs a BlockIdentifier for a block height.
func NewBlockIdentifierFromHeight(height int32) *BlockIdentifier {
	return &BlockIdentifier{height: height}
}

// NewBlockIdentifierFromHash constructs a BlockIdentifier for a block hash.
func NewBlockIdentifierFromHash(hash *chainhash.Hash) *BlockIdentifier {
	return &BlockIdentifier{hash: hash}
}

// GetTransactionsResult is the result of the wallet's GetTransactions method.
// See GetTransactions for more details.
type GetTransactionsResult struct {
	MinedTransactions   []Block
	UnminedTransactions []TransactionSummary
}

// GetTransactions returns transaction results between a starting and ending
// block.  Blocks in the block range may be specified by either a height or a
// hash.
//
// Because this is a possibly lenghtly operation, a cancel channel is provided
// to cancel the task.  If this channel unblocks, the results created thus far
// will be returned.
//
// Transaction results are organized by blocks in ascending order and unmined
// transactions in an unspecified order.  Mined transactions are saved in a
// Block structure which records properties about the block.

// AccountResult is a single account result for the AccountsResult type.

// AccountsResult is the resutl of the wallet's Accounts method.  See that
// method for more details.
// Accounts returns the current names, numbers, and total balances of all
// accounts in the wallet restricted to a particular key scope.  The current
// chain tip is included in the result for atomicity reasons.
//

// AccountBalances returns all accounts in the wallet and their balances.
// Balances are determined by excluding transactions that have not met
// requiredConfs confirmations.

// creditSlice satisifies the sort.Interface interface to provide sorting
// transaction credits from oldest to newest.  Credits with the same receive
// time and mined in the same block are not guaranteed to be sorted by the order
// they appear in the block.  Credits from the same transaction are sorted by
// output index.

// unspentUTXOSlice would be used for choose UTXO or other intention for sort
type unspentUTXOSlice []wtxmgr.UnspentUTXO

func (u unspentUTXOSlice) Len() int {
	return len(u)
}
func (u unspentUTXOSlice) Less(i, j int) bool {
	switch {
	// If both credits are from the same tx, sort by output index.
	case u[i].TxOutput.TxHash == u[j].TxOutput.TxHash:
		return u[i].TxOutput.Index < u[j].TxOutput.Index

	// If both transactions are unmined, sort by their received date.
	case u[i].Height == -1 && u[j].Height == -1:
		return u[i].GenerationTime.Before(u[j].GenerationTime)

	// Unmined (newer) txs always come last.
	case u[i].Height == -1:
		return false
	case u[j].Height == -1:
		return true

	// If both txs are mined in different blocks, sort by block height.
	default:
		return u[i].Height < u[j].Height
	}
}

func (u unspentUTXOSlice) Swap(i, j int) {
	u[i], u[j] = u[j], u[i]
}

// ListUnspent returns a slice of objects representing the unspent wallet
// transactions fitting the given criteria. The confirmations will be more than
// minconf, less than maxconf and if addresses is populated only the addresses
// contained within it will be considered.  If we know nothing about a
// transaction an empty array will be returned.

// DumpPrivKeys returns the WIF-encoded private keys for all addresses with
// private keys in a wallet.

// DumpWIFPrivateKey returns the WIF encoded private key for a
// single wallet address.

// ImportPrivateKey imports a private key to the wallet and writes the new
// wallet to disk.
// TODO : this function would be delete
// NOTE: If a block stamp is not provided, then the wallet's birthday will be
// set to the genesis block of the corresponding chain.
func (w *Wallet) ImportPrivateKey(wif *abeutil.WIF,
	bs *waddrmgr.BlockStamp, rescan bool) (string, error) {
	// Return the payment address string of the imported private key.
	return "", fmt.Errorf("not support now")
}

// LockedOutpoint returns whether an outpoint has been marked as locked and
// should not be used as an input for created transactions.
// TODO: this function would be used after gRPC is supported.
func (w *Wallet) LockedOutpoint(op wire.OutPoint) bool {
	_, locked := w.lockedOutpoints[op]
	return locked
}

// LockOutpoint marks an outpoint as locked, that is, it should not be used as
// an input for newly created transactions.
// TODO: this function would be used after gRPC is supported.
func (w *Wallet) LockOutpoint(op wire.OutPoint) {
	w.lockedOutpoints[op] = struct{}{}
}

// UnlockOutpoint marks an outpoint as unlocked, that is, it may be used as an
// input for newly created transactions.
func (w *Wallet) UnlockOutpoint(op wire.OutPoint) {
	delete(w.lockedOutpoints, op)
}

// ResetLockedOutpoints resets the set of locked outpoints so all may be used
// as inputs for new transactions.
func (w *Wallet) ResetLockedOutpoints() {
	w.lockedOutpoints = map[wire.OutPoint]struct{}{}
}

// LockedOutpoints returns a slice of currently locked outpoints.  This is
// intended to be used by marshaling the result as a JSON array for
// listlockunspent RPC results.
func (w *Wallet) LockedOutpoints() []abejson.TransactionInput {
	locked := make([]abejson.TransactionInput, len(w.lockedOutpoints))
	i := 0
	for op := range w.lockedOutpoints {
		locked[i] = abejson.TransactionInput{
			Txid: op.Hash.String(),
			Vout: op.Index,
		}
		i++
	}
	return locked
}

// LeaseOutput locks an output to the given ID, preventing it from being
// available for coin selection. The absolute time of the lock's expiration is
// returned. The expiration of the lock can be extended by successive
// invocations of this call.
//
// Outputs can be unlocked before their expiration through `UnlockOutput`.
// Otherwise, they are unlocked lazily through calls which iterate through all
// known outputs, e.g., `CalculateBalance`, `ListUnspent`.
//
// If the output is not known, ErrUnknownOutput is returned. If the output has
// already been locked to a different ID, then ErrOutputAlreadyLocked is
// returned.
//
// NOTE: This differs from LockOutpoint in that outputs are locked for a limited
// amount of time and their locks are persisted to disk.
func (w *Wallet) LeaseOutput(id wtxmgr.LockID, op wire.OutPoint) (time.Time, error) {
	var expiry time.Time
	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		var err error
		expiry, err = w.TxStore.LockOutput(ns, id, op)
		return err
	})
	return expiry, err
}

// ReleaseOutput unlocks an output, allowing it to be available for coin
// selection if it remains unspent. The ID should match the one used to
// originally lock the output.
func (w *Wallet) ReleaseOutput(id wtxmgr.LockID, op wire.OutPoint) error {
	return walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		return w.TxStore.UnlockOutput(ns, id, op)
	})
}

// resendUnminedTxs iterates through all transactions that spend from wallet
// credits that are not known to have been mined into a block, and attempts
// to send each to the chain server for relay.
func (w *Wallet) resendUnminedTx() {
	if w.resendUnminedTxFlag.Load().(bool) {
		log.Debug("resendUnminedTxFlag is set true, return...")
		return
	}
	if !w.resendUnminedTxFlag.CompareAndSwap(false, true) {
		log.Debug("fail to set resendUnminedTxFlag  true, return...")
		return
	}
	log.Debug("working for resend transaction")
	var txs []*wire.MsgTxAbe
	err := walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		var err error
		txs, err = w.TxStore.UnconfirmedTxs(txmgrNs)
		return err
	})
	if err != nil {
		log.Errorf("Unable to retrieve unconfirmed transactions to "+
			"resend: %v", err)
		w.resendUnminedTxFlag.CompareAndSwap(true, false)
		return
	}
	if txs == nil || len(txs) == 0 {
		w.resendUnminedTxFlag.CompareAndSwap(true, false)
		return
	}

	for i := 0; i < len(txs); i++ {
		tx := txs[i]
		_, err = w.publishTransaction(tx)
		// TODO 20220611 according to the response to handle
		// not all delete the unmined transaction
		if err != nil {
			log.Errorf("Unable to rebroadcast transaction %v: %v",
				tx.TxHash(), err)

			err = walletdb.Update(w.db, func(dbtx walletdb.ReadWriteTx) error {
				txmgrNs := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)
				return wtxmgr.DeleteRawUnmined(txmgrNs, tx)
			})
			if err != nil {
				log.Errorf("Unable to delete unconfirmed transactions %s which is "+
					"resended: %v", tx.TxHash(), err)
			}
		}
		log.Debugf("Successfully rebroadcast unconfirmed transaction %v",
			tx.TxHash())
	}

	w.resendUnminedTxFlag.CompareAndSwap(true, false)
	log.Debug("Done for resend transaction")
}

// SortedActivePaymentAddresses returns a slice of all active payment
// addresses in a wallet.

// NewAddress returns the next external chained address for a wallet.

func (w *Wallet) AddressMaxSequenceNumber() (uint64, error) {
	var addressNum uint64
	var err error
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		addressNum, err = waddrmgr.FetchSeedStatus(addrmgrNs)
		return err
	})
	return addressNum, err
}

func (w *Wallet) AddressRange(start uint64, end uint64) (res map[uint64]string, err error) {
	addrKeys := make(map[uint64][]byte, end-start)
	addresses := make(map[uint64][]byte, end-start)
	res = make(map[uint64]string, end-start)
	var addressMaxNum uint64
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)

		addressMaxNum, err = waddrmgr.FetchSeedStatus(addrmgrNs)
		if err != nil {
			return err
		}

		addrKeys, err = waddrmgr.FetchAddressKeys(addrmgrNs, start, end)
		for i := start; i < end && i <= addressMaxNum; i++ {
			serializedAddressEnc, _, _, _, err := w.Manager.FetchAddressKeyEncByAddressKey(addrmgrNs, addrKeys[i])
			if err != nil {
				return err
			}
			addresses[i], _, _, _, err = w.Manager.DecryptAddressKey(serializedAddressEnc, nil, nil, nil)
			if err != nil {
				return err
			}
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	for i := start; i < end; i++ {
		if i <= addressMaxNum {
			res[i] = hex.EncodeToString(addresses[i])
		} else {
			res[i] = ""
		}
	}
	return res, nil
}

// NewAddressKey returns a new address for a wallet.
func (w *Wallet) NewAddressKey() ([]byte, uint64, []byte, error) {
	var numberOrder uint64
	var addr []byte
	var netID []byte
	err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		var err error
		addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		netID, err = w.Manager.FetchNetID(addrmgrNs)
		if err != nil {
			return err
		}
		seedEnc, err := w.Manager.FetchSeedEnc(addrmgrNs)
		if err != nil {
			return err
		}
		seed, err := w.Manager.Decrypt(waddrmgr.CKTSeed, seedEnc)
		if err != nil {
			return err
		}
		var serializedASksp, serializedASksn, serializedVSk []byte
		numberOrder, addr, serializedASksp, serializedASksn, serializedVSk, err = w.Manager.GenerateAddressKeys(addrmgrNs, seed)
		if err != nil {
			return err
		}
		addressSecretKeySpEnc, err :=
			w.Manager.Encrypt(waddrmgr.CKTPrivate, serializedASksp)
		if err != nil {
			return err
		}
		addressSecretKeySnEnc, err :=
			w.Manager.Encrypt(waddrmgr.CKTPublic, serializedASksn)
		if err != nil {
			return err
		}
		addressKeyEnc, err :=
			w.Manager.Encrypt(waddrmgr.CKTPublic, addr)
		if err != nil {
			return err
		}
		valueSecretKeyEnc, err :=
			w.Manager.Encrypt(waddrmgr.CKTPublic, serializedVSk)
		if err != nil {
			return err
		}

		addKey := chainhash.DoubleHashB(addr[4 : 4+abecryptoparam.PQRingCTPP.AddressPublicKeySerializeSize()])

		err = w.Manager.PutAddressKeysEnc(addrmgrNs, numberOrder, addKey[:], valueSecretKeyEnc,
			addressSecretKeySpEnc, addressSecretKeySnEnc, addressKeyEnc)
		if err != nil {
			return err
		}

		return err
	})
	if err != nil {
		return nil, 0, nil, err
	}
	return netID, numberOrder, addr, nil
}

// newChangeAddress returns a new change address for the wallet.
//
// NOTE: This method requires the caller to use the backend's NotifyReceived
// method in order to detect when an on-chain transaction pays to the address
// being created.

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

// AccountTotalReceivedResult is a single result for the
// Wallet.TotalReceivedForAccounts method.

// TotalReceivedForAccounts iterates through a wallet's transaction history,
// returning the total amount of Abelian received for all accounts.

// TotalReceivedForAddr iterates through a wallet's transaction history,
// returning the total amount of abelian received for a single wallet
// address.

// SendOutputs creates and sends payment transactions. It returns the
// transaction upon success.

func (w *Wallet) SendOutputs(outputDescs []*abecrypto.AbeTxOutputDesc,
	minconf int32, feePerKbSpecified abeutil.Amount, feeSpecified abeutil.Amount,
	utxoSpecified []string, label string, requestHash *chainhash.Hash) (*txauthor.AuthoredTxAbe, error) {
	// Ensure the outputs to be created adhere to the network's consensus
	// rules.
	for _, txOutDesc := range outputDescs {
		err := txrules.CheckOutputDescAbe(
			txOutDesc, txrules.DefaultRelayFeePerKb,
		)
		if err != nil {
			return nil, err
		}
	}

	// Create the transaction and broadcast it to the network. The
	// transaction will be added to the database in order to ensure that we
	// continue to re-broadcast the transaction upon restarts until it has
	// been confirmed.
	createdTx, err := w.CreateSimpleTx(outputDescs, minconf, feePerKbSpecified, feeSpecified, utxoSpecified, false)
	if err != nil {
		if w.RecordRequestFlag {
			log.Errorf("can not create a transaction for request hash %s with specified utxo %s", requestHash, utxoSpecified)
		}
		return nil, err
	}

	// it means that the transaction is created successful
	txHash, err := w.reliablyPublishTransaction(createdTx.Tx, label, requestHash)
	if err != nil {
		// the wallet would fetch the transaction
		// due to error double spending
		// And then insert the transaction into database
		// But current do nothing? TODO 202207
		if _, ok := err.(*ErrDoubleSpend); ok {
			// do nothing
		}
		return nil, err
	}

	for i := 0; i < len(createdTx.Tx.TxOuts); i++ {
		log.Debugf("tx output [%d] = %x\n", i, createdTx.Tx.TxOuts[i].TxoScript)
	}
	// Sanity check on the returned tx hash.
	// something error ?
	if *txHash != createdTx.Tx.TxHash() {
		return nil, errors.New("tx hash mismatch")
	}

	return createdTx, nil
}

// SignTransaction uses secrets of the wallet, as well as additional secrets
// passed in by the caller, to create and add input signatures to a transaction.
//
// Transaction input script validation is used to confirm that all signatures
// are valid.  For any invalid input, a SignatureError is added to the returns.
// The final error return is reserved for unexpected or fatal errors, such as
// being unable to determine a previous output script to redeem.
//
// The transaction pointed to by tx is modified by this function.

// ErrDoubleSpend is an error returned from PublishTransaction in case the
// published transaction failed to propagate since it was double spending a
// confirmed transaction or a transaction in the mempool.
type ErrDoubleSpend struct {
	backendError error
}

// Error returns the string representation of ErrDoubleSpend.
//
// NOTE: Satisfies the error interface.
func (e *ErrDoubleSpend) Error() string {
	return fmt.Sprintf("double spend: %v", e.backendError)
}

// Unwrap returns the underlying error returned from the backend.
func (e *ErrDoubleSpend) Unwrap() error {
	return e.backendError
}

// ErrReplacement is an error returned from PublishTransaction in case the
// published transaction failed to propagate since it was double spending a
// replacable transaction but did not satisfy the requirements to replace it.
type ErrReplacement struct {
	backendError error
}

// Error returns the string representation of ErrReplacement.
//
// NOTE: Satisfies the error interface.
func (e *ErrReplacement) Error() string {
	return fmt.Sprintf("unable to replace transaction: %v", e.backendError)
}

// Unwrap returns the underlying error returned from the backend.
func (e *ErrReplacement) Unwrap() error {
	return e.backendError
}

// PublishTransaction sends the transaction to the consensus RPC server so it
// can be propagated to other nodes and eventually mined.
//
// This function is unstable and will be removed once syncing code is moved out
// of the wallet.
func (w *Wallet) PublishTransaction(tx *wire.MsgTxAbe, label string) error {
	_, err := w.reliablyPublishTransaction(tx, label, nil)
	return err
}

// reliablyPublishTransaction is a superset of publishTransaction which contains
// the primary logic required for publishing a transaction, updating the
// relevant database state, and finally possible removing the transaction from
// the database (along with cleaning up all inputs used, and outputs created) if
// the transaction is rejected by the backend.
func (w *Wallet) reliablyPublishTransaction(tx *wire.MsgTxAbe,
	label string, requestHash *chainhash.Hash) (*chainhash.Hash, error) {
	// firstly, send the transaction to the backend
	hash, err := w.publishTransaction(tx)
	// if failed, do nothing
	if err != nil {
		// failed
		log.Errorf("publish transaction %s err %s", tx.TxHash(), err)
		return nil, err
	}
	// if successfully, add the transaction into unmined bucket
	txRec, err := wtxmgr.NewTxRecordFromMsgTx(tx, time.Now())
	if err != nil {
		return nil, err
	}
	log.Infof("insert transaction %s into unmined bucket", tx.TxHash())
	// add the transaction into unmined bucket
	err = walletdb.Update(w.db, func(dbTx walletdb.ReadWriteTx) error {
		if err := w.addRelevantTx(dbTx, txRec, nil); err != nil {
			log.Errorf("add the transaction %s err %s", hash, err)
			return err
		}

		if w.RecordRequestFlag {
			if requestHash == nil {
				log.Errorf("request hash is nil but the record request flag is enabled")
				return errors.New("request hash is nil but the record request flag is enabled")
			}
			txmgrNs := dbTx.ReadWriteBucket(wtxmgrNamespaceKey)
			err = w.TxStore.PutRequestHashAndTxHash(txmgrNs, requestHash.String(), hash.String())
			if err != nil {
				log.Errorf("Fail to record the request hash %s and transaction hash %s", requestHash, hash.String())
				return err
			}
			log.Infof("map request hash %s to tx hash %s", requestHash, hash)
		}

		// If the tx label is empty, we can return early.
		if len(label) == 0 {
			return nil
		}
		// If there is a label we should write, get the namespace key
		// and record it in the tx store.
		txmgrNs := dbTx.ReadWriteBucket(wtxmgrNamespaceKey)
		return w.TxStore.PutTxLabel(txmgrNs, *hash, label) // use the label to explain the tx?
	})
	if err != nil {
		return nil, err
	}
	return hash, nil
}

// publishTransaction attempts to send an unconfirmed transaction to the
// wallet's current backend. In the event that sending the transaction fails for
// whatever reason, it will be removed from the wallet's unconfirmed transaction
// store.
func (w *Wallet) publishTransaction(tx *wire.MsgTxAbe) (*chainhash.Hash, error) {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	// match is a helper method to easily string match on the error
	// message.
	match := func(err error, s string) bool {
		return strings.Contains(strings.ToLower(err.Error()), s)
	}

	_, err = chainClient.SendRawTransactionAbe(tx, false) // send the transaction to backend

	// Determine if this was an RPC error thrown due to the transaction
	// already confirming.
	var rpcTxConfirmed bool
	if rpcErr, ok := err.(*abejson.RPCError); ok {
		rpcTxConfirmed = rpcErr.Code == abejson.ErrRPCTxAlreadyInChain
	}

	var (
		txid      = tx.TxHash()
		returnErr error
	)

	switch {
	case err == nil:
		return &txid, nil

	// Since we have different backends that can be used with the wallet,
	// we'll need to check specific errors for each one.
	//
	// If the transaction is already in the mempool, we can just return now.
	//
	// This error is returned when broadcasting/sending a transaction to a
	// abec node that already has it in their mempool.
	// https://github.com/btcsuite/btcd/blob/130ea5bddde33df32b06a1cdb42a6316eb73cff5/mempool/mempool.go#L953
	case match(err, "already have transaction"):
		fallthrough

	// This error is returned when broadcasting a transaction to a bitcoind
	// node that already has it in their mempool.
	// https://github.com/bitcoin/bitcoin/blob/9bf5768dd628b3a7c30dd42b5ed477a92c4d3540/src/validation.cpp#L590
	case match(err, "txn-already-in-mempool"):
		return &txid, nil

	// If the transaction has already confirmed, we can safely remove it
	// from the unconfirmed store as it should already exist within the
	// confirmed store. We'll avoid returning an error as the broadcast was
	// in a sense successful.
	//
	// This error is returned when sending a transaction that has already
	// confirmed to a btcd/bitcoind node over RPC.
	// https://github.com/btcsuite/btcd/blob/130ea5bddde33df32b06a1cdb42a6316eb73cff5/rpcserver.go#L3355
	// https://github.com/bitcoin/bitcoin/blob/9bf5768dd628b3a7c30dd42b5ed477a92c4d3540/src/node/transaction.cpp#L36
	case rpcTxConfirmed:
		fallthrough

	// This error is returned when broadcasting a transaction that has
	// already confirmed to a btcd node over the P2P network.
	// https://github.com/btcsuite/btcd/blob/130ea5bddde33df32b06a1cdb42a6316eb73cff5/mempool/mempool.go#L1036
	case match(err, "transaction already exists"):
		fallthrough

	// This error is returned when broadcasting a transaction that has
	// already confirmed to a bitcoind node over the P2P network.
	// https://github.com/bitcoin/bitcoin/blob/9bf5768dd628b3a7c30dd42b5ed477a92c4d3540/src/validation.cpp#L648
	case match(err, "txn-already-known"): //update the utxo set
		fallthrough

	// If the transactions is invalid since it attempts to double spend a
	// transaction already in the mempool or in the chain, we'll remove it
	// from the store and return an error.
	//
	// This error is returned from btcd when there is already a transaction
	// not signaling replacement in the mempool that spends one of the
	// referenced outputs.
	// https://github.com/btcsuite/btcd/blob/130ea5bddde33df32b06a1cdb42a6316eb73cff5/mempool/mempool.go#L591
	case match(err, "already spent"):
		fallthrough

	// This error is returned from btcd when a referenced output cannot be
	// found, meaning it etiher has been spent or doesn't exist.
	// https://github.com/btcsuite/btcd/blob/130ea5bddde33df32b06a1cdb42a6316eb73cff5/blockchain/chain.go#L405
	case match(err, "already been spent"):
		fallthrough

	// This error is returned from btcd when a transaction is spending
	// either output that is missing or already spent, and orphans aren't
	// allowed.
	// https://github.com/btcsuite/btcd/blob/130ea5bddde33df32b06a1cdb42a6316eb73cff5/mempool/mempool.go#L1409
	case match(err, "orphan transaction"):
		fallthrough

	// Returned by bitcoind on the RPC when broadcasting a transaction that
	// is spending either output that is missing or already spent.
	//
	// https://github.com/bitcoin/bitcoin/blob/9bf5768dd628b3a7c30dd42b5ed477a92c4d3540/src/node/transaction.cpp#L49
	// https://github.com/bitcoin/bitcoin/blob/0.20/src/validation.cpp#L642
	case match(err, "missing inputs") ||
		match(err, "bad-txns-inputs-missingorspent"):

		returnErr = &ErrDoubleSpend{
			backendError: err,
		}

	// Error returned from bitcoind when output was spent by other
	// non-replacable transaction already in the mempool.
	// https://github.com/bitcoin/bitcoin/blob/9bf5768dd628b3a7c30dd42b5ed477a92c4d3540/src/validation.cpp#L622
	case match(err, "txn-mempool-conflict"):
		// TODO 20220625: In Abelian, the conflict transaction should be fetched from node
		// But now, this procedure just wait the transaction packaged into block
		// In this way, the transaction should be handled when handling the block

	// Returned by bitcoind if the transaction spends outputs that would be
	// replaced by it.
	// https://github.com/bitcoin/bitcoin/blob/9bf5768dd628b3a7c30dd42b5ed477a92c4d3540/src/validation.cpp#L790
	case match(err, "bad-txns-spends-conflicting-tx"):
		fallthrough

	// Returned by bitcoind when a replacement transaction did not have
	// enough fee.
	// https://github.com/bitcoin/bitcoin/blob/9bf5768dd628b3a7c30dd42b5ed477a92c4d3540/src/validation.cpp#L830
	// https://github.com/bitcoin/bitcoin/blob/9bf5768dd628b3a7c30dd42b5ed477a92c4d3540/src/validation.cpp#L894
	// https://github.com/bitcoin/bitcoin/blob/9bf5768dd628b3a7c30dd42b5ed477a92c4d3540/src/validation.cpp#L904
	case match(err, "insufficient fee"):
		fallthrough

	// Returned by bitcoind in case the transaction would replace too many
	// transaction in the mempool.
	// https://github.com/bitcoin/bitcoin/blob/9bf5768dd628b3a7c30dd42b5ed477a92c4d3540/src/validation.cpp#L858
	case match(err, "too many potential replacements"):
		fallthrough

	// Returned by bitcoind if the transaction spends an output that is
	// unconfimed and not spent by the transaction it replaces.
	// https://github.com/bitcoin/bitcoin/blob/9bf5768dd628b3a7c30dd42b5ed477a92c4d3540/src/validation.cpp#L882
	case match(err, "replacement-adds-unconfirmed"):
		fallthrough

	// Returned by btcd when replacement transaction was rejected for
	// whatever reason.
	// https://github.com/btcsuite/btcd/blob/130ea5bddde33df32b06a1cdb42a6316eb73cff5/mempool/mempool.go#L841
	// https://github.com/btcsuite/btcd/blob/130ea5bddde33df32b06a1cdb42a6316eb73cff5/mempool/mempool.go#L854
	// https://github.com/btcsuite/btcd/blob/130ea5bddde33df32b06a1cdb42a6316eb73cff5/mempool/mempool.go#L875
	// https://github.com/btcsuite/btcd/blob/130ea5bddde33df32b06a1cdb42a6316eb73cff5/mempool/mempool.go#L896
	// https://github.com/btcsuite/btcd/blob/130ea5bddde33df32b06a1cdb42a6316eb73cff5/mempool/mempool.go#L913
	case match(err, "replacement transaction"):
		returnErr = &ErrReplacement{
			backendError: err,
		}

	// We received an error not matching any of the above cases.
	default:
		returnErr = fmt.Errorf("unmatched backend error: %v", err)
	}

	return nil, returnErr
}

// ChainParams returns the network parameters for the blockchain the wallet
// belongs to.
func (w *Wallet) ChainParams() *chaincfg.Params {
	return w.chainParams
}

// Database returns the underlying walletdb database. This method is provided
// in order to allow applications wrapping btcwallet to store app-specific data
// with the wallet's database.
func (w *Wallet) Database() walletdb.DB {
	return w.db
}

func (w *Wallet) GetTxHashRequestHash(requestHash string) (res map[string]interface{}, err error) {
	var txHashStr string
	var status int
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		txHash, err := w.TxStore.GetTxHashRequestHash(txmgrNs, requestHash)
		if err != nil || txHash == nil || txHash.IsEqual(&chainhash.ZeroHash) {
			return err
		}
		txHashStr = txHash.String()
		status, err = w.TxStore.TxStatus(txmgrNs, txHash)
		return err
	})
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"txHash": txHashStr, "status": status}, nil
}

// Create creates an new wallet, writing it to an empty database.  If the passed
// seed is non-nil, it is used.  Otherwise, a secure random seed of the
// recommended length is generated.

// TODO(abe):
func Create(db walletdb.DB, pubPass, privPass, seed []byte, end uint64,
	params *chaincfg.Params, birthday time.Time) error {

	return create(
		db, pubPass, privPass, seed, end, params, birthday, false,
	)
}

// CreateWatchingOnly creates an new watch-only wallet, writing it to
// an empty database. No seed can be provided as this wallet will be
// watching only.  Likewise no private passphrase may be provided
// either.
func CreateWatchingOnly(db walletdb.DB, pubPass []byte,
	params *chaincfg.Params, birthday time.Time) error {

	return create(
		db, pubPass, nil, nil, 0, params, birthday, true,
	)
}

func create(db walletdb.DB, pubPass, privPass, seed []byte, end uint64,
	params *chaincfg.Params, birthday time.Time, isWatchingOnly bool) error {
	// TODO: the following snippet is not run?
	if !isWatchingOnly {
		// If a seed was provided, ensure that it is of valid length. Otherwise,
		// we generate a random seed for the wallet with the recommended seed
		// length.
		// TODO(abe,20210619): this code snippet seems to not run forever?
		if seed == nil {
			//	todo(ABE.MUST): the generation of the seed
			//	How does ABE generates the seed? By outputting the seed in the process of generating MPK.
			//	Or generating
			seed = make([]byte, prompt.SeedLength)
			_, err := rand.Read(seed[:])
			if err != nil {
				str := "failed to read random source"
				return errors.New(str)
			}
		}
	}
	return walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs, err := tx.CreateTopLevelBucket(waddrmgrNamespaceKey)
		if err != nil {
			return err
		}
		txmgrNs, err := tx.CreateTopLevelBucket(wtxmgrNamespaceKey)
		if err != nil {
			return err
		}

		err = waddrmgr.Create(
			addrmgrNs, seed, pubPass, privPass, end, params, nil, birthday,
		)
		if err != nil {
			return err
		}
		return wtxmgr.Create(txmgrNs)
	})
}

// Open loads an already-created wallet from the passed database and namespaces.
func Open(db walletdb.DB, pubPass []byte, cbs *waddrmgr.OpenCallbacks,
	params *chaincfg.Params, recoveryWindow uint32) (*Wallet, error) {

	var (
		addrMgr *waddrmgr.Manager
		txMgr   *wtxmgr.Store
	)

	// Before attempting to open the wallet, we'll check if there are any
	// database upgrades for us to proceed. We'll also create our references
	// to the address and transaction managers, as they are backed by the
	// database.
	err := walletdb.Update(db, func(tx walletdb.ReadWriteTx) error {
		addrMgrBucket := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		if addrMgrBucket == nil {
			return errors.New("missing address manager namespace")
		}
		txMgrBucket := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		if txMgrBucket == nil {
			return errors.New("missing transaction manager namespace")
		}

		// TODO(abe): the upgrade can discard now
		addrMgrUpgrader := waddrmgr.NewMigrationManager(addrMgrBucket)
		txMgrUpgrader := wtxmgr.NewMigrationManager(txMgrBucket)
		err := migration.Upgrade(txMgrUpgrader, addrMgrUpgrader)
		if err != nil {
			return err
		}

		//TODO(abe):disable old manager
		//addrMgr, err = waddrmgr.Open(addrMgrBucket, pubPass, params)
		addrMgr, err = waddrmgr.Open(addrMgrBucket, pubPass, params)
		if err != nil {
			return err
		}
		txMgr, err = wtxmgr.Open(addrMgr, txMgrBucket, params)
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	log.Infof("Opened wallet") // TODO: log balance? last sync height?

	w := &Wallet{
		publicPassphrase:    pubPass,
		db:                  db,
		Manager:             addrMgr,
		TxStore:             txMgr,
		lockedOutpoints:     map[wire.OutPoint]struct{}{},
		resendUnminedTxFlag: atomic.Value{},
		recoveryWindow:      recoveryWindow,
		createTxRequests:    make(chan createTxRequest),
		unlockRequests:      make(chan unlockRequest),
		lockRequests:        make(chan struct{}),
		holdUnlockRequests:  make(chan chan heldUnlock),
		lockState:           make(chan bool),
		changePassphrase:    make(chan changePassphraseRequest),
		changePassphrases:   make(chan changePassphrasesRequest),
		chainParams:         params,
		quit:                make(chan struct{}),
	}
	w.resendUnminedTxFlag.Store(false)

	//	todo(ABE): ABE does not support spent and unspent notifications.
	w.NtfnServer = newNotificationServer(w)
	w.TxStore.NotifyUnspent = func(hash *chainhash.Hash, index uint32) {
		w.NtfnServer.notifyUnspentOutput(0, hash, index)
	}
	w.TxStore.NotifyTransactionAccepted = func(txInfo *wtxmgr.TransactionInfo) {
		log.Debugf("send transaction accepted notification with hash %s and height %d", txInfo.TxHash, txInfo.Height)
		w.sendNotification(NTTransactionAccepted, txInfo)
	}
	w.TxStore.NotifyTransactionRollback = func(txInfo *wtxmgr.TransactionInfo) {
		log.Debugf("send transaction rollback notification with hash %s and height %d", txInfo.TxHash, txInfo.Height)
		w.sendNotification(NTTransactionRollback, txInfo)
	}
	w.TxStore.NotifyTransactionInvalid = func(txInfo *wtxmgr.TransactionInfo) {
		log.Debugf("send transaction invalid notification with hash %s and height %d", txInfo.TxHash, txInfo.Height)
		w.sendNotification(NTTransactionInvalid, txInfo)
	}
	return w, nil
}
