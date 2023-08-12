package wallet

import (
	"bytes"
	"fmt"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abewallet/chain"
	"github.com/abesuite/abewallet/waddrmgr"
	"github.com/abesuite/abewallet/walletdb"
	"github.com/abesuite/abewallet/wtxmgr"
	"time"
)

const (
	// birthdayBlockDelta is the maximum time delta allowed between our
	// birthday timestamp and our birthday block's timestamp when searching
	// for a better birthday block candidate (if possible).
	birthdayBlockDelta = 2 * time.Hour
)

func (w *Wallet) handleChainNotifications() {
	defer w.wg.Done()

	chainClient, err := w.requireChainClient()
	if err != nil {
		log.Errorf("handleChainNotifications called without RPC client")
		return
	}

	// catchupHashes
	_ = func(w *Wallet, client chain.Interface, endHeight int32) error {
		// TODO(aakselrod): There's a race conditon here, which
		// happens when a reorg occurs between the
		// rescanProgress notification and the last GetBlockHash
		// call. The solution when using btcd is to make btcd
		// send blockconnected notifications with each block
		// the way Neutrino does, and get rid of the loop. The
		// other alternative is to check the final hash and,
		// if it doesn't match the original hash returned by
		// the notification, to roll back and restart the
		// rescan.
		log.Infof("Catching up block hashes to height %d, this"+
			" might take a while", endHeight)
		err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
			addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
			txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)

			syncedHeight := w.Manager.SyncedTo().Height

			for i := syncedHeight + 1; i <= endHeight; i++ {
				hash, err := client.GetBlockHash(int64(i)) //Why use client not chainclient? It uses a interface to adapt to different client.
				if err != nil {
					return err
				}

				blockNum := int32(wire.GetBlockNumPerRingGroupByBlockHeight(i))
				maturedBlockHashs := make([]*chainhash.Hash, blockNum)
				maturity := int32(w.chainParams.CoinbaseMaturity)
				if i >= maturity && (i-maturity+1)%blockNum == 0 {
					for j := int32(0); j < blockNum; j++ {
						maturedBlockHashs[j], err = client.GetBlockHash(int64(i - maturity - j))
						if err != nil {
							return err
						}
					}
				}

				b, err := chainClient.GetBlockAbe(hash)
				if err != nil {
					return err
				}
				blockAbeDetail, err := wtxmgr.NewBlockRecordFromMsgBlock(b)
				if err != nil {
					return err
				}
				extraBlockAbeDetails := make(map[uint32]*wtxmgr.BlockRecord, 2)
				if blockAbeDetail.Height%blockNum == blockNum-1 {
					b1, err := chainClient.GetBlockAbe(&blockAbeDetail.MsgBlock.Header.PrevBlock)
					if err != nil {
						return err
					}
					extraBlockAbeDetails[uint32(blockAbeDetail.Height-1)], err = wtxmgr.NewBlockRecordFromMsgBlock(b1)
					if err != nil {
						return err
					}

					b2, err := chainClient.GetBlockAbe(&extraBlockAbeDetails[uint32(blockAbeDetail.Height-1)].MsgBlock.Header.PrevBlock)
					if err != nil {
						return err
					}
					extraBlockAbeDetails[uint32(blockAbeDetail.Height-2)], err = wtxmgr.NewBlockRecordFromMsgBlock(b2)
					if err != nil {
						return err
					}
				}

				err = w.TxStore.InsertBlock(txmgrNs, addrmgrNs, blockAbeDetail, extraBlockAbeDetails, maturedBlockHashs)
				if err != nil {
					return err
				}
				bs := waddrmgr.BlockStamp{
					Height:    i,
					Hash:      *hash,
					Timestamp: blockAbeDetail.RecvTime,
				}
				//err = w.Manager.SetSyncedTo(ns, &bs)
				err = w.Manager.SetSyncedTo(addrmgrNs, &bs)
				if err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			log.Errorf("Failed to update address manager "+
				"sync state for height %d: %v", endHeight, err)
		}

		log.Info("Done catching up block hashes")
		return err
	}

	for {
		select {
		case n, ok := <-chainClient.Notifications():
			if !ok {
				return
			}

			var notificationName string
			var err error
			switch n := n.(type) {
			case chain.ClientConnected:
				// Before attempting to sync with our backend,
				// we'll make sure that our birthday block has
				// been set correctly to potentially prevent
				// missing relevant events.
				birthdayStore := &walletBirthdayStore{
					db:      w.db,
					manager: w.Manager,
				}
				birthdayBlock, err := birthdaySanityCheck(
					chainClient, birthdayStore,
				)
				if err != nil && !waddrmgr.IsError(err, waddrmgr.ErrBirthdayBlockNotSet) {
					panic(fmt.Errorf("unable to sanity "+
						"check wallet birthday block: %v",
						err))
				}
				// When the wallet has connected to the full node, it need
				// to sync with the chain
				// It would happen that the chain would fork successful
				// So there should be check it and sync to the best chain
				err = w.syncWithChain(birthdayBlock)
				if err != nil && !w.ShuttingDown() {
					panic(fmt.Errorf("unable to synchronize "+
						"wallet to chain: %v", err))
				}

			case chain.BlockAbeConnected:
				// To avoid accumulating a lot of block notifications in the
				// process of obtaining the latest block in wallet side
				// due to the too long synchronization process of nodes
				if w.Manager.SyncedTo().Height < n.Height {
					err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
						return w.connectBlock(tx, wtxmgr.BlockMeta(n))
					})
				}

				// When receiving a notification of connecting block
				// The wallet resend all transaction that is not mined.
				// On the one hand, the transaction would be invalid due
				// to the newer block, so clean the invalid transaction,
				// and update the balance
				// On the other hand, the valid transaction would be resend
				// to the backend, and expected to package into the next block.
				// TODO 20220611: there should be use the wait group to trace the goroutine
				go w.resendUnminedTx()
				notificationName = "block connected"
			case chain.BlockAbeDisconnected:
				err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
					return w.disconnectBlock(tx, wtxmgr.BlockMeta(n))
				})
				notificationName = "block disconnected"
			}
			if err != nil {
				// If we received a block connected notification
				// while rescanning, then we can ignore logging
				// the error as we'll properly catch up once we
				// process the RescanFinished notification.
				if notificationName == "block connected" &&
					waddrmgr.IsError(err, waddrmgr.ErrBlockNotFound) &&
					!w.ChainSynced() {

					log.Debugf("Received block connected "+
						"notification for height %v "+
						"while rescanning",
						n.(chain.BlockAbeConnected).Height)
					continue
				}

				log.Errorf("Unable to process chain backend "+
					"%v notification: %v", notificationName,
					err)
			}
		case <-w.quit:
			return
		}
	}
}

// connectBlock handles a chain server notification by marking a wallet
// that's currently in-sync with the chain server as being synced up to
// the passed block.

// TODO(abe): this function is used to notify the client
func (w *Wallet) connectBlock(dbtx walletdb.ReadWriteTx, b wtxmgr.BlockMeta) error {
	// actually we just used the addrmgrNS to manage the sync state, other content will be deleted
	var err error
	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)

	bs := waddrmgr.BlockStamp{
		Height:    b.Height,
		Hash:      b.Hash,
		Timestamp: b.Time,
	}
	err = w.Manager.SetSyncedTo(addrmgrNs, &bs)
	if err != nil {
		return err
	}
	block, err := w.chainClient.GetBlockAbe(&b.Hash)
	if err != nil {
		return err
	}

	br, err := wtxmgr.NewBlockRecordFromMsgBlock(block)
	if err != nil {
		return err
	}
	txmgrNs := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)

	// At the moment all notified transactions are assumed to actually be
	// relevant.  This assumption will not hold true when SPV support is
	// added, but until then, simply insert the transaction because there
	// should either be one or more relevant inputs or outputs.
	blockNum := int32(wire.GetBlockNumPerRingGroupByBlockHeight(b.Height))
	maturedBlockHashs := make([]*chainhash.Hash, blockNum)
	maturity := int32(w.chainParams.CoinbaseMaturity)
	if b.Height >= maturity && (b.Height-maturity+1)%blockNum == 0 {
		for j := int32(0); j < blockNum; j++ {
			maturedBlockHashs[j], err = w.ChainClient().GetBlockHash(int64(b.Height - maturity - j))
			if err != nil {
				return err
			}
		}
	}
	extraBlockAbeDetails := make(map[uint32]*wtxmgr.BlockRecord, 2)
	if br.Height%blockNum == blockNum-1 {
		b1, err := w.chainClient.GetBlockAbe(&br.MsgBlock.Header.PrevBlock)
		if err != nil {
			return err
		}
		extraBlockAbeDetails[uint32(br.Height-1)], err = wtxmgr.NewBlockRecordFromMsgBlock(b1)
		if err != nil {
			return err
		}

		b2, err := w.chainClient.GetBlockAbe(&extraBlockAbeDetails[uint32(br.Height-1)].MsgBlock.Header.PrevBlock)
		if err != nil {
			return err
		}
		extraBlockAbeDetails[uint32(br.Height-2)], err = wtxmgr.NewBlockRecordFromMsgBlock(b2)
		if err != nil {
			return err
		}
	}

	//err = w.TxStore.InsertBlockAbe(txmgrNs, br,*maturedBlockHash, mpk, msvk)
	err = w.TxStore.InsertBlock(txmgrNs, addrmgrNs, br, extraBlockAbeDetails, maturedBlockHashs)
	if err != nil {
		return err
	}
	//return nil
	// Notify interested clients of the connected block.
	//
	// TODO: move all notifications outside of the database transaction.
	w.NtfnServer.notifyAttachedBlock(dbtx, &b)
	return nil
}

// disconnectBlock handles a chain server reorganize by rolling back all
// block history from the reorged block for a wallet in-sync with the chain
// server.
func (w *Wallet) disconnectBlock(dbtx walletdb.ReadWriteTx, b wtxmgr.BlockMeta) error {
	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)
	txmgrNs := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)
	//if !w.ChainSynced() { // if the wallet is syncing with backend, wait for it...
	//	return nil
	//}

	// Disconnect the removed block and all blocks after it if we know about
	// the disconnected block. Otherwise, the block is in the future.
	if b.Height <= w.Manager.SyncedTo().Height {
		hash, err := w.Manager.BlockHash(addrmgrNs, b.Height)
		if err != nil {
			return err
		}
		// If the hash in that height if matched between database and input
		// Then
		if bytes.Equal(hash[:], b.Hash[:]) {
			bs := waddrmgr.BlockStamp{
				Height: b.Height - 1,
			}
			// fetch the block hash from the database with height
			hash, err = w.Manager.BlockHash(addrmgrNs, bs.Height)
			if err != nil {
				return err
			}
			bs.Hash = *hash

			client := w.ChainClient()
			header, err := client.GetBlockHeader(hash)
			if err != nil {
				return err
			}

			bs.Timestamp = header.Timestamp //if fail to detach, it will be not commited
			// roll back the synced status of database
			err = w.Manager.SetSyncedTo(addrmgrNs, &bs)
			if err != nil {
				return err
			}
			log.Infof("Rollbacking to block with height %d, hash %s", bs.Height, bs.Hash)

			// rollback to the assigned height
			err = w.TxStore.Rollback(w.Manager, addrmgrNs, txmgrNs, bs.Height)
			if err != nil {
				return err
			}
		}
	}

	// Notify interested clients of the disconnected block.
	w.NtfnServer.notifyDetachedBlock(&b.Hash)

	return nil
}

// todo(ABE): Wallet adds transactions to wallet db.
func (w *Wallet) addRelevantTx(dbtx walletdb.ReadWriteTx, rec *wtxmgr.TxRecord, block *wtxmgr.BlockMeta) error {
	txmgrNs := dbtx.ReadWriteBucket(wtxmgrNamespaceKey)
	//addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)
	// At the moment all notified transactions are assumed to actually be
	// relevant.  This assumption will not hold true when SPV support is
	// added, but until then, simply insert the transaction because there
	// should either be one or more relevant inputs or outputs.
	// TODO(abe): when add a transaction to wallet, it means that
	// this transaction is created by the wallet itself, it must
	// move the outputs of this transaction from unspent txo
	// bucket to spentButUmined txo bucket
	err := w.TxStore.InsertTx(txmgrNs, rec, block)
	if err != nil {
		return err
	}
	// TODO(abe):Notificate the client know some coins/utxos has been updated
	// but now, we need to add some struct to express it.
	return nil
}

// chainConn is an interface that abstracts the chain connection logic required
// to perform a wallet's birthday block sanity check.
type chainConn interface {
	// GetBestBlock returns the hash and height of the best block known to
	// the backend.
	GetBestBlock() (*chainhash.Hash, int32, error)

	// GetBlockHash returns the hash of the block with the given height.
	GetBlockHash(int64) (*chainhash.Hash, error)

	// GetBlockHeader returns the header for the block with the given hash.
	GetBlockHeader(*chainhash.Hash) (*wire.BlockHeader, error)
}

// birthdayStore is an interface that abstracts the wallet's sync-related
// information required to perform a birthday block sanity check.
type birthdayStore interface {
	// Birthday returns the birthday timestamp of the wallet.
	Birthday() time.Time

	// BirthdayBlock returns the birthday block of the wallet. The boolean
	// returned should signal whether the wallet has already verified the
	// correctness of its birthday block.
	BirthdayBlock() (waddrmgr.BlockStamp, bool, error)

	// SetBirthdayBlock updates the birthday block of the wallet to the
	// given block. The boolean can be used to signal whether this block
	// should be sanity checked the next time the wallet starts.
	//
	// NOTE: This should also set the wallet's synced tip to reflect the new
	// birthday block. This will allow the wallet to rescan from this point
	// to detect any potentially missed events.
	SetBirthdayBlock(waddrmgr.BlockStamp) error
}

// walletBirthdayStore is a wrapper around the wallet's database and address
// manager that satisfies the birthdayStore interface.
type walletBirthdayStore struct {
	db      walletdb.DB
	manager *waddrmgr.Manager
}

var _ birthdayStore = (*walletBirthdayStore)(nil)

// Birthday returns the birthday timestamp of the wallet.
func (s *walletBirthdayStore) Birthday() time.Time {
	return s.manager.Birthday()
}

// BirthdayBlock returns the birthday block of the wallet.
func (s *walletBirthdayStore) BirthdayBlock() (waddrmgr.BlockStamp, bool, error) {
	var (
		birthdayBlock         waddrmgr.BlockStamp
		birthdayBlockVerified bool
	)

	err := walletdb.View(s.db, func(tx walletdb.ReadTx) error {
		var err error
		ns := tx.ReadBucket(waddrmgrNamespaceKey)
		//TODO(abe):replace manager with abe
		birthdayBlock, birthdayBlockVerified, err = s.manager.BirthdayBlock(ns)
		return err
	})

	return birthdayBlock, birthdayBlockVerified, err
}

// SetBirthdayBlock updates the birthday block of the wallet to the
// given block. The boolean can be used to signal whether this block
// should be sanity checked the next time the wallet starts.
//
// NOTE: This should also set the wallet's synced tip to reflect the new
// birthday block. This will allow the wallet to rescan from this point
// to detect any potentially missed events.
func (s *walletBirthdayStore) SetBirthdayBlock(block waddrmgr.BlockStamp) error {
	return walletdb.Update(s.db, func(tx walletdb.ReadWriteTx) error {
		ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)
		err := s.manager.SetBirthdayBlock(ns, block, true)
		if err != nil {
			return err
		}
		return s.manager.SetSyncedTo(ns, &block)
	})
}

// birthdaySanityCheck is a helper function that ensures a birthday block
// correctly reflects the birthday timestamp within a reasonable timestamp
// delta. It's intended to be run after the wallet establishes its connection
// with the backend, but before it begins syncing. This is done as the second
// part to the wallet's address manager migration where we populate the birthday
// block to ensure we do not miss any relevant events throughout rescans.
// waddrmgr.ErrBirthdayBlockNotSet is returned if the birthday block has not
// been set yet.
func birthdaySanityCheck(chainConn chainConn,
	birthdayStore birthdayStore) (*waddrmgr.BlockStamp, error) {

	// We'll start by fetching our wallet's birthday timestamp and block.
	birthdayTimestamp := birthdayStore.Birthday()
	birthdayBlock, birthdayBlockVerified, err := birthdayStore.BirthdayBlock()
	if err != nil {
		return nil, err
	}

	// If the birthday block has already been verified to be correct, we can
	// exit our sanity check to prevent potentially fetching a better
	// candidate.
	if birthdayBlockVerified {
		log.Debugf("Birthday block has already been verified: "+
			"height=%d, hash=%v", birthdayBlock.Height,
			birthdayBlock.Hash)

		return &birthdayBlock, nil
	}

	// Otherwise, we'll attempt to locate a better one now that we have
	// access to the chain.
	newBirthdayBlock, err := locateBirthdayBlock(chainConn, birthdayTimestamp)
	if err != nil {
		return nil, err
	}

	if err := birthdayStore.SetBirthdayBlock(*newBirthdayBlock); err != nil {
		return nil, err
	}

	return newBirthdayBlock, nil
}
