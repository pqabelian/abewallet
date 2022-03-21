package wallet

import (
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/txscript"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abewallet/chain"
	"github.com/abesuite/abewallet/waddrmgr"
	"github.com/abesuite/abewallet/walletdb"
	"github.com/abesuite/abewallet/wtxmgr"
)

// RescanProgressMsg reports the current progress made by a rescan for a
// set of wallet addresses.
type RescanProgressMsg struct {
	Addresses    []abeutil.Address
	Notification *chain.RescanProgress
}

// RescanFinishedMsg reports the addresses that were rescanned when a
// rescanfinished message was received rescanning a batch of addresses.
type RescanFinishedMsg struct {
	Addresses    []abeutil.Address
	Notification *chain.RescanFinished
}

// RescanJob is a job to be processed by the RescanManager.  The job includes
// a set of wallet addresses, a starting height to begin the rescan, and
// outpoints spendable by the addresses thought to be unspent.  After the
// rescan completes, the error result of the rescan RPC is sent on the Err
// channel.
type RescanJob struct {
	InitialSync bool
	Addrs       []abeutil.Address
	OutPoints   map[wire.OutPoint]abeutil.Address
	BlockStamp  waddrmgr.BlockStamp
	err         chan error
}

// rescanBatch is a collection of one or more RescanJobs that were merged
// together before a rescan is performed.
type rescanBatch struct {
	initialSync bool
	addrs       []abeutil.Address
	outpoints   map[wire.OutPoint]abeutil.Address
	bs          waddrmgr.BlockStamp
	errChans    []chan error
}

// SubmitRescan submits a RescanJob to the RescanManager.  A channel is
// returned with the final error of the rescan.  The channel is buffered
// and does not need to be read to prevent a deadlock.
func (w *Wallet) SubmitRescan(job *RescanJob) <-chan error {
	errChan := make(chan error, 1)
	job.err = errChan
	select {
	case w.rescanAddJob <- job:
	case <-w.quitChan():
		errChan <- ErrWalletShuttingDown
	}
	return errChan
}

// batch creates the rescanBatch for a single rescan job.
func (job *RescanJob) batch() *rescanBatch {
	return &rescanBatch{
		initialSync: job.InitialSync,
		addrs:       job.Addrs,
		outpoints:   job.OutPoints,
		bs:          job.BlockStamp,
		errChans:    []chan error{job.err},
	}
}

// merge merges the work from k into j, setting the starting height to
// the minimum of the two jobs.  This method does not check for
// duplicate addresses or outpoints.
func (b *rescanBatch) merge(job *RescanJob) {
	if job.InitialSync {
		b.initialSync = true
	}
	b.addrs = append(b.addrs, job.Addrs...)

	for op, addr := range job.OutPoints {
		b.outpoints[op] = addr
	}

	if job.BlockStamp.Height < b.bs.Height {
		b.bs = job.BlockStamp
	}
	b.errChans = append(b.errChans, job.err)
}

// done iterates through all error channels, duplicating sending the error
// to inform callers that the rescan finished (or could not complete due
// to an error).
func (b *rescanBatch) done(err error) {
	for _, c := range b.errChans {
		c <- err
	}
}

// rescanBatchHandler handles incoming rescan request, serializing rescan
// submissions, and possibly batching many waiting requests together so they
// can be handled by a single rescan after the current one completes.
func (w *Wallet) rescanBatchHandler() {
	defer w.wg.Done()

	var curBatch, nextBatch *rescanBatch
	quit := w.quitChan()

	for {
		select {
		case job := <-w.rescanAddJob:
			if curBatch == nil {
				// Set current batch as this job and send
				// request.
				curBatch = job.batch()
				select {
				case w.rescanBatch <- curBatch:
				case <-quit:
					job.err <- ErrWalletShuttingDown
					return
				}
			} else {
				// Create next batch if it doesn't exist, or
				// merge the job.
				if nextBatch == nil {
					nextBatch = job.batch()
				} else {
					nextBatch.merge(job)
				}
			}

		case n := <-w.rescanNotifications:
			switch n := n.(type) {
			case *chain.RescanProgress:
				if curBatch == nil {
					log.Warnf("Received rescan progress " +
						"notification but no rescan " +
						"currently running")
					continue
				}
				select {
				case w.rescanProgress <- &RescanProgressMsg{
					Addresses:    curBatch.addrs,
					Notification: n,
				}:
				case <-quit:
					for _, errChan := range curBatch.errChans {
						errChan <- ErrWalletShuttingDown
					}
					return
				}

			case *chain.RescanFinished:
				if curBatch == nil {
					log.Warnf("Received rescan finished " +
						"notification but no rescan " +
						"currently running")
					continue
				}
				select {
				case w.rescanFinished <- &RescanFinishedMsg{
					Addresses:    curBatch.addrs,
					Notification: n,
				}:
				case <-quit:
					for _, errChan := range curBatch.errChans {
						errChan <- ErrWalletShuttingDown
					}
					return
				}

				curBatch, nextBatch = nextBatch, nil

				if curBatch != nil {
					select {
					case w.rescanBatch <- curBatch:
					case <-quit:
						for _, errChan := range curBatch.errChans {
							errChan <- ErrWalletShuttingDown
						}
						return
					}
				}

			default:
				// Unexpected message
				panic(n)
			}

		case <-quit:
			return
		}
	}
}

// rescanProgressHandler handles notifications for partially and fully completed
// rescans by marking each rescanned address as partially or fully synced.
func (w *Wallet) rescanProgressHandler() {
	quit := w.quitChan()
out:
	for {
		// These can't be processed out of order since both chans are
		// unbuffured and are sent from same context (the batch
		// handler).
		select {
		case msg := <-w.rescanProgress:
			n := msg.Notification
			log.Infof("Rescanned through block %v (height %d)",
				n.Hash, n.Height)

		case msg := <-w.rescanFinished:
			n := msg.Notification
			addrs := msg.Addresses
			noun := pickNoun(len(addrs), "address", "addresses")
			log.Infof("Finished rescan for %d %s (synced to block "+
				"%s, height %d)", len(addrs), noun, n.Hash,
				n.Height)

			//go w.resendUnminedTxs()     //TODO(abe):will be deleted or change the name
			go w.resendUnminedTxAbes()

		case <-quit:
			break out
		}
	}
	w.wg.Done()
}

// rescanRPCHandler reads batch jobs sent by rescanBatchHandler and sends the
// RPC requests to perform a rescan.  New jobs are not read until a rescan
// finishes.
func (w *Wallet) rescanRPCHandler() {
	chainClient, err := w.requireChainClient()
	if err != nil {
		log.Errorf("rescanRPCHandler called without an RPC client")
		w.wg.Done()
		return
	}

	quit := w.quitChan()

out:
	for {
		select {
		case batch := <-w.rescanBatch:
			// Log the newly-started rescan.
			numAddrs := len(batch.addrs)
			noun := pickNoun(numAddrs, "address", "addresses")
			log.Infof("Started rescan from block %v (height %d) for %d %s",
				batch.bs.Hash, batch.bs.Height, numAddrs, noun)
			//TODO(abe): replace rescan with rescanAbe
			//err := chainClient.Rescan(&batch.bs.Hash, batch.addrs,
			//	batch.outpoints)
			err := chainClient.RescanAbe(&batch.bs.Hash)
			if err != nil {
				log.Errorf("Rescan for %d %s failed: %v", numAddrs,
					noun, err)
			}
			batch.done(err)
		case <-quit:
			break out
		}
	}

	w.wg.Done()
}

// Rescan begins a rescan for all active addresses and unspent outputs of
// a wallet.  This is intended to be used to sync a wallet back up to the
// current best block in the main chain, and is considered an initial sync
// rescan.
func (w *Wallet) Rescan(addrs []abeutil.Address, unspent []wtxmgr.Credit) error {
	return w.rescanWithTarget(addrs, unspent, nil)
}

// rescanWithTarget performs a rescan starting at the optional startStamp. If
// none is provided, the rescan will begin from the manager's sync tip.
func (w *Wallet) rescanWithTarget(addrs []abeutil.Address,
	unspent []wtxmgr.Credit, startStamp *waddrmgr.BlockStamp) error {

	outpoints := make(map[wire.OutPoint]abeutil.Address, len(unspent))
	for _, output := range unspent {
		_, outputAddrs, _, err := txscript.ExtractPkScriptAddrs(
			output.PkScript, w.chainParams,
		)
		if err != nil {
			return err
		}

		outpoints[output.OutPoint] = outputAddrs[0]
	}

	// If a start block stamp was provided, we will use that as the initial
	// starting point for the rescan.
	if startStamp == nil {
		startStamp = &waddrmgr.BlockStamp{}
		*startStamp = w.Manager.SyncedTo()
	}

	job := &RescanJob{
		InitialSync: true,
		Addrs:       addrs,
		OutPoints:   outpoints,
		BlockStamp:  *startStamp,
	}

	// Submit merged job and block until rescan completes.
	select {
	case err := <-w.SubmitRescan(job):
		return err
	case <-w.quitChan():
		return ErrWalletShuttingDown
	}
}
func (w *Wallet) rescanWithTargetAbe(startStamp *waddrmgr.BlockStamp) error {

	//outpoints := make(map[wire.OutPoint]abeutil.Address, len(unspent))
	//for _, output := range unspent {
	//	_, outputAddrs, _, err := txscript.ExtractPkScriptAddrs(
	//		output.PkScript, w.chainParams,
	//	)
	//	if err != nil {
	//		return err
	//	}
	//
	//	outpoints[output.OutPoint] = outputAddrs[0]
	//}
	//
	//// If a start block stamp was provided, we will use that as the initial
	//// starting point for the rescan.
	if startStamp == nil {
		startStamp = &waddrmgr.BlockStamp{}
		*startStamp = w.ManagerAbe.SyncedTo()
	}
	catchUpHashes := func(w *Wallet, client chain.Interface, height int32) error {
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
			" might take a while", height)
		err := walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
			addrmgrNs := tx.ReadWriteBucket(waddrmgrNamespaceKey)
			txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)
			addressEnc, _, _, valueSecretKeyEnc, err := w.ManagerAbe.FetchAddressKeysAbe(addrmgrNs)
			if err != nil {
				return err
			}
			vskBytes, err := w.ManagerAbe.Decrypt(waddrmgr.CKTPublic, valueSecretKeyEnc)
			if err != nil {
				return err
			}
			addressBytes, err := w.ManagerAbe.Decrypt(waddrmgr.CKTPublic, addressEnc)
			if err != nil {
				return err
			}
			//startBlock := w.Manager.SyncedTo()
			startBlock := w.ManagerAbe.SyncedTo()

			for i := startBlock.Height + 1; i <= height; i++ {
				hash, err := client.GetBlockHash(int64(i))
				if err != nil {
					return err
				}

				// have not reach the target start sync height
				if i < w.SyncFrom {
					blockHeader, err := client.GetBlockHeader(hash)
					if err != nil {
						return err
					}
					bs := waddrmgr.BlockStamp{
						Height:    i,
						Hash:      *hash,
						Timestamp: blockHeader.Timestamp,
					}
					err = w.ManagerAbe.SetSyncedTo(addrmgrNs, &bs)
					if err != nil {
						return err
					}
					continue
				}

				maturedBlockHashs := make([]*chainhash.Hash, 0)
				if i >= int32(w.chainParams.CoinbaseMaturity)+2 && i%3 == 2 && i-int32(w.chainParams.CoinbaseMaturity)-2 >= w.SyncFrom {
					hash1, err := client.GetBlockHash(int64(i - int32(w.chainParams.CoinbaseMaturity)))
					if err != nil {
						return err
					}
					maturedBlockHashs = append(maturedBlockHashs, hash1)
					hash2, err := client.GetBlockHash(int64(i - int32(w.chainParams.CoinbaseMaturity) - 1))
					if err != nil {
						return err
					}
					maturedBlockHashs = append(maturedBlockHashs, hash2)
					hash3, err := client.GetBlockHash(int64(i - int32(w.chainParams.CoinbaseMaturity) - 2))
					if err != nil {
						return err
					}
					maturedBlockHashs = append(maturedBlockHashs, hash3)
				}
				var b *wire.MsgBlockAbe
				b, err = client.GetBlockAbe(hash)
				if err != nil {
					return err
				}
				blockAbeDetail, err := wtxmgr.NewBlockAbeRecordFromMsgBlockAbe(b)
				if err != nil {
					return err
				}
				//err = w.TxStore.InsertBlockAbe(txmgrNs,blockAbeDetail,*maturedBlockHashs, mpk,msvk)
				err = w.TxStore.InsertBlockAbeNew(txmgrNs, blockAbeDetail, maturedBlockHashs, addressBytes, vskBytes)
				if err != nil {
					return err
				}
				bs := waddrmgr.BlockStamp{
					Height:    i,
					Hash:      *hash,
					Timestamp: blockAbeDetail.RecvTime,
				}
				//err = w.Manager.SetSyncedTo(ns, &bs)
				err = w.ManagerAbe.SetSyncedTo(addrmgrNs, &bs)
				if err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			log.Errorf("Failed to update address manager "+
				"sync state for height %d: %v", height, err)
		}

		log.Info("Done catching up block hashes")
		return err
	}
	_, bestBlockHeight, err := w.chainClient.GetBestBlock()
	if err != nil {
		return err
	}
	if err := catchUpHashes(w, w.chainClient, bestBlockHeight); err != nil {
		return err
	}
	//job := &RescanJob{
	//	InitialSync: true,
	//	Addrs:       nil,
	//	OutPoints:   nil,
	//	BlockStamp:  *startStamp,
	//}
	//
	//// Submit merged job and block until rescan completes.
	//select {
	//case err := <-w.SubmitRescan(job):
	//	return err
	//case <-w.quitChan():
	//	return ErrWalletShuttingDown
	//}
	return nil
}
