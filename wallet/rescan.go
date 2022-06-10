package wallet

import (
	"encoding/hex"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abecrypto/abecryptoparam"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abewallet/chain"
	"github.com/abesuite/abewallet/waddrmgr"
	"github.com/abesuite/abewallet/walletdb"
	"github.com/abesuite/abewallet/wtxmgr"
)

// RescanProgressMsg reports the current progress made by a rescan for a
// set of wallet addresses.

// RescanFinishedMsg reports the addresses that were rescanned when a
// rescanfinished message was received rescanning a batch of addresses.

// RescanJob is a job to be processed by the RescanManager.  The job includes
// a set of wallet addresses, a starting height to begin the rescan, and
// outpoints spendable by the addresses thought to be unspent.  After the
// rescan completes, the error result of the rescan RPC is sent on the Err
// channel.

// rescanBatch is a collection of one or more RescanJobs that were merged
// together before a rescan is performed.

// SubmitRescan submits a RescanJob to the RescanManager.  A channel is
// returned with the final error of the rescan.  The channel is buffered
// and does not need to be read to prevent a deadlock.

// batch creates the rescanBatch for a single rescan job.

// merge merges the work from k into j, setting the starting height to
// the minimum of the two jobs.  This method does not check for
// duplicate addresses or outpoints.

// done iterates through all error channels, duplicating sending the error
// to inform callers that the rescan finished (or could not complete due
// to an error).

// rescanBatchHandler handles incoming rescan request, serializing rescan
// submissions, and possibly batching many waiting requests together so they
// can be handled by a single rescan after the current one completes.

// rescanProgressHandler handles notifications for partially and fully completed
// rescans by marking each rescanned address as partially or fully synced.

// rescanRPCHandler reads batch jobs sent by rescanBatchHandler and sends the
// RPC requests to perform a rescan.  New jobs are not read until a rescan
// finishes.

// Rescan begins a rescan for all active addresses and unspent outputs of
// a wallet.  This is intended to be used to sync a wallet back up to the
// current best block in the main chain, and is considered an initial sync
// rescan.

// rescanWithTarget performs a rescan starting at the optional startStamp. If
// none is provided, the rescan will begin from the manager's sync tip.

func (w *Wallet) rescanWithTargetAbe(startStamp *waddrmgr.BlockStamp) error {
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
				var b *wire.MsgBlockAbe
				b, err = client.GetBlockAbe(hash)
				if err != nil {
					return err
				}
				blockAbeDetail, err := wtxmgr.NewBlockAbeRecordFromMsgBlockAbe(b)
				if err != nil {
					return err
				}
				coinAddrToVSK := map[string][]byte{}
				coinAddrToSnSk := map[string][]byte{}
				coinAddrToInstanceAddr := map[string][]byte{}
				for j := 0; j < len(b.Transactions); j++ {
					for k := 0; k < len(b.Transactions[j].TxOuts); k++ {
						coinAddr, err := abecrypto.ExtractCoinAddressFromTxoScript(b.Transactions[j].TxOuts[k].TxoScript, abecryptoparam.CryptoSchemePQRingCT)
						if err != nil {
							return err
						}
						addrKey := hex.EncodeToString(chainhash.DoubleHashB(coinAddr))
						if _, ok := coinAddrToVSK[addrKey]; ok {
							continue
						}
						addrBytesEnc, _, addressSecretSnEnc, vskBytesEnc, err := w.ManagerAbe.FetchAddressKeyEnc(addrmgrNs, coinAddr)
						if addrBytesEnc != nil && vskBytesEnc != nil {
							addrBytes, _, addressSecretSnBytes, vskBytes, err := w.ManagerAbe.DecryptAddressKey(addrBytesEnc, nil, addressSecretSnEnc, vskBytesEnc)
							if err != nil {
								return err
							}
							coinAddrToVSK[addrKey] = vskBytes
							coinAddrToSnSk[addrKey] = addressSecretSnBytes
							coinAddrToInstanceAddr[addrKey] = addrBytes
						}

					}
				}
				extraBlockAbeDetails := make(map[uint32]*wtxmgr.BlockAbeRecord, 2)
				if blockAbeDetail.Height%blockNum == blockNum-1 {
					b1, err := w.chainClient.GetBlockAbe(&blockAbeDetail.MsgBlockAbe.Header.PrevBlock)
					if err != nil {
						return err
					}
					extraBlockAbeDetails[uint32(blockAbeDetail.Height-1)], err = wtxmgr.NewBlockAbeRecordFromMsgBlockAbe(b1)
					if err != nil {
						return err
					}

					b2, err := w.chainClient.GetBlockAbe(&extraBlockAbeDetails[uint32(blockAbeDetail.Height-1)].MsgBlockAbe.Header.PrevBlock)
					if err != nil {
						return err
					}
					extraBlockAbeDetails[uint32(blockAbeDetail.Height-2)], err = wtxmgr.NewBlockAbeRecordFromMsgBlockAbe(b2)
					if err != nil {
						return err
					}
				}

				//err = w.TxStore.InsertBlockAbe(txmgrNs,blockAbeDetail,*maturedBlockHashs, mpk,msvk)
				err = w.TxStore.InsertBlockAbeNew(txmgrNs, addrmgrNs, blockAbeDetail, extraBlockAbeDetails, maturedBlockHashs, coinAddrToSnSk, coinAddrToVSK, coinAddrToInstanceAddr)
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
