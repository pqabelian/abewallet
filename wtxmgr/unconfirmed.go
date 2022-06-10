package wtxmgr

import (
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abewallet/walletdb"
)

// TODO(abe): for abe, we do not add a unmined transaction into db except the transaction the wallet itself generates
// insertMemPoolTx inserts the unmined transaction record.  It also marks
// previous outputs referenced by the inputs as spent.

// removeDoubleSpends checks for any unmined transactions which would introduce
// a double spend if tx was added to the store (either as a confirmed or unmined
// transaction).  Each conflicting transaction and all transactions which spend
// it are recursively removed.

// removeConflict removes an unmined transaction record and all spend chains
// deriving from it from the store.  This is designed to remove transactions
// that would otherwise result in double spend conflicts if left in the store,
// and to remove transactions that spend coinbase transactions on reorgs.

// UnminedTxs returns the underlying transactions for all unmined transactions
// which are not known to have been mined in a block.  Transactions are
// guaranteed to be sorted by their dependency order.

//TODO(abe):this function will be used by some other function

func (s *Store) UnminedTxAbes(ns walletdb.ReadBucket) ([]*wire.MsgTxAbe, error) {
	recSet, err := s.unminedTxAbeRecords(ns)
	if err != nil {
		return nil, err
	}

	txSet := make([]*wire.MsgTxAbe, len(recSet))
	for txHash, txRec := range recSet {
		txSet[txHash] = &txRec.MsgTx
	}

	return txSet, nil
}

func (s *Store) unminedTxAbeRecords(ns walletdb.ReadBucket) ([]*TxRecord, error) {
	unmined := make([]*TxRecord, 0)
	err := ns.NestedReadBucket(bucketUnminedAbe).ForEach(func(k, v []byte) error {
		var txHash chainhash.Hash
		err := readRawUnminedHash(k, &txHash)
		if err != nil {
			return err
		}

		rec := new(TxRecord)
		err = readRawTxRecordAbe(&txHash, v, rec)
		if err != nil {
			return err
		}
		unmined = append(unmined, rec)
		return nil
	})
	return unmined, err
}

// UnminedTxHashes returns the hashes of all transactions not known to have been
// mined in a block.
func (s *Store) UnminedTxHashes(ns walletdb.ReadBucket) ([]*chainhash.Hash, error) {
	return s.unminedTxHashes(ns)
}

func (s *Store) unminedTxHashes(ns walletdb.ReadBucket) ([]*chainhash.Hash, error) {
	var hashes []*chainhash.Hash
	err := ns.NestedReadBucket(bucketUnminedAbe).ForEach(func(k, v []byte) error {
		hash := new(chainhash.Hash)
		err := readRawUnminedHash(k, hash)
		if err == nil {
			hashes = append(hashes, hash)
		}
		return err
	})
	return hashes, err
}
