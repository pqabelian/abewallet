package wtxmgr

import (
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abewallet/walletdb"
	"math/rand"
	"time"
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

// UnconfirmedTxs returns the underlying transactions for all unmined transactions
// which are not known to have been mined in a block.  Transactions are
// guaranteed to be sorted by their dependency order.
func (s *Store) UnconfirmedTxs(ns walletdb.ReadBucket) ([]*wire.MsgTxAbe, error) {
	unconfirmedTxCount, err := s.unconfirmedTxCount(ns)
	if err != nil {
		return nil, err
	}
	recSet, err := s.unconfirmedTxRecords(ns, unconfirmedTxCount, 400)
	if err != nil {
		return nil, err
	}
	txSet := make([]*wire.MsgTxAbe, len(recSet))
	for idx, txRec := range recSet {
		txSet[idx] = &txRec.MsgTx
	}
	return txSet, nil
}

func (s *Store) unconfirmedTxRecords(ns walletdb.ReadBucket, unconfirmedTxCount int64, maxSize int) ([]*TxRecord, error) {
	// When the unconfirmed transaction is more than maxSize
	// to avoid out-of-memory, just pseudo-random choose maxSize
	rand.Seed(int64(time.Now().Nanosecond()))
	unmined := make([]*TxRecord, 0)
	err := ns.NestedReadBucket(bucketUnconfirmedTx).ForEach(func(k, v []byte) error {
		if len(unmined) >= maxSize {
			return nil
		}

		var txHash chainhash.Hash
		err := readRawUnminedHash(k, &txHash)
		if err != nil {
			return err
		}

		if unconfirmedTxCount < int64(maxSize) || rand.Intn(int(unconfirmedTxCount)) < maxSize {
			rec := new(TxRecord)
			err = readRawTxRecord(&txHash, v, rec, bucketUnconfirmedTx)
			if err != nil {
				return err
			}
			unmined = append(unmined, rec)
		}

		return nil
	})
	return unmined, err
}

// UnminedTxHashes returns the hashes of all transactions not known to have been
// mined in a block.
func (s *Store) UnminedTxHashes(ns walletdb.ReadBucket) ([]*chainhash.Hash, error) {
	return s.unconfirmedTxHashes(ns)
}

func (s *Store) unconfirmedTxCount(ns walletdb.ReadBucket) (int64, error) {
	var count int64
	err := ns.NestedReadBucket(bucketUnconfirmedTx).ForEach(func(k, v []byte) error {
		count++
		return nil
	})
	return count, err
}

func (s *Store) unconfirmedTxHashes(ns walletdb.ReadBucket) ([]*chainhash.Hash, error) {
	var hashes []*chainhash.Hash
	err := ns.NestedReadBucket(bucketUnconfirmedTx).ForEach(func(k, v []byte) error {
		hash := new(chainhash.Hash)
		err := readRawUnminedHash(k, hash)
		if err == nil {
			hashes = append(hashes, hash)
		}
		return err
	})
	return hashes, err
}

func (s *Store) ConfirmedTxHashes(ns walletdb.ReadBucket) ([]*chainhash.Hash, error) {
	return s.confirmedTxHashes(ns)
}

func (s *Store) confirmedTxHashes(ns walletdb.ReadBucket) ([]*chainhash.Hash, error) {
	var hashes []*chainhash.Hash
	err := ns.NestedReadBucket(bucketConfirmedTx).ForEach(func(k, v []byte) error {
		hash := new(chainhash.Hash)
		err := readRawUnminedHash(k, hash)
		if err == nil {
			hashes = append(hashes, hash)
		}
		return err
	})
	return hashes, err
}
func (s *Store) InvalidTxHashes(ns walletdb.ReadBucket) ([]*chainhash.Hash, error) {
	return s.invalidTxHashes(ns)
}
func (s *Store) invalidTxHashes(ns walletdb.ReadBucket) ([]*chainhash.Hash, error) {
	var hashes []*chainhash.Hash
	err := ns.NestedReadBucket(bucketInvalidTx).ForEach(func(k, v []byte) error {
		hash := new(chainhash.Hash)
		err := readRawUnminedHash(k, hash)
		if err == nil {
			hashes = append(hashes, hash)
		}
		return err
	})
	return hashes, err
}

func (s *Store) TxStatus(ns walletdb.ReadBucket, hash *chainhash.Hash) (int, error) {
	k := hash.CloneBytes()
	v := existsRawUnconfirmedTx(ns, k)
	if v != nil && len(v) != 0 {
		return 0, nil
	}

	v = existsRawConfirmedTx(ns, k)
	if v != nil && len(v) != 0 {
		return 1, nil
	}

	v = existsRawInvalidTx(ns, k)
	if v != nil && len(v) != 0 {
		return 2, nil
	}
	return -1, nil
}
