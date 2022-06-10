package wtxmgr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abewallet/walletdb"
	"time"
)

// Naming
//
// The following variables are commonly used in this file and given
// reserved names:
//
//   ns: The namespace bucket for this package
//   b:  The primary bucket being operated on
//   k:  A single bucket key
//   v:  A single bucket value
//   c:  A bucket cursor
//   ck: The current cursor key
//   cv: The current cursor value
//
// Functions use the naming scheme `Op[Raw]Type[Field]`, which performs the
// operation `Op` on the type `Type`, optionally dealing with raw keys and
// values if `Raw` is used.  Fetch and extract operations may only need to read
// some portion of a key or value, in which case `Field` describes the component
// being returned.  The following operations are used:
//
//   key:     return a db key for some data
//   value:   return a db value for some data
//   put:     insert or replace a value into a bucket
//   fetch:   read and return a value
//   read:    read a value into an out parameter
//   exists:  return the raw (nil if not found) value for some data
//   delete:  remove a k/v pair
//   extract: perform an unchecked slice to extract a key or value
//
// Other operations which are specific to the types being operated on
// should be explained in a comment.

// Big endian is the preferred byte order, due to cursor scans over integer
// keys iterating in order.
var byteOrder = binary.BigEndian

// This package makes assumptions that the width of a chainhash.Hash is always
// 32 bytes.  If this is ever changed (unlikely for bitcoin, possible for alts),
// offsets have to be rewritten.  Use a compile-time assertion that this
// assumption holds true.
var _ [32]byte = chainhash.Hash{}

const NUMBERBLOCKABE = 24 //TODO(abe):this value need to think about
//	todo(ABE): wallet buckets
// Bucket names
var (
	bucketTxLabels      = []byte("l")  // not support now, but it may be supported
	bucketLockedOutputs = []byte("lo") // not support now, but it may be supported

	//TODO(abe):bucket design
	bucketBlockAbes    = []byte("blocksabe") // store blocks
	bucketBlockOutputs = []byte("blockoutputs")
	bucketBlockInputs  = []byte("blockinputs")

	bucketImmaturedCoinbaseOutput = []byte("immaturedcoinbaseoutput")
	bucketImmaturedOutput         = []byte("immaturedeoutput")
	bucketMaturedOutput           = []byte("maturedoutput")
	bucketSpentButUnmined         = []byte("spentbutumined")
	bucketSpentConfirmed          = []byte("spentconfirmed")

	bucketUTXORing    = []byte("utxoring")
	bucketRingDetails = []byte("utxoringdetails") //TODO(abe):we should add a block height in database, meaning that the txo in ring had consumed completely .

	bucketUnminedAbe = []byte("unminedtx") // for unmined transaction
)

// Root (namespace) bucket keys
var (
	rootCreateDate       = []byte("date")
	rootVersion          = []byte("vers")
	rootMinedBalance     = []byte("bal")          // total balance
	rootSpendableBalance = []byte("spendablebal") // spendable balance
	rootFreezedBalance   = []byte("freezedbal")   // freeze balance
)

// The root bucket's mined balance k/v pair records the total balance for all
// unspent credits from mined transactions.  This includes immature outputs, and
// outputs spent by mempool transactions, which must be considered when
// returning the actual balance for a given number of block confirmations.  The
// value is the amount serialized as a uint64.
func fetchMinedBalance(ns walletdb.ReadBucket) (abeutil.Amount, error) {
	v := ns.Get(rootMinedBalance)
	if len(v) != 8 {
		str := fmt.Sprintf("balance: short read (expected 8 bytes, "+
			"read %v)", len(v))
		return 0, storeError(ErrData, str, nil)
	}
	return abeutil.Amount(byteOrder.Uint64(v)), nil
}

func putMinedBalance(ns walletdb.ReadWriteBucket, amt abeutil.Amount) error {
	v := make([]byte, 8)
	byteOrder.PutUint64(v, uint64(amt))
	err := ns.Put(rootMinedBalance, v)
	if err != nil {
		str := "failed to put balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func fetchSpenableBalance(ns walletdb.ReadBucket) (abeutil.Amount, error) {
	v := ns.Get(rootSpendableBalance)
	if len(v) != 8 {
		str := fmt.Sprintf("balance: short read (expected 8 bytes, "+
			"read %v)", len(v))
		return 0, storeError(ErrData, str, nil)
	}
	return abeutil.Amount(byteOrder.Uint64(v)), nil
}

func putSpenableBalance(ns walletdb.ReadWriteBucket, amt abeutil.Amount) error {
	v := make([]byte, 8)
	byteOrder.PutUint64(v, uint64(amt))
	err := ns.Put(rootSpendableBalance, v)
	if err != nil {
		str := "failed to put balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func fetchFreezedBalance(ns walletdb.ReadBucket) (abeutil.Amount, error) {
	v := ns.Get(rootFreezedBalance)
	if len(v) != 8 {
		str := fmt.Sprintf("balance: short read (expected 8 bytes, "+
			"read %v)", len(v))
		return 0, storeError(ErrData, str, nil)
	}
	return abeutil.Amount(byteOrder.Uint64(v)), nil
}

func putFreezedBalance(ns walletdb.ReadWriteBucket, amt abeutil.Amount) error {
	v := make([]byte, 8)
	byteOrder.PutUint64(v, uint64(amt))
	err := ns.Put(rootFreezedBalance, v)
	if err != nil {
		str := "failed to put balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

// Several data structures are given canonical serialization formats as either
// keys or values.  These common formats allow keys and values to be reused
// across different buckets.
//
// The canonical outpoint serialization format is:
//
//   [0:32]  Trasaction hash (32 bytes)
//   [32:36] Output index (4 bytes)
//
// The canonical transaction hash serialization is simply the hash.

func canonicalOutPoint(txHash *chainhash.Hash, index uint32) []byte {
	var k [36]byte
	copy(k[:32], txHash[:])
	byteOrder.PutUint32(k[32:36], index)
	return k[:]
}

func readCanonicalOutPoint(k []byte, op *wire.OutPoint) error {
	if len(k) < 36 {
		str := "short canonical outpoint"
		return storeError(ErrData, str, nil)
	}
	copy(op.Hash[:], k)
	op.Index = byteOrder.Uint32(k[32:36])
	return nil
}

// TODO(abe):the type of index can not be to serialize have no one of PutUint8?

// The canonical outpoint serialization format is:
//
//   [0:32]  Trasaction hash (32 bytes)
//   [32:36] Output index (4 bytes)
//
// The canonical transaction hash serialization is simply the hash.
func canonicalOutPointAbe(txHash chainhash.Hash, index uint8) []byte {
	var k [33]byte
	copy(k[:32], txHash[:])
	k[32] = index
	return k[:]
}
func readCanonicalOutPointAbe(k []byte, op *wire.OutPointAbe) error {
	if len(k) < 33 {
		str := "short canonical outpoint"
		return storeError(ErrData, str, nil)
	}
	copy(op.TxHash[:], k)
	op.Index = k[32]
	return nil
}
func canonicalBlockAbe(blockHeight int32, blockHash chainhash.Hash) []byte {
	var k [36]byte
	byteOrder.PutUint32(k[0:4], uint32(blockHeight))
	copy(k[4:], blockHash[:])
	return k[:]
}
func readCanonicalBlockAbe(k []byte, b *BlockAbe) error {
	if len(k) < 36 {
		str := "short canonical block"
		return storeError(ErrData, str, nil)
	}
	b.Height = int32(byteOrder.Uint32(k[0:4]))
	copy(b.Hash[:], k[4:36])
	return nil
}

// Details regarding blocks are saved as k/v pairs in the blocks bucket.
// blockRecords are keyed by their height.  The value is serialized as such:
//
//   [0:32]  Hash (32 bytes)
//   [32:40] Unix time (8 bytes)
//   [40:44] Number of transaction hashes (4 bytes)
//   [44:]   For each transaction hash:
//             Hash (32 bytes)

// Details regarding raw block are saved as k/v pairs in the rawblockabe bucket.
// rawblockabe are keyed by their height and hash.
//The key is serialized as such:
//	 [0:4] Height(4 bytes)
//   [4:36]  Hash (32 bytes)
//The value is serialized as such:
//	 [0:80] Header(80 bytes)
//   [80:84]Number of transaction (32 bytes)
//   [84:] transactions?
func valueBlockAbe(block wire.MsgBlockAbe) []byte {
	buf := bytes.NewBuffer(make([]byte, 0, block.SerializeSize()))
	err := block.Serialize(buf)
	if err != nil {
		return nil
	}
	return buf.Bytes()
}
func readBlockAbeBlockAbeRecord(k, v []byte, block *BlockAbeRecord) error {
	if len(k) < 36 {
		str := fmt.Sprintf("%s: short key (expected %d bytes, read %d)",
			bucketBlockAbes, 4, len(k))
		return storeError(ErrData, str, nil)
	}
	block, err := NewBlockAbeRecord(v)
	if err != nil {
		return err
	}
	return nil
}

func putRawBlockAbe(ns walletdb.ReadWriteBucket, k, v []byte) error {
	err := ns.NestedReadWriteBucket(bucketBlockAbes).Put(k, v)
	if err != nil {
		str := "failed to store block"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func putBlockAbeRecord(ns walletdb.ReadWriteBucket, block *BlockAbeRecord) error {
	k := canonicalBlockAbe(block.Height, block.Hash)
	v := block.SerializedBlockAbe
	err := ns.NestedReadWriteBucket(bucketBlockAbes).Put(k, v)
	if err != nil {
		str := "failed to store block"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func fetchRawBlockAbe(ns walletdb.ReadBucket, height int32, hash chainhash.Hash) (k, v []byte) {
	k = canonicalBlockAbe(height, hash)
	v = ns.NestedReadBucket(bucketBlockAbes).Get(k)
	return
}
func existsRawBlock(ns walletdb.ReadBucket, height int32, hash chainhash.Hash) (k, v []byte) {
	k = canonicalBlockAbe(height, hash)
	v = ns.NestedReadBucket(bucketBlockAbes).Get(k)
	return
}
func deleteRawBlockAbe(ns walletdb.ReadWriteBucket, height int32, hash chainhash.Hash) error {
	k := canonicalBlockAbe(height, hash)
	return ns.NestedReadWriteBucket(bucketBlockAbes).Delete(k)
}
func deleteRawBlockAbeWithBlockHeight(ns walletdb.ReadWriteBucket, height int32) (*BlockAbeRecord, error) {
	// iterator the blockabe bucket
	var block *BlockAbeRecord
	err := ns.NestedReadBucket(bucketBlockAbes).ForEach(func(k, v []byte) error {

		if height == int32(byteOrder.Uint32(k[0:4])) {
			block = new(BlockAbeRecord)
			err := readBlockAbeBlockAbeRecord(k, v, block)
			if err != nil {
				return err
			}
			return ns.NestedReadWriteBucket(bucketBlockAbes).Delete(k)
		}
		return nil
	})
	return block, err
}

// appendRawBlockRecord returns a new block record value with a transaction
// hash appended to the end and an incremented number of transactions.

// TODO(abe):has some problem,need to fix
type blockAbeIterator struct {
	c      walletdb.ReadWriteCursor
	prefix []byte // height
	ck     []byte // height || hash
	cv     []byte
	elem   *BlockAbeRecord
	err    error
}

func makeBlockAbeIterator(ns walletdb.ReadWriteBucket, height int32) blockAbeIterator {
	prefix := make([]byte, 4)
	byteOrder.PutUint32(prefix, uint32(height))
	c := ns.NestedReadWriteBucket(bucketBlockAbes).ReadWriteCursor()
	return blockAbeIterator{c: c, prefix: prefix}
}

func makeReadBlockAbeIterator(ns walletdb.ReadBucket, height int32) blockAbeIterator {
	prefix := make([]byte, 4)
	byteOrder.PutUint32(prefix, uint32(height))
	c := ns.NestedReadBucket(bucketBlockAbes).ReadCursor()
	return blockAbeIterator{c: readCursor{c}, prefix: prefix}
}

// Works just like makeBlockIterator but will initially position the cursor at
// the last k/v pair.  Use this with blockIterator.prev.
func makeReverseBlockAbeIterator(ns walletdb.ReadWriteBucket, height int32) blockAbeIterator {
	prefix := make([]byte, 4)
	byteOrder.PutUint32(prefix, uint32(height))
	c := ns.NestedReadWriteBucket(bucketBlockAbes).ReadWriteCursor()
	return blockAbeIterator{c: c, prefix: prefix}
}

func makeReadReverseBlockAbeIterator(ns walletdb.ReadBucket, height int32) blockAbeIterator {
	prefix := make([]byte, 4)
	byteOrder.PutUint32(prefix, uint32(height))
	c := ns.NestedReadBucket(bucketBlockAbes).ReadCursor()
	return blockAbeIterator{c: readCursor{c}, prefix: prefix}
}

func (it *blockAbeIterator) prev() bool {
	if it.c == nil {
		return false
	}

	if it.ck == nil {
		it.ck, it.cv = it.c.Seek(it.prefix)
	} else {
		it.ck, it.cv = it.c.Next()
	}
	if it.ck == nil {
		it.c = nil
		return false
	}

	err := it.readElem()
	if err != nil {
		it.c = nil
		it.err = err
		return false
	}

	return true
}
func (it *blockAbeIterator) next() bool {
	if it.c == nil {
		return false
	}

	if it.ck == nil {
		it.ck, it.cv = it.c.Seek(it.prefix)
	} else {
		it.ck, it.cv = it.c.Next()
	}
	if !bytes.HasPrefix(it.ck, it.prefix) {
		it.c = nil
		return false
	}

	err := it.readElem()
	if err != nil {
		it.err = err
		return false
	}
	return true
}

func (it *blockAbeIterator) readElem() error {
	if len(it.ck) < 36 {
		str := fmt.Sprintf("%s: short key (expected %d bytes, read %d)",
			bucketBlockAbes, 36, len(it.ck))
		return storeError(ErrData, str, nil)
	}
	e, err := NewBlockAbeRecord(it.cv)
	if err != nil {
		return err
	}
	it.elem = e
	return nil
}

// unavailable until https://github.com/boltdb/bolt/issues/620 is fixed.
// func (it *blockIterator) delete() error {
// 	err := it.c.Delete()
// 	if err != nil {
// 		str := "failed to delete block record"
// 		storeError(ErrDatabase, str, err)
// 	}
// 	return nil
// }

// Transaction records are keyed as such:
//
//   [0:32]  Transaction hash (32 bytes)
//   [32:36] Block height (4 bytes)
//   [36:68] Block hash (32 bytes)
//
// The leading transaction hash allows to prefix filter for all records with
// a matching hash.  The block height and hash records a particular incidence
// of the transaction in the blockchain.
//
// The record value is serialized as such:
//
//   [0:8]   Received time (8 bytes)
//   [8:]    Serialized transaction (varies)

func valueTxRecordAbe(rec *TxRecord) ([]byte, error) {
	var v []byte
	if rec.SerializedTx == nil {
		txSize := rec.MsgTx.SerializeSize()
		v = make([]byte, 8, 8+txSize)
		err := rec.MsgTx.Serialize(bytes.NewBuffer(v[8:]))
		if err != nil {
			str := fmt.Sprintf("unable to serialize transaction %v", rec.Hash)
			return nil, storeError(ErrInput, str, err)
		}
		v = v[:cap(v)]
	} else {
		v = make([]byte, 8+len(rec.SerializedTx))
		copy(v[8:], rec.SerializedTx)
	}
	byteOrder.PutUint64(v, uint64(rec.Received.Unix()))
	return v, nil
}

func readRawTxRecordAbe(txHash *chainhash.Hash, v []byte, rec *TxRecord) error {
	if len(v) < 8 {
		str := fmt.Sprintf("%s: short read (expected %d bytes, read %d)",
			bucketUnminedAbe, 8, len(v))
		return storeError(ErrData, str, nil)
	}
	rec.Hash = *txHash
	rec.Received = time.Unix(int64(byteOrder.Uint64(v)), 0)
	err := rec.MsgTx.Deserialize(bytes.NewReader(v[8:]))
	if err != nil {
		str := fmt.Sprintf("%s: failed to deserialize transaction %v",
			bucketUnminedAbe, txHash)
		return storeError(ErrData, str, err)
	}
	return nil
}

// TODO: This reads more than necessary.  Pass the pkscript location instead to
// avoid the wire.MsgTx deserialization.

// latestTxRecord searches for the newest recorded mined transaction record with
// a matching hash.  In case of a hash collision, the record from the newest
// block is returned.  Returns (nil, nil) if no matching transactions are found.

// All transaction credits (outputs) are keyed as such:
//
//   [0:32]  Transaction hash (32 bytes)
//   [32:36] Block height (4 bytes)
//   [36:68] Block hash (32 bytes)
//   [68:72] Output index (4 bytes)
//
// The first 68 bytes match the key for the transaction record and may be used
// as a prefix filter to iterate through all credits in order.
//
// The credit value is serialized as such:
//
//   [0:8]   Amount (8 bytes)
//   [8]     Flags (1 byte)
//             0x01: Spent
//             0x02: Change
//   [9:81]  OPTIONAL Debit bucket key (72 bytes)
//             [9:41]  Spender transaction hash (32 bytes)
//             [41:45] Spender block height (4 bytes)
//             [45:77] Spender block hash (32 bytes)
//             [77:81] Spender transaction input index (4 bytes)
//
// The optional debits key is only included if the credit is spent by another
// mined debit.

// valueUnspentCredit creates a new credit value for an unspent credit.  All
// credits are created unspent, and are only marked spent later, so there is no
// value function to create either spent or unspent credits.

// putUnspentCredit puts a credit record for an unspent credit.  It may only be
// used when the credit is already know to be unspent, or spent by an
// unconfirmed transaction.

// fetchRawCreditAmount returns the amount of the credit.

// fetchRawCreditAmountSpent returns the amount of the credit and whether the
// credit is spent.

// fetchRawCreditAmountChange returns the amount of the credit and whether the
// credit is marked as change.

// fetchRawCreditUnspentValue returns the unspent value for a raw credit key.
// This may be used to mark a credit as unspent.

// spendRawCredit marks the credit with a given key as mined at some particular
// block as spent by the input at some transaction incidence.  The debited
// amount is returned.

// unspendRawCredit rewrites the credit for the given key as unspent.  The
// output amount of the credit is returned.  It returns without error if no
// credit exists for the key.

// creditIter8ator allows for in-order iteration of all credit records for a
// mined transaction.
//
// Example usage:
//
//   prefix := keyTxRecord(txHash, block)
//   it := makeCreditIterator(ns, prefix)
//   for it.next() {
//           // Use it.elem
//           // If necessary, read additional details from it.ck, it.cv
//   }
//   if it.err != nil {
//           // Handle error
//   }
//
// The elem's Spent field is not set to true if the credit is spent by an
// unmined transaction.  To check for this case:
//
//   k := canonicalOutPoint(&txHash, it.elem.Index)
//   it.elem.Spent = existsRawUnminedInput(ns, k) != nil

//All the relevant output in a block are keyed as such:
//
//    [0:4] Block Height(4 bytes)
//    [4:36] Block Hash (32 bytes)
// the value is identified as such:
//    [0:4] number of relevant transaction output
//      For transaction outpoint
//  		[4:36] transaction hash
//  		[36:37] output index...

func appendRawBlockAbeOutput(ns walletdb.ReadWriteBucket, k []byte, v []byte, txHash chainhash.Hash, index uint8) ([]byte, error) {
	if len(v) < 37 {
		str := fmt.Sprintf("%s: short read (expected %d bytes, read %d)",
			bucketBlockOutputs, 40, len(v))
		return nil, storeError(ErrData, str, nil)
	}
	if v == nil || len(v) == 0 {
		v = canonicalOutPointAbe(txHash, index)
		err := putBlockAbeOutput(ns, k, v)
		return v, err
	}
	newv := make([]byte, len(v)+33)
	appended := canonicalOutPointAbe(txHash, index)
	n := byteOrder.Uint32(v[0:4])
	byteOrder.PutUint32(newv[0:4], n+1)
	copy(newv[4:len(v)], v[4:])
	copy(newv[len(v):len(v)+33], appended[:])
	err := putBlockAbeOutput(ns, k, newv)
	return newv, err
}
func putBlockAbeOutput(ns walletdb.ReadWriteBucket, k, v []byte) error {
	err := ns.NestedReadWriteBucket(bucketBlockOutputs).Put(k, v)
	if err != nil {
		str := "failed to put block output"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

//TODO(abe):integrated function
func fetchBlockAbeOutputWithHeight(ns walletdb.ReadBucket, height int32) ([]byte, []*wire.OutPointAbe, error) {
	k := make([]byte, 36)
	var v []byte
	err := ns.NestedReadBucket(bucketBlockOutputs).ForEach(func(key, value []byte) error {
		h := byteOrder.Uint32(key)
		if h == uint32(height) {
			copy(k, key)
			v = make([]byte, len(value))
			copy(v, value)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if v == nil { // it means that there is zero outputs controlled by wallet in this block
		return nil, nil, nil
	}
	n := byteOrder.Uint32(v[:4])
	if len(v) < int(n*33+4) {
		str := "wrong value in block output bucket"
		return nil, nil, fmt.Errorf(str)
	}
	var res []*wire.OutPointAbe
	offset := 4
	for offset < len(v) {
		tmp := new(wire.OutPointAbe)
		copy(tmp.TxHash[:], v[offset:])
		offset += 32
		tmp.Index = v[offset] //TODO(abe): if it run with error, maybe there
		offset += 1
		res = append(res, tmp)
	}
	return k, res, nil
}
func fetchBlockAbeOutput(ns walletdb.ReadBucket, blockHeight int32, blockHash chainhash.Hash) ([]*wire.OutPointAbe, error) {
	k := canonicalBlockAbe(blockHeight, blockHash)
	v := ns.NestedReadBucket(bucketBlockOutputs).Get(k)
	if v == nil {
		return nil, fmt.Errorf("the entry is empty")
	}
	n := byteOrder.Uint32(v[:4])
	if len(v) < int(n*33+4) {
		str := "wrong value in block output bucket"
		return nil, fmt.Errorf(str)
	}
	var res []*wire.OutPointAbe
	offset := 4
	for offset < len(v) {
		tmp := new(wire.OutPointAbe)
		copy(tmp.TxHash[:], v[offset:])
		offset += 32
		tmp.Index = v[offset] //TODO(abe): if it run with error, maybe there
		offset += 1
		res = append(res, tmp)
	}
	return res, nil
}
func fetchRawBlockAbeOutput(ns walletdb.ReadWriteBucket, k []byte) ([]*wire.OutPointAbe, error) {
	v := ns.NestedReadBucket(bucketBlockOutputs).Get(k)
	if v == nil {
		return nil, fmt.Errorf("the entry is empty")
	}
	n := byteOrder.Uint32(v[:4])
	if len(v) < int(n*33+4) {
		str := "wrong value in block output bucket"
		return nil, fmt.Errorf(str)
	}
	res := make([]*wire.OutPointAbe, 0)
	offset := 4
	for offset < len(v) {
		tmp := new(wire.OutPointAbe)
		copy(tmp.TxHash[:], v[offset:offset+32])
		tmp.Index = v[offset+32] //TODO(abe): if it run with error, maybe there
		res = append(res, tmp)
		offset += 33
	}
	return res, nil
}

func deleteBlockAbeOutput(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketBlockOutputs).Delete(k)
	if err != nil {
		str := "failed to delete block output"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

//BlockInputs: block height||block hash => [](utxoRing ||[]serialNumbers)
// For the utxoRing, it is before processing the block, and the serialNumber slice
// is the releavant Ring which contains at least one relevant output in this Ring
func valueBlockAbeInput(blockInputs *RingHashSerialNumbers) []byte {
	res := make([]byte, 6)
	totalSize := 6
	// total size(4 bytes) + utxo ring number(2 bytes)
	byteOrder.PutUint16(res[4:6], uint16(len(blockInputs.utxoRings)))
	// total size of block inputs
	for k, v := range blockInputs.utxoRings {
		addedSNs := blockInputs.serialNumbers[k]
		uSize := v.SerializeSize()
		// totoal size (2 bytes)
		// utxo ring size (2 bytes)
		// serialized utxo ring (uSize)
		// added serialNumber numbers (1 byte)
		// [serialNumber...]
		size := 2 + 2 + uSize + 1
		for i := 0; i < len(addedSNs); i++ {
			size += 1 + len(addedSNs[i])
		}
		tmp := make([]byte, size)
		offset := 0
		byteOrder.PutUint16(tmp[offset:offset+2], uint16(size))
		offset += 2
		byteOrder.PutUint16(tmp[offset:offset+2], uint16(uSize))
		offset += 2
		copy(tmp[offset:offset+uSize], v.Serialize()[:])
		offset += uSize
		tmp[offset] = uint8(len(addedSNs))
		offset += 1
		for j := 0; j < len(addedSNs); j++ {
			tmp[offset] = byte(len(addedSNs[j]))
			offset += 1
			copy(tmp[offset:offset+len(addedSNs[j])], addedSNs[j][:])
			offset += len(addedSNs[j])
		}
		totalSize += offset
		res = append(res, tmp...)
	}
	byteOrder.PutUint32(res[0:4], uint32(totalSize))
	return res
}
func putRawBlockAbeInput(ns walletdb.ReadWriteBucket, k, v []byte) error {
	err := ns.NestedReadWriteBucket(bucketBlockInputs).Put(k, v)
	if err != nil {
		str := "failed to put block input"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func fetchBlockAbeInput(ns walletdb.ReadWriteBucket, k []byte) ([]*UTXORingAbe, [][][]byte, error) {
	if len(k) < 32 {
		str := fmt.Sprintf("%s: short read (expected %d bytes, read %d)",
			bucketBlockInputs, 32, len(k))
		return nil, nil, storeError(ErrData, str, nil)
	}
	v := ns.NestedReadBucket(bucketBlockInputs).Get(k)
	if v == nil {
		return nil, nil, fmt.Errorf("this entry is empty")
	}
	offset := 0
	_ = byteOrder.Uint32(v[offset : offset+4])
	offset += 4
	utxoRingN := int(byteOrder.Uint16(v[offset : offset+2]))
	utxoRings := make([]*UTXORingAbe, utxoRingN)
	serialNs := make([][][]byte, utxoRingN)
	offset += 2
	for i := 0; i < utxoRingN; i++ {
		utxoRings[i] = new(UTXORingAbe)
		_ = int(byteOrder.Uint16(v[offset : offset+2])) //total size
		offset += 2
		uSize := int(byteOrder.Uint16(v[offset : offset+2]))
		offset += 2
		//t:=make([]byte,len(k)+int(size))
		//copy(t[0:len(k)],k)
		//copy(t[len(k):len(v)+len(k)],v[2:size])
		err := utxoRings[i].Deserialize(v[offset : offset+uSize])
		if err != nil {
			return nil, nil, err
		}
		offset += uSize
		addedSNs := int(v[offset])
		serialNs[i] = make([][]byte, addedSNs)
		offset += 1
		for j := 0; j < addedSNs; j++ {
			snLen := int(v[offset])
			offset += 1
			serialNs[i][j] = make([]byte, snLen)
			copy(serialNs[i][j][:], v[offset:offset+snLen])
			offset += snLen
		}
	}
	return utxoRings, serialNs, nil
}
func deleteBlockAbeInput(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketBlockInputs).Delete(k)
	if err != nil {
		str := "failed to delete block input"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

// block height || block hash -> version + []UnspentTXO 【txhash + index + amount + generationTime + ringhash】
func valueImmaturedCoinbaseOutput(immatured map[wire.OutPointAbe]*UnspentUTXO) []byte {
	//res := make([]byte, len(immatured)*(32+1+8+8+32))
	res := make([]byte, len(immatured)*(4+4+32+1+8+1+8+32+1)) // todo: should not use hard codes. and the version field is the same so it can be optimized
	offset := 0
	for _, utxo := range immatured {
		byteOrder.PutUint32(res[offset:offset+4], utxo.Version)
		offset += 4
		byteOrder.PutUint32(res[offset:offset+4], uint32(utxo.Height))
		offset += 4
		copy(res[offset:offset+32], utxo.TxOutput.TxHash[:])
		offset += 32
		res[offset] = utxo.TxOutput.Index
		offset += 1
		byteOrder.PutUint64(res[offset:offset+8], utxo.Amount)
		offset += 8
		res[offset] = utxo.Index
		offset += 1
		byteOrder.PutUint64(res[offset:offset+8], uint64(utxo.GenerationTime.Unix()))
		offset += 8
		copy(res[offset:offset+32], utxo.RingHash[:])
		offset += 32

		res[offset] = utxo.RingSize
	}
	return res
}
func putRawImmaturedCoinbaseOutput(ns walletdb.ReadWriteBucket, k, v []byte) error {
	err := ns.NestedReadWriteBucket(bucketImmaturedCoinbaseOutput).Put(k, v)
	if err != nil {
		str := "failed to put immature coinbase output"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func fetchImmaturedCoinbaseOutput(ns walletdb.ReadBucket, height int32, hash chainhash.Hash) (map[wire.OutPointAbe]*UnspentUTXO, error) {

	k := canonicalBlockAbe(height, hash)
	v := ns.NestedReadBucket(bucketImmaturedCoinbaseOutput).Get(k)
	op := make(map[wire.OutPointAbe]*UnspentUTXO)
	offset := 0
	//for i := 0; i < len(v)/(32+1+8+8+32); i++ {
	for i := 0; i < len(v)/(4+4+32+1+8+1+8+32+1); i++ { // todo: should not use hardcodes
		tmp := new(UnspentUTXO)
		tmp.Version = byteOrder.Uint32(v[offset : offset+4])
		offset += 4
		tmp.Height = int32(byteOrder.Uint32(v[offset : offset+4]))
		offset += 4
		copy(tmp.TxOutput.TxHash[:], v[offset:offset+32])
		offset += 32
		tmp.TxOutput.Index = v[offset]
		offset += 1
		tmp.FromCoinBase = true
		tmp.Amount = byteOrder.Uint64(v[offset : offset+8])
		offset += 8
		tmp.Index = v[offset]
		offset += 1
		tmp.GenerationTime = time.Unix(int64(byteOrder.Uint64(v[offset:offset+8])), 0)
		offset += 8
		copy(tmp.RingHash[:], v[offset:offset+32])
		offset += 32

		tmp.RingSize = v[offset]

		op[tmp.TxOutput] = tmp
	}
	return op, nil
}

func existsRawImmaturedCoinbaseOutput(ns walletdb.ReadBucket, k []byte) (v []byte) {
	return ns.NestedReadBucket(bucketImmaturedCoinbaseOutput).Get(k)
}

func deleteImmaturedCoinbaseOutput(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketImmaturedCoinbaseOutput).Delete(k)
	if err != nil {
		str := "failed to delete immature coinbase output"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

// block height || block hash -> []UnspentTXO 【txhash + index + amount + generationTime + ringhash】
func valueImmaturedOutput(immatured map[wire.OutPointAbe]*UnspentUTXO) []byte {
	//res := make([]byte, len(immatured)*(32+1+8+8+32))
	res := make([]byte, len(immatured)*(4+4+32+1+8+1+8+32+1)) // todo: should not use hard code
	offset := 0
	for _, utxo := range immatured {
		byteOrder.PutUint32(res[offset:offset+4], utxo.Version)
		offset += 4
		byteOrder.PutUint32(res[offset:offset+4], uint32(utxo.Height))
		offset += 4
		copy(res[offset:offset+32], utxo.TxOutput.TxHash[:])
		offset += 32
		res[offset] = utxo.TxOutput.Index
		offset += 1
		byteOrder.PutUint64(res[offset:offset+8], utxo.Amount)
		offset += 8
		res[offset] = utxo.Index
		offset += 1
		byteOrder.PutUint64(res[offset:offset+8], uint64(utxo.GenerationTime.Unix()))
		offset += 8
		copy(res[offset:offset+32], utxo.RingHash[:])
		offset += 32

		res[offset] = utxo.RingSize

	}
	return res
}
func putRawImmaturedOutput(ns walletdb.ReadWriteBucket, k, v []byte) error {
	err := ns.NestedReadWriteBucket(bucketImmaturedOutput).Put(k, v)
	if err != nil {
		str := "failed to put immature output"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func fetchImmaturedOutput(ns walletdb.ReadBucket, height int32, hash chainhash.Hash) (map[wire.OutPointAbe]*UnspentUTXO, error) {

	k := canonicalBlockAbe(height, hash)
	v := ns.NestedReadBucket(bucketImmaturedOutput).Get(k)
	op := make(map[wire.OutPointAbe]*UnspentUTXO)
	offset := 0
	//	for i := 0; i < len(v)/(32+1+8+8+32); i++ {
	for i := 0; i < len(v)/(4+4+32+1+8+1+8+32+1); i++ { // todo: should not use hard code, should use getXXXSize
		tmp := new(UnspentUTXO)
		tmp.Version = byteOrder.Uint32(v[offset : offset+4])
		offset += 4
		tmp.Height = int32(byteOrder.Uint32(v[offset : offset+4]))
		offset += 4
		copy(tmp.TxOutput.TxHash[:], v[offset:offset+32])
		offset += 32
		tmp.TxOutput.Index = v[offset]
		offset += 1
		tmp.FromCoinBase = false
		tmp.Amount = byteOrder.Uint64(v[offset : offset+8])
		offset += 8
		tmp.Index = v[offset]
		offset += 1
		tmp.GenerationTime = time.Unix(int64(byteOrder.Uint64(v[offset:offset+8])), 0)
		offset += 8
		copy(tmp.RingHash[:], v[offset:offset+32])
		offset += 32

		tmp.RingSize = v[offset]

		op[tmp.TxOutput] = tmp
	}
	return op, nil
}

func existsRawImmaturedOutput(ns walletdb.ReadBucket, k []byte) (v []byte) {
	return ns.NestedReadBucket(bucketImmaturedOutput).Get(k)
}

func deleteImmaturedOutput(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketImmaturedOutput).Delete(k)
	if err != nil {
		str := "failed to delete immature output"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func valueMaturedOutput(fromCoinBase bool, height int32, amount int64, generationTime time.Time, ringHash chainhash.Hash) []byte {
	size := 4 + 1 + 8 + 8 + 32
	v := make([]byte, size)
	offset := 0
	byteOrder.PutUint32(v[offset:offset+4], uint32(height))
	offset += 4
	if fromCoinBase {
		v[offset] = byte(1)
	} else {
		v[offset] = byte(0)
	}
	offset += 1
	byteOrder.PutUint64(v[offset:offset+8], uint64(amount))
	offset += 8
	byteOrder.PutUint64(v[offset:offset+8], uint64(generationTime.Unix()))
	offset += 8
	copy(v[offset:offset+32], ringHash[:])
	return v
}
func putRawMaturedOutput(ns walletdb.ReadWriteBucket, k, v []byte) error {
	err := ns.NestedReadWriteBucket(bucketMaturedOutput).Put(k, v)
	if err != nil {
		str := "failed to put unspent output"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func fetchMaturedOutput(ns walletdb.ReadBucket, hash chainhash.Hash, index uint8) (*UnspentUTXO, error) {
	k := canonicalOutPointAbe(hash, index)
	v := ns.NestedReadBucket(bucketMaturedOutput).Get(k)
	op := new(UnspentUTXO)
	err := op.Deserialize(&wire.OutPointAbe{TxHash: hash, Index: index}, v)
	return op, err
}

func existsRawMaturedOutput(ns walletdb.ReadBucket, k []byte) (v []byte) {
	return ns.NestedReadBucket(bucketMaturedOutput).Get(k)
}

func deleteMaturedOutput(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketMaturedOutput).Delete(k)
	if err != nil {
		str := "failed to delete unspent output"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

//UnspentTXO: store the relevant output which is unspent by current wallet
// its key is transaction hash with the output index
// its value is relevant information : From height,Fromcoinbase,amount,generation time, rinhash
func valueUnspentTXO(fromCoinBase bool, version uint32, height int32, amount uint64, index uint8, generationTime time.Time, ringHash chainhash.Hash, ringSize uint8) []byte {
	size := 4 + 4 + 1 + 8 + 1 + 8 + 32 + 1
	//	todo: should use HashSize, rather than 32
	v := make([]byte, size)
	offset := 0
	byteOrder.PutUint32(v[offset:offset+4], version)
	offset += 4
	byteOrder.PutUint32(v[offset:offset+4], uint32(height))
	offset += 4
	if fromCoinBase {
		v[offset] = byte(1)
	} else {
		v[offset] = byte(0)
	}
	offset += 1
	byteOrder.PutUint64(v[offset:offset+8], amount)
	offset += 8
	v[offset] = index
	offset += 1
	byteOrder.PutUint64(v[offset:offset+8], uint64(generationTime.Unix()))
	offset += 8
	copy(v[offset:offset+32], ringHash[:])
	offset += 32
	v[offset] = ringSize
	offset += 1
	return v
}

//UnspentButUnminedTXO: store the relevant output which is spent by current wallet but now not contained in a block
// its key is transaction hash with the output index
// its value is relevant information :
// height, from coinbase,amount,generation time, rinhash,serialNumber，spentBy, spentTime,
func valueSpentButUnminedTXO(version uint32, height int, fromCoinBase bool, amount int64, index uint8, generationTime time.Time,
	ringHash chainhash.Hash, ringSize uint8, spentBy chainhash.Hash, spentTime time.Time) []byte {
	size := 4 + 4 + 1 + 8 + 1 + 8 + 32 + 1 + 32 + 8
	v := make([]byte, size)
	offset := 0
	byteOrder.PutUint32(v[offset:offset+4], version)
	offset += 4
	byteOrder.PutUint32(v[offset:offset+4], uint32(height))
	offset += 4
	if fromCoinBase {
		v[offset] = byte(1)
	} else {
		v[offset] = byte(0)
	}
	offset += 1
	byteOrder.PutUint64(v[offset:offset+8], uint64(amount))
	offset += 8
	v[offset] = index
	offset += 1
	byteOrder.PutUint64(v[offset:offset+8], uint64(generationTime.Unix()))
	offset += 8
	copy(v[offset:offset+32], ringHash[:])
	offset += 32
	v[offset] = ringSize
	offset += 1
	copy(v[offset:offset+32], spentBy[:])
	offset += 32
	byteOrder.PutUint64(v[offset:offset+8], uint64(spentTime.Unix()))
	offset += 8
	return v
}
func putRawSpentButUnminedTXO(ns walletdb.ReadWriteBucket, k, v []byte) error {
	err := ns.NestedReadWriteBucket(bucketSpentButUnmined).Put(k, v)
	if err != nil {
		str := "failed to put spent but unmined output"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func fetchSpentButUnminedTXO(ns walletdb.ReadWriteBucket, hash chainhash.Hash, index uint8) (*SpentButUnminedTXO, error) {
	k := canonicalOutPointAbe(hash, index)
	v := ns.NestedReadBucket(bucketSpentButUnmined).Get(k)
	if v == nil {
		return nil, fmt.Errorf("empty entry")
	}
	sbu := new(SpentButUnminedTXO)
	sbu.TxOutput.TxHash = hash
	sbu.TxOutput.Index = index
	offset := 0
	sbu.Version = byteOrder.Uint32(v[offset : offset+4])
	offset += 4
	sbu.Height = int32(byteOrder.Uint32(v[offset : offset+4]))
	offset += 4
	t := v[offset]
	offset += 1
	if t == 0 {
		sbu.FromCoinBase = false
	} else {
		sbu.FromCoinBase = true
	}
	sbu.Amount = byteOrder.Uint64(v[offset : offset+8])
	offset += 8
	sbu.Index = v[offset]
	offset += 1
	sbu.GenerationTime = time.Unix(int64(byteOrder.Uint64(v[offset:offset+8])), 0)
	offset += 8
	copy(sbu.RingHash[:], v[offset:offset+32])
	offset += 32
	sbu.RingSize = v[offset]
	offset += 1
	copy(sbu.SpentByHash[:], v[offset:offset+32])
	offset += 32
	sbu.SpentTime = time.Unix(int64(byteOrder.Uint64(v[offset:offset+8])), 0)
	offset += 8
	return sbu, nil
}

func existsRawSpentButUnminedTXO(ns walletdb.ReadBucket, k []byte) (v []byte) {
	return ns.NestedReadBucket(bucketSpentButUnmined).Get(k)
}

func deleteSpentButUnminedTXO(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketSpentButUnmined).Delete(k)
	if err != nil {
		str := "failed to delete spent but unmined output"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

// SpentConfirmedTXO: store the relevant output which is spent by current wallet and now is contained in a block
// its key is transaction hash with the output index
// its value is relevant information : height,From coinbase,amount,generation time, rinhash,serialNumber，spentTime,confirmedTime
func valueSpentConfirmedTXO(version uint32, height int, fromCoinBase bool, amount int64, index uint8, generationTime time.Time,
	ringHash chainhash.Hash, ringSize uint8, spentBy chainhash.Hash, spentTime time.Time, confirmTime time.Time) []byte {
	size := 4 + 4 + 1 + 8 + 1 + 8 + 32 + 1 + 32 + 8 + 8
	v := make([]byte, size)
	offset := 0
	byteOrder.PutUint32(v[offset:offset+4], version)
	offset += 4
	byteOrder.PutUint32(v[offset:offset+4], uint32(height))
	offset += 4
	if fromCoinBase {
		v[offset] = byte(1)
	} else {
		v[offset] = byte(0)
	}
	offset += 1
	byteOrder.PutUint64(v[offset:offset+8], uint64(amount))
	offset += 8
	v[offset] = index
	offset += 1
	byteOrder.PutUint64(v[offset:offset+8], uint64(generationTime.Unix()))
	offset += 8
	copy(v[offset:offset+32], ringHash[:])
	offset += 32
	v[offset] = ringSize
	offset += 1
	copy(v[offset:offset+32], spentBy[:])
	offset += 32
	byteOrder.PutUint64(v[offset:offset+8], uint64(spentTime.Unix()))
	offset += 8
	byteOrder.PutUint64(v[offset:offset+8], uint64(confirmTime.Unix()))
	offset += 8
	return v
}
func putRawSpentConfirmedTXO(ns walletdb.ReadWriteBucket, k, v []byte) error {
	err := ns.NestedReadWriteBucket(bucketSpentConfirmed).Put(k, v)
	if err != nil {
		str := "failed to put spent and confirme output"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func fetchSpentConfirmedTXO(ns walletdb.ReadWriteBucket, hash chainhash.Hash, index uint8) (*SpentConfirmedTXO, error) {
	k := canonicalOutPointAbe(hash, index)
	v := ns.NestedReadBucket(bucketSpentConfirmed).Get(k)
	if v == nil {
		return nil, fmt.Errorf("empty entry")
	}
	sct := new(SpentConfirmedTXO)
	sct.TxOutput.TxHash = hash
	sct.TxOutput.Index = index
	offset := 0
	sct.Version = byteOrder.Uint32(v[offset : offset+4])
	offset += 4
	sct.Height = int32(byteOrder.Uint32(v[offset : offset+4]))
	offset += 4
	t := v[offset]
	offset += 1
	if t == 0 {
		sct.FromCoinBase = false
	} else {
		sct.FromCoinBase = true
	}
	sct.Amount = byteOrder.Uint64(v[offset : offset+8])
	offset += 8
	sct.Index = v[offset]
	offset += 1
	sct.GenerationTime = time.Unix(int64(byteOrder.Uint64(v[offset:offset+8])), 0)
	offset += 8
	copy(sct.RingHash[:], v[offset:offset+32])
	offset += 32
	sct.RingSize = v[offset]
	offset += 1
	copy(sct.SpentByHash[:], v[offset:offset+32])
	offset += 32
	sct.SpentTime = time.Unix(int64(byteOrder.Uint64(v[offset:offset+8])), 0)
	offset += 8
	sct.ConfirmTime = time.Unix(int64(byteOrder.Uint64(v[offset:offset+8])), 0)
	offset += 8
	return sct, nil
}
func deleteSpentConfirmedTXO(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketSpentConfirmed).Delete(k)
	if err != nil {
		str := "failed to delete spent and confirmed output"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func ConfirmSpentTXO(ns walletdb.ReadWriteBucket, txHash chainhash.Hash, index uint8, sn []byte) error {
	k := canonicalOutPointAbe(txHash, index)
	balance, err := fetchMinedBalance(ns)
	if err != nil {
		return err
	}
	spendableBal, err := fetchSpenableBalance(ns)
	if err != nil {
		return err
	}
	// if this output is in unspent txo bucket
	v := existsRawMaturedOutput(ns, k)
	if v != nil { //from the MaturedOutput
		//otherwise it has been moved to spentButUnmined bucket
		// update the balances
		amt := abeutil.Amount(byteOrder.Uint64(v[9:17]))
		balance -= amt
		spendableBal -= amt
		v = append(v, sn[:]...)
		var confirmTime [8]byte
		byteOrder.PutUint64(confirmTime[:], uint64(time.Now().Unix()))
		v = append(v, confirmTime[:]...) //spentTime
		v = append(v, confirmTime[:]...) // confirm time
		err = deleteMaturedOutput(ns, k)
		if err != nil {
			return err
		}
	} else { //from the spentButUnmined bucket
		v = existsRawSpentButUnminedTXO(ns, k)
		if v != nil { //otherwise it has been moved to spentButUnmined bucket
			amt := abeutil.Amount(byteOrder.Uint64(v[5:13]))
			balance -= amt
			// freezedBal -= amt
			v = append(v, sn[:]...)
			var confirmTime [8]byte
			byteOrder.PutUint64(confirmTime[:], uint64(time.Now().Unix()))
			v = append(v, confirmTime[:]...)
			err = deleteSpentButUnminedTXO(ns, k)
			if err != nil {
				return err
			}
		}
	}
	// update confirm bucket
	err = putRawSpentConfirmedTXO(ns, k, v)
	if err != nil {
		return err
	}
	err = putSpenableBalance(ns, spendableBal)
	if err != nil {
		return err
	}
	return putMinedBalance(ns, balance)
}

//All the relevant UTXORingAbe are keyed as such:
//
//    [0:32] RingHash(32 bytes)
//    value see the serialize method of Ring
func keyRingDetails(ring *Ring) []byte {
	return ring.Hash()
}
func valueRingDetails(ring *Ring) []byte {
	return ring.Serialize()
}
func putRingDetails(ns walletdb.ReadWriteBucket, k, v []byte) error {
	err := ns.NestedReadWriteBucket(bucketRingDetails).Put(k, v)
	if err != nil {
		str := "failed to put ring details"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func existsRingDetails(ns walletdb.ReadBucket, hash chainhash.Hash) (k, v []byte) {
	copy(k[:], hash[:])
	v = ns.NestedReadBucket(bucketRingDetails).Get(k)
	return
}
func fetchRingDetails(ns walletdb.ReadBucket, k []byte) (*Ring, error) {
	v := ns.NestedReadBucket(bucketRingDetails).Get(k)
	if v == nil {
		return nil, fmt.Errorf("the pair is not exist")
	}
	res := new(Ring)
	err := res.Deserialize(v)
	return res, err
}
func FetchRingDetails(ns walletdb.ReadBucket, k []byte) (*Ring, error) {
	return fetchRingDetails(ns, k)
}
func deleteRingDetails(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketRingDetails).Delete(k)
	if err != nil {
		str := "failed to delete ring details"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func updateDeletedHeightRingDetails(ns walletdb.ReadWriteBucket, k []byte, height int32) error {
	ring, err := fetchRingDetails(ns, k)
	if err != nil {
		str := "failed to fetch ring details"
		return storeError(ErrDatabase, str, err)
	}
	ring.BlockHeight = height
	err = putRingDetails(ns, k, ring.Serialize())
	if err != nil {
		return err
	}
	return nil
}

//All the relevant ring are keyed as such:
//
//    [0:32] RingHash(32 bytes)
//    value see the serialize method of UTXORing
func valueUTXORing(u *UTXORingAbe) []byte {
	return u.Serialize()[:]
}
func existsUTXORing(ns walletdb.ReadBucket, hash chainhash.Hash) (k, v []byte) {
	k = make([]byte, 32)
	copy(k[:], hash[:])
	v = ns.NestedReadBucket(bucketUTXORing).Get(k)
	return
}
func PutUTXORing(ns walletdb.ReadWriteBucket, k []byte, utxoring *UTXORingAbe) error {
	v := valueUTXORing(utxoring)
	return putRawUTXORing(ns, k, v)
}
func putRawUTXORing(ns walletdb.ReadWriteBucket, k, v []byte) error {
	err := ns.NestedReadWriteBucket(bucketUTXORing).Put(k, v)
	if err != nil {
		str := "failed to put utxoring"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func FetchUTXORing(ns walletdb.ReadBucket, k []byte) (*UTXORingAbe, error) {
	return fetchUTXORing(ns, k)
}
func fetchUTXORing(ns walletdb.ReadBucket, k []byte) (*UTXORingAbe, error) {
	v := ns.NestedReadBucket(bucketUTXORing).Get(k)
	if v == nil {
		return nil, fmt.Errorf("the pair is not exist")
	}
	res := new(UTXORingAbe)
	res.Deserialize(v)
	return res, nil
}
func deleteUTXORing(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketUTXORing).Delete(k)
	if err != nil {
		str := "failed to delete utxoring"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

// The unspent index records all outpoints for mined credits which are not spent
// by any other mined transaction records (but may be spent by a mempool
// transaction).
//
// Keys are use the canonical outpoint serialization:
//
//   [0:32]  Transaction hash (32 bytes)
//   [32:36] Output index (4 bytes)
//
// Values are serialized as such:
//
//   [0:4]   Block height (4 bytes)
//   [4:36]  Block hash (32 bytes)

func readUnspentBlockAbe(v []byte, block *BlockAbe) error {
	if len(v) < 36 {
		str := "short unspent value"
		return storeError(ErrData, str, nil)
	}
	block.Height = int32(byteOrder.Uint32(v))
	copy(block.Hash[:], v[4:36])
	return nil
}

// existsUnspent returns the key for the unspent output and the corresponding
// key for the credits bucket.  If there is no unspent output recorded, the
// credit key is nil.

// existsRawUnspent returns the credit key if there exists an output recorded
// for the raw unspent key.  It returns nil if the k/v pair does not exist.

// All transaction debits (inputs which spend credits) are keyed as such:
//
//   [0:32]  Transaction hash (32 bytes)
//   [32:36] Block height (4 bytes)
//   [36:68] Block hash (32 bytes)
//   [68:72] Input index (4 bytes)
//
// The first 68 bytes match the key for the transaction record and may be used
// as a prefix filter to iterate through all debits in order.
//
// The debit value is serialized as such:
//
//   [0:8]   Amount (8 bytes)
//   [8:80]  Credits bucket key (72 bytes)
//             [8:40]  Transaction hash (32 bytes)
//             [40:44] Block height (4 bytes)
//             [44:76] Block hash (32 bytes)
//             [76:80] Output index (4 bytes)

// existsDebit checks for the existance of a debit.  If found, the debit and
// previous credit keys are returned.  If the debit does not exist, both keys
// are nil.

// debitIterator allows for in-order iteration of all debit records for a
// mined transaction.
//
// Example usage:
//
//   prefix := keyTxRecord(txHash, block)
//   it := makeDebitIterator(ns, prefix)
//   for it.next() {
//           // Use it.elem
//           // If necessary, read additional details from it.ck, it.cv
//   }
//   if it.err != nil {
//           // Handle error
//   }

// All unmined transactions are saved in the unmined bucket keyed by the
// transaction hash.  The value matches that of mined transaction records:
//
//   [0:8]   Received time (8 bytes)
//   [8:]    Serialized transaction (varies)

func putRawUnminedAbe(ns walletdb.ReadWriteBucket, k, v []byte) error {
	err := ns.NestedReadWriteBucket(bucketUnminedAbe).Put(k, v)
	if err != nil {
		str := "failt to put unmined transaction"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

//TODO(abe):this function will be reused for unminedAbe
func readRawUnminedHash(k []byte, txHash *chainhash.Hash) error {
	if len(k) < 32 {
		str := "short unmined key"
		return storeError(ErrData, str, nil)
	}
	copy(txHash[:], k)
	return nil
}

func existsRawUnminedAbe(ns walletdb.ReadBucket, k []byte) (v []byte) {
	return ns.NestedReadBucket(bucketUnminedAbe).Get(k)
}

func DeleteRawUnminedAbe(ns walletdb.ReadWriteBucket, tx *wire.MsgTxAbe) error {
	for _, input := range tx.TxIns {
		ringHash := input.PreviousOutPointRing.Hash()

		utxoRing, err := fetchUTXORing(ns, ringHash[:])
		if err != nil {
			continue
		}
		for idx, sn := range utxoRing.OriginSerialNumberes {
			if bytes.Equal(sn, input.SerialNumber) {
				k := canonicalOutPoint(&utxoRing.TxHashes[idx], uint32(utxoRing.OutputIndexes[idx]))
				_ = deleteSpentButUnminedTXO(ns, k)
				break
			}
		}
	}
	txHash := tx.TxHash()
	return deleteRawUnminedAbe(ns, txHash[:])
}

// TODO(abe):when delete the entry in unminedAbe, it must explicit where the corresponding entry in spent but unmined into
//  SpentAndConfirm or UnspentTXO bucket?
func deleteRawUnminedAbe(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketUnminedAbe).Delete(k)
	if err != nil {
		str := "failed to delete unmined record"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

// Unmined transaction credits use the canonical serialization format:
//
//  [0:32]   Transaction hash (32 bytes)
//  [32:36]  Output index (4 bytes)
//
// The value matches the format used by mined credits, but the spent flag is
// never set and the optional debit record is never included.  The simplified
// format is thus:
//
//   [0:8]   Amount (8 bytes)
//   [8]     Flags (1 byte)
//             0x02: Change

// unminedCreditIterator allows for cursor iteration over all credits, in order,
// from a single unmined transaction.
//
//  Example usage:
//
//   it := makeUnminedCreditIterator(ns, txHash)
//   for it.next() {
//           // Use it.elem, it.ck and it.cv
//           // Optionally, use it.delete() to remove this k/v pair
//   }
//   if it.err != nil {
//           // Handle error
//   }
//
// The spentness of the credit is not looked up for performance reasons (because
// for unspent credits, it requires another lookup in another bucket).  If this
// is needed, it may be checked like this:
//
//   spent := existsRawUnminedInput(ns, it.ck) != nil

type readCursor struct {
	walletdb.ReadCursor
}

func (r readCursor) Delete() error {
	str := "failed to delete current cursor item from read-only cursor"
	return storeError(ErrDatabase, str, walletdb.ErrTxNotWritable)
}

// unavailable until https://github.com/boltdb/bolt/issues/620 is fixed.
// func (it *unminedCreditIterator) delete() error {
// 	err := it.c.Delete()
// 	if err != nil {
// 		str := "failed to delete unmined credit"
// 		return storeError(ErrDatabase, str, err)
// 	}
// 	return nil
// }

// Outpoints spent by unmined transactions are saved in the unmined inputs
// bucket.  This bucket maps between each previous output spent, for both mined
// and unmined transactions, to the hash of the unmined transaction.
//
// The key is serialized as such:
//
//   [0:32]   Transaction hash (32 bytes)
//   [32:36]  Output index (4 bytes)
//
// The value is serialized as such:
//
//   [0:32]   Transaction hash (32 bytes)

// putRawUnminedInput maintains a list of unmined transaction hashes that have
// spent an outpoint. Each entry in the bucket is keyed by the outpoint being
// spent.

// fetchUnminedInputSpendTxHashes fetches the list of unmined transactions that
// spend the serialized outpoint.

// deleteRawUnminedInput removes a spending transaction entry from the list of
// spending transactions for a given input.

// serializeLockedOutput serializes the value of a locked output.
func serializeLockedOutput(id LockID, expiry time.Time) []byte {
	var v [len(id) + 8]byte
	copy(v[:len(id)], id[:])
	byteOrder.PutUint64(v[len(id):], uint64(expiry.Unix()))
	return v[:]
}

// deserializeLockedOutput deserializes the value of a locked output.
func deserializeLockedOutput(v []byte) (LockID, time.Time) {
	var id LockID
	copy(id[:], v[:len(id)])
	expiry := time.Unix(int64(byteOrder.Uint64(v[len(id):])), 0)
	return id, expiry
}

// isLockedOutput determines whether an output is locked. If it is, its assigned
// ID is returned, along with its absolute expiration time. If the output lock
// exists, but its expiration has been met, then the output is considered
// unlocked.
func isLockedOutput(ns walletdb.ReadBucket, op wire.OutPoint,
	timeNow time.Time) (LockID, time.Time, bool) {

	// The bucket may not exist, indicating that no outputs have ever been
	// locked, so we can just return now.
	lockedOutputs := ns.NestedReadBucket(bucketLockedOutputs)
	if lockedOutputs == nil {
		return LockID{}, time.Time{}, false
	}

	// Retrieve the output lock, if any, and extract the relevant fields.
	k := canonicalOutPoint(&op.Hash, op.Index)
	v := lockedOutputs.Get(k)
	if v == nil {
		return LockID{}, time.Time{}, false
	}
	lockID, expiry := deserializeLockedOutput(v)

	// If the output lock has already expired, delete it now.
	if !timeNow.Before(expiry) {
		return LockID{}, time.Time{}, false
	}

	return lockID, expiry, true
}

// lockOutput creates a lock for `duration` over an output assigned to the `id`,
// preventing it from becoming eligible for coin selection.
func lockOutput(ns walletdb.ReadWriteBucket, id LockID, op wire.OutPoint,
	expiry time.Time) error {

	// Create the corresponding bucket if necessary.
	lockedOutputs, err := ns.CreateBucketIfNotExists(bucketLockedOutputs)
	if err != nil {
		str := "failed to create locked outputs bucket"
		return storeError(ErrDatabase, str, err)
	}

	// Store a mapping of outpoint -> (id, expiry).
	k := canonicalOutPoint(&op.Hash, op.Index)
	v := serializeLockedOutput(id, expiry)

	if err := lockedOutputs.Put(k, v[:]); err != nil {
		str := fmt.Sprintf("%s: put failed for %v", bucketLockedOutputs,
			op)
		return storeError(ErrDatabase, str, err)
	}

	return nil
}

// unlockOutput removes a lock over an output, making it eligible for coin
// selection if still unspent.
func unlockOutput(ns walletdb.ReadWriteBucket, op wire.OutPoint) error {
	// The bucket may not exist, indicating that no outputs have ever been
	// locked, so we can just return now.
	lockedOutputs := ns.NestedReadWriteBucket(bucketLockedOutputs)
	if lockedOutputs == nil {
		return nil
	}

	// Delete the key-value pair representing the output lock.
	k := canonicalOutPoint(&op.Hash, op.Index)
	if err := lockedOutputs.Delete(k); err != nil {
		str := fmt.Sprintf("%s: delete failed for %v",
			bucketLockedOutputs, op)
		return storeError(ErrDatabase, str, err)
	}

	return nil
}

// forEachLockedOutput iterates over all existing locked outputs and invokes the
// callback `f` for each.
func forEachLockedOutput(ns walletdb.ReadBucket,
	f func(wire.OutPoint, LockID, time.Time)) error {

	// The bucket may not exist, indicating that no outputs have ever been
	// locked, so we can just return now.
	lockedOutputs := ns.NestedReadBucket(bucketLockedOutputs)
	if lockedOutputs == nil {
		return nil
	}

	return lockedOutputs.ForEach(func(k, v []byte) error {
		var op wire.OutPoint
		if err := readCanonicalOutPoint(k, &op); err != nil {
			return err
		}
		lockID, expiry := deserializeLockedOutput(v)

		f(op, lockID, expiry)

		return nil
	})
}

// openStore opens an existing transaction store from the passed namespace.
func openStore(ns walletdb.ReadBucket) error {
	version, err := fetchVersion(ns)
	if err != nil {
		return err
	}

	latestVersion := getLatestVersion()
	if version < latestVersion {
		str := fmt.Sprintf("a database upgrade is required to upgrade "+
			"wtxmgr from recorded version %d to the latest version %d",
			version, latestVersion)
		return storeError(ErrNeedsUpgrade, str, nil)
	}

	if version > latestVersion {
		str := fmt.Sprintf("version recorded version %d is newer that "+
			"latest understood version %d", version, latestVersion)
		return storeError(ErrUnknownVersion, str, nil)
	}

	return nil
}

// createStore creates the tx store (with the latest db version) in the passed
// namespace.  If a store already exists, ErrAlreadyExists is returned.
func createStore(ns walletdb.ReadWriteBucket) error {
	// Ensure that nothing currently exists in the namespace bucket.
	ck, cv := ns.ReadCursor().First()
	if ck != nil || cv != nil {
		const str = "namespace is not empty"
		return storeError(ErrAlreadyExists, str, nil)
	}

	// Write the latest store version.
	if err := putVersion(ns, getLatestVersion()); err != nil {
		return err
	}

	// Save the creation date of the store.
	var v [8]byte
	byteOrder.PutUint64(v[:], uint64(time.Now().Unix()))
	err := ns.Put(rootCreateDate, v[:])
	if err != nil {
		str := "failed to store database creation time"
		return storeError(ErrDatabase, str, err)
	}

	// Write a zero balance.
	byteOrder.PutUint64(v[:], 0)
	err = ns.Put(rootMinedBalance, v[:])
	if err != nil {
		str := "failed to write zero balance"
		return storeError(ErrDatabase, str, err)
	}
	// Write a zero balance.
	byteOrder.PutUint64(v[:], 0)
	err = ns.Put(rootSpendableBalance, v[:])
	if err != nil {
		str := "failed to write zero spendable balance"
		return storeError(ErrDatabase, str, err)
	}
	// Write a zero balance.
	byteOrder.PutUint64(v[:], 0)
	err = ns.Put(rootFreezedBalance, v[:])
	if err != nil {
		str := "failed to write zero freezed balance"
		return storeError(ErrDatabase, str, err)
	}

	// Finally, create all of our required descendant buckets.
	return createBuckets(ns)
}

// createBuckets creates all of the descendants buckets required for the
// transaction store to properly carry its duties.
func createBuckets(ns walletdb.ReadWriteBucket) error {
	if _, err := ns.CreateBucket(bucketLockedOutputs); err != nil {
		str := "failed to create locked outputs bucket"
		return storeError(ErrDatabase, str, err)
	}
	//TODO(abe): change the name of bucket
	if _, err := ns.CreateBucket(bucketBlockAbes); err != nil {
		str := "fialed to create blockabe bucket"
		return storeError(ErrDatabase, str, err)
	}
	if _, err := ns.CreateBucket(bucketBlockInputs); err != nil {
		str := "fialed to create block input bucket"
		return storeError(ErrDatabase, str, err)
	}
	if _, err := ns.CreateBucket(bucketBlockOutputs); err != nil {
		str := "fialed to create block output bucket"
		return storeError(ErrDatabase, str, err)
	}
	if _, err := ns.CreateBucket(bucketImmaturedCoinbaseOutput); err != nil {
		str := "fialed to create immature coinbase txo bucket"
		return storeError(ErrDatabase, str, err)
	}
	if _, err := ns.CreateBucket(bucketImmaturedOutput); err != nil {
		str := "fialed to create immature txo bucket"
		return storeError(ErrDatabase, str, err)
	}
	if _, err := ns.CreateBucket(bucketMaturedOutput); err != nil {
		str := "fialed to create mature txo bucket"
		return storeError(ErrDatabase, str, err)
	}
	if _, err := ns.CreateBucket(bucketSpentButUnmined); err != nil {
		str := "fialed to create unspent but unmined txo bucket"
		return storeError(ErrDatabase, str, err)
	}
	if _, err := ns.CreateBucket(bucketSpentConfirmed); err != nil {
		str := "fialed to create spent and confirmed bucket"
		return storeError(ErrDatabase, str, err)
	}
	if _, err := ns.CreateBucket(bucketUTXORing); err != nil {
		str := "fialed to create utxo ring bucket"
		return storeError(ErrDatabase, str, err)
	}
	if _, err := ns.CreateBucket(bucketRingDetails); err != nil {
		str := "fialed to create ring details bucket"
		return storeError(ErrDatabase, str, err)
	}

	if _, err := ns.CreateBucket(bucketUnminedAbe); err != nil {
		str := "failed to create unmined bucket"
		return storeError(ErrDatabase, str, err)
	}

	return nil
}

// deleteBuckets deletes all of the descendants buckets required for the
// transaction store to properly carry its duties.
func deleteBuckets(ns walletdb.ReadWriteBucket) error {
	if err := ns.DeleteNestedBucket(bucketLockedOutputs); err != nil {
		str := "failed to delete locked outputs bucket"
		return storeError(ErrDatabase, str, err)
	}
	//TODO(abe):change the name of bucket
	if err := ns.DeleteNestedBucket(bucketBlockAbes); err != nil {
		str := "fialed to delete blockabe bucket"
		return storeError(ErrDatabase, str, err)
	}
	if err := ns.DeleteNestedBucket(bucketBlockInputs); err != nil {
		str := "fialed to delete block input bucket"
		return storeError(ErrDatabase, str, err)
	}
	if err := ns.DeleteNestedBucket(bucketBlockOutputs); err != nil {
		str := "fialed to delete block output bucket"
		return storeError(ErrDatabase, str, err)
	}
	if err := ns.DeleteNestedBucket(bucketImmaturedCoinbaseOutput); err != nil {
		str := "fialed to delete immature coinbase txo bucket"
		return storeError(ErrDatabase, str, err)
	}
	if err := ns.DeleteNestedBucket(bucketImmaturedOutput); err != nil {
		str := "fialed to delete immature txo bucket"
		return storeError(ErrDatabase, str, err)
	}
	if err := ns.DeleteNestedBucket(bucketMaturedOutput); err != nil {
		str := "fialed to delete mature txo bucket"
		return storeError(ErrDatabase, str, err)
	}
	if err := ns.DeleteNestedBucket(bucketSpentButUnmined); err != nil {
		str := "fialed to delete spent but unmined txo bucket"
		return storeError(ErrDatabase, str, err)
	}
	if err := ns.DeleteNestedBucket(bucketSpentConfirmed); err != nil {
		str := "fialed to delete spent and confirmed txo bucket"
		return storeError(ErrDatabase, str, err)
	}
	if err := ns.DeleteNestedBucket(bucketUTXORing); err != nil {
		str := "fialed to delete utxo ring bucket"
		return storeError(ErrDatabase, str, err)
	}
	if err := ns.DeleteNestedBucket(bucketRingDetails); err != nil {
		str := "fialed to delete utxo details bucket"
		return storeError(ErrDatabase, str, err)
	}

	if err := ns.DeleteNestedBucket(bucketUnminedAbe); err != nil {
		str := "failed to delete unmined bucket"
		return storeError(ErrDatabase, str, err)
	}

	return nil
}

// putVersion modifies the version of the store to reflect the given version
// number.
func putVersion(ns walletdb.ReadWriteBucket, version uint32) error {
	var v [4]byte
	byteOrder.PutUint32(v[:], version)
	if err := ns.Put(rootVersion, v[:]); err != nil {
		str := "failed to store database version"
		return storeError(ErrDatabase, str, err)
	}

	return nil
}

// fetchVersion fetches the current version of the store.
func fetchVersion(ns walletdb.ReadBucket) (uint32, error) {
	v := ns.Get(rootVersion)
	if len(v) != 4 {
		str := "no transaction store exists in namespace"
		return 0, storeError(ErrNoExists, str, nil)
	}

	return byteOrder.Uint32(v), nil
}
