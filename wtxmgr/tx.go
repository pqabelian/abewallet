package wtxmgr

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abecrypto/abecryptoparam"
	"github.com/abesuite/abec/blockchain"
	"github.com/abesuite/abewallet/waddrmgr"
	"github.com/abesuite/abewallet/walletdb"
	"math"
	"time"

	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"github.com/lightningnetwork/lnd/clock"
)

const (
	// TxLabelLimit is the length limit we impose on transaction labels.
	TxLabelLimit = 500

	// DefaultLockDuration is the default duration used to lock outputs.
	DefaultLockDuration = 10 * time.Minute
)

var (
	// ErrEmptyLabel is returned when an attempt to write a label that is
	// empty is made.
	ErrEmptyLabel = errors.New("empty transaction label not allowed")

	// ErrLabelTooLong is returned when an attempt to write a label that is
	// to long is made.
	ErrLabelTooLong = errors.New("transaction label exceeds limit")

	// ErrNoLabelBucket is returned when the bucket holding optional
	// transaction labels is not found. This occurs when no transactions
	// have been labelled yet.
	ErrNoLabelBucket = errors.New("labels bucket does not exist")

	// ErrTxLabelNotFound is returned when no label is found for a
	// transaction hash.
	ErrTxLabelNotFound = errors.New("label for transaction not found")

	// ErrUnknownOutput is an error returned when an output not known to the
	// wallet is attempted to be locked.
	ErrUnknownOutput = errors.New("unknown output")

	// ErrOutputAlreadyLocked is an error returned when an output has
	// already been locked to a different ID.
	ErrOutputAlreadyLocked = errors.New("output already locked")

	// ErrOutputUnlockNotAllowed is an error returned when an output unlock
	// is attempted with a different ID than the one which locked it.
	ErrOutputUnlockNotAllowed = errors.New("output unlock not alowed")
)

// Block contains the minimum amount of data to uniquely identify any block on
// either the best or side chain.
type Block struct {
	Hash   chainhash.Hash
	Height int32
}

// BlockMeta contains the unique identification for a block and any metadata
// pertaining to the block.  At the moment, this additional metadata only
// includes the block time from the block header.
type BlockMeta struct {
	Block
	Time time.Time
}

type BlockRecord struct {
	MsgBlock        wire.MsgBlockAbe //TODO(abe):using a pointer replace the struct
	Height          int32
	Hash            chainhash.Hash
	RecvTime        time.Time
	TxRecords       []*TxRecord
	SerializedBlock []byte
}

func NewBlockRecord(serializedBlock []byte) (*BlockRecord, error) {
	rec := &BlockRecord{
		SerializedBlock: serializedBlock,
	}
	err := rec.MsgBlock.DeserializeNoWitness(bytes.NewReader(serializedBlock))
	if err != nil {
		str := "failed to deserialize block"
		return nil, storeError(ErrInput, str, err)
	}
	blockHash := rec.MsgBlock.BlockHash()
	copy(rec.Hash[:], blockHash.CloneBytes())
	rec.Height = int32(binary.BigEndian.Uint32(rec.MsgBlock.Transactions[0].TxIns[0].PreviousOutPointRing.BlockHashs[0][0:4]))
	rec.RecvTime = rec.MsgBlock.Header.Timestamp
	rec.TxRecords = make([]*TxRecord, len(rec.MsgBlock.Transactions))
	for i := 0; i < len(rec.MsgBlock.Transactions); i++ {
		rec.TxRecords[i], err = NewTxRecordFromMsgTx(rec.MsgBlock.Transactions[i], rec.RecvTime)
		if err != nil {
			return nil, err
		}
	}
	return rec, nil

}
func NewBlockRecordFromMsgBlock(msgBlock *wire.MsgBlockAbe) (*BlockRecord, error) {
	buf := bytes.NewBuffer(make([]byte, 0, msgBlock.SerializeSize()))
	err := msgBlock.Serialize(buf)
	if err != nil {
		str := "failed to serialize block"
		return nil, storeError(ErrInput, str, err)
	}
	rec := &BlockRecord{
		MsgBlock:        *msgBlock,
		Height:          int32(binary.BigEndian.Uint32(msgBlock.Transactions[0].TxIns[0].PreviousOutPointRing.BlockHashs[0][0:4])),
		Hash:            msgBlock.BlockHash(),
		RecvTime:        msgBlock.Header.Timestamp,
		TxRecords:       make([]*TxRecord, len(msgBlock.Transactions)),
		SerializedBlock: buf.Bytes(),
	}
	for i := 0; i < len(msgBlock.Transactions); i++ {
		rec.TxRecords[i], err = NewTxRecordFromMsgTx(rec.MsgBlock.Transactions[i], rec.RecvTime)
		if err != nil {
			return nil, err
		}
	}
	return rec, nil
}

// blockRecord is an in-memory representation of the block record saved in the
// database.
type blockRecord struct {
	Block
	Time         time.Time
	transactions []chainhash.Hash
}

// incidence records the block hash and blockchain height of a mined transaction.
// Since a transaction hash alone is not enough to uniquely identify a mined
// transaction (duplicate transaction hashes are allowed), the incidence is used
// instead.
type incidence struct {
	txHash chainhash.Hash
	block  Block
}

// indexedIncidence records the transaction incidence and an input or output
// index.
type indexedIncidence struct {
	incidence
	index uint32
}

// debit records the debits a transaction record makes from previous wallet
// transaction credits.

// credit describes a transaction output which was or is spendable by wallet.

// TxRecord represents a transaction managed by the Store.
// TODO: this struct would be add more information for managing transaction
type TxRecord struct {
	MsgTx        wire.MsgTxAbe
	Hash         chainhash.Hash
	Received     time.Time // record the record status
	SerializedTx []byte    // Optional: may be nil
}

// NewTxRecord creates a new transaction record that may be inserted into the
// store.  It uses memoization to save the transaction hash and the serialized
// transaction.
func NewTxRecord(serializedTx []byte, received time.Time) (*TxRecord, error) {
	rec := &TxRecord{
		Received:     received,
		SerializedTx: serializedTx,
	}
	err := rec.MsgTx.Deserialize(bytes.NewReader(serializedTx))
	if err != nil {
		str := "failed to deserialize transaction"
		return nil, storeError(ErrInput, str, err)
	}
	copy(rec.Hash[:], chainhash.DoubleHashB(serializedTx))
	return rec, nil
}

// NewTxRecordFromMsgTx creates a new transaction record that may be inserted
// into the store.
func NewTxRecordFromMsgTx(msgTx *wire.MsgTxAbe, received time.Time) (*TxRecord, error) {
	buf := bytes.NewBuffer(make([]byte, 0, msgTx.SerializeSizeFull()))
	err := msgTx.SerializeFull(buf)
	if err != nil {
		str := "failed to serialize transaction"
		return nil, storeError(ErrInput, str, err)
	}
	rec := &TxRecord{
		MsgTx:        *msgTx,
		Received:     received,
		SerializedTx: buf.Bytes(),
		Hash:         msgTx.TxHash(),
	}

	return rec, nil
}

// Credit is the type representing a transaction output which was spent or
// is still spendable by wallet.  A UTXO is an unspent Credit, but not all
// Credits are UTXOs.

type UnspentUTXO struct {
	Version uint32 // todo: added by AliceBob 20210616, the version of corresponding Txo in blockchain, and the same as that of the ring
	Height  int32  // the block height used to identify whether this utox can be spent in current height
	//BlockHash      chainhash.Hash
	TxOutput     wire.OutPointAbe //the outpoint
	FromCoinBase bool
	Amount       uint64
	Index        uint8 //indicate the index in the ring, if not in a ring, it equals to -1 TODO_DONE(osy,20210617) finish this field read and write
	//ValueScript    int64
	//AddrScript     []byte
	GenerationTime time.Time      //at this moment, it also useless
	RingHash       chainhash.Hash //may be zero
	RingSize       uint8          // set together with RingHash, uint8 is reasonable and larger enough
	UTXOHash       chainhash.Hash
}

func NewUnspentUTXO(version uint32, height int32, txOutput wire.OutPointAbe, fromCoinBase bool, amount uint64, index uint8, generationTime time.Time, ringHash chainhash.Hash, ringSize uint8) *UnspentUTXO {
	return &UnspentUTXO{Version: version, Height: height, TxOutput: txOutput, FromCoinBase: fromCoinBase, Amount: amount, Index: index, GenerationTime: generationTime, RingHash: ringHash, RingSize: ringSize}
}

func (utxo *UnspentUTXO) Hash() chainhash.Hash {
	if !utxo.UTXOHash.IsEqual(&chainhash.ZeroHash) {
		return utxo.UTXOHash
	}

	// Version + Height + TxOutput.TxHash + TxOutput.Index + Amount + Index + RingHash + RingSize
	buf := make([]byte, 83)
	binary.LittleEndian.PutUint32(buf[0:4], utxo.Version)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(utxo.Height))
	copy(buf[8:40], utxo.TxOutput.TxHash[0:32])
	buf[40] = utxo.TxOutput.Index
	binary.LittleEndian.PutUint64(buf[41:49], utxo.Amount)
	buf[49] = utxo.Index
	copy(buf[50:82], utxo.RingHash[0:32])
	buf[82] = utxo.RingSize

	utxo.UTXOHash = chainhash.DoubleHashH(buf)
	return utxo.UTXOHash
}

func (utxo *UnspentUTXO) Deserialize(op *wire.OutPointAbe, v []byte) error {
	if v == nil {
		return fmt.Errorf("empty byte slice")
	}
	//	if len(v) < 49 { // todo: 2021.06.16 hardcode needs to be fixed
	if len(v) < 55 { // todo: 2021.06.16 hardcode needs to be fixed
		str := "wrong size of serialized unspent transaction output"
		return fmt.Errorf(str)
	}
	utxo.TxOutput.TxHash = op.TxHash
	utxo.TxOutput.Index = op.Index
	offset := 0
	utxo.Version = byteOrder.Uint32(v[offset : offset+4])
	offset += 4
	utxo.Height = int32(byteOrder.Uint32(v[offset : offset+4]))
	offset += 4
	t := v[offset]
	offset += 1
	if t == 0 {
		utxo.FromCoinBase = false
	} else {
		utxo.FromCoinBase = true
	}
	utxo.Amount = byteOrder.Uint64(v[offset : offset+8])
	offset += 8
	utxo.Index = v[offset]
	offset += 1
	utxo.GenerationTime = time.Unix(int64(byteOrder.Uint64(v[offset:offset+8])), 0)
	offset += 8
	copy(utxo.RingHash[:], v[offset:offset+32])
	offset += 32

	//	todo: uint8 is equal to byte?
	utxo.RingSize = uint8(v[offset])
	offset += 1

	return nil
}

type SpentButUnminedTXO struct { //TODO(abe):should add a field to denote which tx spent this utxo
	Version uint32 // todo: added by AliceBob 20210616, the version of corresponding Txo in blockchain, and the same as that of the ring
	Height  int32
	//BlockHash      chainhash.Hash
	TxOutput     wire.OutPointAbe
	FromCoinBase bool
	Amount       uint64
	Index        uint8
	//ValueScript    int64
	//AddrScript     []byte
	GenerationTime time.Time
	RingHash       chainhash.Hash //may be zero
	RingSize       uint8          // set together with RingHash
	SpentByHash    chainhash.Hash
	SpentTime      time.Time
}
type SpentConfirmedTXO struct { //TODO(abe):should add a field to denote which tx spent this utxo
	Version uint32 // todo: added by AliceBob 20210616, the version of corresponding Txo in blockchain, and the same as that of the ring
	Height  int32
	//BlockHash      chainhash.Hash
	TxOutput     wire.OutPointAbe
	FromCoinBase bool
	Amount       uint64
	Index        uint8
	//ValueScript    int64
	//AddrScript     []byte
	GenerationTime time.Time
	RingHash       chainhash.Hash //may be zero
	RingSize       uint8          // set together with RingHash
	SpentByHash    chainhash.Hash
	SpentTime      time.Time
	ConfirmTime    time.Time
}

// TODO(osy)20210608 change the serialize and deserialize
type Ring struct {
	Version     uint32
	BlockHashes []chainhash.Hash // three block hashes
	TxHashes    []chainhash.Hash // [2,8]
	Index       []uint8          // [2,8]
	//ValueScript []int64          // [2,8]
	//AddrScript  [][]byte         // [2.8]
	TxoScripts  [][]byte
	BlockHeight int32 // point  height where the utxo ring is deleted
}

type sortTxo struct {
	hash         *chainhash.Hash
	blochHashs   []*chainhash.Hash
	locBlockHash *chainhash.Hash
	txHash       *chainhash.Hash
	index        uint8
	txOut        *wire.TxOutAbe
}

func newSortRing(hash *chainhash.Hash, blocks []*chainhash.Hash, block *chainhash.Hash, txHash *chainhash.Hash, index uint8, out *wire.TxOutAbe) *sortTxo {
	return &sortTxo{
		hash:         hash,
		blochHashs:   blocks,
		locBlockHash: block,
		txHash:       txHash,
		index:        index,
		txOut:        out,
	}
}

type orderedRing []*sortTxo

func (o orderedRing) Len() int {
	return len(o)
}
func (o orderedRing) Less(i, j int) bool {
	return o[i].hash.String() < o[j].hash.String()
}

func (o orderedRing) Swap(i, j int) {
	o[i], o[j] = o[j], o[i]
}

// TODO(abe):change the method of serialization, use offset represent the location of corresonpding addr script size
// Serialize serialize the ring struct as such :
// [block hash...]||transaction number||[transaction hash||output index||addrScript Size...]||[addr script...]||hegiht
func (r Ring) Serialize() []byte {
	addrScriptAllSize := 0 //address script size
	bLen := len(r.BlockHashes)
	txLen := len(r.TxHashes) //transaction number
	txoSize := make([]int, 0, txLen)
	for i := 0; i < txLen; i++ {
		txoSize = append(txoSize, len(r.TxoScripts[i]))
		addrScriptAllSize += len(r.TxoScripts[i])
	}

	total := 4 + 32*bLen + 2 + (32+1+4)*txLen + addrScriptAllSize + 4
	res := make([]byte, total)
	offset := 0
	byteOrder.PutUint32(res, r.Version)
	offset += 4
	for i := 0; i < bLen; i++ {
		copy(res[offset:offset+32], r.BlockHashes[i][:])
		offset += 32
	}
	byteOrder.PutUint16(res[offset:offset+2], uint16(txLen))
	offset += 2
	for i := 0; i < txLen; i++ {
		copy(res[offset:offset+32], r.TxHashes[i][:])
		offset += 32
		res[offset] = r.Index[i]
		offset += 1
		//byteOrder.PutUint64(res[offset:offset+8], uint64(r.ValueScript[i]))
		//offset += 8
		byteOrder.PutUint32(res[offset:offset+4], uint32(txoSize[i]))
		offset += 4
	}
	for i := 0; i < txLen; i++ {
		copy(res[offset:offset+txoSize[i]], r.TxoScripts[i])
		offset += txoSize[i]
	}
	byteOrder.PutUint32(res[offset:offset+4], uint32(r.BlockHeight))
	offset += 4
	return res
}
func (r *Ring) Deserialize(b []byte) error {
	//	todo: AliceBob 20210616, Version is not handled
	// TODO:20210620 change the checking
	if len(b) < 32*wire.BlockNumPerRingGroup+(32+2+8) {
		return fmt.Errorf("wrong length of input byte slice")
	}
	offset := 0
	r.Version = byteOrder.Uint32(b)
	offset += 4
	for i := 0; i < wire.BlockNumPerRingGroup; i++ {
		newHash, err := chainhash.NewHash(b[offset : offset+32])
		if err != nil {
			return err
		}
		r.BlockHashes = append(r.BlockHashes, *newHash)
		offset += 32
	}
	txLen := int(byteOrder.Uint16(b[offset : offset+2]))
	offset += 2
	addrSize := make([]int, 0, txLen)
	for i := 0; i < txLen; i++ {
		newHash, err := chainhash.NewHash(b[offset : offset+32])
		if err != nil {
			return err
		}
		r.TxHashes = append(r.TxHashes, *newHash)
		offset += 32
		r.Index = append(r.Index, b[offset])
		offset += 1
		//r.ValueScript = append(r.ValueScript, int64(byteOrder.Uint64(b[offset:offset+8])))
		//offset += 8
		addrSize = append(addrSize, int(byteOrder.Uint32(b[offset:offset+4])))
		offset += 4
	}
	r.TxoScripts = make([][]byte, txLen)
	for i := 0; i < txLen; i++ {
		r.TxoScripts[i] = b[offset : offset+addrSize[i]]
		offset += addrSize[i]
	}
	r.BlockHeight = int32(byteOrder.Uint32(b[offset : offset+4]))
	offset += 4
	return nil
}

// blockHash0||blockHash1||blockHash2||txHash0||index0||txHash1||index1||...
func (r Ring) Hash() []byte {
	//	todo: AliceBob 20210616, Version is not handled
	//  todo: what is the relation between the ring here and the utxoring in abec? Shall they be kept consistent?

	//blockNum, err := wire.GetBlockNumPerRingGroupByRingVersion(r.Version)
	//if err != nil {
	//	return nil
	//}
	blockNum := len(r.BlockHashes)
	size := 4 + 1 + blockNum*chainhash.HashSize + 1 + len(r.TxHashes)*(chainhash.HashSize+1)
	v := make([]byte, size)
	offset := 0
	byteOrder.PutUint32(v[offset:offset+4], r.Version)
	offset += 4
	v[offset] = uint8(blockNum)
	offset += 1
	for i := 0; i < blockNum; i++ {
		copy(v[offset:offset+32], r.BlockHashes[i][:])
		offset += 32
	}
	v[offset] = uint8(len(r.TxHashes))
	offset += 1
	for i := 0; i < len(r.TxHashes); i++ {
		copy(v[offset:offset+32], r.TxHashes[i][:])
		offset += 32
		v[offset] = r.Index[i]
		offset += 1
	}
	return chainhash.DoubleHashB(v)
}

type UTXORing struct {
	Version              uint32
	AllSpent             bool             //1 // not serialized and when serializing it must be false, otherwise it will be deleted
	Refreshed            bool             //1 // not serialied, it can be computed from any OriginSerializeNumber
	RingHash             chainhash.Hash   //32
	TxHashes             []chainhash.Hash //32*len
	OutputIndexes        []uint8          //1
	OriginSerialNumberes map[uint8][]byte //variable
	IsMy                 []bool           //total 1
	Spent                []bool           // total 1
	GotSerialNumberes    [][]byte         // variable
	//SpentByTxHashes      []chainhash.Hash
	//InputIndexes         []uint8
}

func NewUTXORingFromRing(r *Ring, ringHash chainhash.Hash) (*UTXORing, error) {
	ringSize := len(r.TxHashes)
	return &UTXORing{
		Version:              r.Version,
		AllSpent:             false,
		Refreshed:            false,
		RingHash:             ringHash,
		TxHashes:             r.TxHashes,
		OutputIndexes:        r.Index,
		OriginSerialNumberes: make(map[uint8][]byte),
		IsMy:                 make([]bool, ringSize),
		Spent:                make([]bool, ringSize),
		GotSerialNumberes:    [][]byte{},
	}, nil
}

type RingHashSerialNumbers struct {
	utxoRings     map[chainhash.Hash]UTXORing // utxo ring states before processing the block
	serialNumbers map[chainhash.Hash][][]byte //added serialNumber in given block
}

// ring hash || transaction number || [transaction hash||output index...]||Origin serial number ||[index||serial number...]||isMy||Spent||Got serial number||[serial number...]
func (u UTXORing) SerializeSize() int {
	snSize, _ := abecryptoparam.GetSerialNumberSerializeSize(u.Version)
	return 4 + 32 + 1 + len(u.TxHashes)*(32+1) + 1 + len(u.OriginSerialNumberes)*(1+snSize) + 2 + 1 + len(u.GotSerialNumberes)*snSize

}
func (u UTXORing) Serialize() []byte {
	txLen := len(u.TxHashes) // TODO(osy): may be lack a tx len in serialized utxo ring
	totalSize := u.SerializeSize()
	res := make([]byte, totalSize)
	offset := 0
	byteOrder.PutUint32(res, u.Version)
	offset += 4
	copy(res[offset:offset+32], u.RingHash[:])
	offset += 32
	res[offset] = uint8(txLen)
	offset += 1
	for i := 0; i < txLen; i++ {
		copy(res[offset:offset+32], u.TxHashes[i][:])
		offset += 32
		res[offset] = u.OutputIndexes[i]
		offset += 1
	}
	res[offset] = uint8(len(u.OriginSerialNumberes))
	offset += 1
	snSize, _ := abecryptoparam.GetSerialNumberSerializeSize(u.Version)
	for index, sn := range u.OriginSerialNumberes {
		res[offset] = index
		offset += 1
		copy(res[offset:offset+snSize], sn[:])
		offset += snSize
	}
	var temp uint16
	for i := 0; i < txLen; i++ {
		if u.IsMy[i] {
			temp |= 1 << i
		}
		if u.Spent[i] {
			temp |= 1 << (i + 8)
		}
	}
	byteOrder.PutUint16(res[offset:offset+2], temp)
	offset += 2
	res[offset] = uint8(len(u.GotSerialNumberes))
	offset += 1
	for i := 0; i < len(u.GotSerialNumberes); i++ {
		copy(res[offset:offset+snSize], u.GotSerialNumberes[i][:])
		offset += snSize
	}
	return res
}
func (u *UTXORing) Deserialize(b []byte) error {
	if len(b) < 32+1 {
		return fmt.Errorf("the length of input byte slice less than minimum size")
	}
	offset := 0
	u.Version = byteOrder.Uint32(b[offset : offset+4])
	offset += 4
	copy(u.RingHash[:], b[offset:offset+32])
	offset += 32
	txLen := int(b[offset])
	offset += 1
	u.TxHashes = make([]chainhash.Hash, txLen)
	u.OutputIndexes = make([]uint8, txLen)
	for i := 0; i < txLen; i++ {
		copy(u.TxHashes[i][:], b[offset:offset+32])
		offset += 32
		u.OutputIndexes[i] = b[offset]
		offset += 1
	}
	originSnSize := int(b[offset])
	offset += 1
	snSize, _ := abecryptoparam.GetSerialNumberSerializeSize(u.Version)
	for i := 0; i < originSnSize; i++ {
		h := make([]byte, snSize)
		copy(h, b[offset+1:offset+1+snSize])
		if u.OriginSerialNumberes == nil {
			u.OriginSerialNumberes = make(map[uint8][]byte)
		}
		u.OriginSerialNumberes[b[offset]] = h[:]
		offset += 1 + snSize
	}
	temp := byteOrder.Uint16(b[offset : offset+2])
	offset += 2
	u.IsMy = make([]bool, txLen)
	u.Spent = make([]bool, txLen)
	for i := 0; i < txLen; i++ {
		if temp&(1<<i) != 0 {
			u.IsMy[i] = true
		}
		if temp&(1<<(i+8)) != 0 {
			u.Spent[i] = true
		}
	}
	gotSnSize := int(b[offset])
	offset += 1
	u.GotSerialNumberes = make([][]byte, gotSnSize)
	for i := 0; i < gotSnSize; i++ {
		u.GotSerialNumberes[i] = make([]byte, snSize)
		copy(u.GotSerialNumberes[i][:], b[offset:offset+snSize])
		offset += snSize
	}
	u.AllSpent = false
	return nil
}

// AddGotSerialNumber The caller must check the u.AllSpent after return
func (u *UTXORing) AddGotSerialNumber(serialNumber []byte) error {
	if u.GotSerialNumberes == nil || len(u.GotSerialNumberes) == 0 {
		u.GotSerialNumberes = make([][]byte, 0)
	}
	for i := 0; i < len(u.GotSerialNumberes); i++ {
		if bytes.Equal(serialNumber, u.GotSerialNumberes[i]) {
			return fmt.Errorf("there has a same serialNumber in UTXORing")
		}
	}

	u.GotSerialNumberes = append(u.GotSerialNumberes, serialNumber)
	// if all serialNumber shown in the chain or all utxo are spent,
	// mark all unspent utxo as spent
	if len(u.GotSerialNumberes) == len(u.TxHashes) {
		for i := 0; i < len(u.IsMy); i++ {
			if u.IsMy[i] && !u.Spent[i] {
				u.Spent[i] = true
			}
		}
		u.AllSpent = true //this utxo will be deleted
		return nil
	}
	// update
	for i := 0; i < len(u.IsMy); i++ {
		if u.IsMy[i] && !u.Spent[i] {
			sn, ok := u.OriginSerialNumberes[uint8(i)]
			if ok && bytes.Equal(sn, serialNumber) {
				u.Spent[i] = true
				break
			}
		}
	}
	// check
	u.AllSpent = true
	for i := 0; i < len(u.IsMy); i++ {
		if u.IsMy[i] && !u.Spent[i] {
			u.AllSpent = false
			break
		}
	}
	return nil
}

func (u UTXORing) Copy() *UTXORing {
	res := new(UTXORing)
	res.Version = u.Version
	res.AllSpent = u.AllSpent
	res.Refreshed = u.Refreshed
	res.RingHash = u.RingHash
	res.TxHashes = make([]chainhash.Hash, len(u.TxHashes))
	for i := 0; i < len(u.TxHashes); i++ {
		res.TxHashes[i] = u.TxHashes[i]
	}
	res.OutputIndexes = make([]uint8, len(u.OutputIndexes))
	for i := 0; i < len(u.OutputIndexes); i++ {
		res.OutputIndexes[i] = u.OutputIndexes[i]
	}
	if res.OriginSerialNumberes == nil {
		res.OriginSerialNumberes = make(map[uint8][]byte)
	}
	for k, v := range u.OriginSerialNumberes {
		res.OriginSerialNumberes[k] = v
	}
	res.IsMy = make([]bool, len(u.IsMy))
	for i := 0; i < len(u.IsMy); i++ {
		res.IsMy[i] = u.IsMy[i]
	}
	res.Spent = make([]bool, len(u.Spent))
	for i := 0; i < len(u.Spent); i++ {
		res.Spent[i] = u.Spent[i]
	}
	res.GotSerialNumberes = make([][]byte, len(u.GotSerialNumberes))
	for i := 0; i < len(u.GotSerialNumberes); i++ {
		res.GotSerialNumberes[i] = u.GotSerialNumberes[i]
	}
	return res
}

// LockID represents a unique context-specific ID assigned to an output lock.
type LockID [32]byte

// Store implements a transaction store for storing and managing wallet
// transactions.
type Store struct {
	manager *waddrmgr.Manager

	chainParams *chaincfg.Params

	// clock is used to determine when outputs locks have expired.
	clock clock.Clock

	// Event callbacks.  These execute in the same goroutine as the wtxmgr
	// caller.
	NotifyUnspent             func(hash *chainhash.Hash, index uint32)
	NotifyTransactionAccepted func(txInfo *TransactionInfo)
	NotifyTransactionRollback func(txInfo *TransactionInfo)
	NotifyTransactionInvalid  func(txInfo *TransactionInfo)
}
type TransactionInfo struct {
	TxHash *chainhash.Hash
	Height int32
}

// Open opens the wallet transaction store from a walletdb namespace.  If the
// store does not exist, ErrNoExist is returned. `lockDuration` represents how
// long outputs are locked for.
func Open(addrMgr *waddrmgr.Manager, ns walletdb.ReadBucket, chainParams *chaincfg.Params) (*Store, error) {

	// Open the store.
	err := openStore(ns)
	if err != nil {
		return nil, err
	}
	s := &Store{addrMgr, chainParams, clock.NewDefaultClock(), nil, nil, nil, nil} // TODO: set callbacks
	return s, nil
}

// Create creates a new persistent transaction store in the walletdb namespace.
// Creating the store when one already exists in this namespace will error with
// ErrAlreadyExists.
func Create(ns walletdb.ReadWriteBucket) error {
	return createStore(ns)
}

// updateMinedBalance updates the mined balance within the store, if changed,
// after processing the given transaction record.

// deleteUnminedTx deletes an unmined transaction from the store.
//
// NOTE: This should only be used once the transaction has been mined.

// InsertTx records a transaction as belonging to a wallet's transaction
// history.  If block is nil, the transaction is considered unspent, and the
// transaction's index must be unset.
// TODO(abe): actually, we must move the outputs of this transaction from unspent txo bucket to spentButUnmined txo bucket
// TODO(abe): update the balance in this function
// TODO(abe): record this transaction in unmined transaction bucket,
// TODO(abe): wait for a mempool transacion, need to design
func (s *Store) InsertTx(wtxmgrNs walletdb.ReadWriteBucket, rec *TxRecord, block *BlockMeta) error {
	//TODO(abe):remove the outputs of the wallet spent by given tx from UnspentTXObucket to SpentButUmined bucket
	if block != nil {
		return fmt.Errorf("InsertTx just considerates the unconfirmed transaction")
	}
	v := existsRawUnconfirmedTx(wtxmgrNs, rec.Hash[:])
	if v != nil { // it means that has exists unmined transaction bucket
		return nil
	}
	// move the unspentutxo bucket to spentbutunmined bucket
	for i := 0; i < len(rec.MsgTx.TxIns); i++ {
		// do not update the utxoring bucket  until the transaction packaged into a block
		// just mark it is spent and move from unspent bucket to spentbutunmined bucket
		// to avoid next time spent the same coins
		ringHash := rec.MsgTx.TxIns[i].PreviousOutPointRing.Hash()
		u, err := fetchUTXORing(wtxmgrNs, ringHash[:])
		if err != nil {
			return err
		}
		//find the index
		index := -1
		// We expected that when spent this utxo, the utxo ring will be update when add the script
		for k, sn := range u.OriginSerialNumberes {
			if bytes.Equal(sn, rec.MsgTx.TxIns[i].SerialNumber) {
				index = int(k)
				break
			}
		}
		if index == -1 { //it do not belong the wallet
			continue
		}
		//move from the unspentUtxo bucket to spentUtxobucket if necessary
		k := canonicalOutPointAbe(rec.MsgTx.TxIns[i].PreviousOutPointRing.OutPoints[index].TxHash, rec.MsgTx.TxIns[i].PreviousOutPointRing.OutPoints[index].Index)
		//v := wtxmgrNs.NestedReadWriteBucket(bucketUnspentTXO).Get(k)
		v := wtxmgrNs.NestedReadWriteBucket(bucketMaturedOutput).Get(k)
		if v == nil {
			return fmt.Errorf("there is no such a utxo in bucket")
		}
		// update the spendable balance
		spendableBal, err := fetchSpenableBalance(wtxmgrNs)
		if err != nil {
			return err
		}
		unconfirmedBal, err := fetchUnconfirmedBalance(wtxmgrNs)
		if err != nil {
			return err
		}
		amt := abeutil.Amount(byteOrder.Uint64(v[9:17]))
		spendableBal -= amt
		unconfirmedBal += amt
		err = putSpenableBalance(wtxmgrNs, spendableBal)
		if err != nil {
			return err
		}
		err = putUnconfirmedBalance(wtxmgrNs, unconfirmedBal)
		if err != nil {
			return err
		}
		err = deleteMaturedOutput(wtxmgrNs, k)
		if err != nil {
			return err
		}

		newv := make([]byte, len(v)+40)
		offset := 0
		copy(newv[offset:], v)
		offset += len(v)
		copy(newv[offset:], rec.Hash[:])
		offset += 32
		byteOrder.PutUint64(newv[len(newv)-8:], uint64(time.Now().Unix()))
		err = putRawSpentButUnminedTXO(wtxmgrNs, k, newv)
		if err != nil {
			return err
		}

		flag := false
		relevantTxs := existsRawReleventTxs(wtxmgrNs, k)
		if len(relevantTxs) != 0 {
			offset := 0
			for offset+chainhash.HashSize <= len(relevantTxs) {
				if bytes.Equal(rec.Hash[:], relevantTxs[offset:offset+chainhash.HashSize]) {
					flag = true
					err = deleteRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
					if err != nil {
						return err
					}
					err = deleteRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
					if err != nil {
						return err
					}
					offset += chainhash.HashSize
					continue
				}
				// other conflict transaction should be marked invalid
				conflictTx := existsRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
				if len(conflictTx) != 0 {
					err = deleteRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
					if err != nil {
						return err
					}
					err = putRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
					if err != nil {
						return err
					}
					txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
					txInfo := &TransactionInfo{
						TxHash: txHash,
						Height: s.manager.SyncedTo().Height,
					}
					s.NotifyTransactionInvalid(txInfo)
					log.Infof("send invalid transaction notification %v at height %d", txInfo.TxHash, txInfo.Height)
				}
				conflictTx = existsRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
				if len(conflictTx) != 0 {
					err = deleteRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
					if err != nil {
						return err
					}
					err = putRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
					if err != nil {
						return err
					}
					txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
					txInfo := &TransactionInfo{
						TxHash: txHash,
						Height: s.manager.SyncedTo().Height,
					}
					s.NotifyTransactionInvalid(txInfo)
					log.Infof("send invalid transaction notification %v at height %d", txInfo.TxHash, txInfo.Height)
				}
				offset += chainhash.HashSize
			}
		}
		if !flag {
			relevantTxs = append(relevantTxs, rec.Hash[:]...)
			err = putRawRelevantTxs(wtxmgrNs, k, relevantTxs)
			if err != nil {
				return err
			}
		}
	}
	// add this transaction to unminedAbe bucket,and notify the index has spent
	v, err := valueTxRecord(rec)
	if err != nil {
		return err
	}
	err = putRawUnconfirmedTx(wtxmgrNs, rec.Hash[:], v)
	if err != nil {
		return err
	}
	txInfo := &TransactionInfo{
		TxHash: &rec.Hash,
		Height: s.manager.SyncedTo().Height,
	}
	s.NotifyTransactionRollback(txInfo)
	log.Infof("send unconfirmed transaction notification %v at height %d", txInfo.TxHash, txInfo.Height)
	return nil
}

func (s *Store) InsertGenesisBlock(ns walletdb.ReadWriteBucket, block *BlockRecord, addrToVskMap map[string][]byte, coinAddrToInstanceAddr map[string][]byte) error {
	balance, err := fetchMinedBalance(ns)
	if err != nil {
		return err
	}
	spendableBal, err := fetchSpenableBalance(ns)
	if err != nil {
		return err
	}
	immatureCBBal, err := fetchImmatureCoinbaseBalance(ns)
	if err != nil {
		return err
	}
	immatureTRBal, err := fetchImmatureTransferBalance(ns)
	if err != nil {
		return err
	}
	unconfirmedBal, err := fetchUnconfirmedBalance(ns)
	if err != nil {
		return err
	}

	// put the genesis block into database
	err = putBlockRecord(ns, block)
	if err != nil {
		return err
	}
	b := Block{
		Hash:   block.Hash,
		Height: block.Height,
	}
	blockOutputs := make(map[Block][]wire.OutPointAbe) // if the block height meet the requirement, it also store previous two block outputs belong the wallet

	coinbaseTx := block.TxRecords[0].MsgTx
	coinbaseOutput := make(map[wire.OutPointAbe]*UnspentUTXO)
	for i := 0; i < len(coinbaseTx.TxOuts); i++ {
		// TODO: the genesis block is handled when creating a new wallet, so this time the address would be just initial address
		coinAddr, err := abecrypto.ExtractCoinAddressFromTxoScript(coinbaseTx.TxOuts[i].TxoScript, abecryptoparam.CryptoSchemePQRingCT)
		if err != nil {
			return err
		}
		key := hex.EncodeToString(chainhash.DoubleHashB(coinAddr))
		var vskBytes []byte
		var ok bool
		if vskBytes, ok = addrToVskMap[key]; !ok {
			continue
		}
		copyedVskBytes := make([]byte, len(vskBytes))
		copy(copyedVskBytes, vskBytes)
		valid, v, err := abecrypto.TxoCoinReceive(coinbaseTx.TxOuts[i], coinAddrToInstanceAddr[key], copyedVskBytes)
		if err != nil {
			return err
		}
		if valid {
			amt := abeutil.Amount(v)
			log.Infof("(Coinbase) Find my txo at block height %d (hash %s) with value %v", block.Height, block.Hash, amt.ToABE())
			immatureCBBal += amt
			balance += amt
			k := wire.OutPointAbe{
				TxHash: coinbaseTx.TxHash(),
				Index:  uint8(i),
			}
			tmp := NewUnspentUTXO(coinbaseTx.TxOuts[i].Version, b.Height, k, true, v, 255, block.RecvTime, chainhash.ZeroHash, 0)
			coinbaseOutput[k] = tmp
			blockOutputs[b] = append(blockOutputs[b], k)
		}
	}
	if len(blockOutputs) != 0 {
		err := putRawImmaturedCoinbaseOutput(ns, canonicalBlock(block.Height, block.Hash), valueImmaturedCoinbaseOutput(coinbaseOutput))
		if err != nil {
			return err
		}
	}
	if len(blockOutputs) != 0 { //add the block outputs in to bucket block outputs
		// TODO(abe): this process should transfer to byte slices and then append to given
		for blk, ops := range blockOutputs {
			k := canonicalBlock(blk.Height, blk.Hash) // TODO(osy): this process can avoid
			v := make([]byte, 4+len(ops)*(32+1))
			offset := 0
			byteOrder.PutUint32(v[offset:], uint32(len(ops)))
			offset += 4
			for j := 0; j < len(ops); j++ {
				copy(v[offset:], ops[j].TxHash[:])
				offset += 32
				v[offset] = ops[j].Index
				offset += 1
			}
			err := putBlockOutput(ns, k, v)
			if err != nil {
				return err
			}
		}
	}
	// update the balances
	// return handle
	err = putSpenableBalance(ns, spendableBal)
	if err != nil {
		return err
	}
	err = putImmatureCoinbaseBalance(ns, immatureCBBal)
	if err != nil {
		return err
	}
	err = putImmatureTransferBalance(ns, immatureTRBal)
	if err != nil {
		return err
	}
	err = putUnconfirmedBalance(ns, unconfirmedBal)
	if err != nil {
		return err
	}
	return putMinedBalance(ns, balance)
}

func (s *Store) InsertBlock(txMgrNs walletdb.ReadWriteBucket, addrMgrNs walletdb.ReadWriteBucket, block *BlockRecord, extraBlock map[uint32]*BlockRecord, maturedBlockHashs []*chainhash.Hash) error {
	log.Infof("Current sync height %d", block.Height)

	balance, err := fetchMinedBalance(txMgrNs)
	if err != nil {
		return err
	}
	spendableBal, err := fetchSpenableBalance(txMgrNs)
	if err != nil {
		return err
	}
	immatureCBBal, err := fetchImmatureCoinbaseBalance(txMgrNs)
	if err != nil {
		return err
	}
	immatureTRBal, err := fetchImmatureTransferBalance(txMgrNs)
	if err != nil {
		return err
	}
	unconfirmedBal, err := fetchUnconfirmedBalance(txMgrNs)
	if err != nil {
		return err
	}

	// put the serialized block into database
	err = putBlockRecord(txMgrNs, block)
	if err != nil {
		return err
	}

	// delete oldest block in the database
	// It assumes that the deleted block would not be reverted.
	if block.Height > NUMBERBLOCK {
		_, err = deleteRawBlockWithBlockHeight(txMgrNs, block.Height-NUMBERBLOCK)
		if err != nil {
			return err
		}
	}

	b := Block{
		Hash:   block.Hash,
		Height: block.Height,
	}

	coinbaseTx := block.TxRecords[0].MsgTx

	coinbaseOutput := make(map[wire.OutPointAbe]*UnspentUTXO)
	blockOutputs := make(map[Block][]wire.OutPointAbe)

	// store all outputs of coinbaseTx which belong to us into a map : coinbaseOutput
	for i := 0; i < len(coinbaseTx.TxOuts); i++ {
		coinAddr, err := abecrypto.ExtractCoinAddressFromTxoScript(coinbaseTx.TxOuts[i].TxoScript, abecryptoparam.CryptoSchemePQRingCT)
		if err != nil {
			return err
		}
		addressEnc, _, _, valueSecretKeyEnc, err := s.manager.FetchAddressKeyEnc(addrMgrNs, coinAddr)
		if err != nil {
			return err
		}
		addressBytes, _, _, vskBytes, err := s.manager.DecryptAddressKey(addressEnc, nil, nil, valueSecretKeyEnc)
		if err != nil {
			return err
		}
		if vskBytes == nil {
			continue
		}
		copyedVskBytes := make([]byte, len(vskBytes))
		copy(copyedVskBytes, vskBytes)
		valid, v, err := abecrypto.TxoCoinReceive(coinbaseTx.TxOuts[i], addressBytes, copyedVskBytes)
		if err != nil {
			return err
		}
		if valid {
			amt := abeutil.Amount(v)
			log.Infof("(Coinbase) Find my txo at block height %d (hash %s) with value %v", block.Height, block.Hash, amt.ToABE())
			immatureCBBal += amt
			balance += amt
			// TODO: the transaction hash and index cannot be a unique key
			k := wire.OutPointAbe{
				TxHash: coinbaseTx.TxHash(),
				Index:  uint8(i),
			}
			tmp := NewUnspentUTXO(coinbaseTx.TxOuts[i].Version, b.Height, k, true, v, 255, block.RecvTime, chainhash.ZeroHash, 0)
			coinbaseOutput[k] = tmp
			blockOutputs[b] = append(blockOutputs[b], k)
		}
	}

	transferOutputs := make(map[wire.OutPointAbe]*UnspentUTXO) // store the outputs which belong to the wallet
	var blockInputs *RingHashSerialNumbers                     // save the inputs which belong to the wallet spent by this block and store the increment and the utxo ring before adding this block
	relevantUTXORings := make(map[chainhash.Hash]*UTXORing)

	// handle with the transfer transactions
	for i := 1; i < len(block.TxRecords); i++ { // trace every tx in this block
		txi := block.TxRecords[i].MsgTx
		txhash := txi.TxHash()
		// traverse all the inputs of a transaction
		// 1. add serial number to corresponding ring if needed
		// 2. move consumed txo to spentconfirmed bucket
		// TODO:need to check for this section
		trFlag := false
		for j := 0; j < len(txi.TxIns); j++ {
			// compute the ring hash of each input in every transaction to match the utxo in the database
			ringHash := txi.TxIns[j].PreviousOutPointRing.Hash()
			u, ok := relevantUTXORings[ringHash] // firstly, check it exist in relevantUTXORing
			serialNumber := txi.TxIns[j].SerialNumber
			if !ok {
				// TODO(abe):why in the bucket utxo ring, this entry which is keyed by ringHash is not found?
				key, value := existsUTXORing(txMgrNs, ringHash) // if not, check it the bucket
				if value == nil {                               //if not, it means that this input do not belong to wallet
					// if there is no value in utxo ring bucket.
					// the pointed output must not belong to the wallet
					continue
				}
				// if the ring hash exists in the database, fetch the utxo ring
				oldU, err := fetchUTXORing(txMgrNs, key) //get the value from utxoring bucket, it will be one coins of wallet
				// if the utxo ring is nil or the err is not nil, it means that the utxo ring of pointed output has consumed out.
				if oldU == nil || err != nil {
					return err
				}
				// match the serialNumber, just a check for database
				for k := 0; k < len(oldU.GotSerialNumberes); k++ {
					// check doubling serialNumber
					if bytes.Equal(serialNumber, oldU.GotSerialNumberes[k][:]) {
						log.Errorf("There has a same serialNumber in UTXORing")
						return fmt.Errorf("there has a same serialNumber in UTXORing")
					}
				}
				// save the previous utxoring for quick roll back
				if blockInputs == nil {
					blockInputs = new(RingHashSerialNumbers)
					blockInputs.utxoRings = make(map[chainhash.Hash]UTXORing)
					blockInputs.serialNumbers = make(map[chainhash.Hash][][]byte)
				}
				_, ok = blockInputs.utxoRings[ringHash]
				if !ok { // the utxo ring has not cached,record it in block input
					blockInputs.utxoRings[ringHash] = *oldU
				}
				u = oldU.Copy()
			}

			for index, sn := range u.OriginSerialNumberes {
				if bytes.Equal(sn, serialNumber) {
					// it means that the consumed input belongs wallet
					trFlag = true
					// add it's hash to relevant bucket
					k := canonicalOutPointAbe(u.TxHashes[index], u.OutputIndexes[index])
					txiHash := txi.TxHash()
					// read relevant transaction hashes
					relevantTxs := existsRawReleventTxs(txMgrNs, k)
					// check the current transaction is included or not in relevant transaction
					// remove the relevant except current transaction in unconfirmed bucket into invalid transaction bucket
					flag := false
					if len(relevantTxs) != 0 {
						offset := 0
						for offset+chainhash.HashSize <= len(relevantTxs) {
							if bytes.Equal(txiHash[:], relevantTxs[offset:offset+chainhash.HashSize]) {
								// it means that the wallet know the transaction
								flag = true
								offset += chainhash.HashSize
								continue
							}
							conflictTx := existsRawUnconfirmedTx(txMgrNs, relevantTxs[offset:offset+chainhash.HashSize])
							if len(conflictTx) != 0 {
								err = deleteRawUnconfirmedTx(txMgrNs, relevantTxs[offset:offset+chainhash.HashSize])
								if err != nil {
									return err
								}
								err = putRawInvalidTx(txMgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
								if err != nil {
									return err
								}
								txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
								// TODO(202211) send invalid notification to registered client
								s.NotifyTransactionInvalid(&TransactionInfo{
									TxHash: txHash,
									Height: block.Height,
								})
								log.Infof("send invalid transaction notification %v at height %d", txHash, block.Height)
							}
							offset += chainhash.HashSize
						}
					}
					if !flag {
						// add relevant relation: outpoint(txHash,Index) -> TxHash
						relevantTxs = append(relevantTxs, txiHash[:]...)
						err = putRawRelevantTxs(txMgrNs, k, relevantTxs)
						if err != nil {
							return err
						}
					}
					break
				}
			}
			blockInputs.serialNumbers[ringHash] = append(blockInputs.serialNumbers[ringHash], serialNumber)
			// copy a new utxoring and update the new utxoring variable
			err := u.AddGotSerialNumber(serialNumber)
			if err != nil {
				return err
			}

			//update the relevantUTXORing
			relevantUTXORings[ringHash] = u
		}

		// it means current transaction consumes some txo belongs wallet
		// move it from unconfirmed/invalid bucket to confirmed bucket
		if trFlag {
			// delete from unconfirmed transaction set if exist
			if len(existsRawUnconfirmedTx(txMgrNs, txhash[:])) != 0 {
				err = deleteRawUnconfirmedTx(txMgrNs, txhash[:])
				if err != nil {
					return err
				}
			}
			// delete from invalid transaction set if exist
			if len(existsRawInvalidTx(txMgrNs, txhash[:])) != 0 {
				err = deleteRawInvalidTx(txMgrNs, txhash[:])
				if err != nil {
					return err
				}
			}

			// TODO(202211) send confirmed notification to registered client
			// and move to confirmed transaction set
			txRecord, err := NewTxRecordFromMsgTx(&txi, block.RecvTime)
			if err != nil {
				return err
			}
			v, err := valueTxRecord(txRecord)
			if err != nil {
				return err
			}
			err = putRawConfirmedTx(txMgrNs, txhash[:], v)
			if err != nil {
				return err
			}
			txHash := txi.TxHash()
			s.NotifyTransactionAccepted(&TransactionInfo{
				TxHash: &txHash,
				Height: block.Height,
			})
			log.Infof("send confirmed transaction notification %v at height %d", txHash, block.Height)
		}
		// update the utxo ring bucket
		for k, v := range relevantUTXORings {
			//  move relevant utxo from unspentTXO or SpentButUnmined bucket to SpentConfirmTXO
			for t := 0; t < len(v.IsMy); t++ {
				// the outpoint owned by wallet is spent
				// it should be move to spent and confirmed bucket
				if v.IsMy[t] && v.Spent[t] {
					// it means that the transaction related to wallet
					k := canonicalOutPointAbe(v.TxHashes[t], v.OutputIndexes[t])
					// if this transaction is create by the wallet, the outpoint should be stored
					// in spentButUnmined bucket.
					// But if the wallet is restored, the outpoint should be in the matured bucket
					v := existsRawMaturedOutput(txMgrNs, k)
					if v != nil {
						//otherwise it has been moved to spentButUnmined bucket
						// update the balances
						amt := abeutil.Amount(byteOrder.Uint64(v[9:17]))
						balance -= amt
						spendableBal -= amt
						v = append(v, txhash[:]...)
						var confirmTime [8]byte
						byteOrder.PutUint64(confirmTime[:], uint64(block.RecvTime.Unix()))
						v = append(v, confirmTime[:]...) //spentTime
						v = append(v, confirmTime[:]...) // confirm time
						err = deleteMaturedOutput(txMgrNs, k)
						if err != nil {
							return err
						}
					} else {
						v = existsRawSpentButUnminedTXO(txMgrNs, k)
						if v != nil { //otherwise it has been moved to spentButUnmined bucket
							amt := abeutil.Amount(byteOrder.Uint64(v[9:17]))
							balance -= amt
							unconfirmedBal -= amt

							var confirmTime [8]byte
							byteOrder.PutUint64(confirmTime[:], uint64(block.RecvTime.Unix()))
							v = append(v, confirmTime[:]...)
							err = deleteSpentButUnminedTXO(txMgrNs, k)
							if err != nil {
								return err
							}
						}
					}
					// move to spent and confirm bucket
					if v != nil {
						err := putRawSpentConfirmedTXO(txMgrNs, k, v)
						if err != nil {
							return err
						}
					}
				}
			}

			if v.AllSpent {
				// if all outpoints have been spent, so this utxo ring will be deleted,
				// and mark deleted flag in ring bucket
				err := deleteUTXORing(txMgrNs, k[:])
				if err != nil {
					return err
				}
				err = updateDeletedHeightRingDetails(txMgrNs, k[:], block.Height)
				if err != nil {
					return err
				}
				continue
			}
			// if not, update the entry
			err := putRawUTXORing(txMgrNs, k[:], v.Serialize()[:])
			if err != nil {
				return err
			}
		}

		// traverse all outputs of a transaction and check if it is ours
		for j := 0; j < len(txi.TxOuts); j++ {
			coinAddr, err := abecrypto.ExtractCoinAddressFromTxoScript(txi.TxOuts[j].TxoScript, abecryptoparam.CryptoSchemePQRingCT)
			if err != nil {
				return err
			}
			addressEnc, _, _, valueSecretKeyEnc, err := s.manager.FetchAddressKeyEnc(addrMgrNs, coinAddr)
			if err != nil {
				return err
			}
			addressBytes, _, _, vskBytes, err := s.manager.DecryptAddressKey(addressEnc, nil, nil, valueSecretKeyEnc)
			if err != nil {
				return err
			}
			if vskBytes == nil {
				continue
			}
			copyedVskBytes := make([]byte, len(vskBytes))
			copy(copyedVskBytes, vskBytes)
			valid, v, err := abecrypto.TxoCoinReceive(txi.TxOuts[j], addressBytes, copyedVskBytes)
			if err != nil {
				return err
			}
			if valid {
				amt := abeutil.Amount(v)
				log.Infof("(Transfer) Find my txo at block height %d (hash %s) with value %v", block.Height, block.Hash, amt.ToABE())
				immatureTRBal += amt
				balance += amt
				k := wire.OutPointAbe{
					TxHash: txi.TxHash(),
					Index:  uint8(j),
				}
				tmp := NewUnspentUTXO(txi.TxOuts[j].Version, b.Height, k, true, v, 255, block.RecvTime, chainhash.ZeroHash, 0)
				transferOutputs[k] = tmp
				blockOutputs[b] = append(blockOutputs[b], k)
			}
		}
	}

	// store the inputs of block for quick rollback
	if blockInputs != nil {
		k := canonicalBlock(block.Height, block.Hash)
		v := valueBlockInput(blockInputs)
		err = putRawBlockInput(txMgrNs, k, v)
		if err != nil {
			return err
		}
	}

	// store the output of block for quick rollback
	// TODO: there just is a block, so the map:block -> is useless
	if len(blockOutputs) != 0 { //add the block outputs in to bucket block outputs
		// TODO(abe): this process should transfer to byte slices and then append to given
		for blk, ops := range blockOutputs {
			k := canonicalBlock(blk.Height, blk.Hash) // TODO(osy): this process can avoid
			v := make([]byte, 4+len(ops)*(32+1))
			offset := 0
			byteOrder.PutUint32(v[offset:], uint32(len(ops)))
			offset += 4
			for j := 0; j < len(ops); j++ {
				copy(v[offset:], ops[j].TxHash[:])
				offset += 32
				v[offset] = ops[j].Index
				offset += 1
			}
			err := putBlockOutput(txMgrNs, k, v)
			if err != nil {
				return err
			}
		}
	}

	// move matured coinbase outputs to maturedOutput bucket
	blockNum := int32(wire.GetBlockNumPerRingGroupByBlockHeight(block.Height))
	maturity := int32(s.chainParams.CoinbaseMaturity)
	if block.Height >= maturity && (block.Height-maturity+1)%blockNum == 0 {
		for i := 0; i < len(maturedBlockHashs); i++ {
			utxoHeight := block.Height - maturity - int32(i)
			utxos, err := fetchImmaturedCoinbaseOutput(txMgrNs, utxoHeight, *maturedBlockHashs[i])
			if err != nil {
				return err
			}
			for op, utxo := range utxos {
				v := valueUnspentTXO(true, utxo.Version, utxoHeight, utxo.Amount, utxo.Index, utxo.GenerationTime, utxo.RingHash, utxo.RingSize)
				amt := abeutil.Amount(byteOrder.Uint64(v[9:17]))
				spendableBal += amt
				immatureCBBal -= amt
				err = putRawMaturedOutput(txMgrNs, canonicalOutPointAbe(op.TxHash, op.Index), v)
				if err != nil {
					return err
				}
				log.Infof("Coinbase txo at Height %d (Hash %s) , Value %v is matured!", utxo.Height, maturedBlockHashs[i], float64(utxo.Amount)/math.Pow10(7))
			}
			err = deleteImmaturedCoinbaseOutput(txMgrNs, canonicalBlock(utxoHeight, *maturedBlockHashs[i]))
			if err != nil {
				return err
			}
		}

	}

	// fetch the outputs of recent three blocks and form rings
	// move matured transfer outputs of previous two blocks to maturedOutput bucket
	// TODO(abe): check the correctness of generating ring and modify the utxo in bucket unspentUtxo
	if block.Height%blockNum == blockNum-1 {
		var block1CoinbaseUTXO, block1TransferUTXO, block0CoinbaseUTXO, block0TransferUTXO map[wire.OutPointAbe]*UnspentUTXO
		// if the height is match, it need to generate the utxo ring
		// if the number of utxo in previous two block is not zero, take it
		msgBlock2 := block.MsgBlock
		block1Outputs, err := fetchBlockOutput(txMgrNs, block.Height-1, msgBlock2.Header.PrevBlock)
		if err != nil && err.Error() != "the entry is empty" {
			return err
		}
		if block1Outputs != nil {
			block1CoinbaseUTXO, err = fetchImmaturedCoinbaseOutput(txMgrNs, block.Height-1, msgBlock2.Header.PrevBlock)
			if err != nil {
				return err
			}
			block1TransferUTXO, err = fetchImmaturedOutput(txMgrNs, block.Height-1, msgBlock2.Header.PrevBlock)
			if err != nil {
				return err
			}
		}
		_, v := fetchRawBlock(txMgrNs, block.Height-1, msgBlock2.Header.PrevBlock)
		msgBlock1 := new(wire.MsgBlockAbe)
		if v == nil {
			msgBlock1 = &extraBlock[uint32(block.Height-1)].MsgBlock
			err = putBlockRecord(txMgrNs, extraBlock[uint32(block.Height-1)])
			if err != nil {
				return err
			}
			buf := bytes.NewBuffer(make([]byte, 0, msgBlock1.SerializeSize()))
			err := msgBlock1.Serialize(buf)
			if err != nil {
				return err
			}
			v = buf.Bytes()
		}
		err = msgBlock1.DeserializeNoWitness(bytes.NewReader(v))
		if err != nil {
			return err
		}

		block0Outputs, err := fetchBlockOutput(txMgrNs, block.Height-2, msgBlock1.Header.PrevBlock)
		if err != nil && err.Error() != "the entry is empty" {
			return err
		}
		if block0Outputs != nil {
			block0CoinbaseUTXO, err = fetchImmaturedCoinbaseOutput(txMgrNs, block.Height-2, msgBlock1.Header.PrevBlock)
			if err != nil {
				return err
			}
			block0TransferUTXO, err = fetchImmaturedOutput(txMgrNs, block.Height-2, msgBlock1.Header.PrevBlock)
			if err != nil {
				return err
			}
		}

		// if there is zero output in three block belongs to the wallet, we return
		if len(coinbaseOutput) == 0 && len(transferOutputs) == 0 &&
			len(block1CoinbaseUTXO) == 0 && len(block1TransferUTXO) == 0 &&
			len(block0CoinbaseUTXO) == 0 && len(block0TransferUTXO) == 0 {
			// return handle
			err = putSpenableBalance(txMgrNs, spendableBal)
			if err != nil {
				return err
			}
			err = putImmatureCoinbaseBalance(txMgrNs, immatureCBBal)
			if err != nil {
				return err
			}
			err = putImmatureTransferBalance(txMgrNs, immatureTRBal)
			if err != nil {
				return err
			}
			err = putUnconfirmedBalance(txMgrNs, unconfirmedBal)
			if err != nil {
				return err
			}
			return putMinedBalance(txMgrNs, balance)
		}

		// generate the utxoring
		_, v = fetchRawBlock(txMgrNs, block.Height-2, msgBlock1.Header.PrevBlock)
		msgBlock0 := new(wire.MsgBlockAbe)
		if v == nil {
			msgBlock0 = &extraBlock[uint32(block.Height-2)].MsgBlock
			err = putBlockRecord(txMgrNs, extraBlock[uint32(block.Height-2)])
			if err != nil {
				return err
			}
			buf := bytes.NewBuffer(make([]byte, 0, msgBlock0.SerializeSize()))
			err := msgBlock0.Serialize(buf)
			if err != nil {
				return err
			}
			v = buf.Bytes()
		}
		err = msgBlock0.DeserializeNoWitness(bytes.NewReader(v))
		if err != nil {
			return err
		}

		if msgBlock0 == nil || msgBlock1 == nil {
			return fmt.Errorf("newUtxoRingEntries is called with node that does not have 2 previous successive blocks in database")
		}

		block0 := abeutil.NewBlockAbe(msgBlock0) // height % 3 = 0
		block0.SetHeight(block.Height - 2)
		block1 := abeutil.NewBlockAbe(msgBlock1) // height %3 = 1
		block1.SetHeight(block.Height - 1)
		block2 := abeutil.NewBlockAbe(&msgBlock2) // height % 3 = 2
		block2.SetHeight(block.Height)
		blocks := []*abeutil.BlockAbe{block0, block1, block2}
		//ringBlockHeight := blocks[2].Height()
		blocksNum := len(blocks)
		blockHashs := make([]*chainhash.Hash, blocksNum)
		coinBaseRmTxoNum := 0
		transferRmTxoNum := 0
		for i := 0; i < blocksNum; i++ {
			blockHashs[i] = blocks[i].Hash()
			coinBaseRmTxoNum += len(blocks[i].Transactions()[0].MsgTx().TxOuts)
			for _, tx := range blocks[i].Transactions()[1:] {
				transferRmTxoNum += len(tx.MsgTx().TxOuts)
			}
		}
		ringBlockHeight := block.Height
		allCoinBaseRmTxos := make([]*blockchain.RingMemberTxo, 0, coinBaseRmTxoNum)
		allTransferRmTxos := make([]*blockchain.RingMemberTxo, 0, transferRmTxoNum)

		//allCoinBaseRmTxos, allTransferRmTxos := blockchain.NewUTXORingEntriesPreparation(blocks)
		// str = block1.hash, block2.hash, block3.hash, blockhash, txHash, outIndex
		// all Txos are ordered by Hash(str), then grouped into rings
		txoSortStr := make([]byte, blocksNum*chainhash.HashSize+chainhash.HashSize+chainhash.HashSize+1)
		for i := 0; i < blocksNum; i++ {
			copy(txoSortStr[i*chainhash.HashSize:], blocks[i].Hash()[:])
		}

		for i := 0; i < blocksNum; i++ {
			block := blocks[i]
			blockHash := block.Hash()
			blockHeight := block.Height()

			copy(txoSortStr[blocksNum*chainhash.HashSize:], blockHash[:])

			coinBaseTx := block.Transactions()[0]
			txHash := coinBaseTx.Hash()
			copy(txoSortStr[(blocksNum+1)*chainhash.HashSize:], txHash[:])
			for outIndex, txOut := range coinBaseTx.MsgTx().TxOuts {
				txoSortStr[(blocksNum+2)*chainhash.HashSize] = uint8(outIndex)

				txoOrderHash := chainhash.DoubleHashH(txoSortStr)

				ringMemberTxo := blockchain.NewRingMemberTxo(coinBaseTx.MsgTx().Version, &txoOrderHash, blockHash, blockHeight, txHash, uint8(outIndex), txOut)
				allCoinBaseRmTxos = append(allCoinBaseRmTxos, ringMemberTxo)
			}
			for _, tx := range block.Transactions()[1:] {
				txHash := tx.Hash()
				copy(txoSortStr[(blocksNum+1)*chainhash.HashSize:], txHash[:])

				for outIndex, txOut := range tx.MsgTx().TxOuts {
					txoSortStr[(blocksNum+2)*chainhash.HashSize] = uint8(outIndex)

					txoOrderHash := chainhash.DoubleHashH(txoSortStr)

					ringMemberTxo := blockchain.NewRingMemberTxo(tx.MsgTx().Version, &txoOrderHash, blockHash, blockHeight, txHash, uint8(outIndex), txOut)
					allTransferRmTxos = append(allTransferRmTxos, ringMemberTxo)
				}
			}
		}
		//create a view to generate the all rings
		view := blockchain.NewUtxoRingViewpoint()
		err = view.NewUtxoRingEntriesFromTxos(allCoinBaseRmTxos, ringBlockHeight, blockHashs, int(wire.GetTxoRingSizeByBlockHeight(ringBlockHeight)), true)
		if err != nil {
			return err
		}

		err = view.NewUtxoRingEntriesFromTxos(allTransferRmTxos, ringBlockHeight, blockHashs, int(wire.GetTxoRingSizeByBlockHeight(ringBlockHeight)), false)
		if err != nil {
			return err
		}

		willAddUTXORing := make(map[chainhash.Hash]*UTXORing)
		willAddRing := make(map[chainhash.Hash]*Ring)
		for ringHash, utxoRingEntry := range view.Entries() {
			for _, outpoint := range utxoRingEntry.OutPointRing().OutPoints {
				var utxo *UnspentUTXO
				var curMap int
				var ok bool
				if utxo, ok = coinbaseOutput[*outpoint]; ok {
					curMap = 1
				} else if utxo, ok = transferOutputs[*outpoint]; ok {
					curMap = 2
				} else if utxo, ok = block1CoinbaseUTXO[*outpoint]; ok {
					curMap = 3
				} else if utxo, ok = block1TransferUTXO[*outpoint]; ok {
					curMap = 4
				} else if utxo, ok = block0CoinbaseUTXO[*outpoint]; ok {
					curMap = 5
				} else if utxo, ok = block0TransferUTXO[*outpoint]; ok {
					curMap = 6
				}

				if utxo != nil { // this ring has utxo belonging to the wallet
					utxoRing, ok1 := willAddUTXORing[ringHash]
					if !ok1 {
						// add this ring and utxo ring to database
						//generate a ringDetails
						ring := Ring{}
						ring.Version = utxoRingEntry.Version
						outpointRing := utxoRingEntry.OutPointRing()
						for i := 0; i < len(outpointRing.BlockHashs); i++ {
							ring.BlockHashes = append(ring.BlockHashes, *outpointRing.BlockHashs[i])
						}
						for i := 0; i < len(outpointRing.OutPoints); i++ {
							ring.TxHashes = append(ring.TxHashes, outpointRing.OutPoints[i].TxHash)
							ring.Index = append(ring.Index, outpointRing.OutPoints[i].Index)
						}
						txOuts := utxoRingEntry.TxOuts()
						for i := 0; i < len(txOuts); i++ {
							ring.TxoScripts = append(ring.TxoScripts, txOuts[i].TxoScript)
						}

						//generate the utxoring, then add it to wllAddUTXORing for updating
						utxoRing, err = NewUTXORingFromRing(&ring, ringHash)
						if err != nil {
							return err
						}
						willAddUTXORing[ringHash] = utxoRing
						willAddRing[ringHash] = &ring
					}
					utxo.RingHash = ringHash
					utxo.RingSize = uint8(len(utxoRing.TxHashes))
					switch curMap {
					case 1:
						coinbaseOutput[*outpoint] = utxo
					case 2:
						transferOutputs[*outpoint] = utxo
					case 3:
						block1CoinbaseUTXO[*outpoint] = utxo
					case 4:
						block1TransferUTXO[*outpoint] = utxo
					case 5:
						block0CoinbaseUTXO[*outpoint] = utxo
					case 6:
						block0TransferUTXO[*outpoint] = utxo
					default:
						panic("do not know where is from")
					}

					//update the utxo ring
					index := 0
					for ; index < len(utxoRing.TxHashes); index++ {
						if outpoint.TxHash.IsEqual(&utxoRing.TxHashes[index]) &&
							outpoint.Index == utxoRing.OutputIndexes[index] {
							break
						}
					}
					utxo.Index = uint8(index)
					utxoRing.IsMy[index] = true

					// update the serialNumber
					ring := willAddRing[ringHash]
					coinAddr, err := abecrypto.ExtractCoinAddressFromTxoScript(ring.TxoScripts[index], abecryptoparam.CryptoSchemePQRingCT)
					if err != nil {
						return err
					}
					_, _, addressSecretSnEnc, _, err := s.manager.FetchAddressKeyEnc(addrMgrNs, coinAddr)
					if err != nil {
						return err
					}
					_, _, asksn, _, err := s.manager.DecryptAddressKey(nil, nil, addressSecretSnEnc, nil)
					if err != nil {
						return err
					}

					sn, err := abecrypto.TxoCoinSerialNumberGen(&wire.TxOutAbe{
						Version:   ring.Version,
						TxoScript: ring.TxoScripts[index],
					}, utxoRing.RingHash, uint8(index), asksn)
					if err != nil {
						return err
					}
					if utxoRing.OriginSerialNumberes == nil {
						utxoRing.OriginSerialNumberes = make(map[uint8][]byte)
					}
					utxoRing.OriginSerialNumberes[uint8(index)] = sn
				}
			}
		}
		// put the utxo ring into database
		for ringHash, utxoRing := range willAddUTXORing {
			err := putRawUTXORing(txMgrNs, ringHash[:], utxoRing.Serialize()[:])
			if err != nil {
				return err
			}
			// put the ring to coinbase
			err = putRingDetails(txMgrNs, ringHash[:], willAddRing[ringHash].Serialize()[:])
			if err != nil {
				return err
			}
		}

		// coinbase output -> immature
		if len(block1CoinbaseUTXO) != 0 {
			err := putRawImmaturedCoinbaseOutput(txMgrNs, canonicalBlock(block1.Height(), *block1.Hash()), valueImmaturedCoinbaseOutput(block1CoinbaseUTXO))
			if err != nil {
				return err
			}
		}
		if len(block0CoinbaseUTXO) != 0 {
			err := putRawImmaturedCoinbaseOutput(txMgrNs, canonicalBlock(block0.Height(), *block0.Hash()), valueImmaturedCoinbaseOutput(block0CoinbaseUTXO))
			if err != nil {
				return err
			}
		}
		// transfer output -> mature
		for op, utxo := range block1TransferUTXO {
			v := valueUnspentTXO(false, utxo.Version, utxo.Height, utxo.Amount, utxo.Index, utxo.GenerationTime, utxo.RingHash, utxo.RingSize)
			amt := abeutil.Amount(byteOrder.Uint64(v[9:17]))
			spendableBal += amt
			immatureTRBal -= amt
			log.Infof("Transfer txo at Height %d (Hash %s) , Value %v is matured!", utxo.Height, msgBlock1.BlockHash(), float64(utxo.Amount)/math.Pow10(7))
			err = putRawMaturedOutput(txMgrNs, canonicalOutPointAbe(op.TxHash, op.Index), v)
			if err != nil {
				return err
			}
		}
		err = deleteImmaturedOutput(txMgrNs, canonicalBlock(block.Height-1, msgBlock2.Header.PrevBlock))
		if err != nil {
			return err
		}

		for op, utxo := range block0TransferUTXO {
			v := valueUnspentTXO(false, utxo.Version, utxo.Height, utxo.Amount, utxo.Index, utxo.GenerationTime, utxo.RingHash, utxo.RingSize)
			amt := abeutil.Amount(byteOrder.Uint64(v[9:17]))
			spendableBal += amt
			immatureTRBal -= amt
			log.Infof("Transfer txo at Height %d (Hash %s) , Value %v is matured!", utxo.Height, msgBlock0.BlockHash(), float64(utxo.Amount)/math.Pow10(7))
			err = putRawMaturedOutput(txMgrNs, canonicalOutPointAbe(op.TxHash, op.Index), v)
			if err != nil {
				return err
			}
		}
		err = deleteImmaturedOutput(txMgrNs, canonicalBlock(block.Height-2, msgBlock1.Header.PrevBlock))
		if err != nil {
			return err
		}
	}

	// store the coinbase outputs of current block
	if len(coinbaseOutput) != 0 {
		err := putRawImmaturedCoinbaseOutput(txMgrNs, canonicalBlock(block.Height, block.Hash), valueImmaturedCoinbaseOutput(coinbaseOutput))
		if err != nil {
			return err
		}
	}

	// move the matured transfer outputs to maturedOutput bucket
	if block.Height%blockNum == blockNum-1 {
		var newBal uint64 = 0
		if err != nil {
			return err
		}
		for op, utxo := range transferOutputs {
			log.Infof("Transfer txo at Height %d (Hash %s) , Value %v is matured!", utxo.Height, block.Hash, float64(utxo.Amount)/math.Pow10(7))
			v := valueUnspentTXO(false, utxo.Version, utxo.Height, utxo.Amount, utxo.Index, utxo.GenerationTime, utxo.RingHash, utxo.RingSize)
			err = putRawMaturedOutput(txMgrNs, canonicalOutPointAbe(op.TxHash, op.Index), v)
			if err != nil {
				return err
			}
			newBal += utxo.Amount
		}
		amt := abeutil.Amount(newBal)
		spendableBal += amt
		immatureTRBal -= amt
	} else { // immatured
		if len(transferOutputs) != 0 {
			err := putRawImmaturedOutput(txMgrNs, canonicalBlock(block.Height, block.Hash), valueImmaturedOutput(transferOutputs))
			if err != nil {
				return err
			}
		}
	}

	// update the balances
	// return handle
	err = putSpenableBalance(txMgrNs, spendableBal)
	if err != nil {
		return err
	}
	err = putImmatureCoinbaseBalance(txMgrNs, immatureCBBal)
	if err != nil {
		return err
	}
	err = putImmatureTransferBalance(txMgrNs, immatureTRBal)
	if err != nil {
		return err
	}
	err = putUnconfirmedBalance(txMgrNs, unconfirmedBal)
	if err != nil {
		return err
	}
	return putMinedBalance(txMgrNs, balance)
}

// RemoveUnminedTx attempts to remove an unmined transaction from the
// transaction store. This is to be used in the scenario that a transaction
// that we attempt to rebroadcast, turns out to double spend one of our
// existing inputs. This function we remove the conflicting transaction
// identified by the tx record, and also recursively remove all transactions
// that depend on it.

// insertMinedTx inserts a new transaction record for a mined transaction into
// the database under the confirmed bucket. It guarantees that, if the
// tranasction was previously unconfirmed, then it will take care of cleaning up
// the unconfirmed state. All other unconfirmed double spend attempts will be
// removed as well.

// AddCredit marks a transaction record as containing a transaction output
// spendable by wallet.  The output is added unspent, and is marked spent
// when a new transaction spending the output is inserted into the store.
//
// TODO(jrick): This should not be necessary.  Instead, pass the indexes
// that are known to contain credits when a transaction or merkleblock is
// inserted into the store.

// addCredit is an AddCredit helper that runs in an update transaction.  The
// bool return specifies whether the unspent output is newly added (true) or a
// duplicate (false).

// Rollback removes all blocks at height onwards, moving any transactions within
// each block to the unconfirmed pool.

func (s *Store) Rollback(managerAbe *waddrmgr.Manager, waddrmgr walletdb.ReadWriteBucket, wtxmgr walletdb.ReadWriteBucket, height int32) error {
	return s.rollback(managerAbe, waddrmgr, wtxmgr, height)
}

// TODO(abe): we center with block not transaction, because we do not support single transaction
// TODO(abe): need to update the balance in the function.
// TODO(abe):this function need to be test
// we will delete the block after given height in database
func (s *Store) rollback(manager *waddrmgr.Manager, waddrmgrNs walletdb.ReadWriteBucket, wtxmgrNs walletdb.ReadWriteBucket, height int32) error {
	balance, err := fetchMinedBalance(wtxmgrNs)
	if err != nil {
		return err
	}
	spendableBal, err := fetchSpenableBalance(wtxmgrNs)
	if err != nil {
		return err
	}
	immatureCBBal, err := fetchImmatureCoinbaseBalance(wtxmgrNs)
	if err != nil {
		return err
	}
	immatureTRBal, err := fetchImmatureTransferBalance(wtxmgrNs)
	if err != nil {
		return err
	}
	unconfirmedBal, err := fetchUnconfirmedBalance(wtxmgrNs)
	if err != nil {
		return err
	}
	keysWithHeight := make(map[int32][]byte)
	maxHeight := height
	// because we do not know whether the blockIterator works properly,
	// we just use as following:
	blockNum := int32(wire.GetBlockNumPerRingGroupByBlockHeight(height))
	err = wtxmgrNs.NestedReadBucket(bucketBlocks).ForEach(func(k []byte, v []byte) error {
		heightK := int32(byteOrder.Uint32(k[0:4]))
		if heightK >= height-blockNum {
			keysWithHeight[heightK] = k
			if maxHeight < heightK {
				maxHeight = heightK
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	// for all block whose height is more than height
	for i := maxHeight; i > height; i-- {
		willDeleteRingHash := make(map[chainhash.Hash]struct{})

		// modify the ring hash of outputs in previous two blocks if the block is the special height
		blockNumOfRing := int32(wire.GetBlockNumPerRingGroupByBlockHeight(i))
		if i%blockNumOfRing == blockNumOfRing-1 {
			// previous blocks' outputs
			for j := int32(0); j < blockNumOfRing; j++ {
				var blockHash *chainhash.Hash
				var key []byte
				if _, ok := keysWithHeight[i-j]; ok {
					blockHash, err = chainhash.NewHash(keysWithHeight[i-j][4:])
					if err != nil {
						return err
					}
					//  compare database data
					otherblockHash, _ := manager.BlockHash(waddrmgrNs, i-j)
					if !otherblockHash.IsEqual(blockHash) {
						log.Infof("err on database")
					}
					key = keysWithHeight[i-j]
				} else {
					blockHash, err = manager.BlockHash(waddrmgrNs, i-j)
					if err != nil {
						return err
					}
					key = make([]byte, 36)
					byteOrder.PutUint32(key, uint32(i-j))
					copy(key[4:], blockHash[:])
				}

				outpoints, err := fetchBlockOutput(wtxmgrNs, i-j, *blockHash)
				if outpoints == nil {
					continue
				}
				cbOutput, err := fetchImmaturedCoinbaseOutput(wtxmgrNs, i-j, *blockHash)
				if err != nil {
					return err
				}
				trOutput := make(map[wire.OutPointAbe]*UnspentUTXO, len(outpoints))
				for _, outpoint := range outpoints {
					// check in immature coinbase output -> immature coinbase output
					if cbOutput != nil {
						if utxo, ok := cbOutput[*outpoint]; ok {
							tmp, err := chainhash.NewHash(utxo.RingHash[:])
							if err != nil {
								return err
							}
							if _, ok := willDeleteRingHash[*tmp]; !ok {
								willDeleteRingHash[*tmp] = struct{}{}
							}
							utxo.RingHash = chainhash.ZeroHash
							utxo.Index = 0xFF
							continue
						}
					}
					// mature/spendbutunmined/spentandconfirmed output -> immature output
					// check in mature output
					if output, err := fetchMaturedOutput(wtxmgrNs, outpoint.TxHash, outpoint.Index); err == nil {
						amt := abeutil.Amount(output.Amount)
						spendableBal -= amt
						immatureTRBal += amt
						log.Infof("(Rollback) Transfer txo in %d (hash %s) with value %v: spendable -> immature", i-j, blockHash, amt.ToABE())

						tmp, err := chainhash.NewHash(output.RingHash[:])
						if err != nil {
							return err
						}
						if _, ok := willDeleteRingHash[*tmp]; !ok {
							willDeleteRingHash[*tmp] = struct{}{}
						}

						k := canonicalOutPointAbe(outpoint.TxHash, outpoint.Index)
						output.RingHash = chainhash.ZeroHash
						output.Index = 0xFF
						output.RingSize = 0
						// mark the all relevant transaction invalid
						relevantTxs := existsRawReleventTxs(wtxmgrNs, k)
						if len(relevantTxs) != 0 {
							offset := 0
							for offset+chainhash.HashSize <= len(relevantTxs) {
								conflictTx := existsRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
								if len(conflictTx) != 0 {
									err = deleteRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if err != nil {
										return err
									}
									// TODO(202211) send invalid notification to registered client
									err = putRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
									if err != nil {
										return err
									}
									txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
									s.NotifyTransactionInvalid(&TransactionInfo{
										TxHash: txHash,
										Height: i,
									})
									log.Infof("send invalid transaction notification %v at height %d", txHash, i)
								}
								offset += chainhash.HashSize
							}
						}
						err = deleteMaturedOutput(wtxmgrNs, k)
						if err != nil {
							return err
						}
						trOutput[*outpoint] = output
						continue
					}
					// check in spend but unmined output
					if output, err := fetchSpentButUnminedTXO(wtxmgrNs, outpoint.TxHash, outpoint.Index); err == nil {
						amt := abeutil.Amount(output.Amount)
						unconfirmedBal -= amt
						immatureTRBal += amt
						log.Infof("(Rollback) Transfer txo in %d (hash %s) with value %v: spent but unmined -> immature", i-j, blockHash, amt.ToABE())

						tmp, err := chainhash.NewHash(output.RingHash[:])
						if err != nil {
							return err
						}
						if _, ok := willDeleteRingHash[*tmp]; !ok {
							willDeleteRingHash[*tmp] = struct{}{}
						}

						k := canonicalOutPointAbe(outpoint.TxHash, outpoint.Index)
						output.RingHash = chainhash.ZeroHash
						output.Index = 0xFF
						output.RingSize = 0
						// mark the all relevant transaction invalid
						relevantTxs := existsRawReleventTxs(wtxmgrNs, k)
						if len(relevantTxs) != 0 {
							offset := 0
							for offset+chainhash.HashSize <= len(relevantTxs) {
								conflictTx := existsRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
								if len(conflictTx) != 0 {
									err = deleteRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if err != nil {
										return err
									}
									// TODO(202211) send invalid notification to registered client
									err = putRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
									if err != nil {
										return err
									}
									txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
									s.NotifyTransactionInvalid(&TransactionInfo{
										TxHash: txHash,
										Height: i,
									})
									log.Infof("send invalid transaction notification %v at height %d", txHash, i)

								}
								offset += chainhash.HashSize
							}
						}
						err = deleteSpentButUnminedTXO(wtxmgrNs, k)
						if err != nil {
							return err
						}
						trOutput[*outpoint] = &UnspentUTXO{
							Version:        output.Version,
							Height:         output.Height,
							TxOutput:       output.TxOutput,
							FromCoinBase:   output.FromCoinBase,
							Amount:         output.Amount,
							Index:          output.Index,
							GenerationTime: output.GenerationTime,
							RingHash:       output.RingHash,
							RingSize:       output.RingSize,
						}
						continue
					}
					// check in spent and mined output
					if output, err := fetchSpentConfirmedTXO(wtxmgrNs, outpoint.TxHash, outpoint.Index); err == nil {
						amt := abeutil.Amount(output.Amount)
						immatureTRBal += amt
						balance += amt
						log.Infof("(Rollback) Transfer txo in %d (hash %s) with value %v: spent and minded -> immature", i-j, blockHash, amt.ToABE())

						tmp, err := chainhash.NewHash(output.RingHash[:])
						if err != nil {
							return err
						}
						if _, ok := willDeleteRingHash[*tmp]; !ok {
							willDeleteRingHash[*tmp] = struct{}{}
						}

						k := canonicalOutPointAbe(outpoint.TxHash, outpoint.Index)
						output.RingHash = chainhash.ZeroHash
						output.Index = 0xFF
						output.RingSize = 0
						// mark the all relevant transaction invalid
						relevantTxs := existsRawReleventTxs(wtxmgrNs, k)
						if len(relevantTxs) != 0 {
							offset := 0
							for offset+chainhash.HashSize <= len(relevantTxs) {
								conflictTx := existsRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
								if len(conflictTx) != 0 {
									err = deleteRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if err != nil {
										return err
									}
									// TODO(202211) send invalid notification to registered client
									err = putRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
									if err != nil {
										return err
									}
									txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
									s.NotifyTransactionInvalid(&TransactionInfo{
										TxHash: txHash,
										Height: i,
									})
									log.Infof("send invalid transaction notification %v at height %d", txHash, i)
								}
								conflictTx = existsRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
								if len(conflictTx) != 0 {
									err = deleteRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if err != nil {
										return err
									}
									// TODO(202211) send invalid notification to registered client
									err = putRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
									if err != nil {
										return err
									}
									txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
									s.NotifyTransactionInvalid(&TransactionInfo{
										TxHash: txHash,
										Height: i,
									})
									log.Infof("send invalid transaction notification %v at height %d", txHash, i)
								}
								offset += chainhash.HashSize
							}
						}
						err = deleteSpentConfirmedTXO(wtxmgrNs, k)
						if err != nil {
							return err
						}
						trOutput[*outpoint] = &UnspentUTXO{
							Version:        output.Version,
							Height:         output.Height,
							TxOutput:       output.TxOutput,
							FromCoinBase:   output.FromCoinBase,
							Amount:         output.Amount,
							Index:          output.Index,
							GenerationTime: output.GenerationTime,
							RingHash:       output.RingHash,
							RingSize:       output.RingSize,
						}
					} else {
						// something error in database
						log.Errorf("rollback wrong in height %d with outpoint %s:%d", i, outpoint.TxHash, outpoint.Index)
					}
				}
				err = putRawImmaturedCoinbaseOutput(wtxmgrNs, key, valueImmaturedCoinbaseOutput(cbOutput))
				if err != nil {
					return err
				}
				err = putRawImmaturedOutput(wtxmgrNs, key, valueImmaturedCoinbaseOutput(trOutput))
				if err != nil {
					return err
				}
			}
		}

		//delete the utxoring and the ring
		for hash, _ := range willDeleteRingHash {
			err := deleteUTXORing(wtxmgrNs, hash[:])
			if err != nil {
				return fmt.Errorf("error in deleteUTXORing in rollbackAbe: %v", err)
			}
			err = deleteRingDetails(wtxmgrNs, hash[:]) //delete the ring detail when delete the utxo ring in rollback
			if err != nil {
				return fmt.Errorf("error in deleteRingDetail in rollbackAbe: %v", err)
			}
		}

		// fetch all output in current block, and delete it
		// When the block height hit the condition, the output would be in Immature Bucket base on above operation

		var blockHash *chainhash.Hash
		if _, ok := keysWithHeight[i]; ok {
			blockHash, err = chainhash.NewHash(keysWithHeight[i][4:])
			if err != nil {
				return err
			}
			//  compare database data
			otherblockHash, _ := manager.BlockHash(waddrmgrNs, i)
			if !otherblockHash.IsEqual(blockHash) {
				log.Infof("err on database")
			}
		} else {
			blockHash, err = manager.BlockHash(waddrmgrNs, i)
			if err != nil {
				return err
			}
		}
		coinbaseOutputs, err := fetchImmaturedCoinbaseOutput(wtxmgrNs, i, *blockHash)
		if err == nil && coinbaseOutputs != nil {
			for _, unspentUTXO := range coinbaseOutputs {
				amt := abeutil.Amount(unspentUTXO.Amount)
				immatureCBBal -= amt
				balance -= amt
				log.Infof("(Rollback) Coinbase txo in %d (hash %s) with value %v: immature -> null", i, blockHash, amt.ToABE())
			}
			err = deleteImmaturedCoinbaseOutput(wtxmgrNs, keysWithHeight[i])
			if err != nil {
				return fmt.Errorf("error in deleteImmaturedCoinbaseOutput in rollback")
			}
		}
		transferOutputs, err := fetchImmaturedOutput(wtxmgrNs, i, *blockHash)
		if err == nil && transferOutputs != nil {
			for _, unspentUTXO := range transferOutputs {
				amt := abeutil.Amount(unspentUTXO.Amount)
				immatureTRBal -= amt
				balance -= amt
				log.Infof("(Rollback) Transfer txo in %d (hash %s) with value %v: immature -> null", i, blockHash, amt.ToABE())
				// TODO(abe) 20220728 whether remove all transaction whose inputs contains this output or not?
				// when the output is removed from wallet.
			}
			err = deleteImmaturedOutput(wtxmgrNs, keysWithHeight[i])
			if err != nil {
				return fmt.Errorf("error in deleteImmaturedOutput in rollback")
			}
		}

		// restore the input in block
		utxoRings, ss, err := fetchBlockInput(wtxmgrNs, keysWithHeight[i]) //there should be fetch the byte not the utxoRing
		for j := 0; j < len(utxoRings); j++ {
			u, err := fetchUTXORing(wtxmgrNs, utxoRings[j].RingHash[:])
			if err != nil {
				// if the utxo ring do not exist in utxoring bucket, it means that the utxoring is delete when processing this block
				// restore the outputs deleted when attaching this block
				for k := 0; k < len(utxoRings[j].IsMy); k++ {
					if utxoRings[j].IsMy[k] && !utxoRings[j].Spent[k] { // is my but not spend
						key := canonicalOutPointAbe(utxoRings[j].TxHashes[k], utxoRings[j].OutputIndexes[k])
						scoutput, err := fetchSpentConfirmedTXO(wtxmgrNs, utxoRings[j].TxHashes[k], utxoRings[j].OutputIndexes[k])
						err = putRawMaturedOutput(wtxmgrNs, key, valueUnspentTXO(scoutput.FromCoinBase, scoutput.Version, scoutput.Height, scoutput.Amount, scoutput.Index, scoutput.GenerationTime, scoutput.RingHash, scoutput.RingSize))
						if err != nil {
							return err
						}
						amt := abeutil.Amount(scoutput.Amount)
						spendableBal += amt
						balance += amt
						if scoutput.FromCoinBase {
							log.Infof("(Rollback) Spent coinbase txo in %d (hash %s) with value %v: -> spendable", i, blockHash, amt.ToABE())
						} else {
							log.Infof("(Rollback) Spent transfer txo in %d (hash %s) with value %v: -> spendable", i, blockHash, amt.ToABE())
						}
						outpint := canonicalOutPointAbe(scoutput.TxOutput.TxHash, scoutput.TxOutput.Index)
						// mark the all relevant transaction invalid
						relevantTxs := existsRawReleventTxs(wtxmgrNs, outpint)
						if len(relevantTxs) != 0 {
							offset := 0
							for offset+chainhash.HashSize <= len(relevantTxs) {
								conflictTx := existsRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
								if len(conflictTx) != 0 {
									err = deleteRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if err != nil {
										return err
									}
									// TODO(202211) send unconfirmed notification to registered client
									err = putRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
									if err != nil {
										return err
									}
									txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
									s.NotifyTransactionRollback(&TransactionInfo{
										TxHash: txHash,
										Height: i,
									})
									log.Infof("send unconfirmed transaction notification %v at height %d", txHash, i)
								}
								conflictTx = existsRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
								if len(conflictTx) != 0 {
									err = deleteRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if err != nil {
										return err
									}
									// TODO(202211) send unconfirmed notification to registered client
									err = putRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
									if err != nil {
										return err
									}
									txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
									s.NotifyTransactionRollback(&TransactionInfo{
										TxHash: txHash,
										Height: i,
									})
									log.Infof("send unconfirmed transaction notification %v at height %d", txHash, i)
								}
								offset += chainhash.HashSize
							}
						}
						err = deleteSpentConfirmedTXO(wtxmgrNs, key)
						if err != nil {
							return err
						}
					}
				}
			} else {
				// compare the delta and update the utxo ring entry
				for k := 0; k < len(ss[j]); k++ {
					for m, sn := range u.OriginSerialNumberes {
						if bytes.Equal(sn, ss[j][k]) && utxoRings[j].IsMy[m] && !utxoRings[j].Spent[m] {
							key := canonicalOutPointAbe(utxoRings[j].TxHashes[m], utxoRings[j].OutputIndexes[m])
							scoutput, err := fetchSpentConfirmedTXO(wtxmgrNs, utxoRings[j].TxHashes[m], utxoRings[j].OutputIndexes[m])
							err = putRawMaturedOutput(wtxmgrNs, key, valueUnspentTXO(scoutput.FromCoinBase, scoutput.Version, scoutput.Height, scoutput.Amount, scoutput.Index, scoutput.GenerationTime, scoutput.RingHash, scoutput.RingSize))
							if err != nil {
								return err
							}
							amt := abeutil.Amount(scoutput.Amount)
							spendableBal += amt
							balance += amt
							if scoutput.FromCoinBase {
								log.Infof("(Rollback) Coinbase txo spent in %d (hash %s) with value %v: -> spendable", i, blockHash, amt.ToABE())
							} else {
								log.Infof("(Rollback) Transfer txo spent in %d (hash %s) with value %v: -> spendable", i, blockHash, amt.ToABE())
							}
							outpint := canonicalOutPointAbe(scoutput.TxOutput.TxHash, scoutput.TxOutput.Index)
							// mark the all relevant transaction invalid
							relevantTxs := existsRawReleventTxs(wtxmgrNs, outpint)
							if len(relevantTxs) != 0 {
								offset := 0
								for offset+chainhash.HashSize <= len(relevantTxs) {
									conflictTx := existsRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if len(conflictTx) != 0 {
										err = deleteRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
										if err != nil {
											return err
										}
										// TODO(202211) send unconfirmed notification to registered client
										err = putRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
										if err != nil {
											return err
										}
										txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
										s.NotifyTransactionRollback(&TransactionInfo{
											TxHash: txHash,
											Height: i,
										})
										log.Infof("send unconfirmed transaction notification %v at height %d", txHash, i)
									}
									conflictTx = existsRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if len(conflictTx) != 0 {
										err = deleteRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
										if err != nil {
											return err
										}
										// TODO(202211) send unconfirmed notification to registered client
										err = putRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
										if err != nil {
											return err
										}
										txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
										s.NotifyTransactionRollback(&TransactionInfo{
											TxHash: txHash,
											Height: i,
										})
										log.Infof("send unconfirmed transaction notification %v at height %d", txHash, i)
									}
									offset += chainhash.HashSize
								}
							}
							err = deleteSpentConfirmedTXO(wtxmgrNs, key)
							if err != nil {
								return err
							}
							break
						}
					}
				}
			}
			err = putRawUTXORing(wtxmgrNs, utxoRings[j].RingHash[:], utxoRings[j].Serialize()[:])
			if err != nil {
				return err
			}
		}
		//delete the block
		_, err = deleteRawBlockWithBlockHeight(wtxmgrNs, i)
		if err != nil {
			return fmt.Errorf("deleteRawBlockWithBlockHeight in rollback with err:%v", err)
		}

		// immature coinbase outputs if exist
		maturity := int32(s.chainParams.CoinbaseMaturity)
		if i >= maturity && (i-maturity+1)%blockNum == 0 {
			for ii := int32(0); ii < blockNum; ii++ {
				key, outpoints, err := fetchBlockOutputWithHeight(wtxmgrNs, i-maturity-ii)
				if err != nil {
					return err
				}
				if key == nil || outpoints == nil {
					continue
				}
				currentBlockHash, err := chainhash.NewHash(key[4:36])
				if err != nil {
					return err
				}
				cbOutput := make(map[wire.OutPointAbe]*UnspentUTXO, len(outpoints))
				for _, outpoint := range outpoints {
					// check in mature output
					if output, err := fetchMaturedOutput(wtxmgrNs, outpoint.TxHash, outpoint.Index); err == nil && output.FromCoinBase {
						amt := abeutil.Amount(output.Amount)
						spendableBal -= amt
						immatureCBBal += amt
						log.Infof("(Rollback) Coinbase txo in %d (hash %s) with value %v: spendable -> immature", i-maturity-ii, currentBlockHash, amt.ToABE())
						outpint := canonicalOutPointAbe(output.TxOutput.TxHash, output.TxOutput.Index)
						// mark the all relevant transaction invalid
						relevantTxs := existsRawReleventTxs(wtxmgrNs, outpint)
						if len(relevantTxs) != 0 {
							offset := 0
							for offset+chainhash.HashSize <= len(relevantTxs) {
								conflictTx := existsRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
								if len(conflictTx) != 0 {
									err = deleteRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if err != nil {
										return err
									}
									// TODO(202211) send invalid notification to registered client
									err = putRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
									if err != nil {
										return err
									}
									txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
									s.NotifyTransactionInvalid(&TransactionInfo{
										TxHash: txHash,
										Height: i,
									})
									log.Infof("send invalid transaction notification %v at height %d", txHash, i)
								}
								conflictTx = existsRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
								if len(conflictTx) != 0 {
									err = deleteRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if err != nil {
										return err
									}
									// TODO(202211) send invalid notification to registered client
									err = putRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
									if err != nil {
										return err
									}
									txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
									s.NotifyTransactionInvalid(&TransactionInfo{
										TxHash: txHash,
										Height: i,
									})
									log.Infof("send invalid transaction notification %v at height %d", txHash, i)
								}
								offset += chainhash.HashSize
							}
						}
						err = deleteMaturedOutput(wtxmgrNs, canonicalOutPointAbe(outpoint.TxHash, outpoint.Index))
						if err != nil {
							return err
						}
						cbOutput[*outpoint] = output
						continue
					}
					// check in spend but unmined output
					if output, err := fetchSpentButUnminedTXO(wtxmgrNs, outpoint.TxHash, outpoint.Index); err == nil && output.FromCoinBase {
						amt := abeutil.Amount(output.Amount)
						unconfirmedBal -= amt
						immatureCBBal += amt
						log.Infof("(Rollback) Coinbase txo in %d (hash %s) with value %v: spent but unmined -> immature", i-maturity-ii, currentBlockHash, amt.ToABE())

						outpint := canonicalOutPointAbe(output.TxOutput.TxHash, output.TxOutput.Index)
						// mark the all relevant transaction invalid
						relevantTxs := existsRawReleventTxs(wtxmgrNs, outpint)
						if len(relevantTxs) != 0 {
							offset := 0
							for offset+chainhash.HashSize <= len(relevantTxs) {
								conflictTx := existsRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
								if len(conflictTx) != 0 {
									err = deleteRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if err != nil {
										return err
									}
									// TODO(202211) send invalid notification to registered client
									err = putRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
									if err != nil {
										return err
									}
									txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
									s.NotifyTransactionInvalid(&TransactionInfo{
										TxHash: txHash,
										Height: i,
									})
									log.Infof("send invalid transaction notification %v at height %d", txHash, i)
								}
								conflictTx = existsRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
								if len(conflictTx) != 0 {
									err = deleteRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if err != nil {
										return err
									}
									// TODO(202211) send invalid notification to registered client
									err = putRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
									if err != nil {
										return err
									}
									txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
									s.NotifyTransactionInvalid(&TransactionInfo{
										TxHash: txHash,
										Height: i,
									})
									log.Infof("send invalid transaction notification %v at height %d", txHash, i)
								}
								offset += chainhash.HashSize
							}
						}
						err = deleteSpentButUnminedTXO(wtxmgrNs, canonicalOutPointAbe(outpoint.TxHash, outpoint.Index))
						if err != nil {
							return err
						}
						cbOutput[*outpoint] = &UnspentUTXO{
							Version:        output.Version,
							Height:         output.Height,
							TxOutput:       output.TxOutput,
							FromCoinBase:   output.FromCoinBase,
							Amount:         output.Amount,
							Index:          output.Index,
							GenerationTime: output.GenerationTime,
							RingHash:       output.RingHash,
							RingSize:       output.RingSize,
						}
						continue
					}
					// check in spent and mined output
					if output, err := fetchSpentConfirmedTXO(wtxmgrNs, outpoint.TxHash, outpoint.Index); err == nil && output.FromCoinBase {
						amt := abeutil.Amount(output.Amount)
						unconfirmedBal += amt
						balance += amt
						log.Infof("(Rollback) Coinbase txo in %d (hash %s) with value %v: spent -> unconfirmed", i-maturity-ii, currentBlockHash, amt.ToABE())
						outpint := canonicalOutPointAbe(output.TxOutput.TxHash, output.TxOutput.Index)
						// mark the all relevant transaction invalid
						relevantTxs := existsRawReleventTxs(wtxmgrNs, outpint)
						if len(relevantTxs) != 0 {
							offset := 0
							for offset+chainhash.HashSize <= len(relevantTxs) {
								conflictTx := existsRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
								if len(conflictTx) != 0 {
									err = deleteRawUnconfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if err != nil {
										return err
									}
									// TODO(202211) send invalid notification to registered client
									err = putRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
									if err != nil {
										return err
									}
									txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
									s.NotifyTransactionInvalid(&TransactionInfo{
										TxHash: txHash,
										Height: i,
									})
									log.Infof("send invalid transaction notification %v at height %d", txHash, i)
								}
								conflictTx = existsRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
								if len(conflictTx) != 0 {
									err = deleteRawConfirmedTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize])
									if err != nil {
										return err
									}
									// TODO(202211) send invalid notification to registered client
									err = putRawInvalidTx(wtxmgrNs, relevantTxs[offset:offset+chainhash.HashSize], conflictTx)
									if err != nil {
										return err
									}
									txHash, _ := chainhash.NewHash(relevantTxs[offset : offset+chainhash.HashSize])
									s.NotifyTransactionInvalid(&TransactionInfo{
										TxHash: txHash,
										Height: i,
									})
									log.Infof("send invalid transaction notification %v at height %d", txHash, i)
								}
								offset += chainhash.HashSize
							}
						}
						err = deleteSpentConfirmedTXO(wtxmgrNs, canonicalOutPointAbe(outpoint.TxHash, outpoint.Index))
						if err != nil {
							return err
						}
						cbOutput[*outpoint] = &UnspentUTXO{
							Version:        output.Version,
							Height:         output.Height,
							TxOutput:       output.TxOutput,
							FromCoinBase:   output.FromCoinBase,
							Amount:         output.Amount,
							Index:          output.Index,
							GenerationTime: output.GenerationTime,
							RingHash:       output.RingHash,
							RingSize:       output.RingSize,
						}
						continue
					}
				}
				err = putRawImmaturedCoinbaseOutput(wtxmgrNs, key, valueImmaturedCoinbaseOutput(cbOutput))
				if err != nil {
					return err
				}
			}
		}
	}

	// update the balances
	err = putSpenableBalance(wtxmgrNs, spendableBal)
	if err != nil {
		return err
	}
	err = putImmatureCoinbaseBalance(wtxmgrNs, immatureCBBal)
	if err != nil {
		return err
	}
	err = putImmatureTransferBalance(wtxmgrNs, immatureTRBal)
	if err != nil {
		return err
	}
	err = putUnconfirmedBalance(wtxmgrNs, unconfirmedBal)
	if err != nil {
		return err
	}
	return putMinedBalance(wtxmgrNs, balance)
}

// UnspentOutputs returns all unspent received transaction outputs.
// The order is undefined.
func (s *Store) UnmaturedOutputs(ns walletdb.ReadBucket) ([]UnspentUTXO, error) {
	unmatureds := make([]UnspentUTXO, 0)

	// block height block hash -> []Unspent
	err := ns.NestedReadBucket(bucketImmaturedCoinbaseOutput).ForEach(func(_, v []byte) error {
		op := make(map[wire.OutPointAbe]*UnspentUTXO)
		offset := 0
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
		for _, ust := range op {
			unmatureds = append(unmatureds, *ust)
		}
		return nil
	})
	if err != nil {
		if _, ok := err.(Error); ok {
			return nil, err
		}
		str := "failed iterating unspent bucket"
		return nil, storeError(ErrDatabase, str, err)
	}
	err = ns.NestedReadBucket(bucketImmaturedOutput).ForEach(func(k, v []byte) error {
		op := make(map[wire.OutPointAbe]*UnspentUTXO)
		offset := 0
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
		for _, ust := range op {
			unmatureds = append(unmatureds, *ust)
		}
		return nil
	})
	if err != nil {
		if _, ok := err.(Error); ok {
			return nil, err
		}
		str := "failed iterating unspent bucket"
		return nil, storeError(ErrDatabase, str, err)
	}

	//	todo(ABE): For ABE, only the Txos confirmed by blocks and contained in some ring are spentable.
	return unmatureds, nil
}
func (s *Store) SpentAndMinedOutputs(ns walletdb.ReadBucket) ([]SpentConfirmedTXO, error) {
	samtxos := make([]SpentConfirmedTXO, 0)

	var op wire.OutPointAbe
	//var block BlockAbe
	err := ns.NestedReadBucket(bucketSpentConfirmed).ForEach(func(k, v []byte) error {
		err := readCanonicalOutPointAbe(k, &op)
		if err != nil {
			return err
		}
		sct := new(SpentConfirmedTXO)
		hash, err := chainhash.NewHash(k[:32])
		if err != nil {
			return err
		}
		sct.TxOutput.TxHash = *hash
		sct.TxOutput.Index = k[32]
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
		sct.Amount = uint64(byteOrder.Uint64(v[offset : offset+8]))
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
		samtxos = append(samtxos, *sct)
		return nil
	})
	if err != nil {
		if _, ok := err.(Error); ok {
			return nil, err
		}
		str := "failed iterating unspent bucket"
		return nil, storeError(ErrDatabase, str, err)
	}

	//	todo(ABE): For ABE, only the Txos confirmed by blocks and contained in some ring are spentable.
	return samtxos, nil
}
func (s *Store) SpentButUnminedOutputs(ns walletdb.ReadBucket) ([]SpentButUnminedTXO, error) {
	sbutxos := make([]SpentButUnminedTXO, 0)

	var op wire.OutPointAbe
	//var block BlockAbe
	err := ns.NestedReadBucket(bucketSpentButUnmined).ForEach(func(k, v []byte) error {
		err := readCanonicalOutPointAbe(k, &op)
		if err != nil {
			return err
		}
		sbu := new(SpentButUnminedTXO)
		hash, err := chainhash.NewHash(k[:32])
		if err != nil {
			return err
		}
		sbu.TxOutput.TxHash = *hash
		sbu.TxOutput.Index = k[32]
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
		sbutxos = append(sbutxos, *sbu)
		return nil
	})
	if err != nil {
		if _, ok := err.(Error); ok {
			return nil, err
		}
		str := "failed iterating unspent bucket"
		return nil, storeError(ErrDatabase, str, err)
	}

	//	todo(ABE): For ABE, only the Txos confirmed by blocks and contained in some ring are spentable.
	return sbutxos, nil
}
func (s *Store) UnspentOutputs(ns walletdb.ReadBucket) ([]UnspentUTXO, error) {
	unspent := make([]UnspentUTXO, 0)

	var op wire.OutPointAbe
	//var block BlockAbe
	err := ns.NestedReadBucket(bucketMaturedOutput).ForEach(func(k, v []byte) error {

		err := readCanonicalOutPointAbe(k, &op)
		if err != nil {
			return err
		}
		ust := new(UnspentUTXO)
		err = ust.Deserialize(&op, v)
		if err != nil {
			return err
		}
		unspent = append(unspent, *ust)
		return nil
		//	todo(ABE): what happens when a TXO is spent and confirmed by a block?
		//if existsRawUnminedInput(ns, k) != nil {
		//	// Output is spent by an unmined transaction.
		//	// Skip this k/v pair.
		//	return nil
		//}

		//err = readCanonicalBlock(k, &block)
		//if err != nil {
		//	return err
		//}

		//blockTime, err := fetchBlockTime(ns, block.Height)
		//if err != nil {
		//	return err
		//}
		// TODO(jrick): reading the entire transaction should
		// be avoidable.  Creating the credit only requires the
		// output amount and pkScript.
		//	todo(ABE): Agreed on that Creating the credit only requires the output amount and pkScript.
		//	todo(ABE): The wallet database should be TXO-centric.
		//rec, err := fetchTxRecord(ns, &op.TxHash, &block)
		//if err != nil {
		//	return fmt.Errorf("unable to retrieve transaction %v: "+
		//		"%v", op.Hash, err)
		//}
		//txOut := rec.MsgTx.TxOut[op.Index]
		//ust := UnspentUTXO{
		//	Height:         -1,
		//	TxOutput:       op,
		//	FromCoinBase:   false,
		//	Amount:         0,
		//	GenerationTime: time.Time{},
		//	RingHash:       chainhash.Hash{},
		//}
		//TODO(abe): provided a function to deserialize the unspent output
		//offset := 0
		//ust.Height = int32(byteOrder.Uint32(v[offset : offset+4]))
		//offset += 4
		//t := v[offset]
		//offset += 1
		//if t == 0 {
		//	ust.FromCoinBase = false
		//} else {
		//	ust.FromCoinBase = true
		//}
		//ust.Amount = int64(byteOrder.Uint64(v[offset : offset+8]))
		//offset += 8
		//ust.GenerationTime = time.Unix(int64(byteOrder.Uint64(v[offset:offset+8])), 0)
		//offset += 8
		//copy(ust.RingHash[:], v[offset:offset+32])
		//offset += 32
		//if !ust.RingHash.IsEqual(&chainhash.ZeroHash) {
		//	unspent = append(unspent, ust)
		//}
		//return nil
	})
	if err != nil {
		if _, ok := err.(Error); ok {
			return nil, err
		}
		str := "failed iterating unspent bucket"
		return nil, storeError(ErrDatabase, str, err)
	}

	//	todo(ABE): For ABE, only the Txos confirmed by blocks and contained in some ring are spentable.
	return unspent, nil
}

// Balance returns the spendable wallet balance (total value of all unspent
// transaction outputs) given a minimum of minConf confirmations, calculated
// at a current chain height of curHeight.  Coinbase outputs are only included
// in the balance if maturity has been reached.
//
// Balance may return unexpected results if syncHeight is lower than the block
// height of the most recent mined transaction in the store.

func (s *Store) Balance(ns walletdb.ReadBucket, minConf int32, syncHeight int32) ([]abeutil.Amount, error) {
	allBal, err := fetchMinedBalance(ns)
	if err != nil {
		return []abeutil.Amount{}, err
	}
	spendableBal, err := fetchSpenableBalance(ns)
	if err != nil {
		return []abeutil.Amount{}, err
	}
	immatureCBBal, err := fetchImmatureCoinbaseBalance(ns)
	if err != nil {
		return []abeutil.Amount{}, err
	}
	immatureTRBal, err := fetchImmatureTransferBalance(ns)
	if err != nil {
		return []abeutil.Amount{}, err
	}
	unconfirmdBal, err := fetchUnconfirmedBalance(ns)
	if err != nil {
		return []abeutil.Amount{}, err
	}
	return []abeutil.Amount{allBal, spendableBal, immatureCBBal, immatureTRBal, unconfirmdBal}, nil
}

// PutTxLabel validates transaction labels and writes them to disk if they
// are non-zero and within the label length limit. The entry is keyed by the
// transaction hash:
// [0:32] Transaction hash (32 bytes)
//
// The label itself is written to disk in length value format:
// [0:2] Label length
// [2: +len] Label
func (s *Store) PutTxLabel(ns walletdb.ReadWriteBucket, txid chainhash.Hash,
	label string) error {

	if len(label) == 0 {
		return ErrEmptyLabel
	}

	if len(label) > TxLabelLimit {
		return ErrLabelTooLong
	}

	labelBucket, err := ns.CreateBucketIfNotExists(bucketTxLabels)
	if err != nil {
		return err
	}

	return PutTxLabel(labelBucket, txid, label)
}

// PutTxLabel writes a label for a tx to the bucket provided. Note that it does
// not perform any validation on the label provided, or check whether there is
// an existing label for the txid.
func PutTxLabel(labelBucket walletdb.ReadWriteBucket, txid chainhash.Hash,
	label string) error {

	// We expect the label length to be limited on creation, so we can
	// store the label's length as a uint16.
	labelLen := uint16(len(label))

	var buf bytes.Buffer

	var b [2]byte
	binary.BigEndian.PutUint16(b[:], labelLen)
	if _, err := buf.Write(b[:]); err != nil {
		return err
	}

	if _, err := buf.WriteString(label); err != nil {
		return err
	}

	return labelBucket.Put(txid[:], buf.Bytes())
}

// FetchTxLabel reads a transaction label from the tx labels bucket. If a label
// with 0 length was written, we return an error, since this is unexpected.
func FetchTxLabel(ns walletdb.ReadBucket, txid chainhash.Hash) (string, error) {
	labelBucket := ns.NestedReadBucket(bucketTxLabels)
	if labelBucket == nil {
		return "", ErrNoLabelBucket
	}

	v := labelBucket.Get(txid[:])
	if v == nil {
		return "", ErrTxLabelNotFound
	}

	return DeserializeLabel(v)
}

// DeserializeLabel reads a deserializes a length-value encoded label from the
// byte array provided.
func DeserializeLabel(v []byte) (string, error) {
	// If the label is empty, return an error.
	length := binary.BigEndian.Uint16(v[0:2])
	if length == 0 {
		return "", ErrEmptyLabel
	}

	// Read the remainder of the bytes into a label string.
	label := string(v[2:])
	return label, nil
}

// isKnownOutput returns whether the output is known to the transaction store
// either as confirmed or unconfirmed.
func isKnownOutput(ns walletdb.ReadWriteBucket, op wire.OutPoint) bool {
	// TODO match to abe
	// (1) Check the unmine
	// (2) Check the matured
	//k := canonicalOutPoint(&op.Hash, op.Index)
	//if existsRawUnminedCredit(ns, k) != nil {
	//	return true
	//}
	//if existsRawUnspent(ns, k) != nil {
	//	return true
	//}
	return false
}

// LockOutput locks an output to the given ID, preventing it from being
// available for coin selection. The absolute time of the lock's expiration is
// returned. The expiration of the lock can be extended by successive
// invocations of this call.
//
// Outputs can be unlocked before their expiration through `UnlockOutput`.
// Otherwise, they are unlocked lazily through calls which iterate through all
// known outputs, e.g., `Balance`, `UnspentOutputs`.
//
// If the output is not known, ErrUnknownOutput is returned. If the output has
// already been locked to a different ID, then ErrOutputAlreadyLocked is
// returned.
func (s *Store) LockOutput(ns walletdb.ReadWriteBucket, id LockID,
	op wire.OutPoint) (time.Time, error) {

	// Make sure the output is known.
	if !isKnownOutput(ns, op) {
		return time.Time{}, ErrUnknownOutput
	}

	// Make sure the output hasn't already been locked to some other ID.
	lockedID, _, isLocked := isLockedOutput(ns, op, s.clock.Now())
	if isLocked && lockedID != id {
		return time.Time{}, ErrOutputAlreadyLocked
	}

	expiry := s.clock.Now().Add(DefaultLockDuration)
	if err := lockOutput(ns, id, op, expiry); err != nil {
		return time.Time{}, err
	}

	return expiry, nil
}

// UnlockOutput unlocks an output, allowing it to be available for coin
// selection if it remains unspent. The ID should match the one used to
// originally lock the output.
func (s *Store) UnlockOutput(ns walletdb.ReadWriteBucket, id LockID,
	op wire.OutPoint) error {

	// Make sure the output is known.
	if !isKnownOutput(ns, op) {
		return ErrUnknownOutput
	}

	// If the output has already been unlocked, we can return now.
	lockedID, _, isLocked := isLockedOutput(ns, op, s.clock.Now())
	if !isLocked {
		return nil
	}

	// Make sure the output was locked to the same ID.
	if lockedID != id {
		return ErrOutputUnlockNotAllowed
	}

	return unlockOutput(ns, op)
}

// DeleteExpiredLockedOutputs iterates through all existing locked outputs and
// deletes those which have already expired.
func (s *Store) DeleteExpiredLockedOutputs(ns walletdb.ReadWriteBucket) error {
	// Collect all expired output locks first to remove them later on. This
	// is necessary as deleting while iterating would invalidate the
	// iterator.
	var expiredOutputs []wire.OutPoint
	err := forEachLockedOutput(
		ns, func(op wire.OutPoint, _ LockID, expiration time.Time) {
			if !s.clock.Now().Before(expiration) {
				expiredOutputs = append(expiredOutputs, op)
			}
		},
	)
	if err != nil {
		return err
	}

	for _, op := range expiredOutputs {
		if err := unlockOutput(ns, op); err != nil {
			return err
		}
	}

	return nil
}
