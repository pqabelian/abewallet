package wtxmgr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/abesuite/abec/abecrypto/abesalrs"
	"github.com/abesuite/abec/blockchain"
	"github.com/abesuite/abec/txscript"
	"github.com/abesuite/abewallet/walletdb"
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
type BlockAbe struct {
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
type BlockAbeMeta struct {
	BlockAbe
	Time time.Time
}
type BlockAbeRecord struct {
	MsgBlockAbe        wire.MsgBlockAbe //TODO(abe):using a pointer replace the struct
	Height             int32
	Hash               chainhash.Hash
	RecvTime           time.Time
	TxRecordAbes       []*TxRecordAbe
	SerializedBlockAbe []byte
}

func NewBlockAbeRecord(serializedBlockAbe []byte) (*BlockAbeRecord, error) {
	rec := &BlockAbeRecord{
		SerializedBlockAbe: serializedBlockAbe,
	}
	err := rec.MsgBlockAbe.Deserialize(bytes.NewReader(serializedBlockAbe))
	if err != nil {
		str := "failed to deserialize block"
		return nil, storeError(ErrInput, str, err)
	}
	blockHash := rec.MsgBlockAbe.BlockHash()
	copy(rec.Hash[:], blockHash.CloneBytes())
	rec.Height = int32(binary.BigEndian.Uint32(rec.MsgBlockAbe.Transactions[0].TxIns[0].PreviousOutPointRing.BlockHashs[0][0:4]))
	rec.RecvTime = rec.MsgBlockAbe.Header.Timestamp
	rec.TxRecordAbes = make([]*TxRecordAbe, len(rec.MsgBlockAbe.Transactions))
	for i := 0; i < len(rec.MsgBlockAbe.Transactions); i++ {
		rec.TxRecordAbes[i], err = NewTxRecordAbeFromMsgTxAbe(rec.MsgBlockAbe.Transactions[i], rec.RecvTime)
		if err != nil {
			return nil, err
		}
	}
	return rec, nil

}
func NewBlockAbeRecordFromMsgBlockAbe(msgBlockAbe *wire.MsgBlockAbe) (*BlockAbeRecord, error) {
	buf := bytes.NewBuffer(make([]byte, 0, msgBlockAbe.SerializeSize()))
	err := msgBlockAbe.Serialize(buf)
	if err != nil {
		str := "failed to serialize block"
		return nil, storeError(ErrInput, str, err)
	}
	rec := &BlockAbeRecord{
		MsgBlockAbe:        *msgBlockAbe,
		Height:             int32(binary.BigEndian.Uint32(msgBlockAbe.Transactions[0].TxIns[0].PreviousOutPointRing.BlockHashs[0][0:4])),
		Hash:               msgBlockAbe.BlockHash(),
		RecvTime:           msgBlockAbe.Header.Timestamp,
		TxRecordAbes:       make([]*TxRecordAbe, len(msgBlockAbe.Transactions)),
		SerializedBlockAbe: buf.Bytes(),
	}
	for i := 0; i < len(msgBlockAbe.Transactions); i++ {
		rec.TxRecordAbes[i], err = NewTxRecordAbeFromMsgTxAbe(rec.MsgBlockAbe.Transactions[i], rec.RecvTime)
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
type debit struct {
	txHash chainhash.Hash
	index  uint32
	amount abeutil.Amount
	spends indexedIncidence
}

// credit describes a transaction output which was or is spendable by wallet.
type credit struct {
	outPoint wire.OutPoint
	block    Block
	amount   abeutil.Amount
	change   bool
	spentBy  indexedIncidence // Index == ^uint32(0) if unspent
}

// TxRecord represents a transaction managed by the Store.
type TxRecord struct {
	MsgTx        wire.MsgTx
	Hash         chainhash.Hash
	Received     time.Time
	SerializedTx []byte // Optional: may be nil
}
type TxRecordAbe struct {
	MsgTx        wire.MsgTxAbe
	Hash         chainhash.Hash
	Received     time.Time
	SerializedTx []byte // Optional: may be nil
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
func NewTxRecordAbe(serializedTx []byte, received time.Time) (*TxRecordAbe, error) {
	rec := &TxRecordAbe{
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
func NewTxRecordFromMsgTx(msgTx *wire.MsgTx, received time.Time) (*TxRecord, error) {
	buf := bytes.NewBuffer(make([]byte, 0, msgTx.SerializeSize()))
	err := msgTx.Serialize(buf)
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
func NewTxRecordAbeFromMsgTxAbe(msgTx *wire.MsgTxAbe, received time.Time) (*TxRecordAbe, error) {
	buf := bytes.NewBuffer(make([]byte, 0, msgTx.SerializeSize()))
	err := msgTx.Serialize(buf)
	if err != nil {
		str := "failed to serialize transaction"
		return nil, storeError(ErrInput, str, err)
	}
	rec := &TxRecordAbe{
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
type Credit struct {
	wire.OutPoint
	BlockMeta
	Amount       abeutil.Amount
	PkScript     []byte
	Received     time.Time
	FromCoinBase bool
}
type UnspentUTXO struct {
	Height int32 // the block height used to identify whether this utox can be spent in current height
	//BlockHash      chainhash.Hash
	TxOutput     wire.OutPointAbe //the outpoint
	FromCoinBase bool
	Amount       int64
	//ValueScript    int64
	//AddrScript     []byte
	GenerationTime time.Time      //at this moment, it also useless
	RingHash       chainhash.Hash //may be zero
}

func NewUnspentUTXO(height int32, txOutput wire.OutPointAbe, fromCoinBase bool, amount int64, generationTime time.Time, ringHash chainhash.Hash) *UnspentUTXO {
	return &UnspentUTXO{Height: height, TxOutput: txOutput, FromCoinBase: fromCoinBase, Amount: amount, GenerationTime: generationTime, RingHash: ringHash}
}

func (utxo *UnspentUTXO) Deserialize(op *wire.OutPointAbe, v []byte) error {
	if v == nil {
		return fmt.Errorf("empty byte slice")
	}
	if len(v) < 49 {
		str := "wrong size of serialized unspent transaction output"
		return fmt.Errorf(str)
	}
	utxo.TxOutput.TxHash = op.TxHash
	utxo.TxOutput.Index = op.Index
	offset := 0
	utxo.Height = int32(byteOrder.Uint32(v[offset : offset+4]))
	offset += 4
	t := v[offset]
	offset += 1
	if t == 0 {
		utxo.FromCoinBase = false
	} else {
		utxo.FromCoinBase = true
	}
	utxo.Amount = int64(byteOrder.Uint64(v[offset : offset+8]))
	offset += 8
	utxo.GenerationTime = time.Unix(int64(byteOrder.Uint64(v[offset:offset+8])), 0)
	offset += 8
	copy(utxo.RingHash[:], v[offset:offset+32])
	offset += 32
	return nil
}

type SpentButUnminedTXO struct { //TODO(abe):should add a field to denote which tx spent this utxo
	Height int32
	//BlockHash      chainhash.Hash
	TxOutput     wire.OutPointAbe
	FromCoinBase bool
	Amount       int64
	//ValueScript    int64
	//AddrScript     []byte
	GenerationTime time.Time
	RingHash       chainhash.Hash //may be zero
	SpentByHash    chainhash.Hash
	SpentTime      time.Time
}
type SpentConfirmedTXO struct { //TODO(abe):should add a field to denote which tx spent this utxo
	Height int32
	//BlockHash      chainhash.Hash
	TxOutput     wire.OutPointAbe
	FromCoinBase bool
	Amount       int64
	//ValueScript    int64
	//AddrScript     []byte
	GenerationTime time.Time
	RingHash       chainhash.Hash //may be zero
	SpentByHash    chainhash.Hash
	SpentTime      time.Time
	ConfirmTime    time.Time
}

type Ring struct {
	BlockHashes []chainhash.Hash // three block hashes
	TxHashes    []chainhash.Hash // [2,8]
	Index       []uint8          // [2,8]
	ValueScript []int64          // [2,8]
	AddrScript  [][]byte         // [2.8]
	BlockHeight int32            // point  height where the utxo ring is deleted
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
	var addrSize []int
	for i := 0; i < txLen; i++ {
		addrSize = append(addrSize, len(r.AddrScript[i]))
		addrScriptAllSize += len(r.AddrScript[i])
	}

	total := 32*bLen + 2 + (32+1+8)*txLen + 2*txLen + addrScriptAllSize + 4
	res := make([]byte, total)
	offset := 0
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
		byteOrder.PutUint64(res[offset:offset+8], uint64(r.ValueScript[i]))
		offset += 8
		byteOrder.PutUint16(res[offset:offset+2], uint16(addrSize[i]))
		offset += 2
	}
	for i := 0; i < txLen; i++ {
		copy(res[offset:offset+addrSize[i]], r.AddrScript[i])
		offset += addrSize[i]
	}
	byteOrder.PutUint32(res[offset:offset+4], uint32(r.BlockHeight))
	offset += 4
	return res
}
func (r *Ring) Deserialize(b []byte) error {
	if len(b) < 32*wire.BlockNumPerRingGroup+(32+2+8) {
		return fmt.Errorf("wrong length of input byte slice")
	}
	offset := 0
	// TODO(osy):The deserialized process has some error, has fixed
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
	var addrSize []int
	for i := 0; i < txLen; i++ {
		newHash, err := chainhash.NewHash(b[offset : offset+32])
		if err != nil {
			return err
		}
		r.TxHashes = append(r.TxHashes, *newHash)
		offset += 32
		r.Index = append(r.Index, b[offset])
		offset += 1
		r.ValueScript = append(r.ValueScript, int64(byteOrder.Uint64(b[offset:offset+8])))
		offset += 8
		addrSize = append(addrSize, int(byteOrder.Uint16(b[offset:offset+2])))
		offset += 2
	}
	r.AddrScript = make([][]byte, txLen)
	for i := 0; i < txLen; i++ {
		r.AddrScript[i] = b[offset : offset+addrSize[i]]
		offset += addrSize[i]
	}
	r.BlockHeight = int32(byteOrder.Uint32(b[offset : offset+4]))
	offset += 4
	return nil
}

// blockHash0||blockHash1||blockHash2||txHash0||index0||txHash1||index1||...
func (r Ring) Hash() []byte {
	size := wire.BlockNumPerRingGroup*32 + len(r.TxHashes)*(32+1)
	v := make([]byte, size)
	offset := 0
	for i := 0; i < wire.BlockNumPerRingGroup; i++ {
		copy(v[offset:offset+32], r.BlockHashes[i][:])
		offset += 32
	}
	for i := 0; i < len(r.TxHashes); i++ {
		copy(v[offset:offset+32], r.TxHashes[i][:])
		offset += 32
		v[offset] = r.Index[i]
		offset += 1
	}
	return chainhash.DoubleHashB(v)
}

type UTXORingAbe struct {
	AllSpent             bool                     //1 // not serialized and when serializing it must be false, otherwise it will be deleted
	Refreshed            bool                     //1 // not serialied, it can be computed from any OriginSerializeNumber
	RingHash             chainhash.Hash           //32
	TxHashes             []chainhash.Hash         //32*len
	OutputIndexes        []uint8                  //1
	OriginSerialNumberes map[uint8]chainhash.Hash //variable
	IsMy                 []bool                   //total 1
	Spent                []bool                   // total 1
	GotSerialNumberes    []chainhash.Hash         // variable
	//SpentByTxHashes      []chainhash.Hash
	//InputIndexes         []uint8
}

func NewUTXORingAbeFromRing(r *Ring) (*UTXORingAbe, error) {
	hash, err := chainhash.NewHash(r.Hash())
	if err != nil {
		return nil, err
	}
	ringSize := len(r.TxHashes)
	return &UTXORingAbe{
		AllSpent:             false,
		Refreshed:            false,
		RingHash:             *hash,
		TxHashes:             r.TxHashes,
		OutputIndexes:        r.Index,
		OriginSerialNumberes: make(map[uint8]chainhash.Hash),
		IsMy:                 make([]bool, ringSize),
		Spent:                make([]bool, ringSize),
		GotSerialNumberes:    *new([]chainhash.Hash),
	}, nil
}

type RingHashSerialNumbers struct {
	utxoRings     map[chainhash.Hash]UTXORingAbe      // utxo ring states before processing the block
	serialNumbers map[chainhash.Hash][]chainhash.Hash //added serialNumber in given block
}

// ring hash || transaction number || [transaction hash||output index...]||Origin serial number ||[index||serial number...]||isMy||Spent||Got serial number||[serial number...]
func (u UTXORingAbe) SerializeSize() int {
	return 32 + 1 + len(u.TxHashes)*(32+1) + 1 + len(u.OriginSerialNumberes)*(1+32) + 2 + 1 + len(u.GotSerialNumberes)*32

}
func (u UTXORingAbe) Serialize() []byte {
	txLen := len(u.TxHashes) // TODO(osy): may be lack a tx len in serialized utxo ring
	totalSize := u.SerializeSize()
	res := make([]byte, totalSize)
	offset := 0
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
	for index, sn := range u.OriginSerialNumberes {
		res[offset] = index
		offset += 1
		copy(res[offset:offset+32], sn[:])
		offset += 32
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
		copy(res[offset:offset+32], u.GotSerialNumberes[i][:])
		offset += 32
	}
	return res
}
func (u *UTXORingAbe) Deserialize(b []byte) error {
	if len(b) < 32+1 {
		return fmt.Errorf("the length of input byte slice less than minimum size")
	}
	offset := 0
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
	for i := 0; i < originSnSize; i++ {
		h, err := chainhash.NewHash(b[offset+1 : offset+33])
		if err != nil {
			return err
		}
		if u.OriginSerialNumberes == nil {
			u.OriginSerialNumberes = make(map[uint8]chainhash.Hash)
		}
		u.OriginSerialNumberes[b[offset]] = *h
		offset += 33
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
	offset+=1
	u.GotSerialNumberes = make([]chainhash.Hash, gotSnSize)
	for i := 0; i < gotSnSize; i++ {
		copy(u.GotSerialNumberes[i][:], b[offset:offset+32])
		offset += 32
	}
	u.AllSpent = false
	return nil
}

// The caller must check the u.AllSpent after return
func (u *UTXORingAbe) AddGotSerialNumber(serialNumber chainhash.Hash) error {
	if u.GotSerialNumberes == nil || len(u.GotSerialNumberes) == 0 {
		u.GotSerialNumberes = make([]chainhash.Hash, 0)
	}
	for i := 0; i < len(u.GotSerialNumberes); i++ {
		if serialNumber.IsEqual(&u.GotSerialNumberes[i]) {
			return fmt.Errorf("there has a same serialNumber in UTXORingAbe")
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
			hash, ok := u.OriginSerialNumberes[uint8(i)]
			if ok && hash.IsEqual(&serialNumber) {
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

func (u UTXORingAbe) Copy() *UTXORingAbe {
	res := new(UTXORingAbe)
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
		res.OriginSerialNumberes = make(map[uint8]chainhash.Hash)
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
	res.GotSerialNumberes = make([]chainhash.Hash, len(u.GotSerialNumberes))
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
	chainParams *chaincfg.Params

	// clock is used to determine when outputs locks have expired.
	clock clock.Clock

	// Event callbacks.  These execute in the same goroutine as the wtxmgr
	// caller.
	NotifyUnspent func(hash *chainhash.Hash, index uint32)
}

// Open opens the wallet transaction store from a walletdb namespace.  If the
// store does not exist, ErrNoExist is returned. `lockDuration` represents how
// long outputs are locked for.
func Open(ns walletdb.ReadBucket, chainParams *chaincfg.Params) (*Store, error) {

	// Open the store.
	err := openStore(ns)
	if err != nil {
		return nil, err
	}
	s := &Store{chainParams, clock.NewDefaultClock(), nil} // TODO: set callbacks
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
func (s *Store) updateMinedBalance(ns walletdb.ReadWriteBucket, rec *TxRecord,
	block *BlockMeta) error {

	// Fetch the mined balance in case we need to update it.
	minedBalance, err := fetchMinedBalance(ns)
	if err != nil {
		return err
	}

	// Add a debit record for each unspent credit spent by this transaction.
	// The index is set in each iteration below.
	spender := indexedIncidence{
		incidence: incidence{
			txHash: rec.Hash,
			block:  block.Block,
		},
	}

	newMinedBalance := minedBalance
	for i, input := range rec.MsgTx.TxIn {
		unspentKey, credKey := existsUnspent(ns, &input.PreviousOutPoint)
		if credKey == nil {
			// Debits for unmined transactions are not explicitly
			// tracked.  Instead, all previous outputs spent by any
			// unmined transaction are added to a map for quick
			// lookups when it must be checked whether a mined
			// output is unspent or not.
			//
			// Tracking individual debits for unmined transactions
			// could be added later to simplify (and increase
			// performance of) determining some details that need
			// the previous outputs (e.g. determining a fee), but at
			// the moment that is not done (and a db lookup is used
			// for those cases instead).  There is also a good
			// chance that all unmined transaction handling will
			// move entirely to the db rather than being handled in
			// memory for atomicity reasons, so the simplist
			// implementation is currently used.
			continue
		}

		// If this output is relevant to us, we'll mark the it as spent
		// and remove its amount from the store.
		spender.index = uint32(i)
		amt, err := spendCredit(ns, credKey, &spender)
		if err != nil {
			return err
		}
		err = putDebit(
			ns, &rec.Hash, uint32(i), amt, &block.Block, credKey,
		)
		if err != nil {
			return err
		}
		if err := deleteRawUnspent(ns, unspentKey); err != nil {
			return err
		}

		newMinedBalance -= amt
	}

	// For each output of the record that is marked as a credit, if the
	// output is marked as a credit by the unconfirmed store, remove the
	// marker and mark the output as a credit in the db.
	//
	// Moved credits are added as unspents, even if there is another
	// unconfirmed transaction which spends them.
	cred := credit{
		outPoint: wire.OutPoint{Hash: rec.Hash},
		block:    block.Block,
		spentBy:  indexedIncidence{index: ^uint32(0)},
	}

	it := makeUnminedCreditIterator(ns, &rec.Hash)
	for it.next() {
		// TODO: This should use the raw apis.  The credit value (it.cv)
		// can be moved from unmined directly to the credits bucket.
		// The key needs a modification to include the block
		// height/hash.
		index, err := fetchRawUnminedCreditIndex(it.ck)
		if err != nil {
			return err
		}
		amount, change, err := fetchRawUnminedCreditAmountChange(it.cv)
		if err != nil {
			return err
		}

		cred.outPoint.Index = index
		cred.amount = amount
		cred.change = change

		if err := putUnspentCredit(ns, &cred); err != nil {
			return err
		}
		err = putUnspent(ns, &cred.outPoint, &block.Block)
		if err != nil {
			return err
		}

		newMinedBalance += amount
	}
	if it.err != nil {
		return it.err
	}

	// Update the balance if it has changed.
	if newMinedBalance != minedBalance {
		return putMinedBalance(ns, newMinedBalance)
	}

	return nil
}

// deleteUnminedTx deletes an unmined transaction from the store.
//
// NOTE: This should only be used once the transaction has been mined.
func (s *Store) deleteUnminedTx(ns walletdb.ReadWriteBucket, rec *TxRecord) error {
	for _, input := range rec.MsgTx.TxIn {
		prevOut := input.PreviousOutPoint
		k := canonicalOutPoint(&prevOut.Hash, prevOut.Index)
		if err := deleteRawUnminedInput(ns, k, rec.Hash); err != nil {
			return err
		}
	}
	for i := range rec.MsgTx.TxOut {
		k := canonicalOutPoint(&rec.Hash, uint32(i))
		if err := deleteRawUnminedCredit(ns, k); err != nil {
			return err
		}
	}

	return deleteRawUnmined(ns, rec.Hash[:])
}

// InsertTx records a transaction as belonging to a wallet's transaction
// history.  If block is nil, the transaction is considered unspent, and the
// transaction's index must be unset.
func (s *Store) InsertTx(ns walletdb.ReadWriteBucket, rec *TxRecord, block *BlockMeta) error {
	if block == nil {
		//	todo(ABE): Does ABE wallet need to care the transactions in mempool?
		//	minds: ABE can spend TXOs of transactions confirmed by blocks, so that the transactions in memoopl do not provide any useful information.
		//
		return s.insertMemPoolTx(ns, rec)
	}
	return s.insertMinedTx(ns, rec, block)
}

// TODO(abe): actually, we must move the outputs of this transaction from unspent txo bucket to spentButUnmined txo bucket
// TODO(abe): update the balance in this function
// TODO(abe): record this transaction in unmined transaction bucket,
// TODO(abe): wait for a mempool transacion, need to design
func (s *Store) InsertTxAbe(wtxmgrNs walletdb.ReadWriteBucket, rec *TxRecordAbe, block *BlockAbeMeta) error {
	//TODO(abe):remove the outputs of the wallet spent by given tx from UnspentTXObucket to SpentButUmined bucket

	if block != nil {
		return fmt.Errorf("InsertTx just consideates the unconfirmed transaction")
	}
	v := existsRawUnminedAbe(wtxmgrNs, rec.Hash[:])
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
		for k, v := range u.OriginSerialNumberes {
			if v.IsEqual(&rec.MsgTx.TxIns[i].SerialNumber) {
				index = int(k)
				break
			}
		}
		if index == -1 { //it do not belong the wallet
			continue
		}
		// mark it as spent
		if u.IsMy[index] {
			u.Spent[index] = true
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
		amt, err := abeutil.NewAmountAbe(float64(byteOrder.Uint64(v[5:13])))
		if err != nil {
			return err
		}
		spendableBal -= amt
		err = putSpenableBalance(wtxmgrNs, spendableBal)
		if err != nil {
			return err
		}
		//err = deleteUnspentTXO(wtxmgrNs, k)
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
	}

	// add this function to unminedAbe bucket,and notify the index has spent
	v, err := valueTxRecordAbe(rec)
	if err != nil {
		return err
	}
	err = putRawUnminedAbe(wtxmgrNs, rec.Hash[:], v)
	if err != nil {
		return err
	}

	return nil
}

func (s *Store) InsertGenesisBlockAbe(ns walletdb.ReadWriteBucket, block *BlockAbeRecord, mpk *abesalrs.MasterPubKey, msvk *abesalrs.MasterSecretViewKey) error {
	balance, err := fetchMinedBalance(ns)
	if err != nil {
		return err
	}
	// put the genesis block into database
	err = putBlockAbeRecord(ns, block)
	if err != nil {
		return err
	}
	b := Block{
		Hash:   block.Hash,
		Height: block.Height,
	}
	myUnspetTXO := map[wire.OutPointAbe][]byte{}
	coinbaseTx := block.TxRecordAbes[0].MsgTx
	for i := 0; i < len(coinbaseTx.TxOuts); i++ {
		addr, err := txscript.ExtractAddressFromScriptAbe(coinbaseTx.TxOuts[0].AddressScript) // may have more than one outputs
		if err != nil {
			return err
		}
		dpk := addr.DerivedPubKey()
		isMy, err := abesalrs.CheckDerivedPubKeyAttribute(dpk, mpk, msvk)
		if isMy && err == nil {
			//k := canonicalOutPointAbe(block.MsgBlockAbe.Transactions[0].TxHash(), 0)
			//v := &UnspentUTXO{
			//	TxOutput: wire.OutPointAbe{
			//		TxHash: coinbaseTx.TxHash(),
			//		Index:  0,
			//	},
			//	FromCoinBase: true,
			//	Amount: coinbaseTx.TxOuts[0].ValueScript,
			//	GenerationTime: block.RecvTime,
			//	RingHash: chainhash.ZeroHash,
			//}
			amt, err := abeutil.NewAmountAbe(float64(coinbaseTx.TxOuts[i].ValueScript))
			if err != nil {
				return err
			}
			balance += amt

			k := wire.OutPointAbe{
				TxHash: coinbaseTx.TxHash(),
				Index:  uint8(i),
			}
			v := valueUnspentTXO(true, block.Height, coinbaseTx.TxOuts[i].ValueScript, block.RecvTime, chainhash.ZeroHash)
			myUnspetTXO[k] = v
		}
	}
	if len(myUnspetTXO) != 0 {
		blockOutputKey := canonicalBlockAbe(b.Height, b.Hash) // TODO(osy): this process can avoid
		blockOutputValue := make([]byte, 4+len(myUnspetTXO)*(32+1))
		offset := 0
		byteOrder.PutUint32(blockOutputValue[offset:], uint32(len(myUnspetTXO)))
		offset += 4
		for k, v := range myUnspetTXO {
			copy(blockOutputValue[offset:], k.TxHash[:])
			offset += 32
			blockOutputValue[offset] = k.Index
			offset += 1

			err := putRawUnspentTXO(ns, canonicalOutPointAbe(k.TxHash, k.Index), v)
			if err != nil {
				return err
			}
		}
		err := putBlockAbeOutput(ns, blockOutputKey, blockOutputValue)
		if err != nil {
			return err
		}
	}
	return putMinedBalance(ns, balance)
}
func (s *Store) InsertGenesisBlockAbeNew(ns walletdb.ReadWriteBucket, block *BlockAbeRecord, mpk *abesalrs.MasterPubKey, msvk *abesalrs.MasterSecretViewKey) error {
	balance, err := fetchMinedBalance(ns)
	if err != nil {
		return err
	}
	spendableBal, err := fetchSpenableBalance(ns)
	if err != nil {
		return err
	}
	freezedBal, err := fetchFreezedBalance(ns)
	if err != nil {
		return err
	}
	// put the genesis block into database
	err = putBlockAbeRecord(ns, block)
	if err != nil {
		return err
	}
	b := Block{
		Hash:   block.Hash,
		Height: block.Height,
	}
	blockOutputs := make(map[Block][]wire.OutPointAbe) // if the block height meet the requirement, it also store previous two block outputs belong the wallet

	coinbaseTx := block.TxRecordAbes[0].MsgTx
	coinbaseOutput := make(map[wire.OutPointAbe]*UnspentUTXO)
	for i := 0; i < len(coinbaseTx.TxOuts); i++ {
		addr, err := txscript.ExtractAddressFromScriptAbe(coinbaseTx.TxOuts[i].AddressScript) // may have more than one outputs
		if err != nil {
			return err
		}
		dpk := addr.DerivedPubKey()
		isMy, err := abesalrs.CheckDerivedPubKeyAttribute(dpk, mpk, msvk)
		if isMy {
			k := wire.OutPointAbe{
				TxHash: coinbaseTx.TxHash(),
				Index:  uint8(i),
			}
			amt, err := abeutil.NewAmountAbe(float64(coinbaseTx.TxOuts[i].ValueScript))
			if err != nil {
				return err
			}

			balance += amt
			freezedBal += amt

			tmp := NewUnspentUTXO(b.Height, k, true, coinbaseTx.TxOuts[i].ValueScript, block.RecvTime, chainhash.ZeroHash)
			coinbaseOutput[k] = tmp
			blockOutputs[b] = append(blockOutputs[b], k)
		}
	}
	if len(blockOutputs) != 0 {
		err := putRawImmaturedCoinbaseOutput(ns, canonicalBlockAbe(block.Height, block.Hash), valueImmaturedCoinbaseOutput(coinbaseOutput))
		if err != nil {
			return err
		}
	}
	if len(blockOutputs) != 0 { //add the block outputs in to bucket block outputs
		// TODO(abe): this process should transfer to byte slices and then append to given
		for blk, ops := range blockOutputs {
			k := canonicalBlockAbe(blk.Height, blk.Hash) // TODO(osy): this process can avoid
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
			err := putBlockAbeOutput(ns, k, v)
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
	err = putFreezedBalance(ns, freezedBal)
	if err != nil {
		return err
	}
	return putMinedBalance(ns, balance)
}

// TODO(abe): abstract the check function, it is relevant to the ns
// TODO(abe): update the balance in this function  (finished)
func (s *Store) InsertBlockAbe(ns walletdb.ReadWriteBucket, block *BlockAbeRecord, maturedBlockHash chainhash.Hash, mpk *abesalrs.MasterPubKey, msvk *abesalrs.MasterSecretViewKey) error {
	balance, err := fetchMinedBalance(ns)
	if err != nil {
		return err
	}
	// put the serialized block into database
	err = putBlockAbeRecord(ns, block)
	if err != nil {
		return err
	}
	//TODO(abe),finished:delete oldest block in the database
	if block.Height > NUMBERBLOCKABE {
		_, err = deleteRawBlockAbeWithBlockHeight(ns, block.Height-NUMBERBLOCKABE)
		if err != nil {
			return err
		}
	}
	if err != nil {
		return err
	}
	b := Block{
		Hash:   block.Hash,
		Height: block.Height,
	}
	myUnspetTXO := make(map[wire.OutPointAbe][]byte)   // store the outputs which belong to the wallet
	blockOutputs := make(map[Block][]wire.OutPointAbe) // if the block height meet the requirement, it also store previous two block outputs belong the wallet
	var blockInputs *RingHashSerialNumbers             // save the inputs which belong to the wallet spent by this block and store the increment and the utxo ring before adding this block
	// check the coinbase transaction
	// TODO(abe):for testing 1,2,5,10, the outputs in coinbase transaction may more than one

	// handle the coinbbase transaction
	coinbaseTx := block.TxRecordAbes[0].MsgTx
	for i := 0; i < len(coinbaseTx.TxOuts); i++ {
		addr, err := txscript.ExtractAddressFromScriptAbe(coinbaseTx.TxOuts[i].AddressScript) // may have more than one outputs
		if err != nil {
			return err
		}
		dpk := addr.DerivedPubKey()
		isMy, err := abesalrs.CheckDerivedPubKeyAttribute(dpk, mpk, msvk)
		if isMy && err == nil { // TODO(abe):the err==nil can deleted
			//k := canonicalOutPointAbe(block.MsgBlockAbe.Transactions[0].TxHash(), 0)
			//v := &UnspentUTXO{
			//	TxOutput: wire.OutPointAbe{
			//		TxHash: coinbaseTx.TxHash(),
			//		Index:  0,
			//	},
			//	FromCoinBase: true,
			//	Amount: coinbaseTx.TxOuts[0].ValueScript,
			//	GenerationTime: block.RecvTime,
			//	RingHash: chainhash.ZeroHash,
			//}
			amt, err := abeutil.NewAmountAbe(float64(coinbaseTx.TxOuts[i].ValueScript))
			if err != nil {
				return err
			}
			balance += amt

			k := wire.OutPointAbe{
				TxHash: coinbaseTx.TxHash(),
				Index:  uint8(i),
			}
			v := valueUnspentTXO(true, block.Height, coinbaseTx.TxOuts[i].ValueScript, block.RecvTime, chainhash.ZeroHash)
			myUnspetTXO[k] = v
			blockOutputs[b] = append(blockOutputs[b], k)
		}
	}

	relevantUTXORings := make(map[chainhash.Hash]*UTXORingAbe)
	// handle with the transfer transactions
	for i := 1; i < len(block.TxRecordAbes); i++ { // trace every tx in this block
		txi := block.TxRecordAbes[i].MsgTx
		// handle the inputs,TODO:need to check for this section
		for j := 0; j < len(txi.TxIns); j++ {
			// compute the ring hash of each input in every transaction to match the utxo in the database
			ringHash := txi.TxIns[j].PreviousOutPointRing.Hash()
			u, ok := relevantUTXORings[ringHash] // firstly, check it exist in relevantUTXORing
			serialNumber := txi.TxIns[j].SerialNumber
			if !ok {
				// TODO(abe):why in the bucket utxo ring, this entry which is keyed by ringHash is not found?
				key, value := existsUTXORing(ns, ringHash) // if not, check it the bucket
				if value == nil {                          //if not, it means that this input do not belong to wallet
					// if there is no value in utxo ring bucket. the pointed output must not belong to the wallet
					continue
				}
				// if the ring hash exists in the database, fetch the utxo ring
				oldU, err := fetchUTXORing(ns, key) //get the value from utxoring bucket, it will be one coins of wallet
				// if the utxo ring is nil or the err is not nil, it means that the utxo ring of pointed output has consumed out.
				if oldU == nil || err != nil {
					return err
				}
				// match the serialNumber
				for k := 0; k < len(oldU.GotSerialNumberes); k++ {
					// check doubling serialNumber
					if serialNumber.IsEqual(&oldU.GotSerialNumberes[k]) {
						return fmt.Errorf("There has a same serialNumber in UTXORingAbe")
					}
				}
				// save the previous utxoring for quick roll back
				if blockInputs == nil {
					blockInputs = new(RingHashSerialNumbers)
					blockInputs.utxoRings = make(map[chainhash.Hash]UTXORingAbe)
					blockInputs.serialNumbers = make(map[chainhash.Hash][]chainhash.Hash)
				}
				_, ok = blockInputs.utxoRings[ringHash]
				if !ok { // the utxo ring has not cached,record it in block input
					blockInputs.utxoRings[ringHash] = *oldU
				}
				blockInputs.serialNumbers[ringHash] = append(blockInputs.serialNumbers[ringHash], serialNumber)
				u = oldU.Copy()
			}

			//copy a new utxoring

			//update the new utxoring variable
			err = u.AddGotSerialNumber(serialNumber)
			if err != nil {
				return err
			}
			//u.GotSerialNumberes = append(u.GotSerialNumberes, serialNumber) // update the got serialnumbers
			//u.SpentByTxHashes = append(u.SpentByTxHashes, txi.TxHash())     // it points that one of utox is spent by given hash
			//u.InputIndexes = append(u.InputIndexes, uint8(i))               // the index of input which points to the utxo
			//if len(u.GotSerialNumberes) == len(u.IsMy) {                    // it means that all utxos in this ring have spent whatever the pointed output belong to the wallet
			//	for i := 0; i < len(u.IsMy); i++ {
			//		if u.IsMy[i] && !u.Spent[i] {
			//			u.Spent[i] = true // mark all utxo spent
			//		}
			//	}
			//	u.AllSpent = true // update the utxo ring states
			//} else if u.Refreshed { // if the serial number has refreshed TODO(abe): the refresh process have not finished
			//	for i := 0; i < len(u.OriginSerialNumberes); i++ { // we can find the serial number points to which outpoints in utxo ring
			//		if serialNumber.IsEqual(&u.OriginSerialNumberes[i]) && u.IsMy[i] && !u.Spent[i] {
			//			u.Spent[i] = true
			//			allSpent := true
			//			for i := 0; i < len(u.IsMy); i++ { // check whether all outpoints belong to the wallet are spent, because we may delete the useless utxoring
			//				if u.IsMy[i] && !u.Spent[i] {
			//					allSpent = false
			//				}
			//			}
			//			u.AllSpent = allSpent
			//		}
			//	}
			//}
			// TODO(abe): if the serial number is not refreshed, we have nothing to do. Maybe we must add this utxo ring to a bucket which includes all utxo ring waiting for refresh

			//  move relevant utxo from unspentTXO to SpentConfirmTXO
			// TODO(abe): the utxo may be in SpentButUnmined bucket
			for t := 0; t < len(u.IsMy); t++ {
				if u.IsMy[t] && u.Spent[t] { // need to move to spent and confirmed bucket
					k := canonicalOutPointAbe(u.TxHashes[t], u.OutputIndexes[t])
					// if this output is in unspent txo bucket
					v := existsRawUnspentTXO(ns, k)
					if v != nil {
						//otherwise it has been moved to spentButUnmined bucket
						// update the balances
						amt, err := abeutil.NewAmountAbe(float64(byteOrder.Uint64(v[5:13])))
						if err != nil {
							return err
						}
						balance -= amt
						v = append(v, serialNumber[:]...)
						var confirmTime [8]byte
						byteOrder.PutUint64(confirmTime[:], uint64(block.RecvTime.Unix()))
						v = append(v, confirmTime[:]...) //spentTime
						v = append(v, confirmTime[:]...) // confirm time
						err = deleteUnspentTXO(ns, k)
						if err != nil {
							return err
						}
					} else { //TODO(abe): if this transaction is create by the wallet, the outpoint should be stored in spentButUnmined bucket
						v = existsRawSpentButUnminedTXO(ns, k)
						if v != nil { //otherwise it has been moved to spentButUnmined bucket

							v = append(v, serialNumber[:]...)
							var confirmTime [8]byte
							byteOrder.PutUint64(confirmTime[:], uint64(block.RecvTime.Unix()))
							v = append(v, confirmTime[:]...)
							err := deleteUnspentTXO(ns, k)
							if err != nil {
								return err
							}
						}
					}
					// move to spent and confirm bucket
					err := putRawSpentConfirmedTXO(ns, k, v)
					if err != nil {
						return err
					}
				}
			}

			//update the relevantUTXORing
			relevantUTXORings[ringHash] = u
		}
		// update the utxo ring bucket
		for k, v := range relevantUTXORings {
			if v.AllSpent {
				// if all outpoints have been spent, so this utxo ring will be deleted,
				// and mark deleted flag in ring bucket
				err := deleteUTXORing(ns, k[:])
				if err != nil {
					return err
				}
				// TODO(abe):when delete the utxo ring, we also delete the ring? no,take a heigh flag
				err = updateDeletedHeightRingDetails(ns, k[:], block.Height)
				if err != nil {
					return err
				}
				continue
			}
			// if not, update the entry
			err := putRawUTXORing(ns, k[:], v.Serialize()[32:])
			if err != nil {
				return err
			}
		}

		// for all output in the given transaction
		for j := 0; j < len(txi.TxOuts); j++ {
			k := wire.OutPointAbe{
				TxHash: txi.TxHash(),
			}
			addr, err := txscript.ExtractAddressFromScriptAbe(txi.TxOuts[j].AddressScript)
			if err != nil {
				return err
			}
			dpk := addr.DerivedPubKey()
			isMy, err := abesalrs.CheckDerivedPubKeyAttribute(dpk, mpk, msvk)
			if isMy && err == nil { // just store the outpoints whick belong to the wallet
				v := valueUnspentTXO(true, block.Height, txi.TxOuts[j].ValueScript, block.RecvTime, chainhash.ZeroHash)
				amt, err := abeutil.NewAmountAbe(float64(txi.TxOuts[j].ValueScript))
				if err != nil {
					return err
				}
				balance += amt
				k.Index = uint8(j)
				myUnspetTXO[k] = v
				blockOutputs[b] = append(blockOutputs[b], k)
			}
		}
	}

	// store the inputs of block for quick rollback
	if blockInputs != nil {
		k := canonicalBlockAbe(block.Height, block.Hash)
		v := valueBlockAbeInput(blockInputs)
		err = putRawBlockAbeInput(ns, k, v)
		if err != nil {
			return err
		}
	}

	// store the output of block for quick rollback
	// TODO: there just is a block, so the map:block -> is useless
	if len(blockOutputs) != 0 { //add the block outputs in to bucket block outputs
		// TODO(abe): this process should transfer to byte slices and then append to given
		for blk, ops := range blockOutputs {
			k := canonicalBlockAbe(blk.Height, blk.Hash) // TODO(osy): this process can avoid
			v := make([]byte, 4+len(ops)*(32+1))
			offset := 0
			byteOrder.PutUint32(v[offset:], uint32(len(ops)))
			offset += 4
			for j := 0; j < len(ops); j++ {
				copy(v[offset:], ops[j].TxHash[:])
				offset += 32
				v[offset] = ops[j].Index
				offset += 1
				//v := ns.NestedReadBucket(bucketBlockOutputs).Get(k)
				////v := canonicalOutPointAbe(ops[j].TxHash, ops[j].Index)
				//_, err = appendRawBlockAbeOutput(ns, k, v, ops[j].TxHash, ops[j].Index)
				//if err != nil {
				//	return err
				//}
			}
			err := putBlockAbeOutput(ns, k, v)
			if err != nil {
				return err
			}
		}
	}

	//TODO(abe): check the correctness of generating ring and modify the utxo in bucket unspentUtxo
	if block.Height%3 == 2 {
		// if the height is match, it need to generate the utxo ring
		// if the number of utxo in previous two block is not zero, take it
		msgBlock2 := block.MsgBlockAbe
		block1Outputs, err := fetchBlockAbeOutput(ns, block.Height-1, msgBlock2.Header.PrevBlock)
		if err != nil && err.Error() != "the entry is empty" {
			return err
		}
		if block1Outputs != nil {
			for j := 0; j < len(block1Outputs); j++ { // for all outputs belonging to the wallet in block1
				k := canonicalOutPointAbe(block1Outputs[j].TxHash, block1Outputs[j].Index)
				v := ns.NestedReadBucket(bucketUnspentTXO).Get(k)
				myUnspetTXO[*block1Outputs[j]] = v // in this time, we also need to update the outputs in previous two block
				//blockOutputs[bBlock1] = append(blockOutputs[bBlock1], *block1Outputs[j])
			}
		}
		_, v := fetchRawBlockAbe(ns, block.Height-1, msgBlock2.Header.PrevBlock)
		msgBlock1 := new(wire.MsgBlockAbe)
		err = msgBlock1.Deserialize(bytes.NewReader(v))
		if err != nil {
			return err
		}

		block0Outputs, err := fetchBlockAbeOutput(ns, block.Height-2, msgBlock1.Header.PrevBlock)
		if err != nil && err.Error() != "the entry is empty" {
			return err
		}
		if block0Outputs != nil {
			for j := 0; j < len(block0Outputs); j++ { // transfer the block outputs to utxo
				k := canonicalOutPointAbe(block0Outputs[j].TxHash, block0Outputs[j].Index)
				v := ns.NestedReadBucket(bucketUnspentTXO).Get(k)
				myUnspetTXO[*block0Outputs[j]] = v
				//blockOutputs[bBlock0] = append(blockOutputs[bBlock0], *block0Outputs[j])
			}
		}

		// if there is zero output in three block belongs to the wallet, we return
		if len(myUnspetTXO) == 0 {
			return putMinedBalance(ns, balance)
		}
		_, v = fetchRawBlockAbe(ns, block.Height-2, msgBlock1.Header.PrevBlock)
		msgBlock0 := new(wire.MsgBlockAbe)
		err = msgBlock0.Deserialize(bytes.NewReader(v))
		if err != nil {
			return err
		}
		if msgBlock0 == nil || msgBlock1 == nil {
			return fmt.Errorf("newUtxoRingEntries is called with node that does not have 2 previous successive blocks in database")
		}

		//block1Outputs, err := fetchBlockAbeOutput(ns, block.Height-1, msgBlock2.Header.PrevBlock) // this process can be avoid
		//if err != nil && err.Error() != "the entry is empty" {
		//	return err
		//}
		//bBlock1 := Block{
		//	Hash:   msgBlock2.Header.PrevBlock,
		//	Height: block.Height - 1,
		//}
		//blockOutputs[bBlock1] = *new([]wire.OutPointAbe)
		//for j := 0; j < len(block1Outputs); j++ { // for all outputs belonging to the wallet in block1
		//	k := canonicalOutPointAbe(block1Outputs[j].TxHash, block1Outputs[j].Index)
		//	v := ns.NestedReadBucket(bucketUnspentTXO).Get(k)
		//	myUnspetTXO[*block1Outputs[j]] = v // in this time, we also need to update the outputs in previous two block
		//	//blockOutputs[bBlock1] = append(blockOutputs[bBlock1], *block1Outputs[j])
		//}

		//block0Outputs, err := fetchBlockAbeOutput(ns, block.Height-2, msgBlock1.Header.PrevBlock) // this process can be avoid
		//if err != nil && err.Error() != "the entry is empty" {
		//	return err
		//}
		//bBlock0 := Block{
		//	Hash:   msgBlock2.Header.PrevBlock,
		//	Height: block.Height - 1,
		//}
		//blockOutputs[bBlock0] = *new([]wire.OutPointAbe)

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
		for i := 0; i < blocksNum; i++ {
			blockHashs[i] = blocks[i].Hash()
		}
		ringBlockHeight := block.Height
		allCoinBaseRmTxos, allTransferRmTxos := blockchain.NewUTXORingEntriesPreparation(blocks)

		//create a view to generate the all rings
		view := blockchain.NewUtxoRingViewpoint()
		for i := 0; i < 9; i++ {
			if len(allCoinBaseRmTxos[i]) != 0 {
				err = view.NewUtxoRingEntriesFromTxos(allCoinBaseRmTxos[i], ringBlockHeight, blockHashs, true)
				if err != nil {
					return err
				}
			}
			if len(allTransferRmTxos[i]) != 0 {
				err = view.NewUtxoRingEntriesFromTxos(allTransferRmTxos[i], ringBlockHeight, blockHashs, false)
				if err != nil {
					return err
				}
			}
		}

		willAddUTXORing := make(map[chainhash.Hash]*UTXORingAbe)
		for ringHash, utxoRingEntry := range view.Entries() {
			for _, outpoint := range utxoRingEntry.OutPointRing().OutPoints {
				oldV, ok := myUnspetTXO[*outpoint] //if the outpoint belong the wallet
				if ok {                            // this ring has utxo belonging to the wallet
					utxoRing, ok1 := willAddUTXORing[ringHash]
					if !ok1 {
						// add this ring and utxo ring to database
						//generate a ringDetails
						ring := Ring{}
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
							ring.ValueScript = append(ring.ValueScript, txOuts[i].ValueScript)
							ring.AddrScript = append(ring.AddrScript, txOuts[i].AddressScript)
						}
						// put the ring to coinbase
						err := putRingDetails(ns, ringHash[:], ring.Serialize()[:])
						if err != nil {
							return err
						}

						//generate the utxoring, then add it to wllAddUTXORing for updating
						utxoRing, err = NewUTXORingAbeFromRing(&ring)
						if err != nil {
							return err
						}
						willAddUTXORing[ringHash] = utxoRing
					}
					// update the myUnspent
					//lengthOfNewV:=len(newV)
					//for i:=0;i<len(ringHash);i++{
					//	newV[lengthOfNewV-32+i]=ringHash[i]
					//}
					newV := make([]byte, len(oldV))
					copy(newV[:], oldV[:len(oldV)-32])
					//newV=append(newV[:len(newV)-32],ringHash[:]...)
					copy(newV[len(newV)-32:], ringHash[:])
					// update the unspent utxo
					myUnspetTXO[*outpoint] = newV
					//update the utxo ring
					index := 0
					for ; index < len(utxoRing.TxHashes); index++ {
						if outpoint.TxHash.IsEqual(&utxoRing.TxHashes[index]) &&
							outpoint.Index == utxoRing.OutputIndexes[index] {
							break
						}
					}
					utxoRing.IsMy[index] = true
				}
			}
		}
		// put the utxo ring into database
		for ringHash, utxoRing := range willAddUTXORing {
			err := putRawUTXORing(ns, ringHash[:], utxoRing.Serialize()[32:])
			if err != nil {
				return err
			}
		}
	}
	//	for k, v := range myUnspetTXO {
	//		if hash, ok := (*tTxOut2RingHash)[k]; ok {
	//			copy(v[len(v)-32:], (*hash)[:])
	//			ur, ok := willAddUTXORing[*hash]
	//			if !ok {
	//				putRingDetails(ns, hash[:], (*tRingHash2Ring)[*hash].Serialize()[:])
	//				if ring, ok := (*tRingHash2Ring)[*hash]; ok {
	//					u, err := NewUTXORingAbeFromRing(ring)
	//					if err != nil {
	//						return err
	//					}
	//					willAddUTXORing[*hash] = u
	//					ur = u
	//				}
	//			}
	//			for i, v := range ur.TxHashes {
	//				if bytes.Equal(v[:], k.TxHash[:]) {
	//					ur.IsMy[i] = true
	//					break
	//				}
	//			}
	//		} else if hash, ok := (*cTxOut2RingHash)[k]; ok {
	//			copy(v[len(v)-32:], (*hash)[:])
	//			ur, ok := willAddUTXORing[*hash]
	//			if !ok {
	//				putRingDetails(ns, hash[:], (*cRingHash2Ring)[*hash].Serialize()[:])
	//				if ring, ok := (*cRingHash2Ring)[*hash]; ok {
	//					u, err := NewUTXORingAbeFromRing(ring)
	//					if err != nil {
	//						return err
	//					}
	//					willAddUTXORing[*hash] = u
	//					ur = u
	//				}
	//			}
	//			for i, v := range ur.TxHashes {
	//				if bytes.Equal(v[:], k.TxHash[:]) {
	//					ur.IsMy[i] = true
	//					break
	//				}
	//			}
	//		}
	//	}
	//	for k, v := range willAddUTXORing {
	//		err := putRawUTXORing(ns, k[:], v.Serialize()[32:])
	//		if err != nil {
	//			return err
	//		}
	//	}
	//}
	// store all unspent txo
	for k, v := range myUnspetTXO {
		err := putRawUnspentTXO(ns, canonicalOutPointAbe(k.TxHash, k.Index), v)
		if err != nil {
			return err
		}
	}
	// update the balances
	return putMinedBalance(ns, balance)
}
func (s *Store) InsertBlockAbeNew(ns walletdb.ReadWriteBucket, block *BlockAbeRecord, maturedBlockHashs []*chainhash.Hash, mpk *abesalrs.MasterPubKey, msvk *abesalrs.MasterSecretViewKey) error {
	balance, err := fetchMinedBalance(ns)
	if err != nil {
		return err
	}
	spendableBal, err := fetchSpenableBalance(ns)
	if err != nil {
		return err
	}
	freezedBal, err := fetchFreezedBalance(ns)
	if err != nil {
		return err
	}
	tmpBal, err := abeutil.NewAmountAbe(0)
	if err != nil {
		return err
	}
	// put the serialized block into database
	err = putBlockAbeRecord(ns, block)
	if err != nil {
		return err
	}
	//TODO(abe):finished:delete oldest block in the database
	if block.Height > NUMBERBLOCKABE {
		_, err = deleteRawBlockAbeWithBlockHeight(ns, block.Height-NUMBERBLOCKABE)
		if err != nil {
			return err
		}
	}
	if err != nil {
		return err
	}
	b := Block{
		Hash:   block.Hash,
		Height: block.Height,
	}
	blockOutputs := make(map[Block][]wire.OutPointAbe) // if the block height meet the requirement, it also store previous two block outputs belong the wallet

	coinbaseTx := block.TxRecordAbes[0].MsgTx
	coinbaseOutput := make(map[wire.OutPointAbe]*UnspentUTXO)
	for i := 0; i < len(coinbaseTx.TxOuts); i++ {
		addr, err := txscript.ExtractAddressFromScriptAbe(coinbaseTx.TxOuts[i].AddressScript) // may have more than one outputs
		if err != nil {
			return err
		}
		dpk := addr.DerivedPubKey()
		isMy, err := abesalrs.CheckDerivedPubKeyAttribute(dpk, mpk, msvk)
		if isMy {
			k := wire.OutPointAbe{
				TxHash: coinbaseTx.TxHash(),
				Index:  uint8(i),
			}
			amt, err := abeutil.NewAmountAbe(float64(coinbaseTx.TxOuts[i].ValueScript))
			if err != nil {
				return err
			}
			freezedBal += amt
			balance += amt
			tmp := NewUnspentUTXO(b.Height, k, true, coinbaseTx.TxOuts[i].ValueScript, block.RecvTime, chainhash.ZeroHash)
			coinbaseOutput[k] = tmp
			blockOutputs[b] = append(blockOutputs[b], k)
		}
	}

	transferOutputs := make(map[wire.OutPointAbe]*UnspentUTXO, 0) // store the outputs which belong to the wallet
	var blockInputs *RingHashSerialNumbers                        // save the inputs which belong to the wallet spent by this block and store the increment and the utxo ring before adding this block
	relevantUTXORings := make(map[chainhash.Hash]*UTXORingAbe)
	// handle with the transfer transactions
	for i := 1; i < len(block.TxRecordAbes); i++ { // trace every tx in this block
		txi := block.TxRecordAbes[i].MsgTx
		txhash:=txi.TxHash()
		err := deleteRawUnminedAbe(ns, txhash[:])
		if err != nil {
			return err
		}
		// handle the inputs,TODO:need to check for this section
		for j := 0; j < len(txi.TxIns); j++ {
			// compute the ring hash of each input in every transaction to match the utxo in the database
			ringHash := txi.TxIns[j].PreviousOutPointRing.Hash()
			u, ok := relevantUTXORings[ringHash] // firstly, check it exist in relevantUTXORing
			serialNumber := txi.TxIns[j].SerialNumber
			if !ok {
				// TODO(abe):why in the bucket utxo ring, this entry which is keyed by ringHash is not found?
				key, value := existsUTXORing(ns, ringHash) // if not, check it the bucket
				if value == nil {                          //if not, it means that this input do not belong to wallet
					// if there is no value in utxo ring bucket. the pointed output must not belong to the wallet
					continue
				}
				// if the ring hash exists in the database, fetch the utxo ring
				oldU, err := fetchUTXORing(ns, key) //get the value from utxoring bucket, it will be one coins of wallet
				// if the utxo ring is nil or the err is not nil, it means that the utxo ring of pointed output has consumed out.
				if oldU == nil || err != nil {
					return err
				}
				// match the serialNumber
				for k := 0; k < len(oldU.GotSerialNumberes); k++ {
					// check doubling serialNumber
					if serialNumber.IsEqual(&oldU.GotSerialNumberes[k]) {
						return fmt.Errorf("There has a same serialNumber in UTXORingAbe")
					}
				}
				// save the previous utxoring for quick roll back
				if blockInputs == nil {
					blockInputs = new(RingHashSerialNumbers)
					blockInputs.utxoRings = make(map[chainhash.Hash]UTXORingAbe)
					blockInputs.serialNumbers = make(map[chainhash.Hash][]chainhash.Hash)
				}
				_, ok = blockInputs.utxoRings[ringHash]
				if !ok { // the utxo ring has not cached,record it in block input
					blockInputs.utxoRings[ringHash] = *oldU
				}
				blockInputs.serialNumbers[ringHash] = append(blockInputs.serialNumbers[ringHash], serialNumber)
				u = oldU.Copy()
			}

			//copy a new utxoring and update the new utxoring variable
			err := u.AddGotSerialNumber(serialNumber)
			if err != nil {
				return err
			}

			//  move relevant utxo from unspentTXO or SpentButUnmined bucket to SpentConfirmTXO
			for t := 0; t < len(u.IsMy); t++ {
				if u.IsMy[t] && u.Spent[t] { // need to move to spent and confirmed bucket
					k := canonicalOutPointAbe(u.TxHashes[t], u.OutputIndexes[t])
					// if this output is in unspent txo bucket
					v := existsRawMaturedOutput(ns, k)
					if v != nil {
						//otherwise it has been moved to spentButUnmined bucket
						// update the balances
						amt, err := abeutil.NewAmountAbe(float64(byteOrder.Uint64(v[5:13])))
						if err != nil {
							return err
						}
						balance -= amt
						spendableBal -= amt
						v = append(v, serialNumber[:]...)
						var confirmTime [8]byte
						byteOrder.PutUint64(confirmTime[:], uint64(block.RecvTime.Unix()))
						v = append(v, confirmTime[:]...) //spentTime
						v = append(v, confirmTime[:]...) // confirm time
						err = deleteMaturedOutput(ns, k)
						if err != nil {
							return err
						}
					} else { //TODO(abe): if this transaction is create by the wallet, the outpoint should be stored in spentButUnmined bucket
						v = existsRawSpentButUnminedTXO(ns, k)
						if v != nil { //otherwise it has been moved to spentButUnmined bucket
							amt, err := abeutil.NewAmountAbe(float64(byteOrder.Uint64(v[5:13])))
							if err != nil {
								return err
							}
							balance -= amt
							// freezedBal -= amt
							v = append(v, serialNumber[:]...)
							var confirmTime [8]byte
							byteOrder.PutUint64(confirmTime[:], uint64(block.RecvTime.Unix()))
							v = append(v, confirmTime[:]...)
							err = deleteSpentButUnminedTXO(ns, k)
							if err != nil {
								return err
							}
						}
					}
					// move to spent and confirm bucket
					err := putRawSpentConfirmedTXO(ns, k, v)
					if err != nil {
						return err
					}
				}
			}
			//update the relevantUTXORing
			relevantUTXORings[ringHash] = u
		}
		// update the utxo ring bucket
		for k, v := range relevantUTXORings {
			if v.AllSpent {
				// if all outpoints have been spent, so this utxo ring will be deleted,
				// and mark deleted flag in ring bucket
				err := deleteUTXORing(ns, k[:])
				if err != nil {
					return err
				}
				// TODO(abe):when delete the utxo ring, we also delete the ring? no,take a heigh flag
				err = updateDeletedHeightRingDetails(ns, k[:], block.Height)
				if err != nil {
					return err
				}
				continue
			}
			// if not, update the entry
			err := putRawUTXORing(ns, k[:], v.Serialize()[32:])
			if err != nil {
				return err
			}
		}

		// for all output in the given transaction
		for j := 0; j < len(txi.TxOuts); j++ {
			k := wire.OutPointAbe{
				TxHash: txi.TxHash(),
			}
			addr, err := txscript.ExtractAddressFromScriptAbe(txi.TxOuts[j].AddressScript)
			if err != nil {
				return err
			}
			dpk := addr.DerivedPubKey()
			isMy, err := abesalrs.CheckDerivedPubKeyAttribute(dpk, mpk, msvk)
			if isMy && err == nil { // just store the outpoints whick belong to the wallet
				k.Index = uint8(j)
				amt, err := abeutil.NewAmountAbe(float64(txi.TxOuts[j].ValueScript))
				if err != nil {
					return err
				}
				tmpBal += amt
				balance += amt
				freezedBal += amt
				transferOutputs[k] = NewUnspentUTXO(block.Height, k, false, txi.TxOuts[j].ValueScript, block.RecvTime, chainhash.ZeroHash)
				blockOutputs[b] = append(blockOutputs[b], k)
			}
		}
	}

	// store the inputs of block for quick rollback
	if blockInputs != nil {
		k := canonicalBlockAbe(block.Height, block.Hash)
		v := valueBlockAbeInput(blockInputs)
		err = putRawBlockAbeInput(ns, k, v)
		if err != nil {
			return err
		}
	}

	// store the output of block for quick rollback
	// TODO: there just is a block, so the map:block -> is useless
	if len(blockOutputs) != 0 { //add the block outputs in to bucket block outputs
		// TODO(abe): this process should transfer to byte slices and then append to given
		for blk, ops := range blockOutputs {
			k := canonicalBlockAbe(blk.Height, blk.Hash) // TODO(osy): this process can avoid
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
			err := putBlockAbeOutput(ns, k, v)
			if err != nil {
				return err
			}
		}
	}
	cacheMap := make([]map[wire.OutPointAbe]*UnspentUTXO, 7)
	cacheMap[1] = coinbaseOutput
	cacheMap[2] = transferOutputs
	//TODO(abe): check the correctness of generating ring and modify the utxo in bucket unspentUtxo
	if block.Height%3 == 2 {
		// if the height is match, it need to generate the utxo ring
		// if the number of utxo in previous two block is not zero, take it
		msgBlock2 := block.MsgBlockAbe
		block1Outputs, err := fetchBlockAbeOutput(ns, block.Height-1, msgBlock2.Header.PrevBlock)
		if err != nil && err.Error() != "the entry is empty" {
			return err
		}
		if block1Outputs != nil {
			cacheMap[3], err = fetchImmaturedCoinbaseOutput(ns, block.Height-1, msgBlock2.Header.PrevBlock)
			if err != nil {
				return err
			}
			cacheMap[4], err = fetchImmaturedOutput(ns, block.Height-1, msgBlock2.Header.PrevBlock)
			if err != nil {
				return err
			}
		}
		_, v := fetchRawBlockAbe(ns, block.Height-1, msgBlock2.Header.PrevBlock)
		msgBlock1 := new(wire.MsgBlockAbe)
		err = msgBlock1.Deserialize(bytes.NewReader(v))
		if err != nil {
			return err
		}

		block0Outputs, err := fetchBlockAbeOutput(ns, block.Height-2, msgBlock1.Header.PrevBlock)
		if err != nil && err.Error() != "the entry is empty" {
			return err
		}
		if block0Outputs != nil {
			cacheMap[5], err = fetchImmaturedCoinbaseOutput(ns, block.Height-2, msgBlock1.Header.PrevBlock)
			if err != nil {
				return err
			}
			cacheMap[6], err = fetchImmaturedOutput(ns, block.Height-2, msgBlock1.Header.PrevBlock)
			if err != nil {
				return err
			}
		}

		// if there is zero output in three block belongs to the wallet, we return
		if len(cacheMap[1]) == 0 && len(cacheMap[2]) == 0 &&
			len(cacheMap[3]) == 0 && len(cacheMap[4]) == 0 &&
			len(cacheMap[5]) == 0 && len(cacheMap[6]) == 0 {
			// return handle
			err := putSpenableBalance(ns, spendableBal)
			if err != nil {
				return err
			}
			err = putFreezedBalance(ns, freezedBal)
			if err != nil {
				return err
			}
			return putMinedBalance(ns, balance)
		}
		//create a cache for update
		cache := make(map[wire.OutPointAbe]int)
		for outPointAbe, _ := range cacheMap[1] {
			cache[outPointAbe] = 1
		}
		for outPointAbe, _ := range cacheMap[2] {
			cache[outPointAbe] = 2
		}
		for outPointAbe, _ := range cacheMap[3] {
			cache[outPointAbe] = 3
		}
		for outPointAbe, _ := range cacheMap[4] {
			cache[outPointAbe] = 4
		}
		for outPointAbe, _ := range cacheMap[5] {
			cache[outPointAbe] = 5
		}
		for outPointAbe, _ := range cacheMap[6] {
			cache[outPointAbe] = 6
		}

		_, v = fetchRawBlockAbe(ns, block.Height-2, msgBlock1.Header.PrevBlock)
		msgBlock0 := new(wire.MsgBlockAbe)
		err = msgBlock0.Deserialize(bytes.NewReader(v))
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
		for i := 0; i < blocksNum; i++ {
			blockHashs[i] = blocks[i].Hash()
		}
		ringBlockHeight := block.Height
		allCoinBaseRmTxos, allTransferRmTxos := blockchain.NewUTXORingEntriesPreparation(blocks)

		//create a view to generate the all rings
		view := blockchain.NewUtxoRingViewpoint()
		for i := 0; i < 9; i++ {
			if len(allCoinBaseRmTxos[i]) != 0 {
				err = view.NewUtxoRingEntriesFromTxos(allCoinBaseRmTxos[i], ringBlockHeight, blockHashs, true)
				if err != nil {
					return err
				}
			}
			if len(allTransferRmTxos[i]) != 0 {
				err = view.NewUtxoRingEntriesFromTxos(allTransferRmTxos[i], ringBlockHeight, blockHashs, false)
				if err != nil {
					return err
				}
			}
		}

		willAddUTXORing := make(map[chainhash.Hash]*UTXORingAbe)
		for ringHash, utxoRingEntry := range view.Entries() {
			for _, outpoint := range utxoRingEntry.OutPointRing().OutPoints {
				var utxo *UnspentUTXO
				var curMap int
				switch cache[*outpoint] {
				case 1:
					utxo = cacheMap[1][*outpoint]
					curMap = 1
				case 2:
					utxo = cacheMap[2][*outpoint]
					curMap = 2
				case 3:
					utxo = cacheMap[3][*outpoint]
					curMap = 3
				case 4:
					utxo = cacheMap[4][*outpoint]
					curMap = 4
				case 5:
					utxo = cacheMap[5][*outpoint]
					curMap = 5
				case 6:
					utxo = cacheMap[6][*outpoint]
					curMap = 6
				default:

				}
				if utxo != nil { // this ring has utxo belonging to the wallet
					utxoRing, ok1 := willAddUTXORing[ringHash]
					if !ok1 {
						// add this ring and utxo ring to database
						//generate a ringDetails
						ring := Ring{}
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
							ring.ValueScript = append(ring.ValueScript, txOuts[i].ValueScript)
							ring.AddrScript = append(ring.AddrScript, txOuts[i].AddressScript)
						}
						// put the ring to coinbase
						err := putRingDetails(ns, ringHash[:], ring.Serialize()[:])
						if err != nil {
							return err
						}

						//generate the utxoring, then add it to wllAddUTXORing for updating
						utxoRing, err = NewUTXORingAbeFromRing(&ring)
						if err != nil {
							return err
						}
						willAddUTXORing[ringHash] = utxoRing
					}
					utxo.RingHash = ringHash
					cacheMap[curMap][*outpoint] = utxo
					//update the utxo ring
					index := 0
					for ; index < len(utxoRing.TxHashes); index++ {
						if outpoint.TxHash.IsEqual(&utxoRing.TxHashes[index]) &&
							outpoint.Index == utxoRing.OutputIndexes[index] {
							break
						}
					}
					utxoRing.IsMy[index] = true
				}
			}
		}
		// put the utxo ring into database
		for ringHash, utxoRing := range willAddUTXORing {
			err := putRawUTXORing(ns, ringHash[:], utxoRing.Serialize()[32:])
			if err != nil {
				return err
			}
			err = putRawNeedUpdateUTXORing(ns, ringHash[:], []byte{1})
			if err != nil {
				return err
			}
		}
		// coinbase output -> immature
		if len(cacheMap[3]) != 0 {
			err := putRawImmaturedCoinbaseOutput(ns, canonicalBlockAbe(block1.Height(), *block1.Hash()), valueImmaturedCoinbaseOutput(cacheMap[3]))
			if err != nil {
				return err
			}
		}
		if len(cacheMap[5]) != 0 {
			err := putRawImmaturedCoinbaseOutput(ns, canonicalBlockAbe(block0.Height(), *block0.Hash()), valueImmaturedCoinbaseOutput(cacheMap[5]))
			if err != nil {
				return err
			}
		}
		// transfer output -> mature
		for op, utxo := range cacheMap[4] {
			v := valueUnspentTXO(false, utxo.Height, utxo.Amount, utxo.GenerationTime, utxo.RingHash)
			amt, err := abeutil.NewAmountAbe(float64(byteOrder.Uint64(v[5:13])))
			if err != nil {
				return err
			}
			spendableBal += amt
			freezedBal -= amt
			err = putRawMaturedOutput(ns, canonicalOutPointAbe(op.TxHash, op.Index), v)
			if err != nil {
				return err
			}
		}
		for op, utxo := range cacheMap[6] {
			v := valueUnspentTXO(false, utxo.Height, utxo.Amount, utxo.GenerationTime, utxo.RingHash)
			amt, err := abeutil.NewAmountAbe(float64(byteOrder.Uint64(v[5:13])))
			if err != nil {
				return err
			}
			spendableBal += amt
			freezedBal -= amt
			err = putRawMaturedOutput(ns, canonicalOutPointAbe(op.TxHash, op.Index), v)
			if err != nil {
				return err
			}
		}
	}
	// store this block output
	// coinbase is immatured
	if len(cacheMap[1]) != 0 {
		err := putRawImmaturedCoinbaseOutput(ns, canonicalBlockAbe(block.Height, block.Hash), valueImmaturedCoinbaseOutput(cacheMap[1]))
		if err != nil {
			return err
		}
	}
	if block.Height%3 == 2 { // transfer output is matured
		for op, utxo := range cacheMap[2] {
			v := valueUnspentTXO(false, utxo.Height, utxo.Amount, utxo.GenerationTime, utxo.RingHash)
			err = putRawMaturedOutput(ns, canonicalOutPointAbe(op.TxHash, op.Index), v)
			if err != nil {
				return err
			}
		}
		spendableBal += tmpBal
		freezedBal -= tmpBal
	} else { // immatured
		if len(cacheMap[2]) != 0 {
			err := putRawImmaturedOutput(ns, canonicalBlockAbe(block.Height, block.Hash), valueImmaturedOutput(cacheMap[2]))
			if err != nil {
				return err
			}
		}
	}

	// Fix for spending immarture coinbase transaction output: move it to spendable utxo bucket every 3 blocks
	// fetch the matured coinbase output block.Height-Maturity
	if block.Height>=int32(s.chainParams.CoinbaseMaturity)+2 && block.Height%3==2 {
		for i := 0; i < len(maturedBlockHashs); i++ {
			utxo, err := fetchImmaturedCoinbaseOutput(ns, block.Height-int32(s.chainParams.CoinbaseMaturity)-int32(i), *maturedBlockHashs[i])
			if err != nil {
				return err
			}
			for op, utxo := range utxo {
				v := valueUnspentTXO(true, block.Height-int32(s.chainParams.CoinbaseMaturity), utxo.Amount, utxo.GenerationTime, utxo.RingHash)
				amt, err := abeutil.NewAmountAbe(float64(byteOrder.Uint64(v[5:13])))
				if err != nil {
					return err
				}
				spendableBal += amt
				freezedBal -= amt
				err = putRawMaturedOutput(ns, canonicalOutPointAbe(op.TxHash, op.Index), v)
				if err != nil {
					return err
				}
			}
		}
	}
	// update the balances
	// return handle
	err = putSpenableBalance(ns, spendableBal)
	if err != nil {
		return err
	}
	err = putFreezedBalance(ns, freezedBal)
	if err != nil {
		return err
	}
	return putMinedBalance(ns, balance)
}

//func generateRing(ringMemberTxos []*sortTxo, blockhashs []*chainhash.Hash) (*map[chainhash.Hash]*Ring, *map[wire.OutPointAbe]*chainhash.Hash, error) {
//	res1 := make(map[chainhash.Hash]*Ring)
//	res2 := make(map[wire.OutPointAbe]*chainhash.Hash)
//	if len(ringMemberTxos) == 0 {
//		return nil, nil, nil
//	}
//
//	// sort
//	sort.Sort(orderedRing(ringMemberTxos))
//
//	txoNum := len(ringMemberTxos)
//
//	//	group Txos to rings
//	normalRingNum := txoNum / wire.TxRingSize
//	remainderTxoNum := txoNum % wire.TxRingSize
//
//	//	totalRingNum := normalRingNum
//	if remainderTxoNum != 0 {
//		//	implies 0 < remainderTxoNum < wire.TxRingSize
//		//		totalRingNum += 1
//
//		if normalRingNum >= 1 {
//			//	divide (the last normalRing and the remainder Txos) into 2 rings with ring_1.size = ring_2.size or ring_1.size = ring_2.size + 1
//			normalRingNum -= 1
//		} // else {
//		// implies 	normalRingNum == 0
//		//	the remainder forms the only ring
//		//	}
//	}
//	for i := 0; i < normalRingNum; i++ { //TODO(abe):extract a function to generate a ring
//		// rings with size wire.TxRingSize
//		start := i * wire.TxRingSize
//		outPoints := make([]*wire.OutPointAbe, wire.TxRingSize)
//		txOuts := make([]*wire.TxOutAbe, wire.TxRingSize)
//		for i := start; i < wire.TxRingSize; i++ {
//			outPoints[i] = &wire.OutPointAbe{
//				TxHash: *ringMemberTxos[i].txHash,
//				Index:  ringMemberTxos[i].index,
//			}
//			txOuts[i] = ringMemberTxos[i].txOut
//		}
//
//		r := &Ring{
//			BlockHashes: []chainhash.Hash{*blockhashs[0], *blockhashs[1], *blockhashs[2]},
//			TxHashes: []chainhash.Hash{outPoints[0].TxHash, outPoints[1].TxHash, outPoints[2].TxHash,
//				outPoints[3].TxHash, outPoints[4].TxHash, outPoints[5].TxHash, outPoints[6].TxHash},
//			Index: []uint8{outPoints[0].Index, outPoints[1].Index, outPoints[2].Index,
//				outPoints[3].Index, outPoints[4].Index, outPoints[5].Index, outPoints[6].Index},
//			ValueScript: []int64{txOuts[0].ValueScript, txOuts[1].ValueScript, txOuts[2].ValueScript,
//				txOuts[3].ValueScript, txOuts[4].ValueScript, txOuts[5].ValueScript, txOuts[6].ValueScript},
//			AddrScript: [][]byte{txOuts[0].AddressScript, txOuts[1].AddressScript, txOuts[2].AddressScript,
//				txOuts[3].AddressScript, txOuts[4].AddressScript, txOuts[5].AddressScript, txOuts[6].AddressScript},
//		}
//		outPointRingHash, _ := chainhash.NewHash(r.Hash())
//		res1[*outPointRingHash] = r
//		for j := 0; j < wire.TxRingSize; j++ {
//			res2[*outPoints[j]] = outPointRingHash
//		}
//
//	}
//	remainderTxoNum = txoNum - normalRingNum*wire.TxRingSize
//	if remainderTxoNum > wire.TxRingSize {
//		//	divide (the last normalRing and the remainder Txos) into 2 rings with sizes remainderTxoNum/2
//		ringSize1 := remainderTxoNum / 2
//		if remainderTxoNum%2 != 0 {
//			ringSize1 += 1
//		}
//		start := normalRingNum * wire.TxRingSize
//		outPoints1 := make([]*wire.OutPointAbe, ringSize1)
//		txOuts1 := make([]*wire.TxOutAbe, ringSize1)
//		r1 := &Ring{
//			BlockHashes: []chainhash.Hash{*blockhashs[0], *blockhashs[1], *blockhashs[2]},
//		}
//		for i := start; i < ringSize1; i++ {
//			outPoints1[i] = &wire.OutPointAbe{
//				TxHash: *ringMemberTxos[i].txHash,
//				Index:  ringMemberTxos[i].index,
//			}
//			txOuts1[i] = ringMemberTxos[i].txOut
//			r1.TxHashes[i] = *ringMemberTxos[i].txHash
//			r1.Index[i] = ringMemberTxos[i].index
//			r1.ValueScript[i] = txOuts1[i].ValueScript
//			r1.AddrScript[i] = txOuts1[i].AddressScript
//		}
//		outPointRingHash1, _ := chainhash.NewHash(r1.Hash())
//		res1[*outPointRingHash1] = r1
//		for j := 0; j < ringSize1; j++ {
//			res2[*outPoints1[j]] = outPointRingHash1
//		}
//		start = start + ringSize1
//		ringSize2 := remainderTxoNum - ringSize1
//		outPoints2 := make([]*wire.OutPointAbe, ringSize1)
//		txOuts2 := make([]*wire.TxOutAbe, ringSize1)
//		r2 := &Ring{
//			BlockHashes: []chainhash.Hash{*blockhashs[0], *blockhashs[1], *blockhashs[2]},
//		}
//		for i := start; i < ringSize2; i++ {
//			outPoints2[i] = &wire.OutPointAbe{
//				TxHash: *ringMemberTxos[i].txHash,
//				Index:  ringMemberTxos[i].index,
//			}
//			txOuts2[i] = ringMemberTxos[i].txOut
//			r2.TxHashes[i] = *ringMemberTxos[i].txHash
//			r2.Index[i] = ringMemberTxos[i].index
//			r2.ValueScript[i] = txOuts2[i].ValueScript
//			r2.AddrScript[i] = txOuts2[i].AddressScript
//		}
//		outPointRingHash2, _ := chainhash.NewHash(r2.Hash())
//		res1[*outPointRingHash2] = r2
//		for j := 0; j < ringSize2; j++ {
//			res2[*outPoints2[j]] = outPointRingHash2
//		}
//
//	} else if remainderTxoNum > 0 {
//		//	one ring with size = remainderTxoNum
//		start := normalRingNum * wire.TxRingSize
//		ringSize := remainderTxoNum
//		outPoints := make([]*wire.OutPointAbe, ringSize)
//		txOuts := make([]*wire.TxOutAbe, ringSize)
//		r := &Ring{
//			BlockHashes: []chainhash.Hash{*blockhashs[0], *blockhashs[1], *blockhashs[2]},
//		}
//		for i := start; i < ringSize; i++ {
//			outPoints[i] = &wire.OutPointAbe{
//				TxHash: *ringMemberTxos[i].txHash,
//				Index:  ringMemberTxos[i].index,
//			}
//			txOuts[i] = ringMemberTxos[i].txOut
//			r.TxHashes[i] = *ringMemberTxos[i].txHash
//			r.Index[i] = ringMemberTxos[i].index
//			r.ValueScript[i] = txOuts[i].ValueScript
//			r.AddrScript[i] = txOuts[i].AddressScript
//		}
//		outPointRingHash1, _ := chainhash.NewHash(r.Hash())
//		res1[*outPointRingHash1] = r
//		for j := 0; j < ringSize; j++ {
//			res2[*outPoints[j]] = outPointRingHash1
//		}
//	}
//	return &res1, &res2, nil
//}

// RemoveUnminedTx attempts to remove an unmined transaction from the
// transaction store. This is to be used in the scenario that a transaction
// that we attempt to rebroadcast, turns out to double spend one of our
// existing inputs. This function we remove the conflicting transaction
// identified by the tx record, and also recursively remove all transactions
// that depend on it.
func (s *Store) RemoveUnminedTx(ns walletdb.ReadWriteBucket, rec *TxRecord) error {
	// As we already have a tx record, we can directly call the
	// removeConflict method. This will do the job of recursively removing
	// this unmined transaction, and any transactions that depend on it.
	return s.removeConflict(ns, rec)
}

// In Abe, we this function is used to update the utxo set: move the unspent txo to spent but unmined txo
func (s *Store) RemoveUnminedTxAbe(ns walletdb.ReadWriteBucket, rec *TxRecordAbe) error {
	//TODO(abe): when remove a transaction, we should delete the conflict transaction in bucketUnminedTxAbe
	//  and according the given hash to update the utxo se
	// the code need to be re-writed0
	for i := 0; i < len(rec.MsgTx.TxIns); i++ {
		txIn := rec.MsgTx.TxIns[i]
		for j := 0; j < len(txIn.PreviousOutPointRing.OutPoints); j++ {
			sbutxo, err := fetchSpentButUnminedTXO(ns, txIn.PreviousOutPointRing.OutPoints[j].TxHash, txIn.PreviousOutPointRing.OutPoints[j].Index)
			if err != nil {
				return err
			}
			if !sbutxo.SpentByHash.IsEqual(&rec.Hash) {
				continue
			}
			// move given outpoint from spent but unmined txo bucket to unspent txo bucket
			err = deleteSpentButUnminedTXO(ns,
				canonicalOutPointAbe(txIn.PreviousOutPointRing.OutPoints[j].TxHash, txIn.PreviousOutPointRing.OutPoints[j].Index))
			if err != nil {
				return err
			}
			//err = putRawUnspentTXO(ns,
			err = putRawMaturedOutput(ns,
				canonicalOutPointAbe(txIn.PreviousOutPointRing.OutPoints[j].TxHash, txIn.PreviousOutPointRing.OutPoints[j].Index),
				valueUnspentTXO(sbutxo.FromCoinBase, sbutxo.Height, sbutxo.Amount, sbutxo.GenerationTime, sbutxo.RingHash))
			if err != nil {
				return err
			}
			// TODO(abe):need to update the utxoring bucket? finished
			ringHash := txIn.PreviousOutPointRing.Hash()
			u, err := fetchUTXORing(ns, ringHash[:])
			if err != nil {
				return err
			}
			snIndex := -1
			for index, sn := range u.GotSerialNumberes {
				if sn.IsEqual(&txIn.SerialNumber) {
					snIndex = index
					break
				}
			}
			// delete the sn
			if snIndex != -1 {
				u.GotSerialNumberes = append(u.GotSerialNumberes[:snIndex], u.GotSerialNumberes[snIndex+1:]...)
			}
			utxoIndex := -1
			for index, flag := range u.IsMy {
				hash := u.OriginSerialNumberes[uint8(index)]
				if flag && hash.IsEqual(&txIn.SerialNumber) {
					utxoIndex = index
				}
			}
			// reset the spent flag
			if utxoIndex != -1 {
				u.Spent[utxoIndex] = false
			}
		}
	}
	return nil
}

// insertMinedTx inserts a new transaction record for a mined transaction into
// the database under the confirmed bucket. It guarantees that, if the
// tranasction was previously unconfirmed, then it will take care of cleaning up
// the unconfirmed state. All other unconfirmed double spend attempts will be
// removed as well.
func (s *Store) insertMinedTx(ns walletdb.ReadWriteBucket, rec *TxRecord,
	block *BlockMeta) error {

	// If a transaction record for this hash and block already exists, we
	// can exit early.
	if _, v := existsTxRecord(ns, &rec.Hash, &block.Block); v != nil {
		return nil
	}

	// If a block record does not yet exist for any transactions from this
	// block, insert a block record first. Otherwise, update it by adding
	// the transaction hash to the set of transactions from this block.
	var err error
	blockKey, blockValue := existsBlockRecord(ns, block.Height)
	if blockValue == nil {
		err = putBlockRecord(ns, block, &rec.Hash)
	} else {
		blockValue, err = appendRawBlockRecord(blockValue, &rec.Hash)
		if err != nil {
			return err
		}
		err = putRawBlockRecord(ns, blockKey, blockValue)
	}
	if err != nil {
		return err
	}
	if err := putTxRecord(ns, rec, &block.Block); err != nil {
		return err
	}

	// Determine if this transaction has affected our balance, and if so,
	// update it.
	if err := s.updateMinedBalance(ns, rec, block); err != nil {
		return err
	}

	// If this transaction previously existed within the store as unmined,
	// we'll need to remove it from the unmined bucket.
	if v := existsRawUnmined(ns, rec.Hash[:]); v != nil {
		log.Infof("Marking unconfirmed transaction %v mined in block %d",
			&rec.Hash, block.Height)

		if err := s.deleteUnminedTx(ns, rec); err != nil {
			return err
		}
	}

	// As there may be unconfirmed transactions that are invalidated by this
	// transaction (either being duplicates, or double spends), remove them
	// from the unconfirmed set.  This also handles removing unconfirmed
	// transaction spend chains if any other unconfirmed transactions spend
	// outputs of the removed double spend.
	if err := s.removeDoubleSpends(ns, rec); err != nil {
		return err
	}

	// Clear any locked outputs since we now have a confirmed spend for
	// them, making them not eligible for coin selection anyway.
	for _, txIn := range rec.MsgTx.TxIn {
		if err := unlockOutput(ns, txIn.PreviousOutPoint); err != nil {
			return err
		}
	}

	return nil
}

// AddCredit marks a transaction record as containing a transaction output
// spendable by wallet.  The output is added unspent, and is marked spent
// when a new transaction spending the output is inserted into the store.
//
// TODO(jrick): This should not be necessary.  Instead, pass the indexes
// that are known to contain credits when a transaction or merkleblock is
// inserted into the store.
func (s *Store) AddCredit(ns walletdb.ReadWriteBucket, rec *TxRecord, block *BlockMeta, index uint32, change bool) error {
	if int(index) >= len(rec.MsgTx.TxOut) {
		str := "transaction output does not exist"
		return storeError(ErrInput, str, nil)
	}

	isNew, err := s.addCredit(ns, rec, block, index, change)
	if err == nil && isNew && s.NotifyUnspent != nil {
		s.NotifyUnspent(&rec.Hash, index)
	}
	return err
}

// addCredit is an AddCredit helper that runs in an update transaction.  The
// bool return specifies whether the unspent output is newly added (true) or a
// duplicate (false).
func (s *Store) addCredit(ns walletdb.ReadWriteBucket, rec *TxRecord, block *BlockMeta, index uint32, change bool) (bool, error) {
	if block == nil {
		// If the outpoint that we should mark as credit already exists
		// within the store, either as unconfirmed or confirmed, then we
		// have nothing left to do and can exit.
		k := canonicalOutPoint(&rec.Hash, index)
		if existsRawUnminedCredit(ns, k) != nil {
			return false, nil
		}
		if _, tv := latestTxRecord(ns, &rec.Hash); tv != nil {
			log.Tracef("Ignoring credit for existing confirmed transaction %v",
				rec.Hash.String())
			return false, nil
		}
		v := valueUnminedCredit(abeutil.Amount(rec.MsgTx.TxOut[index].Value), change)
		return true, putRawUnminedCredit(ns, k, v)
	}

	k, v := existsCredit(ns, &rec.Hash, index, &block.Block)
	if v != nil {
		return false, nil
	}

	txOutAmt := abeutil.Amount(rec.MsgTx.TxOut[index].Value)
	log.Debugf("Marking transaction %v output %d (%v) spendable",
		rec.Hash, index, txOutAmt)

	cred := credit{
		outPoint: wire.OutPoint{
			Hash:  rec.Hash,
			Index: index,
		},
		block:   block.Block,
		amount:  txOutAmt,
		change:  change,
		spentBy: indexedIncidence{index: ^uint32(0)},
	}
	v = valueUnspentCredit(&cred)
	err := putRawCredit(ns, k, v)
	if err != nil {
		return false, err
	}

	minedBalance, err := fetchMinedBalance(ns)
	if err != nil {
		return false, err
	}
	err = putMinedBalance(ns, minedBalance+txOutAmt)
	if err != nil {
		return false, err
	}

	return true, putUnspent(ns, &cred.outPoint, &block.Block)
}

// Rollback removes all blocks at height onwards, moving any transactions within
// each block to the unconfirmed pool.
func (s *Store) Rollback(ns walletdb.ReadWriteBucket, height int32) error {
	return s.rollback(ns, height)
}

func (s *Store) RollbackAbe(ns walletdb.ReadWriteBucket, height int32) error {
	return s.rollbackAbe(ns, height)
}

//	todo(ABE):
func (s *Store) rollback(ns walletdb.ReadWriteBucket, height int32) error {
	minedBalance, err := fetchMinedBalance(ns)
	if err != nil {
		return err
	}

	// Keep track of all credits that were removed from coinbase
	// transactions.  After detaching all blocks, if any transaction record
	// exists in unmined that spends these outputs, remove them and their
	// spend chains.
	//
	// It is necessary to keep these in memory and fix the unmined
	// transactions later since blocks are removed in increasing order.
	var coinBaseCredits []wire.OutPoint
	var heightsToRemove []int32

	it := makeReverseBlockIterator(ns)
	for it.prev() {
		b := &it.elem
		if it.elem.Height < height {
			break
		}

		heightsToRemove = append(heightsToRemove, it.elem.Height)

		log.Infof("Rolling back %d transactions from block %v height %d",
			len(b.transactions), b.Hash, b.Height)

		for i := range b.transactions {
			txHash := &b.transactions[i]

			recKey := keyTxRecord(txHash, &b.Block)
			recVal := existsRawTxRecord(ns, recKey)
			var rec TxRecord
			err = readRawTxRecord(txHash, recVal, &rec)
			if err != nil {
				return err
			}

			err = deleteTxRecord(ns, txHash, &b.Block)
			if err != nil {
				return err
			}

			// Handle coinbase transactions specially since they are
			// not moved to the unconfirmed store.  A coinbase cannot
			// contain any debits, but all credits should be removed
			// and the mined balance decremented.
			if blockchain.IsCoinBaseTx(&rec.MsgTx) {
				op := wire.OutPoint{Hash: rec.Hash}
				for i, output := range rec.MsgTx.TxOut {
					k, v := existsCredit(ns, &rec.Hash,
						uint32(i), &b.Block)
					if v == nil {
						continue
					}
					op.Index = uint32(i)

					coinBaseCredits = append(coinBaseCredits, op)

					unspentKey, credKey := existsUnspent(ns, &op)
					if credKey != nil {
						minedBalance -= abeutil.Amount(output.Value)
						err = deleteRawUnspent(ns, unspentKey)
						if err != nil {
							return err
						}
					}
					err = deleteRawCredit(ns, k)
					if err != nil {
						return err
					}
				}

				continue
			}

			err = putRawUnmined(ns, txHash[:], recVal) //	todo(ABE): The wallet maintains the transactions that are in mempool but not mined. Does ABE need this?
			//	todo(ABE): As ABE cannot support filter or AddressReceiveNotifiction, or OutPointSpent notification, it will have to be notified for all transactions received by mempool.
			//	 Thus, ABE may not need to maintain the unmined Tx.
			if err != nil {
				return err
			}

			// For each debit recorded for this transaction, mark
			// the credit it spends as unspent (as long as it still
			// exists) and delete the debit.  The previous output is
			// recorded in the unconfirmed store for every previous
			// output, not just debits.
			for i, input := range rec.MsgTx.TxIn {
				prevOut := &input.PreviousOutPoint
				prevOutKey := canonicalOutPoint(&prevOut.Hash,
					prevOut.Index)
				err = putRawUnminedInput(ns, prevOutKey, rec.Hash[:])
				if err != nil {
					return err
				}

				// If this input is a debit, remove the debit
				// record and mark the credit that it spent as
				// unspent, incrementing the mined balance.
				debKey, credKey, err := existsDebit(ns,
					&rec.Hash, uint32(i), &b.Block)
				if err != nil {
					return err
				}
				if debKey == nil {
					continue
				}

				// unspendRawCredit does not error in case the
				// no credit exists for this key, but this
				// behavior is correct.  Since blocks are
				// removed in increasing order, this credit
				// may have already been removed from a
				// previously removed transaction record in
				// this rollback.
				var amt abeutil.Amount
				amt, err = unspendRawCredit(ns, credKey)
				if err != nil {
					return err
				}
				err = deleteRawDebit(ns, debKey)
				if err != nil {
					return err
				}

				// If the credit was previously removed in the
				// rollback, the credit amount is zero.  Only
				// mark the previously spent credit as unspent
				// if it still exists.
				//	todo(ABE): Why 'removed' by 'amount being zero'?
				if amt == 0 {
					continue
				}
				unspentVal, err := fetchRawCreditUnspentValue(credKey)
				if err != nil {
					return err
				}
				minedBalance += amt
				err = putRawUnspent(ns, prevOutKey, unspentVal)
				if err != nil {
					return err
				}
			}

			// For each detached non-coinbase credit, move the
			// credit output to unmined.  If the credit is marked
			// unspent, it is removed from the utxo set and the
			// mined balance is decremented.
			//
			// TODO: use a credit iterator
			for i, output := range rec.MsgTx.TxOut {
				k, v := existsCredit(ns, &rec.Hash, uint32(i),
					&b.Block)
				if v == nil {
					continue
				}

				amt, change, err := fetchRawCreditAmountChange(v)
				if err != nil {
					return err
				}
				outPointKey := canonicalOutPoint(&rec.Hash, uint32(i))
				unminedCredVal := valueUnminedCredit(amt, change)
				err = putRawUnminedCredit(ns, outPointKey, unminedCredVal)
				if err != nil {
					return err
				}

				err = deleteRawCredit(ns, k)
				if err != nil {
					return err
				}

				credKey := existsRawUnspent(ns, outPointKey)
				if credKey != nil {
					minedBalance -= abeutil.Amount(output.Value)
					err = deleteRawUnspent(ns, outPointKey)
					if err != nil {
						return err
					}
				}
			}
		}

		// reposition cursor before deleting this k/v pair and advancing to the
		// previous.
		it.reposition(it.elem.Height)

		// Avoid cursor deletion until bolt issue #620 is resolved.
		// err = it.delete()
		// if err != nil {
		// 	return err
		// }
	}
	if it.err != nil {
		return it.err
	}

	// Delete the block records outside of the iteration since cursor deletion
	// is broken.
	for _, h := range heightsToRemove {
		err = deleteBlockRecord(ns, h)
		if err != nil {
			return err
		}
	}

	for _, op := range coinBaseCredits {
		opKey := canonicalOutPoint(&op.Hash, op.Index)
		unminedSpendTxHashKeys := fetchUnminedInputSpendTxHashes(ns, opKey)
		for _, unminedSpendTxHashKey := range unminedSpendTxHashKeys {
			unminedVal := existsRawUnmined(ns, unminedSpendTxHashKey[:])

			// If the spending transaction spends multiple outputs
			// from the same transaction, we'll find duplicate
			// entries within the store, so it's possible we're
			// unable to find it if the conflicts have already been
			// removed in a previous iteration.
			if unminedVal == nil {
				continue
			}

			var unminedRec TxRecord
			unminedRec.Hash = unminedSpendTxHashKey
			err = readRawTxRecord(&unminedRec.Hash, unminedVal, &unminedRec)
			if err != nil {
				return err
			}

			log.Debugf("Transaction %v spends a removed coinbase "+
				"output -- removing as well", unminedRec.Hash)
			err = s.removeConflict(ns, &unminedRec)
			if err != nil {
				return err
			}
		}
	}

	return putMinedBalance(ns, minedBalance)
}

// TODO(abe): we center with block not transaction, because we do not support single transaction
// TODO(abe): need to update the balance in the function.
//TODO(abe):this function need to be test
// we will delete the block after given height in database
func (s *Store) rollbackAbe(ns walletdb.ReadWriteBucket, height int32) error {
	balance, err := fetchMinedBalance(ns)
	if err != nil {
		return err
	}
	keysToRemove := make(map[int32][]byte)
	maxHeight := height
	// because we do not know whether the blockAbeIterator works properly,
	// we just use as following:
	err = ns.NestedReadBucket(bucketBlockOutputs).ForEach(func(k []byte, v []byte) error {
		heightK := int32(byteOrder.Uint32(k[0:4]))
		if heightK >= height {
			keysToRemove[heightK] = k
			if maxHeight < heightK {
				maxHeight = heightK
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	// flag:=0 //delete the ring and utxoting if height%3==2,and delete next height
	//TODO(Abe): what influence about previous two block when we delete a height-2 block?
	// TODO(abe):use the blockabeIterator to iterator reversely the blockabe bucket
	for i := maxHeight; i > height; i-- {
		willDeleteRingHash := make(map[chainhash.Hash]struct{})
		// modify the ring hash of outputs in previous two blocks
		if i%3 == 2 {
			// previous two blocks' outputs
			outpoint1, err := fetchBlockAbeOutputWithHeight(ns, i-1)
			if err != nil {
				return err
			}
			for j := 0; j < len(outpoint1); j++ {
				k := canonicalOutPointAbe(outpoint1[j].TxHash, outpoint1[j].Index)
				txo, err := fetchUnspentTXO(ns, outpoint1[j].TxHash, outpoint1[j].Index)
				if err == nil { // this output is in unspent txo bucket
					if _, ok := willDeleteRingHash[txo.RingHash]; !ok {
						willDeleteRingHash[txo.RingHash] = struct{}{}
					}
					newV := valueUnspentTXO(txo.FromCoinBase, txo.Height, txo.Amount, txo.GenerationTime, chainhash.ZeroHash)
					err := putRawUnspentTXO(ns, k, newV)
					if err != nil {
						return fmt.Errorf("putRawUnspentTXO error in rollbackAbe : %v", err)
					}
				} else { //this output is in spent but unmined bucket
					unmined, err := fetchSpentButUnminedTXO(ns, outpoint1[j].TxHash, outpoint1[j].Index)
					if err != nil {
						return err // means error
					}
					if _, ok := willDeleteRingHash[txo.RingHash]; !ok {
						willDeleteRingHash[txo.RingHash] = struct{}{}
					}
					newV := valueUnspentTXO(unmined.FromCoinBase, unmined.Height, unmined.Amount, unmined.GenerationTime, chainhash.ZeroHash)
					err = putRawUnspentTXO(ns, k, newV) // move to unspent txo bucket
					if err != nil {
						return fmt.Errorf("putRawUnspentTXO error in rollbackAbe : %v", err)
					}

				}
			}

			outpoint2, err := fetchBlockAbeOutputWithHeight(ns, i-2)
			if err != nil {
				return err
			}
			for j := 0; j < len(outpoint2); j++ {
				k := canonicalOutPointAbe(outpoint2[j].TxHash, outpoint2[j].Index)
				txo, err := fetchUnspentTXO(ns, outpoint2[j].TxHash, outpoint2[j].Index)
				if err == nil {
					if _, ok := willDeleteRingHash[txo.RingHash]; !ok {
						willDeleteRingHash[txo.RingHash] = struct{}{}
					}
					newV := valueUnspentTXO(txo.FromCoinBase, txo.Height, txo.Amount, txo.GenerationTime, chainhash.ZeroHash)
					err := putRawUnspentTXO(ns, k, newV)
					if err != nil {
						return fmt.Errorf("putRawUnspentTXO error in rollbackAbe : %v", err)
					}
				} else {
					unmined, err := fetchSpentButUnminedTXO(ns, outpoint2[j].TxHash, outpoint2[j].Index)
					if err != nil {
						return err
					}
					if _, ok := willDeleteRingHash[txo.RingHash]; !ok {
						willDeleteRingHash[txo.RingHash] = struct{}{}
					}
					newV := valueUnspentTXO(unmined.FromCoinBase, unmined.Height, unmined.Amount, unmined.GenerationTime, chainhash.ZeroHash)
					err = putRawUnspentTXO(ns, k, newV)
					if err != nil {
						return fmt.Errorf("putRawUnspentTXO error in rollbackAbe : %v", err)
					}

				}
			}
		}
		//deleted current block output
		outpoints, err := fetchRawBlockAbeOutput(ns, keysToRemove[i])
		relevantTx := make(map[chainhash.Hash]struct{})
		if err != nil {
			return fmt.Errorf("fetchRawBlockAbeOutput in rollback is error:%v", err)
		}
		for _, output := range outpoints { //delete the output generated by this block
			// if delete a unexisting one from db, what will happen?
			if _, ok := relevantTx[output.TxHash]; !ok {
				relevantTx[output.TxHash] = struct{}{}
			}
			k := canonicalOutPointAbe(output.TxHash, output.Index)
			txo, err := fetchUnspentTXO(ns, output.TxHash, output.Index)
			if err == nil { //TODO(abe):it must be txo!=nil when err==nil
				if i%3 == 2 { // if the height is 2 mod 3, it need to remove the ring
					if _, ok := willDeleteRingHash[txo.RingHash]; !ok {
						willDeleteRingHash[txo.RingHash] = struct{}{}
					}
				}
				err := deleteUnspentTXO(ns, k)
				if err != nil {
					return fmt.Errorf("error in deleteUnspentTXO in rollback")
				}
				amt, err := abeutil.NewAmountAbe(float64(txo.Amount))
				if err != nil {
					return err
				}
				balance -= amt
			} else {
				_, err := fetchSpentButUnminedTXO(ns, output.TxHash, output.Index)
				if err != nil {
					return err // means error
				}
				if _, ok := willDeleteRingHash[txo.RingHash]; !ok {
					willDeleteRingHash[txo.RingHash] = struct{}{}
				}
				err = deleteSpentButUnminedTXO(ns, k)
				if err != nil {
					return fmt.Errorf("error in deleteSpentButUnminedTXO in rollback")
				}
				// the amount should not be minus, because this output is in a transaction.
				//amt, err := abeutil.NewAmountAbe(float64(unminedTXO.Amount))
				//if err != nil {
				//	return err
				//}
				//balance -= amt
			}

			// actually, the utxo can not in the bucket SpentAndConfirmed
			//err = deleteSpentConfirmedTXO(ns, canonicalOutPointAbe(output.TxHash, output.Index))
			//if err != nil {
			//	return fmt.Errorf("error in deleteSpentConfirmedTXO in rollback")
			//}
			//flag--
		}
		if i%3 == 2 {
			//delete the utxoring and the ring
			for hash, _ := range willDeleteRingHash {
				err := deleteUTXORing(ns, hash[:])
				if err != nil {
					return fmt.Errorf("error in deleteUTXORing in rollbackAbe: %v", err)
				}
				err = deleteRingDetails(ns, hash[:]) //delete the ring detail when delete the utxo ring in rollback
				if err != nil {
					return fmt.Errorf("error in deleteRingDetail in rollbackAbe: %v", err)
				}
			}
		}

		// restore the input in block
		utxoRings, ss, err := fetchBlockAbeInput(ns, keysToRemove[i]) //there should be fetch the byte not the utxoRing
		for j := 0; j < len(utxoRings); j++ {
			u, err := fetchUTXORing(ns, utxoRings[j].RingHash[:])
			if err != nil {
				// if the utxo ring do not exist in utxoring bucket, it means that the utxoring is delete when processing this block
				// restore the outputs deleted when attaching this block
				for k := 0; k < len(utxoRings[j].IsMy); k++ {
					if utxoRings[j].IsMy[k] && !utxoRings[j].Spent[k] { // is my but not spend
						k := canonicalOutPointAbe(utxoRings[j].TxHashes[k], utxoRings[j].OutputIndexes[k])
						v := ns.NestedReadBucket(bucketSpentConfirmed).Get(k)
						//amt, err := abeutil.NewAmountAbe(float64(byteOrder.Uint64(v[5:13])))
						//if err != nil {
						//	return err
						//}
						//balance += amt
						err = putRawSpentButUnminedTXO(ns, k, v[:len(v)-8])
						if err != nil {
							return err
						}
					}
				}
				err := putRawUTXORing(ns, utxoRings[j].RingHash[:], utxoRings[j].Serialize()[32:])
				if err != nil {
					return err
				}
			} else {
				// compare the delta and update the utxo ring entry
				for k := 0; k < len(ss[j]); k++ {
					for m, sn := range utxoRings[j].OriginSerialNumberes {
						if sn.IsEqual(ss[j][k]) && utxoRings[j].IsMy[m] && !utxoRings[j].Spent[m] {
							k := canonicalOutPointAbe(utxoRings[j].TxHashes[m], utxoRings[j].OutputIndexes[m])
							v := ns.NestedReadBucket(bucketSpentConfirmed).Get(k)
							//amt, err := abeutil.NewAmountAbe(float64(byteOrder.Uint64(v[5:13])))
							//if err != nil {
							//	return err
							//}
							//balance += amt
							err = putRawSpentButUnminedTXO(ns, k, v[:len(v)-8])
							if err != nil {
								return err
							}
							break
						}
					}
					// update the origin serialNumber
					for index, sn := range u.OriginSerialNumberes {
						if _, ok := utxoRings[j].OriginSerialNumberes[index]; !ok {
							utxoRings[j].OriginSerialNumberes[index] = sn
						}
					}
				}
				err = putRawUTXORing(ns, utxoRings[j].RingHash[:], utxoRings[j].Serialize()[32:])
				if err != nil {
					return err
				}
			}
		}
		//delete the block
		block, err := deleteRawBlockAbeWithBlockHeight(ns, i)
		if err != nil {
			return fmt.Errorf("deleteRawBlockAbeWithBlockHeight in rollbackAbe with err:%v", err)
		}
		// move the relevant transaction into unmined transaction
		for i := 0; i < len(block.TxRecordAbes); i++ {
			if _, ok := relevantTx[block.TxRecordAbes[i].Hash]; ok {
				rec := block.TxRecordAbes[i]
				v, err := valueTxRecordAbe(rec)
				if err != nil {
					return err
				}
				err = putRawUnminedAbe(ns.NestedReadWriteBucket(bucketUnminedAbe), rec.Hash[:], v)
			}
		}

	}
	return putMinedBalance(ns, balance)
}

// UnspentOutputs returns all unspent received transaction outputs.
// The order is undefined.
func (s *Store) UnspentOutputs(ns walletdb.ReadBucket) ([]Credit, error) {
	var unspent []Credit

	var op wire.OutPoint
	var block Block
	err := ns.NestedReadBucket(bucketUnspent).ForEach(func(k, v []byte) error {
		//	todo(ABE): k is for Outpoint (TxHash||Index), and b is for block (height||hash)
		err := readCanonicalOutPoint(k, &op)
		if err != nil {
			return err
		}

		// Skip the output if it's locked.
		_, _, isLocked := isLockedOutput(ns, op, s.clock.Now())
		if isLocked {
			return nil
		}

		//	todo(ABE): what happens when a TXO is spent and confirmed by a block?
		if existsRawUnminedInput(ns, k) != nil {
			// Output is spent by an unmined transaction.
			// Skip this k/v pair.
			return nil
		}

		err = readUnspentBlock(v, &block)
		if err != nil {
			return err
		}

		blockTime, err := fetchBlockTime(ns, block.Height)
		if err != nil {
			return err
		}
		// TODO(jrick): reading the entire transaction should
		// be avoidable.  Creating the credit only requires the
		// output amount and pkScript.
		//	todo(ABE): Agreed on that Creating the credit only requires the output amount and pkScript.
		//	todo(ABE): The wallet database should be TXO-centric.
		rec, err := fetchTxRecord(ns, &op.Hash, &block)
		if err != nil {
			return fmt.Errorf("unable to retrieve transaction %v: "+
				"%v", op.Hash, err)
		}
		txOut := rec.MsgTx.TxOut[op.Index]
		cred := Credit{
			OutPoint: op,
			BlockMeta: BlockMeta{
				Block: block,
				Time:  blockTime,
			},
			Amount:       abeutil.Amount(txOut.Value),
			PkScript:     txOut.PkScript,
			Received:     rec.Received,
			FromCoinBase: blockchain.IsCoinBaseTx(&rec.MsgTx),
		}
		unspent = append(unspent, cred)
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
	err = ns.NestedReadBucket(bucketUnminedCredits).ForEach(func(k, v []byte) error {
		if err := readCanonicalOutPoint(k, &op); err != nil {
			return err
		}

		// Skip the output if it's locked.
		_, _, isLocked := isLockedOutput(ns, op, s.clock.Now())
		if isLocked {
			return nil
		}

		if existsRawUnminedInput(ns, k) != nil {
			// Output is spent by an unmined transaction.
			// Skip to next unmined credit.
			return nil
		}

		// TODO(jrick): Reading/parsing the entire transaction record
		// just for the output amount and script can be avoided.
		recVal := existsRawUnmined(ns, op.Hash[:])
		var rec TxRecord
		err = readRawTxRecord(&op.Hash, recVal, &rec)
		if err != nil {
			return fmt.Errorf("unable to retrieve raw transaction "+
				"%v: %v", op.Hash, err)
		}

		txOut := rec.MsgTx.TxOut[op.Index]
		cred := Credit{
			OutPoint: op,
			BlockMeta: BlockMeta{
				Block: Block{Height: -1},
			},
			Amount:       abeutil.Amount(txOut.Value),
			PkScript:     txOut.PkScript,
			Received:     rec.Received,
			FromCoinBase: blockchain.IsCoinBaseTx(&rec.MsgTx),
		}
		unspent = append(unspent, cred)
		return nil
	})
	if err != nil {
		if _, ok := err.(Error); ok {
			return nil, err
		}
		str := "failed iterating unmined credits bucket"
		return nil, storeError(ErrDatabase, str, err)
	}

	return unspent, nil
}

func (s *Store) UnspentOutputsAbe(ns walletdb.ReadBucket) ([]UnspentUTXO, error) {
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

		//err = readCanonicalBlockAbe(k, &block)
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
func (s *Store) Balance(ns walletdb.ReadBucket, minConf int32, syncHeight int32) (abeutil.Amount, error) {
	bal, err := fetchMinedBalance(ns)
	if err != nil {
		return 0, err
	}

	// Subtract the balance for each credit that is spent by an unmined
	// transaction.
	var op wire.OutPoint
	var block Block
	err = ns.NestedReadBucket(bucketUnspent).ForEach(func(k, v []byte) error {
		err := readCanonicalOutPoint(k, &op)
		if err != nil {
			return err
		}
		err = readUnspentBlock(v, &block)
		if err != nil {
			return err
		}

		// Subtract the output's amount if it's locked.
		_, _, isLocked := isLockedOutput(ns, op, s.clock.Now())
		if isLocked {
			_, v := existsCredit(ns, &op.Hash, op.Index, &block)
			amt, err := fetchRawCreditAmount(v)
			if err != nil {
				return err
			}
			bal -= amt

			// To prevent decrementing the balance twice if the
			// output has an unconfirmed spend, return now.
			return nil
		}

		if existsRawUnminedInput(ns, k) != nil {
			_, v := existsCredit(ns, &op.Hash, op.Index, &block)
			amt, err := fetchRawCreditAmount(v)
			if err != nil {
				return err
			}
			bal -= amt
		}

		return nil
	})
	if err != nil {
		if _, ok := err.(Error); ok {
			return 0, err
		}
		str := "failed iterating unspent outputs"
		return 0, storeError(ErrDatabase, str, err)
	}

	// Decrement the balance for any unspent credit with less than
	// minConf confirmations and any (unspent) immature coinbase credit.
	coinbaseMaturity := int32(s.chainParams.CoinbaseMaturity)
	stopConf := minConf
	if coinbaseMaturity > stopConf {
		stopConf = coinbaseMaturity
	}
	lastHeight := syncHeight - stopConf
	blockIt := makeReadReverseBlockIterator(ns)
	for blockIt.prev() {
		block := &blockIt.elem

		if block.Height < lastHeight {
			break
		}

		for i := range block.transactions {
			txHash := &block.transactions[i]
			rec, err := fetchTxRecord(ns, txHash, &block.Block)
			if err != nil {
				return 0, err
			}
			numOuts := uint32(len(rec.MsgTx.TxOut))
			for i := uint32(0); i < numOuts; i++ {
				// Avoid double decrementing the credit amount
				// if it was already removed for being spent by
				// an unmined tx or being locked.
				op = wire.OutPoint{Hash: *txHash, Index: i}
				_, _, isLocked := isLockedOutput(
					ns, op, s.clock.Now(),
				)
				if isLocked {
					continue
				}
				opKey := canonicalOutPoint(txHash, i)
				if existsRawUnminedInput(ns, opKey) != nil {
					continue
				}

				_, v := existsCredit(ns, txHash, i, &block.Block)
				if v == nil {
					continue
				}
				amt, spent, err := fetchRawCreditAmountSpent(v)
				if err != nil {
					return 0, err
				}
				if spent {
					continue
				}
				confs := syncHeight - block.Height + 1
				if confs < minConf || (blockchain.IsCoinBaseTx(&rec.MsgTx) &&
					confs < coinbaseMaturity) {
					bal -= amt
				}
			}
		}
	}
	if blockIt.err != nil {
		return 0, blockIt.err
	}

	// If unmined outputs are included, increment the balance for each
	// output that is unspent.
	if minConf == 0 {
		err = ns.NestedReadBucket(bucketUnminedCredits).ForEach(func(k, v []byte) error {
			if err := readCanonicalOutPoint(k, &op); err != nil {
				return err
			}

			// Skip adding the balance for this output if it's
			// locked.
			_, _, isLocked := isLockedOutput(ns, op, s.clock.Now())
			if isLocked {
				return nil
			}

			if existsRawUnminedInput(ns, k) != nil {
				// Output is spent by an unmined transaction.
				// Skip to next unmined credit.
				return nil
			}

			amount, err := fetchRawUnminedCreditAmount(v)
			if err != nil {
				return err
			}
			bal += amount
			return nil
		})
		if err != nil {
			if _, ok := err.(Error); ok {
				return 0, err
			}
			str := "failed to iterate over unmined credits bucket"
			return 0, storeError(ErrDatabase, str, err)
		}
	}

	return bal, nil
}
func (s *Store) BalanceAbe(ns walletdb.ReadBucket, minConf int32, syncHeight int32) ([]abeutil.Amount, error) {
	var allBal, immatureBal abeutil.Amount
	bal, err := fetchMinedBalance(ns)
	if err != nil {
		return []abeutil.Amount{}, err
	}
	// Subtract the balance for each credit that is spent by an unmined
	// transaction.
	//var op wire.OutPointAbe
	var block BlockAbe
	// This for each should be reversed iteration
	err = ns.NestedReadBucket(bucketBlockAbes).ForEach(func(k, v []byte) error {
		err := readUnspentBlockAbe(k, &block)
		if err != nil {
			return err
		}
		// Subtract the output's amount if it's locked.
		// TODO(abe):Abe do not support lock the output at this moment
		//_, _, isLocked := isLockedOutput(ns, op, s.clock.Now())
		//if isLocked {
		//	_, v := existsCredit(ns, &op.Hash, op.Index, &block)
		//	amt, err := fetchRawCreditAmount(v)
		//	if err != nil {
		//		return err
		//	}
		//	bal -= amt
		//
		//	// To prevent decrementing the balance twice if the
		//	// output has an unconfirmed spend, return now.
		//	return nil
		//}
		if block.Height < syncHeight-minConf {
			return nil
		}
		outputs, err := fetchBlockAbeOutput(ns, block.Height, block.Hash) // minus the block outputs if it exist in UnspentTXO bucket
		if err != nil && err.Error() != "the entry is empty" {            //TODO(abe):design a special error to represent the type "empty entry", it can reference btcwallet
			return err
		}
		for _, output := range outputs {
			txo, err := fetchUnspentTXO(ns, output.TxHash, output.Index)
			if err != nil { // have been spent
				continue
			} else {
				amt, err := abeutil.NewAmountAbe(float64(txo.Amount))
				if err != nil {
					return err
				}
				bal -= amt
			}
		}
		return nil
	})
	if err != nil {
		if _, ok := err.(Error); ok {
			return []abeutil.Amount{}, err
		}
		str := "failed iterating unspent outputs"
		return []abeutil.Amount{}, storeError(ErrDatabase, str, err)
	}
	allBal = bal //total amount
	// Decrement the balance for any unspent credit with less than
	// minConf confirmations and any (unspent) immature coinbase credit.
	coinbaseMaturity := int32(s.chainParams.CoinbaseMaturity)
	stopConf := minConf
	if coinbaseMaturity > stopConf {
		stopConf = coinbaseMaturity
	}
	lastHeight := syncHeight - stopConf
	err = ns.NestedReadBucket(bucketBlockAbes).ForEach(func(k, v []byte) error {
		err := readUnspentBlockAbe(k, &block)
		if err != nil {
			return err
		}
		// Subtract the output's amount if it's locked.
		// TODO(abe):Abe do not support lock the output at this moment
		//_, _, isLocked := isLockedOutput(ns, op, s.clock.Now())
		//if isLocked {
		//	_, v := existsCredit(ns, &op.Hash, op.Index, &block)
		//	amt, err := fetchRawCreditAmount(v)
		//	if err != nil {
		//		return err
		//	}
		//	bal -= amt
		//
		//	// To prevent decrementing the balance twice if the
		//	// output has an unconfirmed spend, return now.
		//	return nil
		//}
		if block.Height < lastHeight || block.Height >= syncHeight-minConf {
			return nil
		}
		outputs, err := fetchBlockAbeOutput(ns, block.Height, block.Hash) // minus the block outputs if it exist in UnspentTXO bucket
		if err != nil && err.Error() != "the entry is empty" {
			return err
		}
		for _, output := range outputs {
			txo, err := fetchUnspentTXO(ns, output.TxHash, output.Index)
			if err != nil { // have been spent
				continue
			} else if txo.FromCoinBase {
				amt, err := abeutil.NewAmountAbe(float64(txo.Amount))
				if err != nil {
					return err
				}
				bal -= amt
			}
		}
		return nil
	})
	immatureBal = allBal - bal
	if err != nil {
		if _, ok := err.(Error); ok {
			return []abeutil.Amount{}, err
		}
		str := "failed iterating unspent outputs"
		return []abeutil.Amount{}, storeError(ErrDatabase, str, err)
	}

	// If unmined outputs are included, increment the balance for each
	// output that is unspent.
	// TODO(abe): we can not spent the outputs created by unmined tx
	//if minConf == 0 {
	//	err = ns.NestedReadBucket(bucketUnminedCredits).ForEach(func(k, v []byte) error {
	//		if err := readCanonicalOutPoint(k, &op); err != nil {
	//			return err
	//		}
	//
	//		// Skip adding the balance for this output if it's
	//		// locked.
	//		_, _, isLocked := isLockedOutput(ns, op, s.clock.Now())
	//		if isLocked {
	//			return nil
	//		}
	//
	//		if existsRawUnminedInput(ns, k) != nil {
	//			// Output is spent by an unmined transaction.
	//			// Skip to next unmined credit.
	//			return nil
	//		}
	//
	//		amount, err := fetchRawUnminedCreditAmount(v)
	//		if err != nil {
	//			return err
	//		}
	//		bal += amount
	//		return nil
	//	})
	//	if err != nil {
	//		if _, ok := err.(Error); ok {
	//			return 0, err
	//		}
	//		str := "failed to iterate over unmined credits bucket"
	//		return 0, storeError(ErrDatabase, str, err)
	//	}
	//}

	return []abeutil.Amount{allBal, bal, immatureBal}, nil
}
func (s *Store) BalanceAbeNew(ns walletdb.ReadBucket, minConf int32, syncHeight int32) ([]abeutil.Amount, error) {
	allBal, err := fetchMinedBalance(ns)
	if err != nil {
		return []abeutil.Amount{}, err
	}
	spendableBal, err := fetchSpenableBalance(ns)
	if err != nil {
		return []abeutil.Amount{}, err
	}
	freezedBal, err := fetchFreezedBalance(ns)
	if err != nil {
		return []abeutil.Amount{}, err
	}
	return []abeutil.Amount{allBal, spendableBal, freezedBal, allBal - spendableBal - freezedBal}, nil
}
func (s *Store) NeedUpdateNum(ns walletdb.ReadBucket) (int, error) {
	num:=0
	err := ForEachNeedUpdateUTXORing(ns, func(k, v []byte) error {
		num++
		return nil
	})
	return num,err
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
	k := canonicalOutPoint(&op.Hash, op.Index)
	if existsRawUnminedCredit(ns, k) != nil {
		return true
	}
	if existsRawUnspent(ns, k) != nil {
		return true
	}
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
