package wtxmgr

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abewallet/walletdb"
)

// block height || block hash -> version + []UnspentTXO 【txhash + index + amount + generationTime + ringhash】
func valueAUTCoin(coin *AUTCoin) []byte {
	res := make([]byte, chainhash.HashSize+1+4+len(coin.AUTIdentifier)+1+8+4+len(coin.AddrKey)+1)

	offset := 0
	copy(res[offset:], coin.TxOutput.TxHash[:])
	offset += chainhash.HashSize
	res[offset] = coin.TxOutput.Index
	offset += 1

	byteOrder.PutUint32(res[offset:], uint32(len(coin.AUTIdentifier)))
	offset += 4
	copy(res[offset:], coin.AUTIdentifier)
	offset += len(coin.AUTIdentifier)

	//_ = coin.IsAUTRootCoin //  byte 1
	if coin.IsAUTRootCoin {
		res[offset] = 1
	} else {
		res[offset] = 0
	}
	offset += 1

	//_ = coin.AUTCoinValue  //   8
	byteOrder.PutUint64(res[offset:], coin.AUTCoinValue)
	offset += 8

	byteOrder.PutUint32(res[offset:], uint32(len(coin.AddrKey)))
	offset += 4
	copy(res[offset:], coin.AddrKey)
	offset += len(coin.AddrKey)

	//_ = coin.Spent         //   byte 1
	if coin.Spent {
		res[offset] = 1
	} else {
		res[offset] = 0
	}
	offset += 1

	return res
}

func fetchAUTRootCoinNum(ns walletdb.ReadBucket) (map[string]uint64, error) {
	res := map[string]uint64{}

	v := ns.Get(rootAUTRootCoinNum)
	if len(v) == 0 {
		return res, nil
	}
	if err := json.Unmarshal(v, &res); err != nil {
		str := fmt.Sprintf("balance: fail to deserialize aut balance :%s", err)
		return res, storeError(ErrData, str, nil)
	}

	return res, nil
}

func putAUTRootCoinNum(ns walletdb.ReadWriteBucket, amts map[string]uint64) error {
	v, _ := json.Marshal(amts)
	err := ns.Put(rootAUTRootCoinNum, v)
	if err != nil {
		str := "failed to put aut balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func fetchAUTMinedBalance(ns walletdb.ReadBucket) (map[string]uint64, error) {
	res := map[string]uint64{}

	v := ns.Get(rootAUTBalance)

	if len(v) == 0 {
		return res, nil
	}

	if err := json.Unmarshal(v, &res); err != nil {
		str := fmt.Sprintf("balance: fail to deserialize aut balance :%s", err)
		return res, storeError(ErrData, str, nil)
	}

	return res, nil
}

func putAUTMinedBalance(ns walletdb.ReadWriteBucket, amts map[string]uint64) error {
	v, _ := json.Marshal(amts)
	err := ns.Put(rootAUTBalance, v)
	if err != nil {
		str := "failed to put aut balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func fetchAUTSpenableBalance(ns walletdb.ReadBucket) (map[string]uint64, error) {
	res := map[string]uint64{}

	v := ns.Get(rootAUTSpendableBalance)
	if len(v) == 0 {
		return res, nil
	}

	if err := json.Unmarshal(v, &res); err != nil {
		str := fmt.Sprintf("balance: fail to deserialize aut spendable balance :%s", err)
		return res, storeError(ErrData, str, nil)
	}

	return res, nil
}

func putAUTSpenableBalance(ns walletdb.ReadWriteBucket, amts map[string]uint64) error {
	v, _ := json.Marshal(amts)
	err := ns.Put(rootAUTSpendableBalance, v)
	if err != nil {
		str := "failed to put aut spendable balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func fetchAUTSpenableRootCoinNum(ns walletdb.ReadBucket) (map[string]uint64, error) {
	res := map[string]uint64{}

	v := ns.Get(rootAUTSpendableRootCoinNum)
	if len(v) == 0 {
		return res, nil
	}

	if err := json.Unmarshal(v, &res); err != nil {
		str := fmt.Sprintf("balance: fail to deserialize aut spendable balance :%s", err)
		return res, storeError(ErrData, str, nil)
	}

	return res, nil
}

func putAUTSpenableRootCoinNum(ns walletdb.ReadWriteBucket, amts map[string]uint64) error {
	v, _ := json.Marshal(amts)
	err := ns.Put(rootAUTSpendableRootCoinNum, v)
	if err != nil {
		str := "failed to put aut spendable balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func fetchAUTImmatureRootCoinNum(ns walletdb.ReadBucket) (map[string]uint64, error) {
	res := map[string]uint64{}

	v := ns.Get(rootAUTImmatureRootCoinNum)
	if len(v) == 0 {
		return res, nil
	}

	if err := json.Unmarshal(v, &res); err != nil {
		str := fmt.Sprintf("balance: fail to deserialize aut immature balance :%s", err)
		return res, storeError(ErrData, str, nil)
	}

	return res, nil
}

func putAUTImmatureRootCoinNum(ns walletdb.ReadWriteBucket, amts map[string]uint64) error {
	v, _ := json.Marshal(amts)
	err := ns.Put(rootAUTImmatureRootCoinNum, v)
	if err != nil {
		str := "failed to put aut immature balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func fetchAUTImmatureTransferBalance(ns walletdb.ReadBucket) (map[string]uint64, error) {
	res := map[string]uint64{}

	v := ns.Get(rootAUTImmatureTransferBalance)
	if len(v) == 0 {
		return res, nil
	}

	if err := json.Unmarshal(v, &res); err != nil {
		str := fmt.Sprintf("balance: fail to deserialize aut immature balance :%s", err)
		return res, storeError(ErrData, str, nil)
	}

	return res, nil
}

func putAUTImmatureTransferBalance(ns walletdb.ReadWriteBucket, amts map[string]uint64) error {
	v, _ := json.Marshal(amts)
	err := ns.Put(rootAUTImmatureTransferBalance, v)
	if err != nil {
		str := "failed to put aut immature balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func fetchAUTUnconfirmedRootCoinNum(ns walletdb.ReadBucket) (map[string]uint64, error) {
	res := map[string]uint64{}

	v := ns.Get(rootAUTUnconfirmedRootCoinNum)
	if len(v) == 0 {
		return res, nil
	}

	if err := json.Unmarshal(v, &res); err != nil {
		str := fmt.Sprintf("balance: fail to deserialize aut unconfirmed balance :%s", err)
		return res, storeError(ErrData, str, nil)
	}

	return res, nil
}

func putAUTUnconfirmedRootCoinNum(ns walletdb.ReadWriteBucket, nums map[string]uint64) error {
	v, _ := json.Marshal(nums)
	err := ns.Put(rootAUTUnconfirmedRootCoinNum, v)
	if err != nil {
		str := "failed to put aut unconfirmed balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}
func fetchAUTUnconfirmedBalance(ns walletdb.ReadBucket) (map[string]uint64, error) {
	res := map[string]uint64{}

	v := ns.Get(rootAUTUnconfirmedBalance)
	if len(v) == 0 {
		return res, nil
	}

	if err := json.Unmarshal(v, &res); err != nil {
		str := fmt.Sprintf("balance: fail to deserialize aut unconfirmed balance :%s", err)
		return res, storeError(ErrData, str, nil)
	}

	return res, nil
}

func putAUTUnconfirmedBalance(ns walletdb.ReadWriteBucket, amts map[string]uint64) error {
	v, _ := json.Marshal(amts)
	err := ns.Put(rootAUTUnconfirmedBalance, v)
	if err != nil {
		str := "failed to put aut unconfirmed balance"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func putRawAUTCoin(ns walletdb.ReadWriteBucket, k, v []byte) error {
	autPointBucket := ns.NestedReadWriteBucket(bucketAUTPoint)
	err := autPointBucket.Put(k, v)
	if err != nil {
		str := "failed to put aut entry"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func fetchRawAUTCoin(ns walletdb.ReadBucket, k []byte) (*AUTCoin, error) {
	v := ns.NestedReadBucket(bucketAUTPoint).Get(k)
	if len(v) == 0 {
		str := "failed to fetch aut coin"
		return nil, storeError(ErrDatabase, str, fmt.Errorf("non-exst aut coin"))
	}

	autCoin := new(AUTCoin)
	op := &wire.OutPointAbe{}
	err := readCanonicalOutPointAbe(k, op)
	if err != nil {
		str := "failed to deserialize the outpoint"
		return nil, storeError(ErrDatabase, str, err)
	}
	err = autCoin.Deserialize(op, v)
	if err != nil {
		str := "failed to deserialize the aut coin"
		return nil, storeError(ErrDatabase, str, err)
	}

	return autCoin, err
}

func existsRawAUTCoin(ns walletdb.ReadBucket, k []byte) (v []byte) {
	return ns.NestedReadBucket(bucketAUTPoint).Get(k)
}

func deleteRawAUTCoin(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketAUTPoint).Delete(k)
	if err != nil {
		str := "failed to delete aut coin"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func valueBlockDisabledAUTRootCoins(outpoints []*wire.OutPointAbe) []byte {
	res := make([]byte, 8+len(outpoints)*(chainhash.HashSize+1))
	byteOrder.PutUint32(res[0:4], uint32(8+len(outpoints)*(chainhash.HashSize+1)))
	byteOrder.PutUint32(res[4:8], uint32(len(outpoints)))
	offset := 8
	// total size of outpoints
	for _, outpoint := range outpoints {
		copy(res[offset:offset+chainhash.HashSize], outpoint.TxHash[:])
		offset += chainhash.HashSize
		res[offset] = outpoint.Index
		offset += 1
	}
	return res
}
func putRawBlockDisabledAUTRootCoins(ns walletdb.ReadWriteBucket, k, v []byte) error {
	err := ns.NestedReadWriteBucket(bucketBlockDisabledAUTPoint).Put(k, v)
	if err != nil {
		str := "failed to put block input"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

func fetchBlockDisabledAUTRootCoins(ns walletdb.ReadWriteBucket, k []byte) ([]*wire.OutPointAbe, error) {
	v := ns.NestedReadBucket(bucketBlockDisabledAUTPoint).Get(k)
	if len(v) == 0 {
		return nil, nil
	}
	_ = byteOrder.Uint32(v[0:4])
	outpointNum := int(byteOrder.Uint32(v[4:8]))
	offset := 8
	outpoints := make([]*wire.OutPointAbe, outpointNum)
	for i := 0; i < outpointNum; i++ {
		outpoints[i] = new(wire.OutPointAbe)
		copy(outpoints[i].TxHash[:], v[offset:offset+chainhash.HashSize])
		offset += chainhash.HashSize
		outpoints[i].Index = v[offset]
		offset += 1
	}
	return outpoints, nil
}
func deleteBlockDisabledAUTRootCoins(ns walletdb.ReadWriteBucket, k []byte) error {
	err := ns.NestedReadWriteBucket(bucketBlockDisabledAUTPoint).Delete(k)
	if err != nil {
		str := "failed to delete block input"
		return storeError(ErrDatabase, str, err)
	}
	return nil
}

// bucketAUTEntry:[autName -> [outpoint->aut coins]
func spendAUTCoin(ns walletdb.ReadWriteBucket, k []byte) (*AUTCoin, bool, error) {
	autPointBucket := ns.NestedReadWriteBucket(bucketAUTPoint)
	v := autPointBucket.Get(k)
	if len(v) == 0 {
		return nil, false, nil
	}

	autCoin := new(AUTCoin)
	op := &wire.OutPointAbe{}
	err := readCanonicalOutPointAbe(k, op)
	if err != nil {
		str := "failed to deserialize the outpoint"
		return nil, false, storeError(ErrDatabase, str, err)
	}
	err = autCoin.Deserialize(op, v)
	if err != nil {
		str := "failed to deserialize the aut coin"
		return nil, false, storeError(ErrDatabase, str, err)
	}

	// record the status of aut coin to distinguish that is consumed or just disabled
	spent := autCoin.Spent

	autCoin.Spent = true
	err = autPointBucket.Put(k, valueAUTCoin(autCoin))
	if err != nil {
		str := "failed to spent aut coin"
		return nil, false, storeError(ErrDatabase, str, err)
	}

	return autCoin, spent, nil
}

func restoreAUTCoin(ns walletdb.ReadWriteBucket, k []byte) (*AUTCoin, error) {
	autPointBucket := ns.NestedReadWriteBucket(bucketAUTPoint)
	v := autPointBucket.Get(k)
	if len(v) == 0 {
		return nil, errors.New("non-exist aut coin")
	}

	autCoin := new(AUTCoin)
	op := &wire.OutPointAbe{}
	err := readCanonicalOutPointAbe(k, op)
	if err != nil {
		str := "failed to deserialize the outpoint"
		return nil, storeError(ErrDatabase, str, err)
	}
	err = autCoin.Deserialize(op, v)
	if err != nil {
		str := "failed to deserialize the aut coin"
		return nil, storeError(ErrDatabase, str, err)
	}

	autCoin.Spent = false
	err = autPointBucket.Put(k, valueAUTCoin(autCoin))
	if err != nil {
		str := "failed to spent aut coin"
		return nil, storeError(ErrDatabase, str, err)
	}

	return autCoin, nil
}
