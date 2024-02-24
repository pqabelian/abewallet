package wtxmgr

import (
	"encoding/json"
	"fmt"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abewallet/walletdb"
)

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

// bucketAUTEntry:[autName -> [outpoint->aut coins]
func spendAUTCoin(ns walletdb.ReadWriteBucket, k []byte) (*AUTCoin, error) {
	autPointBucket := ns.NestedReadWriteBucket(bucketAUTPoint)
	v := autPointBucket.Get(k)
	if len(v) == 0 {
		return nil, nil
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

	newv := make([]byte, len(v))
	for i := 0; i < len(newv)-1; i++ {
		newv[i] = v[i]
	}
	newv[len(newv)-1] = 1
	err = autPointBucket.Put(k, newv)
	if err != nil {
		str := "failed to spent aut coin"
		return nil, storeError(ErrDatabase, str, err)
	}

	return autCoin, nil
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
