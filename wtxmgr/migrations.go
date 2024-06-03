package wtxmgr

import (
	"encoding/hex"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abecrypto/abecryptoparam"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abewallet/walletdb"
	"github.com/abesuite/abewallet/walletdb/migration"
)

// TODO(abe): this slice should be re-design, we just have one version
// versions is a list of the different database versions. The last entry should
// reflect the latest database state. If the database happens to be at a version
// number lower than the latest, migrations will be performed in order to catch
// it up.
var versions = []migration.Version{
	{
		Number:    2,
		Migration: nil,
	},
	{
		Number:    3,
		Migration: populateStatistics,
	},
}

// getLatestVersion returns the version number of the latest database version.
func getLatestVersion() uint32 {
	return versions[len(versions)-1].Number
}

// MigrationManager is an implementation of the migration.Manager interface that
// will be used to handle migrations for the address manager. It exposes the
// necessary parameters required to successfully perform migrations.
type MigrationManager struct {
	ns     walletdb.ReadWriteBucket
	addrNs walletdb.ReadWriteBucket
}
type Options func(*MigrationManager) error

// A compile-time assertion to ensure that MigrationManager implements the
// migration.Manager interface.
var _ migration.Manager = (*MigrationManager)(nil)

// NewMigrationManager creates a new migration manager for the transaction
// manager. The given bucket should reflect the top-level bucket in which all
// of the transaction manager's data is contained within.
func NewMigrationManager(ns walletdb.ReadWriteBucket, addrNs walletdb.ReadWriteBucket) *MigrationManager {
	return &MigrationManager{
		ns:     ns,
		addrNs: addrNs,
	}
}

// Name returns the name of the service we'll be attempting to upgrade.
//
// NOTE: This method is part of the migration.Manager interface.
func (m *MigrationManager) Name() string {
	return "wallet transaction manager"
}

// Namespace returns the top-level bucket of the service.
//
// NOTE: This method is part of the migration.Manager interface.
func (m *MigrationManager) Namespace() walletdb.ReadWriteBucket {
	return m.ns
}

// CurrentVersion returns the current version of the service's database.
//
// NOTE: This method is part of the migration.Manager interface.
func (m *MigrationManager) CurrentVersion(ns walletdb.ReadBucket) (uint32, error) {
	if ns == nil {
		ns = m.ns
	}
	return fetchVersion(m.ns)
}

// SetVersion sets the version of the service's database.
//
// NOTE: This method is part of the migration.Manager interface.
func (m *MigrationManager) SetVersion(ns walletdb.ReadWriteBucket,
	version uint32) error {

	if ns == nil {
		ns = m.ns
	}
	return putVersion(m.ns, version)
}

// Versions returns all of the available database versions of the service.
//
// NOTE: This method is part of the migration.Manager interface.
func (m *MigrationManager) Versions() []migration.Version {
	return versions
}

// dropTransactionHistory is a migration that attempts to recreate the
// transaction store with a clean state.
func dropTransactionHistory(ns walletdb.ReadWriteBucket) error {
	log.Info("Dropping wallet transaction history")

	// To drop the store's transaction history, we'll need to remove all of
	// the relevant descendant buckets and key/value pairs.
	if err := deleteBuckets(ns); err != nil {
		return err
	}
	if err := ns.Delete(rootMinedBalance); err != nil {
		return err
	}

	// With everything removed, we'll now recreate our buckets.
	if err := createBuckets(ns); err != nil {
		return err
	}

	// Finally, we'll insert a 0 value for our mined balance.
	return putMinedBalance(ns, 0)
}

// populateStatistics is a migration that attempts to populate the
// statistics data
func populateStatistics(txMgrNs walletdb.ReadWriteBucket) error {
	log.Info("Populating statistics data...")

	var err error
	var statisticsBucket walletdb.ReadWriteBucket
	if statisticsBucket, err = txMgrNs.CreateBucket(bucketStatistics); err != nil {
		str := "fail to create statistics bucket"
		return storeError(ErrDatabase, str, err)
	}

	numTXO := int64(0)
	numImmatureCoinbaseTXO := int64(0)
	numImmatureTransferTXO := int64(0)
	numSpendableTXO := int64(0)
	numUnconfirmedTXO := int64(0)

	txs := map[chainhash.Hash]*TxRecord{}
	ringDetails := map[chainhash.Hash]*Ring{}

	addrMapping := map[string]struct{}{}

	addressNumTXOMapping := map[string]int64{}
	addressNumImmatureCoinbaseTXOMapping := map[string]int64{}
	addressNumImmatureTransferTXOMapping := map[string]int64{}
	addressNumSpendableTXOMapping := map[string]int64{}
	addressNumUnconfirmedTXOMapping := map[string]int64{}

	addressTotalBalanceMapping := map[string]int64{}
	addressImmatureCoinbaseTXOBalanceMapping := map[string]int64{}
	addressImmatureTransferTXOBalanceMapping := map[string]int64{}
	addressSpendableTXOBalanceMapping := map[string]int64{}
	addressUnconfirmedTXOBalanceMapping := map[string]int64{}

	findTxoAddrFromTxOrRing := func(txHash chainhash.Hash, ringIndex uint8, ringHash chainhash.Hash) (string, error) {
		var ok bool
		if !ringHash.IsEqual(&chainhash.ZeroHash) {
			var ringDetail *Ring
			if ringDetail, ok = ringDetails[ringHash]; !ok {
				ringDetail, err = fetchRingDetails(txMgrNs, ringHash[:])
				if err != nil {
					return "", err
				}
				ringDetails[ringHash] = ringDetail
			}
			coinAddress, err := abecrypto.ExtractCoinAddressFromTxoScript(ringDetail.TxoScripts[ringIndex], abecryptoparam.CryptoSchemePQRingCT)
			if err != nil {
				return "", err
			}
			return hex.EncodeToString(chainhash.DoubleHashB(coinAddress)), nil
		}

		var tx *TxRecord
		if tx, ok = txs[txHash]; !ok {
			tx, err = fetchRawConfirmedTx(txMgrNs, txHash[:])
			if err != nil {
				return "", err
			}
			if tx == nil {
				tx, err = fetchRawUnconfirmedTx(txMgrNs, txHash[:])
				if err != nil {
					return "", err
				}
			}
			txs[txHash] = tx
		}

		if tx == nil {
			return "", nil
		}
		if tx.Hash.IsEqual(&chainhash.ZeroHash) {
			return "", nil
		}

		abeTxo := tx.MsgTx.TxOuts[ringIndex]
		coinAddress, err := abecrypto.ExtractCoinAddressFromTxoScript(abeTxo.TxoScript, abecryptoparam.CryptoSchemePQRingCT)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(chainhash.DoubleHashB(coinAddress)), nil
	}

	findTxoAddrFromBlock := func(txHash chainhash.Hash, index uint8, height int32) (string, error) {
		var block *BlockRecord
		err = txMgrNs.NestedReadBucket(bucketBlocks).ForEach(func(k []byte, v []byte) error {
			heightK := int32(byteOrder.Uint32(k[0:4]))
			if heightK == height {
				block, err = readBlockBlockRecord(k, v)
				if err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return "", err
		}
		if block != nil && !block.Hash.IsEqual(&chainhash.ZeroHash) {
			for i := 0; i < len(block.MsgBlock.Transactions); i++ {
				hash := block.MsgBlock.Transactions[i].TxHash()
				if !txHash.IsEqual(&hash) {
					continue
				}
				coinAddress, err := abecrypto.ExtractCoinAddressFromTxoScript(block.MsgBlock.Transactions[i].TxOuts[index].TxoScript, abecryptoparam.CryptoSchemePQRingCT)
				if err != nil {
					return "", err
				}
				return hex.EncodeToString(chainhash.DoubleHashB(coinAddress)), nil
			}
		}
		return "", err
	}

	// fetch data from database
	// bucketImmaturedCoinbaseOutput
	err = txMgrNs.NestedReadBucket(bucketImmaturedCoinbaseOutput).ForEach(func(_, v []byte) error {
		if len(v) == 0 {
			return nil
		}
		immatureCBTXOMapping, err := deserializeImmaturedCoinbaseOutput(v)
		if err != nil {
			return err
		}
		for _, utxo := range immatureCBTXOMapping {
			numTXO++
			numImmatureCoinbaseTXO++

			if addrKey, err := findTxoAddrFromTxOrRing(utxo.TxOutput.TxHash, utxo.Index, utxo.RingHash); err == nil && addrKey != "" {
				addrMapping[addrKey] = struct{}{}
				addressNumTXOMapping[addrKey]++
				addressNumImmatureCoinbaseTXOMapping[addrKey]++

				addressTotalBalanceMapping[addrKey] += int64(utxo.Amount)
				addressImmatureCoinbaseTXOBalanceMapping[addrKey] += int64(utxo.Amount)
			} else if addrKey, err = findTxoAddrFromBlock(utxo.TxOutput.TxHash, utxo.TxOutput.Index, utxo.Height); err == nil && addrKey != "" {
				addrMapping[addrKey] = struct{}{}
				addressNumTXOMapping[addrKey]++
				addressNumImmatureCoinbaseTXOMapping[addrKey]++

				addressTotalBalanceMapping[addrKey] += int64(utxo.Amount)
				addressImmatureCoinbaseTXOBalanceMapping[addrKey] += int64(utxo.Amount)
			} else {
				// add it to pending list
				log.Debugf("immature coinbase output (hash %s, index %d) is a pending txo without address sequence num", utxo.TxOutput.TxHash, utxo.TxOutput.Index)
			}
		}

		return nil
	})
	if err != nil {
		log.Errorf("can not statistics immature coinbase output: %v", err)
		return err
	}
	// bucketImmaturedOutput
	err = txMgrNs.NestedReadBucket(bucketImmaturedOutput).ForEach(func(_, v []byte) error {
		if len(v) == 0 {
			return nil
		}
		immatureTrTXOMapping, err := deserializeImmaturedOutput(v)
		if err != nil {
			return err
		}
		for _, utxo := range immatureTrTXOMapping {
			numTXO++
			numImmatureTransferTXO++

			if addrKey, err := findTxoAddrFromTxOrRing(utxo.TxOutput.TxHash, utxo.Index, utxo.RingHash); err == nil && addrKey != "" {
				addrMapping[addrKey] = struct{}{}
				addressNumTXOMapping[addrKey]++
				addressNumImmatureTransferTXOMapping[addrKey]++

				addressTotalBalanceMapping[addrKey] += int64(utxo.Amount)
				addressImmatureTransferTXOBalanceMapping[addrKey] += int64(utxo.Amount)
			} else if addrKey, err = findTxoAddrFromBlock(utxo.TxOutput.TxHash, utxo.TxOutput.Index, utxo.Height); err == nil && addrKey != "" {
				addrMapping[addrKey] = struct{}{}
				addressNumTXOMapping[addrKey]++
				addressNumImmatureCoinbaseTXOMapping[addrKey]++

				addressTotalBalanceMapping[addrKey] += int64(utxo.Amount)
				addressImmatureCoinbaseTXOBalanceMapping[addrKey] += int64(utxo.Amount)
			} else {
				log.Errorf("immature transfer output (hash %s, index %d) is a pending txo without address sequence num, this should not happen", utxo.TxOutput.TxHash, utxo.TxOutput.Index)
			}
		}

		return nil
	})
	if err != nil {
		log.Errorf("can not statistics immature transfer output: %v", err)
		return err
	}

	// bucketMaturedOutput
	err = txMgrNs.NestedReadBucket(bucketMaturedOutput).ForEach(func(k, v []byte) error {
		if len(v) == 0 {
			return nil
		}
		op := new(wire.OutPointAbe)
		err = readCanonicalOutPointAbe(k, op)
		if err != nil {
			return nil
		}
		utxo := new(UnspentUTXO)
		err = utxo.Deserialize(&wire.OutPointAbe{TxHash: op.TxHash, Index: op.Index}, v)
		if err != nil {
			return nil
		}
		numTXO++
		numSpendableTXO++

		if addrKey, err := findTxoAddrFromTxOrRing(utxo.TxOutput.TxHash, utxo.Index, utxo.RingHash); err == nil && addrKey != "" {
			addrMapping[addrKey] = struct{}{}
			addressNumTXOMapping[addrKey]++
			addressNumSpendableTXOMapping[addrKey]++

			addressTotalBalanceMapping[addrKey] += int64(utxo.Amount)
			addressSpendableTXOBalanceMapping[addrKey] += int64(utxo.Amount)
		} else {
			// add it to pending list
			log.Errorf("mature output (hash %s, index %d) is a pending txo without address sequence num, this should not happen", utxo.TxOutput.TxHash, utxo.TxOutput.Index)
		}

		return nil
	})
	if err != nil {
		log.Errorf("can not statistics mature output: %v", err)
		return err
	}

	// bucketSpentButUnmined
	err = txMgrNs.NestedReadBucket(bucketSpentButUnmined).ForEach(func(k, v []byte) error {
		if len(v) == 0 {
			return nil
		}
		op := new(wire.OutPointAbe)
		err = readCanonicalOutPointAbe(k, op)
		if err != nil {
			return nil
		}
		utxo := new(UnspentUTXO)
		err = utxo.Deserialize(&wire.OutPointAbe{TxHash: op.TxHash, Index: op.Index}, v)
		if err != nil {
			return nil
		}
		numTXO++
		numUnconfirmedTXO++

		if addrKey, err := findTxoAddrFromTxOrRing(utxo.TxOutput.TxHash, utxo.Index, utxo.RingHash); err == nil && addrKey != "" {
			addrMapping[addrKey] = struct{}{}
			addressNumTXOMapping[addrKey]++
			addressNumUnconfirmedTXOMapping[addrKey]++

			addressTotalBalanceMapping[addrKey] += int64(utxo.Amount)
			addressUnconfirmedTXOBalanceMapping[addrKey] += int64(utxo.Amount)
		} else {
			// add it to pending list
			log.Errorf("unconfirmed output (hash %s, index %d) is a pending txo without address sequence num, this should not happen", utxo.TxOutput.TxHash, utxo.TxOutput.Index)
		}

		return nil
	})
	if err != nil {
		log.Errorf("can not statistics unconfirmed output: %v", err)
		return err
	}
	// for bucketSpentConfirmed, we do not handle this bucket

	err = putAddrTXONum(txMgrNs, rootNumTXO, numTXO)
	if err != nil {
		return err
	}
	err = putAddrTXONum(txMgrNs, rootNumImmatureCoinbaseTXO, numImmatureCoinbaseTXO)
	if err != nil {
		return err
	}
	err = putAddrTXONum(txMgrNs, rootNumImmatureTransferTXO, numImmatureTransferTXO)
	if err != nil {
		return err
	}
	err = putAddrTXONum(txMgrNs, rootNumSpendableTXO, numSpendableTXO)
	if err != nil {
		return err
	}
	err = putAddrTXONum(txMgrNs, rootNumUnconfirmedTXO, numUnconfirmedTXO)
	if err != nil {
		return err
	}

	var addrTxoCounter walletdb.ReadWriteBucket
	if addrTxoCounter, err = statisticsBucket.CreateBucket(bucketAddrTXOCounter); err != nil {
		str := "fail to create addrtxocnt bucket in namespace statistics"
		return storeError(ErrDatabase, str, err)
	}
	for addrKey := range addrMapping {
		addrKeyBytes, _ := hex.DecodeString(addrKey)
		subBucket, err := addrTxoCounter.CreateBucket(addrKeyBytes)
		if err != nil {
			str := "fail to create sub bucket in namespace statistics/addrtxocnt for address"
			return storeError(ErrDatabase, str, err)
		}

		err = putAddrTXONum(subBucket, statisticNumTXO, addressNumTXOMapping[addrKey])
		if err != nil {
			return err
		}
		err = putAddrTXONum(subBucket, statisticNumImmatureCoinbaseTXO, addressNumImmatureCoinbaseTXOMapping[addrKey])
		if err != nil {
			return err
		}
		err = putAddrTXONum(subBucket, statisticNumImmatureTransferTXO, addressNumImmatureTransferTXOMapping[addrKey])
		if err != nil {
			return err
		}
		err = putAddrTXONum(subBucket, statisticNumSpendableTXO, addressNumSpendableTXOMapping[addrKey])
		if err != nil {
			return err
		}
		err = putAddrTXONum(subBucket, statisticNumUnconfirmedTXO, addressNumUnconfirmedTXOMapping[addrKey])
		if err != nil {
			return err
		}

		err = putAddrTXOAmount(subBucket, statisticTotalBalance, addressTotalBalanceMapping[addrKey])
		if err != nil {
			return err
		}
		err = putAddrTXOAmount(subBucket, statisticImmatureCoinbaseBalance, addressImmatureCoinbaseTXOBalanceMapping[addrKey])
		if err != nil {
			return err
		}
		err = putAddrTXOAmount(subBucket, statisticImmatureTransferBalance, addressImmatureTransferTXOBalanceMapping[addrKey])
		if err != nil {
			return err
		}
		err = putAddrTXOAmount(subBucket, statisticSpendableBalance, addressSpendableTXOBalanceMapping[addrKey])
		if err != nil {
			return err
		}
		err = putAddrTXOAmount(subBucket, statisticUnconfirmedBalance, addressUnconfirmedTXOBalanceMapping[addrKey])
		if err != nil {
			return err
		}
	}

	return nil
}
