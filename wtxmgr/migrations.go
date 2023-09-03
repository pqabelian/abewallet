package wtxmgr

import (
	"bytes"
	"encoding/binary"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abecrypto/abecryptoparam"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abewallet/waddrmgr"
	"github.com/abesuite/abewallet/walletdb"
	"github.com/abesuite/abewallet/walletdb/migration"
	"github.com/bits-and-blooms/bitset"
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
		Migration: markUsedAddress,
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

func (m *MigrationManager) Namespace2() walletdb.ReadWriteBucket {
	return m.addrNs
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

// markAddressUsedStatus is a migration responsible for marking address belong txo
// used
func markUsedAddress(txMgr walletdb.ReadWriteBucket, addrMgr walletdb.ReadWriteBucket) error {
	mainBucket := addrMgr.NestedReadWriteBucket([]byte("main"))
	// check whether the idx address bucket exist or not
	// this bucket would store the map: addr key -> idx
	idxAddrBucket := mainBucket.NestedReadBucket([]byte("idxaddr"))

	set := bitset.BitSet{}
	// Retrieve all txo from utxoringdetails
	// and mark the address in those used
	ringDetailBucket := txMgr.NestedReadBucket(bucketRingDetails)
	// utxoringdetails
	err := txMgr.NestedReadBucket(bucketUTXORing).ForEach(func(k, v []byte) error {
		ring := &UTXORing{}
		err := ring.Deserialize(v)
		if err != nil {
			return err
		}
		ringDetail := &Ring{}
		ringDetail.Deserialize(ringDetailBucket.Get(k))
		for i := 0; i < len(ring.IsMy); i++ {
			if ring.IsMy[i] {
				address, err := abecrypto.ExtractCoinAddressFromTxoScript(ringDetail.TxoScripts[i], abecryptoparam.CryptoSchemePQRingCT)
				if err != nil {
					return err
				}
				addrKey := chainhash.DoubleHashB(address)
				if idxBytes := idxAddrBucket.Get(addrKey); len(idxBytes) != 0 {
					addrIdx := binary.LittleEndian.Uint64(idxBytes)
					set.Set(uint(addrIdx))
				}
			}

		}
		return nil
	})
	if err != nil {
		return err
	}

	outputBuff := &bytes.Buffer{}
	set.WriteTo(outputBuff)
	err = mainBucket.Put([]byte("addrstatus"), outputBuff.Bytes())
	if err != nil {
		str := "failed to set addr status"
		return waddrmgr.ManagerError{
			ErrorCode:   waddrmgr.ErrDatabase,
			Description: str,
			Err:         err,
		}
	}
	return nil
}
