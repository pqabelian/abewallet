package waddrmgr

import (
	"errors"
	"fmt"
	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abewallet/walletdb"
	"github.com/abesuite/abewallet/walletdb/migration"
	"time"
)

// versions is a list of the different database versions. The last entry should
// reflect the latest database state. If the database happens to be at a version
// number lower than the latest, migrations will be performed in order to catch
// it up.
// TODO 20220610 re-define the version, currently there is just a version
var versions = []migration.Version{
	{
		Number:    6,
		Migration: nil,
	},
	{
		Number:    7,
		Migration: nil,
	},
	{
		Number:    8,
		Migration: nil,
	},
	{
		Number:    9,
		Migration: populateIdxAddrBucket,
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
	ns   walletdb.ReadWriteBucket
	txNs walletdb.ReadWriteBucket
}

type Options func(*MigrationManager) error

// A compile-time assertion to ensure that MigrationManager implements the
// migration.Manager interface.
var _ migration.Manager = (*MigrationManager)(nil)

// NewMigrationManager creates a new migration manager for the address manager.
// The given bucket should reflect the top-level bucket in which all of the
// address manager's data is contained within.
func NewMigrationManager(ns walletdb.ReadWriteBucket, txNs walletdb.ReadWriteBucket) *MigrationManager {
	return &MigrationManager{
		ns:   ns,
		txNs: txNs,
	}
}

// Name returns the name of the service we'll be attempting to upgrade.
//
// NOTE: This method is part of the migration.Manager interface.
func (m *MigrationManager) Name() string {
	return "wallet address manager"
}

// Namespace returns the top-level bucket of the service.
//
// NOTE: This method is part of the migration.Manager interface.
func (m *MigrationManager) Namespace() walletdb.ReadWriteBucket {
	return m.ns
}
func (m *MigrationManager) Namespace2() walletdb.ReadWriteBucket {
	return m.txNs
}

// CurrentVersion returns the current version of the service's database.
//
// NOTE: This method is part of the migration.Manager interface.
func (m *MigrationManager) CurrentVersion(ns walletdb.ReadBucket) (uint32, error) {
	if ns == nil {
		ns = m.ns
	}
	return fetchManagerVersion(ns)
}

// SetVersion sets the version of the service's database.
//
// NOTE: This method is part of the migration.Manager interface.
func (m *MigrationManager) SetVersion(ns walletdb.ReadWriteBucket,
	version uint32) error {

	if ns == nil {
		ns = m.ns
	}
	return putManagerVersion(m.ns, version)
}

// Versions returns all of the available database versions of the service.
//
// NOTE: This method is part of the migration.Manager interface.
func (m *MigrationManager) Versions() []migration.Version {
	return versions
}

// upgradeToVersion2 upgrades the database from version 1 to version 2
// 'usedAddrBucketName' a bucket for storing addrs flagged as marked is
// initialized and it will be updated on the next rescan.

// upgradeToVersion5 upgrades the database from version 4 to version 5. After
// this update, the new ScopedKeyManager features cannot be used. This is due
// to the fact that in version 5, we now store the encrypted master private
// keys on disk. However, using the BIP0044 key scope, users will still be able
// to create old p2pkh addresses.

// migrateRecursively moves a nested bucket from one bucket to another,
// recursing into nested buckets as required.
func migrateRecursively(src, dst walletdb.ReadWriteBucket,
	bucketKey []byte) error {
	// Within this bucket key, we'll migrate over, then delete each key.
	bucketToMigrate := src.NestedReadWriteBucket(bucketKey)
	newBucket, err := dst.CreateBucketIfNotExists(bucketKey)
	if err != nil {
		return err
	}
	err = bucketToMigrate.ForEach(func(k, v []byte) error {
		if nestedBucket := bucketToMigrate.
			NestedReadBucket(k); nestedBucket != nil {
			// We have a nested bucket, so recurse into it.
			return migrateRecursively(bucketToMigrate, newBucket, k)
		}

		if err := newBucket.Put(k, v); err != nil {
			return err
		}

		return bucketToMigrate.Delete(k)
	})
	if err != nil {
		return err
	}
	// Finally, we'll delete the bucket itself.
	if err := src.DeleteNestedBucket(bucketKey); err != nil {
		return err
	}
	return nil
}

// populateBirthdayBlock is a migration that attempts to populate the birthday
// block of the wallet. This is needed so that in the event that we need to
// perform a rescan of the wallet, we can do so starting from this block, rather
// than from the genesis block.
//
// NOTE: This migration cannot guarantee the correctness of the birthday block
// being set as we do not store block timestamps, so a sanity check must be done
// upon starting the wallet to ensure we do not potentially miss any relevant
// events when rescanning.
func populateBirthdayBlock(ns walletdb.ReadWriteBucket) error {
	// We'll need to jump through some hoops in order to determine the
	// corresponding block height for our birthday timestamp. Since we do
	// not store block timestamps, we'll need to estimate our height by
	// looking at the genesis timestamp and assuming a block occurs every 10
	// minutes. This can be unsafe, and cause us to actually miss on-chain
	// events, so a sanity check is done before the wallet attempts to sync
	// itself.
	//
	// We'll start by fetching our birthday timestamp.
	birthdayTimestamp, err := fetchBirthday(ns)
	if err != nil {
		return fmt.Errorf("unable to fetch birthday timestamp: %v", err)
	}

	log.Infof("Setting the wallet's birthday block from timestamp=%v",
		birthdayTimestamp)

	// Now, we'll need to determine the timestamp of the genesis block for
	// the corresponding chain.
	genesisHash, err := fetchBlockHash(ns, 0)
	if err != nil {
		return fmt.Errorf("unable to fetch genesis block hash: %v", err)
	}

	var genesisTimestamp time.Time
	switch *genesisHash {
	case *chaincfg.MainNetParams.GenesisHash:
		genesisTimestamp =
			chaincfg.MainNetParams.GenesisBlock.Header.Timestamp

	case *chaincfg.TestNet3Params.GenesisHash:
		genesisTimestamp =
			chaincfg.TestNet3Params.GenesisBlock.Header.Timestamp

	case *chaincfg.RegressionNetParams.GenesisHash:
		genesisTimestamp =
			chaincfg.RegressionNetParams.GenesisBlock.Header.Timestamp

	case *chaincfg.SimNetParams.GenesisHash:
		genesisTimestamp =
			chaincfg.SimNetParams.GenesisBlock.Header.Timestamp

	default:
		return fmt.Errorf("unknown genesis hash %v", genesisHash)
	}

	// With the timestamps retrieved, we can estimate a block height by
	// taking the difference between them and dividing by the average block
	// time (10 minutes).
	birthdayHeight := int32((birthdayTimestamp.Sub(genesisTimestamp).Seconds() / 600))

	// Now that we have the height estimate, we can fetch the corresponding
	// block and set it as our birthday block.
	birthdayHash, err := fetchBlockHash(ns, birthdayHeight)

	// To ensure we record a height that is known to us from the chain,
	// we'll make sure this height estimate can be found. Otherwise, we'll
	// continue subtracting a day worth of blocks until we can find one.
	for IsError(err, ErrBlockNotFound) {
		birthdayHeight -= 144
		if birthdayHeight < 0 {
			birthdayHeight = 0
		}
		birthdayHash, err = fetchBlockHash(ns, birthdayHeight)
	}
	if err != nil {
		return err
	}

	log.Infof("Estimated birthday block from timestamp=%v: height=%d, "+
		"hash=%v", birthdayTimestamp, birthdayHeight, birthdayHash)

	// NOTE: The timestamp of the birthday block isn't set since we do not
	// store each block's timestamp.
	return PutBirthdayBlock(ns, BlockStamp{
		Height: birthdayHeight,
		Hash:   *birthdayHash,
	})
}

// resetSyncedBlockToBirthday is a migration that resets the wallet's currently
// synced block to its birthday block. This essentially serves as a migration to
// force a rescan of the wallet.
func resetSyncedBlockToBirthday(ns walletdb.ReadWriteBucket) error {
	syncBucket := ns.NestedReadWriteBucket(syncBucketName)
	if syncBucket == nil {
		return errors.New("sync bucket does not exist")
	}

	birthdayBlock, err := FetchBirthdayBlock(ns)
	if err != nil {
		return err
	}

	return PutSyncedTo(ns, &birthdayBlock)
}

// storeMaxReorgDepth is a migration responsible for allowing the wallet to only
// maintain MaxReorgDepth block hashes stored in order to recover from long
// reorgs.
func storeMaxReorgDepth(ns walletdb.ReadWriteBucket) error {
	// Retrieve the current tip of the wallet. We'll use this to determine
	// the highest stale height we currently have stored within it.
	syncedTo, err := fetchSyncedTo(ns)
	if err != nil {
		return err
	}
	maxStaleHeight := staleHeight(syncedTo.Height)

	// It's possible for this height to be non-sensical if we have less than
	// MaxReorgDepth blocks stored, so we can end the migration now.
	if maxStaleHeight < 1 {
		return nil
	}

	log.Infof("Removing block hash entries beyond maximum reorg depth of "+
		"%v from current tip %v", MaxReorgDepth, syncedTo.Height)

	// Otherwise, since we currently store all block hashes of the chain
	// before this migration, we'll remove all stale block hash entries
	// above the genesis block. This would leave us with only MaxReorgDepth
	// blocks stored.
	for height := maxStaleHeight; height > 0; height-- {
		if err := deleteBlockHash(ns, height); err != nil {
			return err
		}
	}

	return nil
}

func populateIdxAddrBucket(addrMgr walletdb.ReadWriteBucket, txNs walletdb.ReadWriteBucket) error {
	mainBucket := addrMgr.NestedReadWriteBucket([]byte("main"))
	// check whether the idx address bucket exist or not
	// this bucket would store the map: addr key -> idx
	idxAddrBucket, err := mainBucket.CreateBucketIfNotExists([]byte("idxaddr"))
	if err != nil {
		str := "failed to create index address bucket"
		return managerError(ErrDatabase, str, err)
	}
	// according idx -> addr key to build addr key -> idx
	err = mainBucket.NestedReadBucket([]byte("addridx")).ForEach(func(k, v []byte) error {
		if err = idxAddrBucket.Put(v, k); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}
