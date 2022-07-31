package waddrmgr

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abewallet/walletdb"
	"time"
)

const (
	// MaxReorgDepth represents the maximum number of block hashes we'll
	// keep within the wallet at any given point in order to recover from
	// long reorgs.
	MaxReorgDepth = 10000 // TODO: this const variable can reuse for other intention such as NUMBERBLOCKABE
)

var (
	// LatestMgrVersion is the most recent manager version.
	LatestMgrVersion = getLatestVersion()

	// latestMgrVersion is the most recent manager version as a variable so
	// the tests can change it to force errors.
	latestMgrVersion = LatestMgrVersion
)

// ObtainUserInputFunc is a function that reads a user input and returns it as
// a byte stream. It is used to accept data required during upgrades, for e.g.
// wallet seed and private passphrase.
type ObtainUserInputFunc func() ([]byte, error)

// maybeConvertDbError converts the passed error to a ManagerError with an
// error code of ErrDatabase if it is not already a ManagerError.  This is
// useful for potential errors returned from managed transaction an other parts
// of the walletdb database.
func maybeConvertDbError(err error) error {
	// When the error is already a ManagerError, just return it.
	if _, ok := err.(ManagerError); ok {
		return err
	}

	return managerError(ErrDatabase, err.Error(), err)
}

// syncStatus represents a address synchronization status stored in the
// database.
type syncStatus uint8

// These constants define the various supported sync status types.
//
// NOTE: These are currently unused but are being defined for the possibility
// of supporting sync status on a per-address basis.
const (
	ssNone    syncStatus = 0 // not iota as they need to be stable for db
	ssPartial syncStatus = 1
	ssFull    syncStatus = 2
)

// addressType represents a type of address stored in the database.
type addressType uint8

// These constants define the various supported address types.
const (
	adtChain  addressType = 0
	adtImport addressType = 1 // not iota as they need to be stable for db
	adtScript addressType = 2
)

// accountType represents a type of address stored in the database.
type accountType uint8

// These constants define the various supported account types.
const (
	// accountDefault is the current "default" account type within the
	// database. This is an account that re-uses the key derivation schema
	// of BIP0044-like accounts.
	accountDefault accountType = 0 // not iota as they need to be stable
)

// dbAccountRow houses information stored about an account in the database.
type dbAccountRow struct {
	acctType accountType
	rawData  []byte // Varies based on account type field.
}

// dbDefaultAccountRow houses additional information stored about a default
// BIP0044-like account in the database.
type dbDefaultAccountRow struct {
	dbAccountRow
	pubKeyEncrypted   []byte
	privKeyEncrypted  []byte
	nextExternalIndex uint32
	nextInternalIndex uint32
	name              string
}

// dbAddressRow houses common information stored about an address in the
// database.
type dbAddressRow struct {
	addrType   addressType
	account    uint32
	addTime    uint64
	syncStatus syncStatus
	rawData    []byte // Varies based on address type field.
}

// dbChainAddressRow houses additional information stored about a chained
// address in the database.
type dbChainAddressRow struct {
	dbAddressRow
	branch uint32
	index  uint32
}

// dbImportedAddressRow houses additional information stored about an imported
// public key address in the database.
type dbImportedAddressRow struct {
	dbAddressRow
	encryptedPubKey  []byte
	encryptedPrivKey []byte
}

// dbImportedAddressRow houses additional information stored about a script
// address in the database.
type dbScriptAddressRow struct {
	dbAddressRow
	encryptedHash   []byte
	encryptedScript []byte
}

// Key names for various database fields.
var (
	// nullVall is null byte used as a flag value in a bucket entry
	nullVal = []byte{0}

	// Bucket names.

	// scopeSchemaBucket is the name of the bucket that maps a particular
	// manager scope to the type of addresses that should be derived for
	// particular branches during key derivation.
	//scopeSchemaBucketName = []byte("scope-schema")

	// scopeBucketNme is the name of the top-level bucket within the
	// hierarchy. It maps: purpose || coinType to a new sub-bucket that
	// will house a scoped address manager. All buckets below are a child
	// of this bucket:
	//
	// scopeBucket -> scope -> acctBucket
	// scopeBucket -> scope -> addrBucket
	// scopeBucket -> scope -> usedAddrBucket
	// scopeBucket -> scope -> addrAcctIdxBucket
	// scopeBucket -> scope -> acctNameIdxBucket
	// scopeBucket -> scope -> acctIDIdxBucketName
	// scopeBucket -> scope -> metaBucket
	// scopeBucket -> scope -> metaBucket -> lastAccountNameKey
	// scopeBucket -> scope -> coinTypePrivKey
	// scopeBucket -> scope -> coinTypePubKey
	//scopeBucketName = []byte("scope")
	// coinTypePrivKeyName is the name of the key within a particular scope
	// bucket that stores the encrypted cointype private keys. Each scope
	// within the database will have its own set of coin type keys.

	// coinTypePrivKeyName is the name of the key within a particular scope
	// bucket that stores the encrypted cointype public keys. Each scope
	// will have its own set of coin type public keys.
	//coinTypePubKeyName = []byte("ctpub")

	// acctBucketName is the bucket directly below the scope bucket in the
	// hierarchy. This bucket stores all the information and indexes
	// relevant to an account.
	//acctBucketName = []byte("acct")

	// addrBucketName is the name of the bucket that stores a mapping of
	// pubkey hash to address type. This will be used to quickly determine
	// if a given address is under our control.
	//addrBucketName = []byte("addr")

	// addrAcctIdxBucketName is used to index account addresses Entries in
	// this index may map:
	// * addr hash => account id
	// * account bucket -> addr hash => null
	//
	// To fetch the account of an address, lookup the value using the
	// address hash.
	//
	// To fetch all addresses of an account, fetch the account bucket,
	// iterate over the keys and fetch the address row from the addr
	// bucket.
	//
	// The index needs to be updated whenever an address is created e.g.
	// NewAddress
	//addrAcctIdxBucketName = []byte("addracctidx")

	// acctNameIdxBucketName is used to create an index mapping an account
	// name string to the corresponding account id.  The index needs to be
	// updated whenever the account name and id changes e.g. RenameAccount
	//
	// string => account_id
	//acctNameIdxBucketName = []byte("acctnameidx")

	// acctIDIdxBucketName is used to create an index mapping an account id
	// to the corresponding account name string.  The index needs to be
	// updated whenever the account name and id changes e.g. RenameAccount
	//
	// account_id => string
	//acctIDIdxBucketName = []byte("acctididx")

	// usedAddrBucketName is the name of the bucket that stores an
	// addresses hash if the address has been used or not.
	//usedAddrBucketName = []byte("usedaddrs")

	// meta is used to store meta-data about the address manager
	// e.g. last account number
	//metaBucketName = []byte("meta")

	// lastAccountName is used to store the metadata - last account
	// in the manager
	//lastAccountName = []byte("lastaccount")

	// mainBucketName is the name of the bucket that stores the encrypted
	// crypto keys that encrypt all other generated keys, the watch only
	// flag, the master private key (encrypted), the master HD private key
	// (encrypted), and also versioning information.
	mainBucketName  = []byte("main")
	addrBukcetName  = []byte("address") // instance address = coin address + value address
	askspBukcetName = []byte("asksp")   // coin spend key
	asksnBukcetName = []byte("asksn")   // coin serial number key
	vskBukcetName   = []byte("valuesk") // value secret key
	// masterHDPrivName is the name of the key that stores the master HD
	// private key. This key is encrypted with the master private crypto
	// encryption key. This resides under the main bucket.
	//masterHDPrivName = []byte("mhdpriv")

	// derived seed and its used status
	seedKeyName    = []byte("seed")
	seedStatusName = []byte("sdcnt")
	netIDName      = []byte("netid")

	// masterHDPubName is the name of the key that stores the master HD
	// public key. This key is encrypted with the master public crypto
	// encryption key. This reside under the main bucket.
	//masterHDPubName      = []byte("mhdpub")
	//masterSecretViewName = []byte("msvk")
	//masterPubName        = []byte("mpk")

	//addressKeyName = []byte("address")
	// syncBucketName is the name of the bucket that stores the current
	// sync state of the root manager.
	syncBucketName = []byte("sync")

	// Db related key names (main bucket).
	mgrVersionName    = []byte("mgrver")
	mgrCreateDateName = []byte("mgrcreated")

	// Crypto related key names (main bucket).
	masterPrivKeyName = []byte("mpriv")
	masterPubKeyName  = []byte("mpub")

	cryptoSeedKeyName   = []byte("cseed")
	cryptoPrivKeyName   = []byte("cpriv")
	cryptoPubKeyName    = []byte("cpub")
	cryptoScriptKeyName = []byte("cscript") // useless temporary
	watchingOnlyName    = []byte("watchonly")

	// Sync related key names (sync bucket).
	syncedToName              = []byte("syncedto")
	startBlockName            = []byte("startblock")
	birthdayName              = []byte("birthday")
	birthdayBlockName         = []byte("birthdayblock")
	birthdayBlockVerifiedName = []byte("birthdayblockverified")
)

// uint32ToBytes converts a 32 bit unsigned integer into a 4-byte slice in
// little-endian order: 1 -> [1 0 0 0].
func uint32ToBytes(number uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, number)
	return buf
}

// uint64ToBytes converts a 64 bit unsigned integer into a 8-byte slice in
// little-endian order: 1 -> [1 0 0 0 0 0 0 0].
func uint64ToBytes(number uint64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, number)
	return buf
}

// stringToBytes converts a string into a variable length byte slice in
// little-endian order: "abc" -> [3 0 0 0 61 62 63]
func stringToBytes(s string) []byte {
	// The serialized format is:
	//   <size><string>
	//
	// 4 bytes string size + string
	size := len(s)
	buf := make([]byte, 4+size)
	copy(buf[0:4], uint32ToBytes(uint32(size)))
	copy(buf[4:4+size], s)
	return buf
}

// scopeKeySize is the size of a scope as stored within the database.
const scopeKeySize = 8

// scopeToBytes transforms a manager's scope into the form that will be used to
// retrieve the bucket that all information for a particular scope is stored
// under

// scopeFromBytes decodes a serializes manager scope into its concrete manager
// scope struct.

// scopeSchemaToBytes encodes the passed scope schema as a set of bytes
// suitable for storage within the database.

// scopeSchemaFromBytes decodes a new scope schema instance from the set of
// serialized bytes.

// fetchScopeAddrSchema will attempt to retrieve the address schema for a
// particular manager scope stored within the database. These are used in order
// to properly type each address generated by the scope address manager.

// putScopeAddrSchema attempts to store the passed addr scehma for the given
// manager scope.

// fetchManagerVersion fetches the current manager version from the database.
func fetchManagerVersion(ns walletdb.ReadBucket) (uint32, error) {
	mainBucket := ns.NestedReadBucket(mainBucketName)
	verBytes := mainBucket.Get(mgrVersionName)
	if verBytes == nil {
		str := "required version number not stored in database"
		return 0, managerError(ErrDatabase, str, nil)
	}
	version := binary.LittleEndian.Uint32(verBytes)
	return version, nil
}

// putManagerVersion stores the provided version to the database.
func putManagerVersion(ns walletdb.ReadWriteBucket, version uint32) error {
	bucket := ns.NestedReadWriteBucket(mainBucketName)

	verBytes := uint32ToBytes(version)
	err := bucket.Put(mgrVersionName, verBytes)
	if err != nil {
		str := "failed to store version"
		return managerError(ErrDatabase, str, err)
	}
	return nil
}

// fetchMasterKeyParams loads the master key parameters needed to derive them
// (when given the correct user-supplied passphrase) from the database.  Either
// returned value can be nil, but in practice only the private key params will
// be nil for a watching-only database.
func fetchMasterKeyParams(ns walletdb.ReadBucket) ([]byte, []byte, error) {
	bucket := ns.NestedReadBucket(mainBucketName)

	// Load the master public key parameters.  Required.
	val := bucket.Get(masterPubKeyName)
	if val == nil {
		str := "required master public key parameters not stored in " +
			"database"
		return nil, nil, managerError(ErrDatabase, str, nil)
	}
	pubParams := make([]byte, len(val))
	copy(pubParams, val)

	// Load the master private key parameters if they were stored.
	var privParams []byte
	val = bucket.Get(masterPrivKeyName)
	if val != nil {
		privParams = make([]byte, len(val))
		copy(privParams, val)
	}

	return pubParams, privParams, nil
}

// putMasterKeyParams stores the master key parameters needed to derive them to
// the database.  Either parameter can be nil in which case no value is
// written for the parameter.
func putMasterKeyParams(ns walletdb.ReadWriteBucket, pubParams, privParams []byte) error {
	bucket := ns.NestedReadWriteBucket(mainBucketName)

	if privParams != nil {
		err := bucket.Put(masterPrivKeyName, privParams)
		if err != nil {
			str := "failed to store master private key parameters"
			return managerError(ErrDatabase, str, err)
		}
	}

	if pubParams != nil {
		err := bucket.Put(masterPubKeyName, pubParams)
		if err != nil {
			str := "failed to store master public key parameters"
			return managerError(ErrDatabase, str, err)
		}
	}

	return nil
}

// fetchCoinTypeKeys loads the encrypted cointype keys which are in turn used
// to derive the extended keys for all accounts. Each cointype key is
// associated with a particular manager scoped.

// putCoinTypeKeys stores the encrypted cointype keys which are in turn used to
// derive the extended keys for all accounts.  Either parameter can be nil in
// which case no value is written for the parameter. Each cointype key is
// associated with a particular manager scope.

// putMasterHDKeys stores the encrypted master HD keys in the top level main
// bucket. These are required in order to create any new manager scopes, as
// those are created via hardened derivation of the children of this key.

func FetchSeedStatus(ns walletdb.ReadBucket) (uint64, error) {
	return fetchSeedStatus(ns)
}

func fetchSeedStatus(ns walletdb.ReadBucket) (uint64, error) {
	// As this is the key for the root manager, we don't need to fetch any
	// particular scope, and can insert directly within the main bucket.
	bucket := ns.NestedReadBucket(mainBucketName)
	status := bucket.Get(seedStatusName)
	if status == nil {
		str := "failed to fetch seed status"
		return 0, managerError(ErrDatabase, str, errors.New("the status of seed is wrong"))
	}
	cnt := binary.LittleEndian.Uint64(status)
	return cnt, nil
}
func putSeedStatus(ns walletdb.ReadWriteBucket, cnt uint64) error {
	// As this is the key for the root manager, we don't need to fetch any
	// particular scope, and can insert directly within the main bucket.
	bucket := ns.NestedReadWriteBucket(mainBucketName)
	status := make([]byte, 8)
	binary.LittleEndian.PutUint64(status, cnt)
	err := bucket.Put(seedStatusName, status)
	if err != nil {
		str := "failed to store seed status"
		return managerError(ErrDatabase, str, err)
	}
	return nil
}

//putAddressKeysEnc TODO 20220610: check the internal logic of function
func putAddressKeysEnc(ns walletdb.ReadWriteBucket, addrKey []byte, valueSecretKeyEnc,
	addressSecretKeySpEnc, addressSecretKeySnEnc, addressKeyEnc []byte) error {
	// As this is the key for the root manager, we don't need to fetch any
	// particular scope, and can insert directly within the main bucket.
	mainBucket := ns.NestedReadWriteBucket(mainBucketName)

	if addressKeyEnc != nil {
		addrBucket := mainBucket.NestedReadWriteBucket(addrBukcetName)
		err := addrBucket.Put(addrKey, addressKeyEnc)
		if err != nil {
			str := "failed to store encrypted master public key"
			return managerError(ErrDatabase, str, err)
		}
	}

	// Now that we have the main bucket, we can directly store each of the
	// relevant keys. If we're in watch only mode, then some or all of
	// these keys might not be available.
	if valueSecretKeyEnc != nil {
		vskBukcet := mainBucket.NestedReadWriteBucket(vskBukcetName)
		err := vskBukcet.Put(addrKey, valueSecretKeyEnc)
		if err != nil {
			str := "failed to store encrypted master private signing key"
			return managerError(ErrDatabase, str, err)
		}
	}

	if addressSecretKeySpEnc != nil {
		askspBukcet := mainBucket.NestedReadWriteBucket(askspBukcetName)
		err := askspBukcet.Put(addrKey, addressSecretKeySpEnc)
		if err != nil {
			str := "failed to store encrypted master private signing key"
			return managerError(ErrDatabase, str, err)
		}
	}

	if addressSecretKeySnEnc != nil {
		asksnBukcet := mainBucket.NestedReadWriteBucket(asksnBukcetName)
		err := asksnBukcet.Put(addrKey, addressSecretKeySnEnc)
		if err != nil {
			str := "failed to store encrypted master public key"
			return managerError(ErrDatabase, str, err)
		}
	}

	return nil
}
func fetchAddressKeyEnc(ns walletdb.ReadBucket, addrKey []byte) ([]byte, []byte, []byte, []byte, error) {
	mainBucket := ns.NestedReadBucket(mainBucketName)

	addrBucket := mainBucket.NestedReadBucket(addrBukcetName)
	addrEnc := addrBucket.Get(addrKey)
	vskBukcet := mainBucket.NestedReadBucket(vskBukcetName)
	vskEnc := vskBukcet.Get(addrKey)

	askspBucket := mainBucket.NestedReadBucket(askspBukcetName)
	askspEnc := askspBucket.Get(addrKey)
	asksnBucket := mainBucket.NestedReadBucket(asksnBukcetName)
	asksnEnc := asksnBucket.Get(addrKey)
	return addrEnc, askspEnc, asksnEnc, vskEnc, nil
}

// fetchMasterHDKeys attempts to fetch both the master HD private and public
// keys from the database. If this is a watch only wallet, then it's possible
// that the master private key isn't stored.
func putNetID(ns walletdb.ReadWriteBucket, netID []byte) error {
	bucket := ns.NestedReadWriteBucket(mainBucketName)

	return bucket.Put(netIDName, netID)
}
func putSeedEnc(ns walletdb.ReadWriteBucket, seedEnc []byte) error {
	bucket := ns.NestedReadWriteBucket(mainBucketName)

	if seedEnc != nil {
		err := bucket.Put(seedKeyName, seedEnc)
		if err != nil {
			str := "failed to store encrypted seed"
			return managerError(ErrDatabase, str, err)
		}
	}
	return nil
}
func fetchNetID(ns walletdb.ReadBucket) ([]byte, error) {
	bucket := ns.NestedReadBucket(mainBucketName)
	return bucket.Get(netIDName), nil
}
func fetchSeedEnc(ns walletdb.ReadBucket) ([]byte, error) {
	bucket := ns.NestedReadBucket(mainBucketName)
	var seedEnc []byte

	key := bucket.Get(seedKeyName)
	if key != nil {
		seedEnc = make([]byte, len(key))
		copy(seedEnc[:], key)
	}
	return seedEnc, nil
}

// fetchCryptoKeys loads the encrypted crypto keys which are in turn used to
// protect the extended keys, imported keys, and scripts.  Any of the returned
// values can be nil, but in practice only the crypto private and script keys
// will be nil for a watching-only database.
func fetchCryptoKeys(ns walletdb.ReadBucket) ([]byte, []byte, []byte, []byte, error) {
	bucket := ns.NestedReadBucket(mainBucketName)

	// Load the crypto public key parameters.  Required.
	val := bucket.Get(cryptoPubKeyName)
	if val == nil {
		str := "required encrypted crypto public not stored in database"
		return nil, nil, nil, nil, managerError(ErrDatabase, str, nil)
	}
	pubKey := make([]byte, len(val))
	copy(pubKey, val)

	// Load the crypto private key parameters if they were stored.
	var seedKey []byte
	val = bucket.Get(cryptoSeedKeyName)
	if val != nil {
		seedKey = make([]byte, len(val))
		copy(seedKey, val)
	}

	// Load the crypto private key parameters if they were stored.
	var privKey []byte
	val = bucket.Get(cryptoPrivKeyName)
	if val != nil {
		privKey = make([]byte, len(val))
		copy(privKey, val)
	}

	// Load the crypto script key parameters if they were stored.
	var scriptKey []byte
	val = bucket.Get(cryptoScriptKeyName)
	if val != nil {
		scriptKey = make([]byte, len(val))
		copy(scriptKey, val)
	}

	return pubKey, seedKey, privKey, scriptKey, nil
}

// putCryptoKeys stores the encrypted crypto keys which are in turn used to
// protect the extended and imported keys.  Either parameter can be nil in
// which case no value is written for the parameter.
func putCryptoKeys(ns walletdb.ReadWriteBucket, pubKeyEncrypted, privKeyEncrypted,
	scriptKeyEncrypted, cryptoKeySeedEnc []byte) error {

	bucket := ns.NestedReadWriteBucket(mainBucketName)

	if pubKeyEncrypted != nil {
		err := bucket.Put(cryptoPubKeyName, pubKeyEncrypted)
		if err != nil {
			str := "failed to store encrypted crypto public key"
			return managerError(ErrDatabase, str, err)
		}
	}

	if privKeyEncrypted != nil {
		err := bucket.Put(cryptoPrivKeyName, privKeyEncrypted)
		if err != nil {
			str := "failed to store encrypted crypto private key"
			return managerError(ErrDatabase, str, err)
		}
	}

	if scriptKeyEncrypted != nil {
		err := bucket.Put(cryptoScriptKeyName, scriptKeyEncrypted)
		if err != nil {
			str := "failed to store encrypted crypto script key"
			return managerError(ErrDatabase, str, err)
		}
	}

	if cryptoKeySeedEnc != nil {
		err := bucket.Put(cryptoSeedKeyName, cryptoKeySeedEnc)
		if err != nil {
			str := "failed to store encrypted crypto script key"
			return managerError(ErrDatabase, str, err)
		}
	}

	return nil
}

// fetchWatchingOnly loads the watching-only flag from the database.
func fetchWatchingOnly(ns walletdb.ReadBucket) (bool, error) {
	bucket := ns.NestedReadBucket(mainBucketName)

	buf := bucket.Get(watchingOnlyName)
	if len(buf) != 1 {
		str := "malformed watching-only flag stored in database"
		return false, managerError(ErrDatabase, str, nil)
	}

	return buf[0] != 0, nil
}

// putWatchingOnly stores the watching-only flag to the database.
func putWatchingOnly(ns walletdb.ReadWriteBucket, watchingOnly bool) error {
	bucket := ns.NestedReadWriteBucket(mainBucketName)

	var encoded byte
	if watchingOnly {
		encoded = 1
	}

	if err := bucket.Put(watchingOnlyName, []byte{encoded}); err != nil {
		str := "failed to store watching only flag"
		return managerError(ErrDatabase, str, err)
	}
	return nil
}

// deserializeAccountRow deserializes the passed serialized account information.
// This is used as a common base for the various account types to deserialize
// the common parts.

// serializeAccountRow returns the serialization of the passed account row.

// deserializeDefaultAccountRow deserializes the raw data from the passed
// account row as a BIP0044-like account.

// serializeDefaultAccountRow returns the serialization of the raw data field
// for a BIP0044-like account.

// forEachKeyScope calls the given function for each known manager scope
// within the set of scopes known by the root manager.

// forEachAccount calls the given function with each account stored in the
// manager, breaking early on error.

// fetchLastAccount retrieves the last account from the database.
// If no accounts, returns twos-complement representation of -1, so that the next account is zero

// fetchAccountName retrieves the account name given an account number from the
// database.

// fetchAccountByName retrieves the account number given an account name from
// the database.

// fetchAccountInfo loads information about the passed account from the
// database.

// deleteAccountNameIndex deletes the given key from the account name index of the database.

// deleteAccounIdIndex deletes the given key from the account id index of the database.

// putAccountNameIndex stores the given key to the account name index of the
// database.

// putAccountIDIndex stores the given key to the account id index of the database.

// putAddrAccountIndex stores the given key to the address account index of the
// database.

// putAccountRow stores the provided account information to the database.  This
// is used a common base for storing the various account types.

// putAccountInfo stores the provided account information to the database.

// putLastAccount stores the provided metadata - last account - to the
// database.

// deserializeAddressRow deserializes the passed serialized address
// information.  This is used as a common base for the various address types to
// deserialize the common parts.

// serializeAddressRow returns the serialization of the passed address row.

// deserializeChainedAddress deserializes the raw data from the passed address
// row as a chained address.

// serializeChainedAddress returns the serialization of the raw data field for
// a chained address.

// deserializeImportedAddress deserializes the raw data from the passed address
// row as an imported address.

// serializeImportedAddress returns the serialization of the raw data field for
// an imported address.

// deserializeScriptAddress deserializes the raw data from the passed address
// row as a script address.

// serializeScriptAddress returns the serialization of the raw data field for
// a script address.

// fetchAddressByHash loads address information for the provided address hash
// from the database.  The returned value is one of the address rows for the
// specific address type.  The caller should use type assertions to ascertain
// the type.  The caller should prefix the error message with the address hash
// which caused the failure.

// fetchAddressUsed returns true if the provided address id was flagged as used.

// markAddressUsed flags the provided address id as used in the database.

// fetchAddress loads address information for the provided address id from the
// database.  The returned value is one of the address rows for the specific
// address type.  The caller should use type assertions to ascertain the type.
// The caller should prefix the error message with the address which caused the
// failure.

// putAddress stores the provided address information to the database.  This is
// used a common base for storing the various address types.

// putChainedAddress stores the provided chained address information to the
// database.

// putImportedAddress stores the provided imported address information to the
// database.

// putScriptAddress stores the provided script address information to the
// database.

// existsAddress returns whether or not the address id exists in the database.

// fetchAddrAccount returns the account to which the given address belongs to.
// It looks up the account using the addracctidx index which maps the address
// hash to its corresponding account id.

// forEachAccountAddress calls the given function with each address of the
// given account stored in the manager, breaking early on error.

// forEachActiveAddress calls the given function with each active address
// stored in the manager, breaking early on error.

// deletePrivateKeys removes all private key material from the database.
//
// NOTE: Care should be taken when calling this function.  It is primarily
// intended for use in converting to a watching-only copy.  Removing the private
// keys from the main database without also marking it watching-only will result
// in an unusable database.  It will also make any imported scripts and private
// keys unrecoverable unless there is a backup copy available.
func deletePrivateKeys(ns walletdb.ReadWriteBucket) error {
	bucket := ns.NestedReadWriteBucket(mainBucketName)

	// Delete the master private key params and the crypto private and
	// script keys.
	if err := bucket.Delete(masterPrivKeyName); err != nil {
		str := "failed to delete master private key parameters"
		return managerError(ErrDatabase, str, err)
	}
	if err := bucket.Delete(cryptoPrivKeyName); err != nil {
		str := "failed to delete crypto private key"
		return managerError(ErrDatabase, str, err)
	}
	if err := bucket.Delete(cryptoSeedKeyName); err != nil {
		str := "failed to delete crypto seed key"
		return managerError(ErrDatabase, str, err)
	}
	if err := bucket.Delete(cryptoScriptKeyName); err != nil {
		str := "failed to delete crypto script key"
		return managerError(ErrDatabase, str, err)
	}
	return nil
}

// fetchSyncedTo loads the block stamp the manager is synced to from the
// database.
func fetchSyncedTo(ns walletdb.ReadBucket) (*BlockStamp, error) {
	bucket := ns.NestedReadBucket(syncBucketName)

	// The serialized synced to format is:
	//   <blockheight><blockhash><timestamp>
	//
	// 4 bytes block height + 32 bytes hash length
	buf := bucket.Get(syncedToName)
	if len(buf) < 36 {
		str := "malformed sync information stored in database"
		return nil, managerError(ErrDatabase, str, nil)
	}

	var bs BlockStamp
	bs.Height = int32(binary.LittleEndian.Uint32(buf[0:4]))
	copy(bs.Hash[:], buf[4:36])

	if len(buf) == 40 {
		bs.Timestamp = time.Unix(
			int64(binary.LittleEndian.Uint32(buf[36:])), 0,
		)
	}

	return &bs, nil
}

// PutSyncedTo stores the provided synced to blockstamp to the database.
func PutSyncedTo(ns walletdb.ReadWriteBucket, bs *BlockStamp) error {
	errStr := fmt.Sprintf("failed to store sync information %v", bs.Hash)

	// If the block height is greater than zero, check that the previous
	// block height exists.	This prevents reorg issues in the future. We use
	// BigEndian so that keys/values are added to the bucket in order,
	// making writes more efficient for some database backends.
	if bs.Height > 0 {
		// We'll only check the previous block height exists if we've
		// determined our birthday block. This is needed as we'll no
		// longer store _all_ block hashes of the chain, so we only
		// expect the previous block to exist once our initial sync has
		// completed, which is dictated by our birthday block being set.
		if _, err := FetchBirthdayBlock(ns); err == nil {
			_, err := fetchBlockHash(ns, bs.Height-1)
			if err != nil {
				return managerError(ErrBlockNotFound, errStr, err)
			}
		}
	}

	// Store the block hash by block height.
	if err := addBlockHash(ns, bs.Height, bs.Hash); err != nil {
		return managerError(ErrDatabase, errStr, err)
	}

	// Remove the stale height if any, as we should only store MaxReorgDepth
	// block hashes at any given point.
	staleHeight := staleHeight(bs.Height)
	if staleHeight > 0 {
		if err := deleteBlockHash(ns, staleHeight); err != nil {
			return managerError(ErrDatabase, errStr, err)
		}
	}

	// Finally, we can update the syncedTo value.
	if err := updateSyncedTo(ns, bs); err != nil {
		return managerError(ErrDatabase, errStr, err)
	}

	return nil
}

// fetchBlockHash loads the block hash for the provided height from the
// database.
func fetchBlockHash(ns walletdb.ReadBucket, height int32) (*chainhash.Hash, error) {
	bucket := ns.NestedReadBucket(syncBucketName)
	errStr := fmt.Sprintf("failed to fetch block hash for height %d", height)

	heightBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(heightBytes, uint32(height))
	hashBytes := bucket.Get(heightBytes)
	if hashBytes == nil {
		err := errors.New("block not found")
		return nil, managerError(ErrBlockNotFound, errStr, err)
	}
	if len(hashBytes) != 32 {
		err := fmt.Errorf("couldn't get hash from database")
		return nil, managerError(ErrDatabase, errStr, err)
	}
	var hash chainhash.Hash
	if err := hash.SetBytes(hashBytes); err != nil {
		return nil, managerError(ErrDatabase, errStr, err)
	}
	return &hash, nil
}

// addBlockHash adds a block hash entry to the index within the syncBucket.
func addBlockHash(ns walletdb.ReadWriteBucket, height int32, hash chainhash.Hash) error {
	var rawHeight [4]byte
	binary.BigEndian.PutUint32(rawHeight[:], uint32(height))
	bucket := ns.NestedReadWriteBucket(syncBucketName)
	if err := bucket.Put(rawHeight[:], hash[:]); err != nil {
		errStr := fmt.Sprintf("failed to add hash %v", hash)
		return managerError(ErrDatabase, errStr, err)
	}
	return nil
}

// deleteBlockHash deletes the block hash entry within the syncBucket for the
// given height.
func deleteBlockHash(ns walletdb.ReadWriteBucket, height int32) error {
	var rawHeight [4]byte
	binary.BigEndian.PutUint32(rawHeight[:], uint32(height))
	bucket := ns.NestedReadWriteBucket(syncBucketName)
	if err := bucket.Delete(rawHeight[:]); err != nil {
		errStr := fmt.Sprintf("failed to delete hash for height %v",
			height)
		return managerError(ErrDatabase, errStr, err)
	}
	return nil
}

// updateSyncedTo updates the value behind the syncedToName key to the given
// block.
func updateSyncedTo(ns walletdb.ReadWriteBucket, bs *BlockStamp) error {
	// The serialized synced to format is:
	//   <blockheight><blockhash><timestamp>
	//
	// 4 bytes block height + 32 bytes hash length + 4 byte timestamp length
	var serializedStamp [40]byte
	binary.LittleEndian.PutUint32(serializedStamp[0:4], uint32(bs.Height))
	copy(serializedStamp[4:36], bs.Hash[0:32])
	binary.LittleEndian.PutUint32(
		serializedStamp[36:], uint32(bs.Timestamp.Unix()),
	)

	bucket := ns.NestedReadWriteBucket(syncBucketName)
	if err := bucket.Put(syncedToName, serializedStamp[:]); err != nil {
		errStr := "failed to update synced to value"
		return managerError(ErrDatabase, errStr, err)
	}

	return nil
}

// staleHeight returns the stale height for the given height. The stale height
// indicates the height we should remove in order to maintain a maximum of
// MaxReorgDepth block hashes.
func staleHeight(height int32) int32 {
	return height - MaxReorgDepth
}

// FetchStartBlock loads the start block stamp for the manager from the
// database.
func FetchStartBlock(ns walletdb.ReadBucket) (*BlockStamp, error) {
	bucket := ns.NestedReadBucket(syncBucketName)

	// The serialized start block format is:
	//   <blockheight><blockhash>
	//
	// 4 bytes block height + 32 bytes hash length
	buf := bucket.Get(startBlockName)
	if len(buf) != 36 {
		str := "malformed start block stored in database"
		return nil, managerError(ErrDatabase, str, nil)
	}

	var bs BlockStamp
	bs.Height = int32(binary.LittleEndian.Uint32(buf[0:4]))
	copy(bs.Hash[:], buf[4:36])
	return &bs, nil
}

// putStartBlock stores the provided start block stamp to the database.
func putStartBlock(ns walletdb.ReadWriteBucket, bs *BlockStamp) error {
	bucket := ns.NestedReadWriteBucket(syncBucketName)

	// The serialized start block format is:
	//   <blockheight><blockhash>
	//
	// 4 bytes block height + 32 bytes hash length
	buf := make([]byte, 36)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(bs.Height))
	copy(buf[4:36], bs.Hash[0:32])

	err := bucket.Put(startBlockName, buf)
	if err != nil {
		str := fmt.Sprintf("failed to store start block %v", bs.Hash)
		return managerError(ErrDatabase, str, err)
	}
	return nil
}

// fetchBirthday loads the manager's bithday timestamp from the database.
func fetchBirthday(ns walletdb.ReadBucket) (time.Time, error) {
	var t time.Time

	bucket := ns.NestedReadBucket(syncBucketName)
	birthdayTimestamp := bucket.Get(birthdayName)
	if len(birthdayTimestamp) != 8 {
		str := "malformed birthday stored in database"
		return t, managerError(ErrDatabase, str, nil)
	}

	t = time.Unix(int64(binary.BigEndian.Uint64(birthdayTimestamp)), 0)

	return t, nil
}

// putBirthday stores the provided birthday timestamp to the database.
func putBirthday(ns walletdb.ReadWriteBucket, t time.Time) error {
	var birthdayTimestamp [8]byte
	binary.BigEndian.PutUint64(birthdayTimestamp[:], uint64(t.Unix()))

	bucket := ns.NestedReadWriteBucket(syncBucketName)
	if err := bucket.Put(birthdayName, birthdayTimestamp[:]); err != nil {
		str := "failed to store birthday"
		return managerError(ErrDatabase, str, err)
	}

	return nil
}

// FetchBirthdayBlock retrieves the birthday block from the database.
//
// The block is serialized as follows:
//   [0:4]   block height
//   [4:36]  block hash
//   [36:44] block timestamp
func FetchBirthdayBlock(ns walletdb.ReadBucket) (BlockStamp, error) {
	var block BlockStamp

	bucket := ns.NestedReadBucket(syncBucketName)
	birthdayBlock := bucket.Get(birthdayBlockName)
	if birthdayBlock == nil {
		str := "birthday block not set"
		return block, managerError(ErrBirthdayBlockNotSet, str, nil)
	}
	if len(birthdayBlock) != 44 {
		str := "malformed birthday block stored in database"
		return block, managerError(ErrDatabase, str, nil)
	}

	block.Height = int32(binary.BigEndian.Uint32(birthdayBlock[:4]))
	copy(block.Hash[:], birthdayBlock[4:36])
	t := int64(binary.BigEndian.Uint64(birthdayBlock[36:]))
	block.Timestamp = time.Unix(t, 0)

	return block, nil
}

// DeleteBirthdayBlock removes the birthday block from the database.
//
// NOTE: This does not alter the birthday block verification state.
func DeleteBirthdayBlock(ns walletdb.ReadWriteBucket) error {
	bucket := ns.NestedReadWriteBucket(syncBucketName)
	if err := bucket.Delete(birthdayBlockName); err != nil {
		str := "failed to remove birthday block"
		return managerError(ErrDatabase, str, err)
	}
	return nil
}

// PutBirthdayBlock stores the provided birthday block to the database.
//
// The block is serialized as follows:
//   [0:4]   block height
//   [4:36]  block hash
//   [36:44] block timestamp
//
// NOTE: This does not alter the birthday block verification state.
func PutBirthdayBlock(ns walletdb.ReadWriteBucket, block BlockStamp) error {
	var birthdayBlock [44]byte
	binary.BigEndian.PutUint32(birthdayBlock[:4], uint32(block.Height))
	copy(birthdayBlock[4:36], block.Hash[:])
	binary.BigEndian.PutUint64(birthdayBlock[36:], uint64(block.Timestamp.Unix()))

	bucket := ns.NestedReadWriteBucket(syncBucketName)
	if err := bucket.Put(birthdayBlockName, birthdayBlock[:]); err != nil {
		str := "failed to store birthday block"
		return managerError(ErrDatabase, str, err)
	}

	return nil
}

// fetchBirthdayBlockVerification retrieves the bit that determines whether the
// wallet has verified that its birthday block is correct.
func fetchBirthdayBlockVerification(ns walletdb.ReadBucket) bool {
	bucket := ns.NestedReadBucket(syncBucketName)
	verifiedValue := bucket.Get(birthdayBlockVerifiedName)

	// If there is no verification status, we can assume it has not been
	// verified yet.
	if verifiedValue == nil {
		return false
	}

	// Otherwise, we'll determine if it's verified by the value stored.
	verified := binary.BigEndian.Uint16(verifiedValue[:])
	return verified != 0
}

// putBirthdayBlockVerification stores a bit that determines whether the
// birthday block has been verified by the wallet to be correct.
func putBirthdayBlockVerification(ns walletdb.ReadWriteBucket, verified bool) error {
	// Convert the boolean to an integer in its binary representation as
	// there is no way to insert a boolean directly as a value of a
	// key/value pair.
	verifiedValue := uint16(0)
	if verified {
		verifiedValue = 1
	}

	var verifiedBytes [2]byte
	binary.BigEndian.PutUint16(verifiedBytes[:], verifiedValue)

	bucket := ns.NestedReadWriteBucket(syncBucketName)
	err := bucket.Put(birthdayBlockVerifiedName, verifiedBytes[:])
	if err != nil {
		str := "failed to store birthday block verification"
		return managerError(ErrDatabase, str, err)
	}

	return nil
}

// managerExists returns whether or not the manager has already been created
// in the given database namespace.
func managerExists(ns walletdb.ReadBucket) bool {
	if ns == nil {
		return false
	}
	mainBucket := ns.NestedReadBucket(mainBucketName)
	return mainBucket != nil
}

// createScopedManagerNS creates the namespace buckets for a new registered
// manager scope within the top level bucket. All relevant sub-buckets that a
// ScopedManager needs to perform its duties are also created.

// createManagerNS creates the initial namespace structure needed for all of
// the manager data.  This includes things such as all of the buckets as well
// as the version and creation date. In addition to creating the key space for
// the root address manager, we'll also create internal scopes for all the
// default manager scope types.
func createManagerNS(ns walletdb.ReadWriteBucket) error {

	// First, we'll create a main bucket
	mainBucket, err := ns.CreateBucket(mainBucketName)
	if err != nil {
		str := "failed to create main bucket"
		return managerError(ErrDatabase, str, err)
	}

	// Then, we'll create a bucket for storing the sync status
	_, err = ns.CreateBucket(syncBucketName)
	if err != nil {
		str := "failed to create sync bucket"
		return managerError(ErrDatabase, str, err)
	}

	// Last, we'll create all the relevant buckets and key/value that
	// stem off of the main bucket.

	if err := putManagerVersion(ns, latestMgrVersion); err != nil {
		return err
	}

	createDate := uint64(time.Now().Unix())
	var dateBytes [8]byte
	binary.LittleEndian.PutUint64(dateBytes[:], createDate)
	err = mainBucket.Put(mgrCreateDateName, dateBytes[:])
	if err != nil {
		str := "failed to store database creation time"
		return managerError(ErrDatabase, str, err)
	}

	_, err = mainBucket.CreateBucket(addrBukcetName)
	if err != nil {
		str := "failed to create address bucket"
		return managerError(ErrDatabase, str, err)
	}
	_, err = mainBucket.CreateBucket(askspBukcetName)
	if err != nil {
		str := "failed to create asksp bucket"
		return managerError(ErrDatabase, str, err)
	}
	_, err = mainBucket.CreateBucket(asksnBukcetName)
	if err != nil {
		str := "failed to create asksn bucket"
		return managerError(ErrDatabase, str, err)
	}
	_, err = mainBucket.CreateBucket(vskBukcetName)
	if err != nil {
		str := "failed to create valuesk bucket"
		return managerError(ErrDatabase, str, err)
	}

	return nil
}
