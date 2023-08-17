package waddrmgr

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abecrypto/abecryptoparam"
	"github.com/abesuite/abec/abeutil/hdkeychain"
	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abewallet/internal/prompt"
	"github.com/abesuite/abewallet/internal/zero"
	"github.com/abesuite/abewallet/snacl"
	"github.com/abesuite/abewallet/walletdb"
	"golang.org/x/crypto/sha3"
	"sync"
	"time"
)

const (
	// MaxAccountNum is the maximum allowed account number.  This value was
	// chosen because accounts are hardened children and therefore must not
	// exceed the hardened child range of extended keys and it provides a
	// reserved account at the top of the range for supporting imported
	// addresses.
	MaxAccountNum = hdkeychain.HardenedKeyStart - 2 // 2^31 - 2

	// MaxAddressesPerAccount is the maximum allowed number of addresses
	// per account number.  This value is based on the limitation of the
	// underlying hierarchical deterministic key derivation.
	MaxAddressesPerAccount = hdkeychain.HardenedKeyStart - 1

	// ImportedAddrAccount is the account number to use for all imported
	// addresses.  This is useful since normal accounts are derived from
	// the root hierarchical deterministic key and imported addresses do
	// not fit into that model.
	ImportedAddrAccount = MaxAccountNum + 1 // 2^31 - 1

	// ImportedAddrAccountName is the name of the imported account.
	ImportedAddrAccountName = "imported"

	// DefaultAccountNum is the number of the default account.
	DefaultAccountNum = 0

	// defaultAccountName is the initial name of the default account.  Note
	// that the default account may be renamed and is not a reserved name,
	// so the default account might not be named "default" and non-default
	// accounts may be named "default".
	//
	// Account numbers never change, so the DefaultAccountNum should be
	// used to refer to (and only to) the default account.
	defaultAccountName = "default"

	// The hierarchy described by BIP0043 is:
	//  m/<purpose>'/*
	// This is further extended by BIP0044 to:
	//  m/44'/<coin type>'/<account>'/<branch>/<address index>
	//
	// The branch is 0 for external addresses and 1 for internal addresses.

	// maxCoinType is the maximum allowed coin type used when structuring
	// the BIP0044 multi-account hierarchy.  This value is based on the
	// limitation of the underlying hierarchical deterministic key
	// derivation.
	maxCoinType = hdkeychain.HardenedKeyStart - 1

	// ExternalBranch is the child number to use when performing BIP0044
	// style hierarchical deterministic key derivation for the external
	// branch.
	ExternalBranch uint32 = 0

	// InternalBranch is the child number to use when performing BIP0044
	// style hierarchical deterministic key derivation for the internal
	// branch.
	InternalBranch uint32 = 1

	// saltSize is the number of bytes of the salt used when hashing
	// private passphrases.
	saltSize = 32
)

// isReservedAccountName returns true if the account name is reserved.
// Reserved accounts may never be renamed, and other accounts may not be
// renamed to a reserved name.
func isReservedAccountName(name string) bool {
	return name == ImportedAddrAccountName
}

// isReservedAccountNum returns true if the account number is reserved.
// Reserved accounts may not be renamed.

// ScryptOptions is used to hold the scrypt parameters needed when deriving new
// passphrase keys.
type ScryptOptions struct {
	N, R, P int
}

// OpenCallbacks houses caller-provided callbacks that may be called when
// opening an existing manager.  The open blocks on the execution of these
// functions.
type OpenCallbacks struct {
	// ObtainSeed is a callback function that is potentially invoked during
	// upgrades.  It is intended to be used to request the wallet seed
	// from the user (or any other mechanism the caller deems fit).
	ObtainSeed ObtainUserInputFunc

	// ObtainPrivatePass is a callback function that is potentially invoked
	// during upgrades.  It is intended to be used to request the wallet
	// private passphrase from the user (or any other mechanism the caller
	// deems fit).
	ObtainPrivatePass ObtainUserInputFunc
}

// DefaultScryptOptions is the default options used with scrypt.
var DefaultScryptOptions = ScryptOptions{
	N: 262144, // 2^18
	R: 8,
	P: 1,
}

// FastScryptOptions are the scrypt options that should be used for testing
// purposes only where speed is more important than security.
var FastScryptOptions = ScryptOptions{
	N: 16,
	R: 8,
	P: 1,
}

// accountInfo houses the current state of the internal and external branches
// of an account along with the extended keys needed to derive new keys.  It
// also handles locking by keeping an encrypted version of the serialized
// private extended key so the unencrypted versions can be cleared from memory
// when the address manager is locked.

// AccountProperties contains properties associated with each account, such as
// the account name, number, and the nubmer of derived and imported keys.

// unlockDeriveInfo houses the information needed to derive a private key for a
// managed address when the address manager is unlocked.  See the
// deriveOnUnlock field in the Manager struct for more details on how this is
// used.

// SecretKeyGenerator is the function signature of a method that can generate
// secret keys for the address manager.
type SecretKeyGenerator func(
	passphrase *[]byte, config *ScryptOptions) (*snacl.SecretKey, error)

// defaultNewSecretKey returns a new secret key.  See newSecretKey.
func defaultNewSecretKey(passphrase *[]byte,
	config *ScryptOptions) (*snacl.SecretKey, error) {
	return snacl.NewSecretKey(passphrase, config.N, config.R, config.P)
}

var (
	// secretKeyGen is the inner method that is executed when calling
	// newSecretKey.
	secretKeyGen = defaultNewSecretKey

	// secretKeyGenMtx protects access to secretKeyGen, so that it can be
	// replaced in testing.
	secretKeyGenMtx sync.RWMutex
)

// SetSecretKeyGen replaces the existing secret key generator, and returns the
// previous generator.
func SetSecretKeyGen(keyGen SecretKeyGenerator) SecretKeyGenerator {
	secretKeyGenMtx.Lock()
	oldKeyGen := secretKeyGen
	secretKeyGen = keyGen
	secretKeyGenMtx.Unlock()

	return oldKeyGen
}

// newSecretKey generates a new secret key using the active secretKeyGen.
func newSecretKey(passphrase *[]byte, config *ScryptOptions) (*snacl.SecretKey, error) {

	secretKeyGenMtx.RLock()
	defer secretKeyGenMtx.RUnlock()
	return secretKeyGen(passphrase, config)
}

// EncryptorDecryptor provides an abstraction on top of snacl.CryptoKey so that
// our tests can use dependency injection to force the behaviour they need.
type EncryptorDecryptor interface {
	Encrypt(in []byte) ([]byte, error)
	Decrypt(in []byte) ([]byte, error)
	Bytes() []byte
	CopyBytes([]byte)
	Zero()
}

// cryptoKey extends snacl.CryptoKey to implement EncryptorDecryptor.
type cryptoKey struct {
	snacl.CryptoKey
}

// Bytes returns a copy of this crypto key's byte slice.
func (ck *cryptoKey) Bytes() []byte {
	return ck.CryptoKey[:]
}

// CopyBytes copies the bytes from the given slice into this CryptoKey.
func (ck *cryptoKey) CopyBytes(from []byte) {
	copy(ck.CryptoKey[:], from)
}

// defaultNewCryptoKey returns a new CryptoKey.  See newCryptoKey.
func defaultNewCryptoKey() (EncryptorDecryptor, error) {
	key, err := snacl.GenerateCryptoKey()
	if err != nil {
		return nil, err
	}
	return &cryptoKey{*key}, nil
}

// CryptoKeyType is used to differentiate between different kinds of
// crypto keys.
type CryptoKeyType byte

// Crypto key types.
const (
	// CKTPrivate specifies the key that is used for encryption of private
	// key material such as derived extended private keys and imported
	// private keys.
	CKTPrivate CryptoKeyType = iota
	CKTSeed
	// CKTScript specifies the key that is used for encryption of scripts.
	CKTScript

	// CKTPublic specifies the key that is used for encryption of public
	// key material such as dervied extended public keys and imported public
	// keys.
	CKTPublic
)

// newCryptoKey is used as a way to replace the new crypto key generation
// function used so tests can provide a version that fails for testing error
// paths.
var newCryptoKey = defaultNewCryptoKey

type Manager struct {
	mtx sync.RWMutex

	// scopedManager is a mapping of scope of scoped manager, the manager
	// itself loaded into memory.
	//scopedManagers map[KeyScope]*ScopedKeyManager
	//payeeManagers []*PayeeManager

	//externalAddrSchemas map[AddressType][]KeyScope
	//internalAddrSchemas map[AddressType][]KeyScope
	gcnt         uint64 // global count for generate address and information for spending
	syncState    syncState
	watchingOnly bool
	birthday     time.Time
	locked       bool
	closed       bool
	chainParams  *chaincfg.Params

	// masterKeyPub is the secret key used to secure the cryptoKeyPub key
	// and masterKeyPriv is the secret key used to secure the cryptoKeyPriv
	// key.  This approach is used because it makes changing the passwords
	// much simpler as it then becomes just changing these keys.  It also
	// provides future flexibility.
	//
	// NOTE: This is not the same thing as BIP0032 master node extended
	// key.
	//
	// The underlying master private key will be zeroed when the address
	// manager is locked.
	masterKeyPub  *snacl.SecretKey
	masterKeyPriv *snacl.SecretKey

	// cryptoKeyPub is the key used to encrypt public extended keys and
	// addresses.
	cryptoKeyPub EncryptorDecryptor

	// cryptoKeyPriv is the key used to encrypt private data such as the
	// master hierarchical deterministic extended key.
	//
	// This key will be zeroed when the address manager is locked.
	cryptoKeyPrivEncrypted []byte
	cryptoKeyPriv          EncryptorDecryptor

	cryptoKeySeedEncrypted []byte
	cryptoKeySeed          EncryptorDecryptor
	// cryptoKeyScript is the key used to encrypt script data.
	//
	// This key will be zeroed when the address manager is locked.
	cryptoKeyScriptEncrypted []byte
	cryptoKeyScript          EncryptorDecryptor

	// privPassphraseSalt and hashedPrivPassphrase allow for the secure
	// detection of a correct passphrase on manager unlock when the
	// manager is already unlocked.  The hash is zeroed each lock.
	privPassphraseSalt   [saltSize]byte //To not compare the private key directly
	hashedPrivPassphrase [sha512.Size]byte
}

// WatchOnly returns true if the root manager is in watch only mode, and false
// otherwise.
func (m *Manager) WatchOnly() bool {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	return m.watchOnly()
}

// watchOnly returns true if the root manager is in watch only mode, and false
// otherwise.
//
// NOTE: This method requires the Manager's lock to be held.
func (m *Manager) watchOnly() bool {
	return m.watchingOnly
}

// lock performs a best try effort to remove and zero all secret keys associated
// with the address manager.
//
// This function MUST be called with the manager lock held for writes.
func (m *Manager) lock() {
	// Remove clear text private master and crypto keys from memory.
	m.cryptoKeyScript.Zero()
	m.cryptoKeyPriv.Zero()
	m.cryptoKeySeed.Zero()
	m.masterKeyPriv.Zero()

	// Zero the hashed passphrase.
	zero.Bytea64(&m.hashedPrivPassphrase)

	// NOTE: m.cryptoKeyPub is intentionally not cleared here as the address
	// manager needs to be able to continue to read and decrypt public data
	// which uses a separate derived key from the database even when it is
	// locked.

	m.locked = true
}

// Close cleanly shuts down the manager.  It makes a best try effort to remove
// and zero all private key and sensitive public key material associated with
// the address manager from memory.
func (m *Manager) Close() {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	if m.closed {
		return
	}
	// we have no public key to zero
	//for _, manager := range m.scopedManagers {
	//	// Zero out the account keys (if any) of all sub key managers.
	//	manager.Close()
	//}

	// Attempt to clear private key material from memory.
	if !m.watchingOnly && !m.locked {
		m.lock()
	}

	// Remove clear text public master and crypto keys from memory.
	m.cryptoKeyPub.Zero()
	m.masterKeyPub.Zero()

	m.closed = true
	return
}

// FetchScopedKeyManager attempts to fetch an active scoped manager according to
// its registered scope. If the manger is found, then a nil error is returned
// along with the active scoped manager. Otherwise, a nil manager and a non-nil
// error will be returned.

func (m *Manager) DecryptAddressKey(addressEnc, addressSecretSpEnc, addressSecretSnEnc, valueSecretKeyEnc []byte) ([]byte, []byte, []byte, []byte, error) {
	var addressBytes, valueSecretKeyBytes []byte
	var err error

	if addressEnc != nil {
		addressBytes, err = m.Decrypt(CKTPublic, addressEnc)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}

	if valueSecretKeyEnc != nil {
		valueSecretKeyBytes, err = m.Decrypt(CKTPublic, valueSecretKeyEnc)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}
	var addressSecretSnBytes []byte
	if addressSecretSnEnc != nil {
		addressSecretSnBytes, err = m.Decrypt(CKTPublic, addressSecretSnEnc)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}

	var addressSecretSpBytes []byte
	if !m.IsLocked() {
		if addressSecretSpEnc != nil {
			addressSecretSpBytes, err = m.Decrypt(CKTPrivate, addressSecretSpEnc)
			if err != nil {
				return nil, nil, nil, nil, err
			}
		}

	}
	return addressBytes, addressSecretSpBytes, addressSecretSnBytes, valueSecretKeyBytes, nil
}

// FetchAddressKeyEnc got addressEnc, addressSecretSpEnc, addressSecretSnEnc, valueSecretKeyEnc,
func (m *Manager) FetchAddressKeyEnc(ns walletdb.ReadBucket, coinAddrBytes []byte) ([]byte, []byte, []byte, []byte, uint64, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	addrKey := chainhash.DoubleHashB(coinAddrBytes)
	return fetchAddressKeyEnc(ns, addrKey)
}

// FetchAddressKeyEnc got addressEnc, addressSecretSpEnc, addressSecretSnEnc, valueSecretKeyEnc,
func (m *Manager) FetchAddressKeyEncByAddressKey(ns walletdb.ReadBucket, addrKey []byte) ([]byte, []byte, []byte, []byte, uint64, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return fetchAddressKeyEnc(ns, addrKey)
}

func (m *Manager) MarkAddrUsed(ns walletdb.ReadWriteBucket, idx uint64) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	log.Infof("No.%d address is marked used.", idx)
	return markAddrUsed(ns, idx)
}
func (m *Manager) CheckFreeAddress(ns walletdb.ReadBucket) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return checkFreeAddress(ns)
}
func (m *Manager) ListFreeAddresses(ns walletdb.ReadBucket) (map[uint64][]byte, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	res, err := fetchFreeAddressKeys(ns)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (m *Manager) FetchSeedEnc(ns walletdb.ReadBucket) ([]byte, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return fetchSeedEnc(ns)
}
func (m *Manager) FetchNetID(ns walletdb.ReadBucket) ([]byte, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return fetchNetID(ns)
}

func (m *Manager) PutAddressKeysEnc(ns walletdb.ReadWriteBucket, idx uint64, addrKey []byte, valueSecretKeyEnc,
	addressSecretKeySpEnc, addressSecretKeySnEnc, addressKeyEnc []byte) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return putAddressKeysEnc(ns, idx, addrKey, valueSecretKeyEnc, addressSecretKeySpEnc, addressSecretKeySnEnc, addressKeyEnc)

}
func (m *Manager) GenerateAddressKeys(ns walletdb.ReadWriteBucket, seed []byte) (uint64, []byte, []byte, []byte, []byte, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	// fetch the seed status
	cnt, err := fetchSeedStatus(ns)
	if err != nil {
		return 0, nil, nil, nil, nil, err
	}

	serializedCryptoAddress, serializedASksp, serializedASksn, serializedVSk, err := generateAddressSk(seed, len(seed), cnt+1)
	if err != nil {
		return 0, nil, nil, nil, nil, fmt.Errorf("failed to generate address and key")
	}
	log.Infof("The address with No. %d is created.", cnt+1)
	log.Infof("Wallet status: current max No. of address is %v.", cnt+1)

	err = markAddrUnused(ns, cnt+1)
	if err != nil {
		return 0, nil, nil, nil, nil, err
	}
	// update the seedStatus
	err = putSeedStatus(ns, cnt+1)
	if err != nil {
		return 0, nil, nil, nil, nil, err
	}

	return cnt + 1, serializedCryptoAddress, serializedASksp, serializedASksn, serializedVSk, nil
}

// ChainParams returns the chain parameters for this address manager.
func (m *Manager) ChainParams() *chaincfg.Params {
	// NOTE: No need for mutex here since the net field does not change
	// after the manager instance is created.

	return m.chainParams
}

// ChangePassphrase changes either the public or private passphrase to the
// provided value depending on the private flag.  In order to change the
// private password, the address manager must not be watching-only.  The new
// passphrase keys are derived using the scrypt parameters in the options, so
// changing the passphrase may be used to bump the computational difficulty
// needed to brute force the passphrase.
func (m *Manager) ChangePassphrase(ns walletdb.ReadWriteBucket, oldPassphrase,
	newPassphrase []byte, private bool, config *ScryptOptions) error {

	// No private passphrase to change for a watching-only address manager.
	if private && m.watchingOnly {
		return managerError(ErrWatchingOnly, errWatchingOnly, nil)
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	// Ensure the provided old passphrase is correct.  This check is done
	// using a copy of the appropriate master key depending on the private
	// flag to ensure the current state is not altered.  The temp key is
	// cleared when done to avoid leaving a copy in memory.
	var keyName string
	secretKey := snacl.SecretKey{Key: &snacl.CryptoKey{}}
	if private {
		keyName = "private"
		secretKey.Parameters = m.masterKeyPriv.Parameters
	} else {
		keyName = "public"
		secretKey.Parameters = m.masterKeyPub.Parameters
	}
	if err := secretKey.DeriveKey(&oldPassphrase); err != nil {
		if err == snacl.ErrInvalidPassword {
			str := fmt.Sprintf("invalid passphrase for %s master "+
				"key", keyName)
			return managerError(ErrWrongPassphrase, str, nil)
		}

		str := fmt.Sprintf("failed to derive %s master key", keyName)
		return managerError(ErrCrypto, str, err)
	}
	defer secretKey.Zero()

	// Generate a new master key from the passphrase which is used to secure
	// the actual secret keys.
	newMasterKey, err := newSecretKey(&newPassphrase, config)
	if err != nil {
		str := "failed to create new master private key"
		return managerError(ErrCrypto, str, err)
	}
	newKeyParams := newMasterKey.Marshal()

	if private {
		// Technically, the locked state could be checked here to only
		// do the decrypts when the address manager is locked as the
		// clear text keys are already available in memory when it is
		// unlocked, but this is not a hot path, decryption is quite
		// fast, and it's less cyclomatic complexity to simply decrypt
		// in either case.

		// Create a new salt that will be used for hashing the new
		// passphrase each unlock.
		var passphraseSalt [saltSize]byte
		_, err := rand.Read(passphraseSalt[:])
		if err != nil {
			str := "failed to read random source for passhprase salt"
			return managerError(ErrCrypto, str, err)
		}

		// Re-encrypt the crypto private key using the new master
		// private key.
		decPriv, err := secretKey.Decrypt(m.cryptoKeyPrivEncrypted)
		if err != nil {
			str := "failed to decrypt crypto private key"
			return managerError(ErrCrypto, str, err)
		}
		encPriv, err := newMasterKey.Encrypt(decPriv)
		zero.Bytes(decPriv)
		if err != nil {
			str := "failed to encrypt crypto private key"
			return managerError(ErrCrypto, str, err)
		}

		// Re-encrypt the crypto private key using the new master
		// private key.
		decSeed, err := secretKey.Decrypt(m.cryptoKeySeedEncrypted)
		if err != nil {
			str := "failed to decrypt crypto seed key"
			return managerError(ErrCrypto, str, err)
		}
		encSeed, err := newMasterKey.Encrypt(decSeed)
		zero.Bytes(encSeed)
		if err != nil {
			str := "failed to encrypt crypto seed key"
			return managerError(ErrCrypto, str, err)
		}

		// Re-encrypt the crypto script key using the new master
		// private key.
		decScript, err := secretKey.Decrypt(m.cryptoKeyScriptEncrypted)
		if err != nil {
			str := "failed to decrypt crypto script key"
			return managerError(ErrCrypto, str, err)
		}
		encScript, err := newMasterKey.Encrypt(decScript)
		zero.Bytes(decScript)
		if err != nil {
			str := "failed to encrypt crypto script key"
			return managerError(ErrCrypto, str, err)
		}

		// When the manager is locked, ensure the new clear text master
		// key is cleared from memory now that it is no longer needed.
		// If unlocked, create the new passphrase hash with the new
		// passphrase and salt.
		var hashedPassphrase [sha512.Size]byte
		if m.locked {
			newMasterKey.Zero()
		} else {
			saltedPassphrase := append(passphraseSalt[:],
				newPassphrase...)
			hashedPassphrase = sha512.Sum512(saltedPassphrase)
			zero.Bytes(saltedPassphrase)
		}

		// Save the new keys and params to the db in a single
		// transaction.
		// TODO 20220610 the public encrypt and the crypto key
		err = putCryptoKeys(ns, nil, encPriv, encScript, nil)
		if err != nil {
			return maybeConvertDbError(err)
		}

		err = putMasterKeyParams(ns, nil, newKeyParams)
		if err != nil {
			return maybeConvertDbError(err)
		}

		// Now that the db has been successfully updated, clear the old
		// key and set the new one.
		copy(m.cryptoKeySeedEncrypted[:], encSeed)
		copy(m.cryptoKeyPrivEncrypted[:], encPriv)
		copy(m.cryptoKeyScriptEncrypted[:], encScript)
		m.masterKeyPriv.Zero() // Clear the old key.
		m.masterKeyPriv = newMasterKey
		m.privPassphraseSalt = passphraseSalt
		m.hashedPrivPassphrase = hashedPassphrase
	} else {
		// Re-encrypt the crypto public key using the new master public
		// key.
		encryptedPub, err := newMasterKey.Encrypt(m.cryptoKeyPub.Bytes())
		if err != nil {
			str := "failed to encrypt crypto public key"
			return managerError(ErrCrypto, str, err)
		}

		// Save the new keys and params to the the db in a single
		// transaction.
		// TODO 20220610 the private key, script key, crypto key
		err = putCryptoKeys(ns, encryptedPub, nil, nil, nil)
		if err != nil {
			return maybeConvertDbError(err)
		}

		err = putMasterKeyParams(ns, newKeyParams, nil)
		if err != nil {
			return maybeConvertDbError(err)
		}

		// Now that the db has been successfully updated, clear the old
		// key and set the new one.
		m.masterKeyPub.Zero()
		m.masterKeyPub = newMasterKey
	}

	return nil
}

// ConvertToWatchingOnly converts the current address manager to a locked
// watching-only address manager.
//
// WARNING: This function removes private keys from the existing address manager
// which means they will no longer be available.  Typically the caller will make
// a copy of the existing wallet database and modify the copy since otherwise it
// would mean permanent loss of any imported private keys and scripts.
//
// Executing this function on a manager that is already watching-only will have
// no effect.
func (m *Manager) ConvertToWatchingOnly(ns walletdb.ReadWriteBucket) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	// Exit now if the manager is already watching-only.
	if m.watchingOnly {
		return nil
	}

	var err error

	// Remove all private key material and mark the new database as
	// watching only.
	if err := deletePrivateKeys(ns); err != nil {
		return maybeConvertDbError(err)
	}

	err = putWatchingOnly(ns, true)
	if err != nil {
		return maybeConvertDbError(err)
	}

	// Lock the manager to remove all clear text private key material from
	// memory if needed.
	if !m.locked {
		m.lock()
	}

	// Clear and remove encrypted private and script crypto keys.
	zero.Bytes(m.cryptoKeyScriptEncrypted)
	m.cryptoKeyScriptEncrypted = nil
	m.cryptoKeyScript = nil
	zero.Bytes(m.cryptoKeyPrivEncrypted)
	m.cryptoKeyPrivEncrypted = nil
	m.cryptoKeyPriv = nil
	zero.Bytes(m.cryptoKeySeedEncrypted)
	m.cryptoKeySeedEncrypted = nil
	m.cryptoKeySeed = nil

	// The master private key is derived from a passphrase when the manager
	// is unlocked, so there is no encrypted version to zero.  However,
	// it is no longer needed, so nil it.
	m.masterKeyPriv = nil

	// Mark the manager watching-only.
	m.watchingOnly = true
	return nil

}

// IsLocked returns whether or not the address managed is locked.  When it is
// unlocked, the decryption key needed to decrypt private keys used for signing
// is in memory.
func (m *Manager) IsLocked() bool {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	return m.isLocked()
}

// isLocked is an internal method returning whether or not the address manager
// is locked via an unprotected read.
//
// NOTE: The caller *MUST* acquire the Manager's mutex before invocation to
// avoid data races.
func (m *Manager) isLocked() bool {
	return m.locked
}

// Lock performs a best try effort to remove and zero all secret keys associated
// with the address manager.
//
// This function will return an error if invoked on a watching-only address
// manager.
func (m *Manager) Lock() error {
	// A watching-only address manager can't be locked.
	if m.watchingOnly {
		return managerError(ErrWatchingOnly, errWatchingOnly, nil)
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	// Error on attempt to lock an already locked manager.
	if m.locked {
		return managerError(ErrLocked, errLocked, nil)
	}

	m.lock()
	return nil
}

// Unlock derives the master private key from the specified passphrase.  An
// invalid passphrase will return an error.  Otherwise, the derived secret key
// is stored in memory until the address manager is locked.  Any failures that
// occur during this function will result in the address manager being locked,
// even if it was already unlocked prior to calling this function.
//
// This function will return an error if invoked on a watching-only address
// manager.
func (m *Manager) Unlock(ns walletdb.ReadBucket, passphrase []byte) error {
	// A watching-only address manager can't be unlocked.
	if m.watchingOnly {
		return managerError(ErrWatchingOnly, errWatchingOnly, nil)
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	// Avoid actually unlocking if the manager is already unlocked
	// and the passphrases match.
	if !m.locked {
		saltedPassphrase := append(m.privPassphraseSalt[:],
			passphrase...)
		hashedPassphrase := sha512.Sum512(saltedPassphrase)
		zero.Bytes(saltedPassphrase)
		if hashedPassphrase != m.hashedPrivPassphrase {
			m.lock()
			str := "invalid passphrase for master private key"
			return managerError(ErrWrongPassphrase, str, nil)
		}
		return nil
	}

	// Derive the master private key using the provided passphrase.
	if err := m.masterKeyPriv.DeriveKey(&passphrase); err != nil {
		m.lock()
		if err == snacl.ErrInvalidPassword {
			str := "invalid passphrase for master private key"
			return managerError(ErrWrongPassphrase, str, nil)
		}

		str := "failed to derive master private key"
		return managerError(ErrCrypto, str, err)
	}

	// Use the master private key to decrypt the crypto private key.
	decryptedKey, err := m.masterKeyPriv.Decrypt(m.cryptoKeyPrivEncrypted)
	if err != nil {
		m.lock()
		str := "failed to decrypt crypto private key"
		return managerError(ErrCrypto, str, err)
	}
	m.cryptoKeyPriv.CopyBytes(decryptedKey)
	zero.Bytes(decryptedKey)

	// Use the master private key to decrypt the crypto private key.
	decryptedKey, err = m.masterKeyPriv.Decrypt(m.cryptoKeySeedEncrypted)
	if err != nil {
		m.lock()
		str := "failed to decrypt crypto seed key"
		return managerError(ErrCrypto, str, err)
	}
	m.cryptoKeySeed.CopyBytes(decryptedKey)
	zero.Bytes(decryptedKey)

	m.locked = false
	saltedPassphrase := append(m.privPassphraseSalt[:], passphrase...)
	m.hashedPrivPassphrase = sha512.Sum512(saltedPassphrase)
	zero.Bytes(saltedPassphrase)
	return nil
}

// selectCryptoKey selects the appropriate crypto key based on the key type. An
// error is returned when an invalid key type is specified or the requested key
// requires the manager to be unlocked when it isn't.
//
// This function MUST be called with the manager lock held for reads.
func (m *Manager) selectCryptoKey(keyType CryptoKeyType) (EncryptorDecryptor, error) {
	if keyType == CKTPrivate || keyType == CKTSeed || keyType == CKTScript {
		// The manager must be unlocked to work with the private keys.
		if m.locked || m.watchingOnly {
			return nil, managerError(ErrLocked, errLocked, nil)
		}
	}

	var cryptoKey EncryptorDecryptor
	switch keyType {
	case CKTPrivate:
		cryptoKey = m.cryptoKeyPriv
	case CKTSeed:
		cryptoKey = m.cryptoKeySeed
	case CKTScript:
		cryptoKey = m.cryptoKeyScript
	case CKTPublic:
		cryptoKey = m.cryptoKeyPub
	default:
		return nil, managerError(ErrInvalidKeyType, "invalid key type",
			nil)
	}

	return cryptoKey, nil
}

// Encrypt in using the crypto key type specified by keyType.
func (m *Manager) Encrypt(keyType CryptoKeyType, in []byte) ([]byte, error) {
	// Encryption must be performed under the manager mutex since the
	// keys are cleared when the manager is locked.
	m.mtx.Lock()
	defer m.mtx.Unlock()

	cryptoKey, err := m.selectCryptoKey(keyType)
	if err != nil {
		return nil, err
	}

	encrypted, err := cryptoKey.Encrypt(in)
	if err != nil {
		return nil, managerError(ErrCrypto, "failed to encrypt", err)
	}
	return encrypted, nil
}

// Decrypt in using the crypto key type specified by keyType.
func (m *Manager) Decrypt(keyType CryptoKeyType, in []byte) ([]byte, error) {
	// Decryption must be performed under the manager mutex since the keys
	// are cleared when the manager is locked.
	m.mtx.Lock()
	defer m.mtx.Unlock()

	cryptoKey, err := m.selectCryptoKey(keyType)
	if err != nil {
		return nil, err
	}

	decrypted, err := cryptoKey.Decrypt(in)
	if err != nil {
		return nil, managerError(ErrCrypto, "failed to decrypt", err)
	}
	return decrypted, nil
}

// newManager returns a new locked address manager with the given parameters.
func newManager(chainParams *chaincfg.Params, masterKeyPub,
	masterKeyPriv *snacl.SecretKey, cryptoKeyPub EncryptorDecryptor,
	cryptoKeySeedEncrypted, cryptoKeyPrivEncrypted,
	cryptoKeyScriptEncrypted []byte, syncInfo *syncState,
	birthday time.Time, privPassphraseSalt [32]byte,
	watchingOnly bool) *Manager {
	m := &Manager{
		chainParams:              chainParams,
		syncState:                *syncInfo,
		locked:                   true,
		birthday:                 birthday,
		masterKeyPub:             masterKeyPub,
		masterKeyPriv:            masterKeyPriv,
		cryptoKeyPub:             cryptoKeyPub,
		cryptoKeySeedEncrypted:   cryptoKeySeedEncrypted,
		cryptoKeySeed:            &cryptoKey{},
		cryptoKeyPrivEncrypted:   cryptoKeyPrivEncrypted,
		cryptoKeyPriv:            &cryptoKey{},
		cryptoKeyScriptEncrypted: cryptoKeyScriptEncrypted,
		cryptoKeyScript:          &cryptoKey{},
		privPassphraseSalt:       privPassphraseSalt,
		//scopedManagers:           scopedManagers,
		//externalAddrSchemas:      make(map[AddressType][]KeyScope),
		//internalAddrSchemas:      make(map[AddressType][]KeyScope),
		watchingOnly: watchingOnly,
	}

	//for _, sMgr := range m.scopedManagers {
	//	externalType := sMgr.AddrSchema().ExternalAddrType
	//	internalType := sMgr.AddrSchema().InternalAddrType
	//	scope := sMgr.Scope()
	//
	//	m.externalAddrSchemas[externalType] = append(
	//		m.externalAddrSchemas[externalType], scope,
	//	)
	//	m.internalAddrSchemas[internalType] = append(
	//		m.internalAddrSchemas[internalType], scope,
	//	)
	//}

	return m
}
func loadManager(ns walletdb.ReadBucket, pubPassphrase []byte,
	chainParams *chaincfg.Params) (*Manager, error) {
	// Verify the version is neither too old or too new.
	version, err := fetchManagerVersion(ns)
	if err != nil {
		str := "failed to fetch version for update"
		return nil, managerError(ErrDatabase, str, err)
	}
	if version < latestMgrVersion {
		str := "database upgrade required"
		return nil, managerError(ErrUpgrade, str, nil)
	} else if version > latestMgrVersion {
		str := "database version is greater than latest understood version"
		return nil, managerError(ErrUpgrade, str, nil)
	}

	// Load whether or not the manager is watching-only from the db.
	watchingOnly, err := fetchWatchingOnly(ns)
	if err != nil {
		return nil, maybeConvertDbError(err)
	}

	// Load the master key params from the db.
	masterKeyPubParams, masterKeyPrivParams, err := fetchMasterKeyParams(ns)
	if err != nil {
		return nil, maybeConvertDbError(err)
	}

	// Load the crypto keys from the db.
	cryptoKeyPubEnc, cryptoKeySeedEnc, cryptoKeyPrivEnc, cryptoKeyScriptEnc, err :=
		fetchCryptoKeys(ns)
	if err != nil {
		return nil, maybeConvertDbError(err)
	}

	// Load the sync state from the db.
	syncedTo, err := fetchSyncedTo(ns)
	if err != nil {
		return nil, maybeConvertDbError(err)
	}
	startBlock, err := FetchStartBlock(ns)
	if err != nil {
		return nil, maybeConvertDbError(err)
	}
	birthday, err := fetchBirthday(ns)
	if err != nil {
		return nil, maybeConvertDbError(err)
	}

	// When not a watching-only manager, set the master private key params,
	// but don't derive it now since the manager starts off locked.
	var masterKeyPriv snacl.SecretKey
	if !watchingOnly {
		err := masterKeyPriv.Unmarshal(masterKeyPrivParams)
		if err != nil {
			str := "failed to unmarshal master private key"
			return nil, managerError(ErrCrypto, str, err)
		}
	}

	// Derive the master public key using the serialized params and provided
	// passphrase.
	var masterKeyPub snacl.SecretKey
	if err := masterKeyPub.Unmarshal(masterKeyPubParams); err != nil {
		str := "failed to unmarshal master public key"
		return nil, managerError(ErrCrypto, str, err)
	}
	if err := masterKeyPub.DeriveKey(&pubPassphrase); err != nil {
		str := "invalid passphrase for master public key"
		return nil, managerError(ErrWrongPassphrase, str, nil)
	}

	// Use the master public key to decrypt the crypto public key.
	cryptoKeyPub := &cryptoKey{snacl.CryptoKey{}}
	cryptoKeyPubCT, err := masterKeyPub.Decrypt(cryptoKeyPubEnc)
	if err != nil {
		str := "failed to decrypt crypto public key"
		return nil, managerError(ErrCrypto, str, err)
	}
	cryptoKeyPub.CopyBytes(cryptoKeyPubCT)
	zero.Bytes(cryptoKeyPubCT)

	// Create the sync state struct.
	syncInfo := newSyncState(startBlock, syncedTo)

	// Generate private passphrase salt.
	// TODO(abe) why generate a new salt?
	var privPassphraseSalt [saltSize]byte
	_, err = rand.Read(privPassphraseSalt[:])
	if err != nil {
		str := "failed to read random source for passphrase salt"
		return nil, managerError(ErrCrypto, str, err)
	}

	// Next, we'll need to load all known manager scopes from disk. Each
	// scope is on a distinct top-level path within our HD key chain.
	//scopedManagers := make(map[KeyScope]*ScopedKeyManager)
	//err = forEachKeyScope(ns, func(scope KeyScope) error {
	//	scopeSchema, err := fetchScopeAddrSchema(ns, &scope)
	//	if err != nil {
	//		return err
	//	}
	//
	//	scopedManagers[scope] = &ScopedKeyManager{
	//		scope:      scope,
	//		addrSchema: *scopeSchema,
	//		addrs:      make(map[addrKey]ManagedAddress),
	//		acctInfo:   make(map[uint32]*accountInfo),
	//	}
	//
	//	return nil
	//})
	//if err != nil {
	//	return nil, err
	//}

	// Create new address manager with the given parameters.  Also,
	// override the defaults for the additional fields which are not
	// specified in the call to new with the values loaded from the
	// database.
	mgr := newManager(
		chainParams, &masterKeyPub, &masterKeyPriv,
		cryptoKeyPub, cryptoKeySeedEnc, cryptoKeyPrivEnc, cryptoKeyScriptEnc, syncInfo,
		birthday, privPassphraseSalt, watchingOnly,
	)

	return mgr, nil
}

// Open loads an existing address manager from the given namespace.  The public
// passphrase is required to decrypt the public keys used to protect the public
// information such as addresses.  This is important since access to BIP0032
// extended keys means it is possible to generate all future addresses.
//
// If a config structure is passed to the function, that configuration will
// override the defaults.
//
// A ManagerError with an error code of ErrNoExist will be returned if the
// passed manager does not exist in the specified namespace.
func Open(ns walletdb.ReadBucket, pubPassphrase []byte,
	chainParams *chaincfg.Params) (*Manager, error) {

	// Return an error if the manager has NOT already been created in the
	// given database namespace.
	exists := managerExists(ns)
	if !exists {
		str := "the specified address manager does not exist"
		return nil, managerError(ErrNoExist, str, nil)
	}

	return loadManager(ns, pubPassphrase, chainParams)
}

// Create creates a new address manager in the given namespace.
//
// The seed must conform to the standards described in
// hdkeychain.NewMaster and will be used to create the master root
// node from which all hierarchical deterministic addresses are
// derived.  This allows all chained addresses in the address manager
// to be recovered by using the same seed.
//
// If the provided seed value is nil the address manager will be
// created in watchingOnly mode in which case no default accounts or
// scoped managers are created - it is up to the caller to create a
// new one with NewAccountWatchingOnly and NewScopedKeyManager.
//
// All private and public keys and information are protected by secret
// keys derived from the provided private and public passphrases.  The
// public passphrase is required on subsequent opens of the address
// manager, and the private passphrase is required to unlock the
// address manager in order to gain access to any private keys and
// information.
//
// If a config structure is passed to the function, that configuration
// will override the defaults.
//
// A ManagerError with an error code of ErrAlreadyExists will be
// returned the address manager already exists in the specified
// namespace.

// 																		        (add,asksp,asksn,vsk)
// 																		           ^          ^
// 																		           |          |
// 																		           |No       |No
// 																		           |          |
//  																	seed(x)-> seedAdd(√) + seedValue(√)
// privpassphrase -> masterkeyprive  | [cryptoKeyPriv/cryptoKeyScript -> masterViewKey/masterPrivKey]
//    							     | [cryptoKeySeed ->  				 seedAdd/seedValue]
//                       	         |
// pubpassphrase -> masterkeypub     | [cryptoKeyPub -> 				 masterPubKey]

func Create(ns walletdb.ReadWriteBucket,
	seed, pubPassphrase, privPassphrase []byte, end uint64,
	chainParams *chaincfg.Params, config *ScryptOptions,
	birthday time.Time) error {

	// If the seed argument is nil we create in watchingOnly mode.
	isWatchingOnly := seed == nil

	// Return an error if the manager has already been created in
	// the given database namespace.
	exists := managerExists(ns)
	if exists {
		return managerError(ErrAlreadyExists, errAlreadyExists, nil)
	}

	// Ensure the private passphrase is not empty.
	if !isWatchingOnly && len(privPassphrase) == 0 {
		str := "private passphrase may not be empty"
		return managerError(ErrEmptyPassphrase, str, nil)
	}

	if err := createManagerNS(ns); err != nil {
		return maybeConvertDbError(err)
	}

	if config == nil {
		config = &DefaultScryptOptions
	}

	// Generate new master keys.  These master keys are used to protect the
	// crypto keys that will be generated next.
	masterKeyPub, err := newSecretKey(&pubPassphrase, config)
	if err != nil {
		str := "failed to master public key"
		return managerError(ErrCrypto, str, err)
	}

	// Generate new crypto public, private, and script keys.  These keys are
	// used to protect the actual public and private data such as addresses,
	// extended keys, and scripts.
	cryptoKeyPub, err := newCryptoKey()
	if err != nil {
		str := "failed to generate crypto public key"
		return managerError(ErrCrypto, str, err)
	}

	// Encrypt the crypto keys with the associated master keys.
	cryptoKeyPubEnc, err := masterKeyPub.Encrypt(cryptoKeyPub.Bytes())
	if err != nil {
		str := "failed to encrypt crypto public key"
		return managerError(ErrCrypto, str, err)
	}

	// Use the genesis block for the passed chain as the created at block
	// for the default.
	createdAt := &BlockStamp{
		Hash:      *chainParams.GenesisHash,
		Height:    0,
		Timestamp: chainParams.GenesisBlock.Header.Timestamp,
	}

	// Create the initial sync state.
	syncInfo := newSyncState(createdAt, createdAt)

	pubParams := masterKeyPub.Marshal()

	var privParams []byte = nil
	var masterKeyPriv *snacl.SecretKey
	var cryptoKeyPrivEnc []byte = nil
	var cryptoKeyScriptEnc []byte = nil
	var cryptoKeySeedEnc []byte = nil
	if !isWatchingOnly {
		masterKeyPriv, err = newSecretKey(&privPassphrase, config)
		if err != nil {
			str := "failed to master private key"
			return managerError(ErrCrypto, str, err)
		}
		defer masterKeyPriv.Zero()

		// Generate the private passphrase salt.  This is used when
		// hashing passwords to detect whether an unlock can be
		// avoided when the manager is already unlocked.
		var privPassphraseSalt [saltSize]byte
		_, err = rand.Read(privPassphraseSalt[:])
		if err != nil {
			str := "failed to read random source for passphrase salt"
			return managerError(ErrCrypto, str, err)
		}

		cryptoKeyPriv, err := newCryptoKey()
		if err != nil {
			str := "failed to generate crypto private key"
			return managerError(ErrCrypto, str, err)
		}
		defer cryptoKeyPriv.Zero()

		cryptoKeyScript, err := newCryptoKey()
		if err != nil {
			str := "failed to generate crypto script key"
			return managerError(ErrCrypto, str, err)
		}
		defer cryptoKeyScript.Zero()

		cryptoKeySeed, err := newCryptoKey()
		if err != nil {
			str := "failed to generate crypto seed key"
			return managerError(ErrCrypto, str, err)
		}
		defer cryptoKeySeed.Zero()

		cryptoKeyPrivEnc, err =
			masterKeyPriv.Encrypt(cryptoKeyPriv.Bytes())
		if err != nil {
			str := "failed to encrypt crypto private key"
			return managerError(ErrCrypto, str, err)
		}
		cryptoKeyScriptEnc, err =
			masterKeyPriv.Encrypt(cryptoKeyScript.Bytes())
		if err != nil {
			str := "failed to encrypt crypto script key"
			return managerError(ErrCrypto, str, err)
		}
		cryptoKeySeedEnc, err =
			masterKeyPriv.Encrypt(cryptoKeySeed.Bytes())
		if err != nil {
			str := "failed to encrypt crypto seed key"
			return managerError(ErrCrypto, str, err)
		}

		// generate a longer seed from origin seed via hash function such as shake256
		seedLength := len(seed)
		usedSeed := make([]byte, seedLength*2)
		shake256 := sha3.NewShake256()
		shake256.Reset()
		tmp := []byte{'a', 'd', 'd', 'r', 'e', 's', 's'}
		tmp = append(tmp, seed...)
		shake256.Write(tmp)
		shake256.Read(usedSeed[:seedLength])

		shake256.Reset()
		tmp = []byte{'v', 'a', 'l', 'u', 'e'}
		tmp = append(tmp, seed...)
		shake256.Write(tmp)
		shake256.Read(usedSeed[seedLength:])

		seedEnc, err :=
			cryptoKeySeed.Encrypt(usedSeed)
		if err != nil {
			return maybeConvertDbError(err)
		}
		if end == prompt.MAXCOUNTERADDRESS {
			cnt := uint64(0)
			// create and generate an address and print it
			// generate an address and information for spending
			serializedCryptoAddress, serializedASksp, serializedASksn, serializedVSk, err := generateAddressSk(usedSeed, 2*seedLength, cnt)
			if err != nil {
				return fmt.Errorf("failed to generate address and key")
			}
			addKey := chainhash.DoubleHashB(serializedCryptoAddress[4 : 4+abecryptoparam.PQRingCTPP.AddressPublicKeySerializeSize()])
			addressSecretKeySpEnc, err :=
				cryptoKeyPriv.Encrypt(serializedASksp)
			if err != nil {
				return maybeConvertDbError(err)
			}
			addressSecretKeySnEnc, err :=
				cryptoKeyPub.Encrypt(serializedASksn)
			if err != nil {
				return maybeConvertDbError(err)
			}
			addressKeyEnc, err :=
				cryptoKeyPub.Encrypt(serializedCryptoAddress)
			if err != nil {
				return maybeConvertDbError(err)
			}
			valueSecretKeyEnc, err :=
				cryptoKeyPub.Encrypt(serializedVSk)
			if err != nil {
				return maybeConvertDbError(err)
			}

			err = putAddressKeysEnc(ns, cnt, addKey, valueSecretKeyEnc,
				addressSecretKeySpEnc, addressSecretKeySnEnc, addressKeyEnc)
			if err != nil {
				return maybeConvertDbError(err)
			}
			// record the status
			end = 0

			b := make([]byte, len(serializedCryptoAddress)+1)
			b[0] = chainParams.AbelAddressNetId
			copy(b[1:], serializedCryptoAddress)
			// generate the hash of (abecrypto.CryptoSchemePQRINGCT || serialized address)
			hash := chainhash.DoubleHashB(b)
			b = append(b, hash...)
			fmt.Println(`Please remember the initial address:`)
			fmt.Println(hex.EncodeToString(b))
		} else {
			// restore the previous address
			for i := uint64(0); i <= end; i++ {
				// generate an address and information for spending
				serializedCryptoAddress, serializedASksp, serializedASksn, serializedVSk, err := generateAddressSk(usedSeed, 2*seedLength, i)
				if err != nil {
					return fmt.Errorf("failed to generate address and key")
				}
				addKey := chainhash.DoubleHashB(serializedCryptoAddress[4 : 4+abecryptoparam.PQRingCTPP.AddressPublicKeySerializeSize()])
				addressSecretKeySpEnc, err :=
					cryptoKeyPriv.Encrypt(serializedASksp)
				if err != nil {
					return maybeConvertDbError(err)
				}
				addressSecretKeySnEnc, err :=
					cryptoKeyPub.Encrypt(serializedASksn)
				if err != nil {
					return maybeConvertDbError(err)
				}
				addressKeyEnc, err :=
					cryptoKeyPub.Encrypt(serializedCryptoAddress)
				if err != nil {
					return maybeConvertDbError(err)
				}
				valueSecretKeyEnc, err :=
					cryptoKeyPub.Encrypt(serializedVSk)
				if err != nil {
					return maybeConvertDbError(err)
				}

				err = putAddressKeysEnc(ns, i, addKey, valueSecretKeyEnc,
					addressSecretKeySpEnc, addressSecretKeySnEnc, addressKeyEnc)
				if err != nil {
					return maybeConvertDbError(err)
				}
			}
			log.Infof("The addresses with No. in [0, %d] have been restored.", end)
		}

		startSeedStatus := end

		err = putSeedEnc(ns, seedEnc)
		if err != nil {
			return maybeConvertDbError(err)
		}
		err = putSeedStatus(ns, startSeedStatus)
		if err != nil {
			return maybeConvertDbError(err)
		}
		err = putNetID(ns, []byte{chainParams.PQRingCTID})
		if err != nil {
			return maybeConvertDbError(err)
		}

		privParams = masterKeyPriv.Marshal()
	}

	// Save the master key params to the database.
	err = putMasterKeyParams(ns, pubParams, privParams)
	if err != nil {
		return maybeConvertDbError(err)
	}

	// Save the encrypted crypto keys to the database.
	err = putCryptoKeys(ns, cryptoKeyPubEnc, cryptoKeyPrivEnc,
		cryptoKeyScriptEnc, cryptoKeySeedEnc)
	if err != nil {
		return maybeConvertDbError(err)
	}

	// Save the watching-only mode of the address manager to the
	// database.
	err = putWatchingOnly(ns, isWatchingOnly)
	if err != nil {
		return maybeConvertDbError(err)
	}

	// Save the initial synced to state.
	err = PutSyncedTo(ns, &syncInfo.syncedTo)
	if err != nil {
		return maybeConvertDbError(err)
	}
	err = putStartBlock(ns, &syncInfo.startBlock)
	if err != nil {
		return maybeConvertDbError(err)
	}

	// Use 48 hours as margin of safety for wallet birthday.
	return putBirthday(ns, birthday.Add(-48*time.Hour))
}

func generateAddressSk(seed []byte, length int, cnt uint64) ([]byte, []byte, []byte, []byte, error) {
	if len(seed) != length {
		return nil, nil, nil, nil, errors.New("the length of given seed is not matched")
	}
	seedHalfLength := length >> 1
	halfLength := abecryptoparam.PQRingCTPP.ParamSeedBytesLen()
	usedSeed := make([]byte, 2*halfLength)

	var tmp []byte
	tmp = make([]byte, seedHalfLength+10)
	copy(tmp, seed[:seedHalfLength])
	tmp[seedHalfLength+0] = 'N'
	tmp[seedHalfLength+1] = 'o'
	tmp[seedHalfLength+2] = byte(cnt >> 0)
	tmp[seedHalfLength+3] = byte(cnt >> 1)
	tmp[seedHalfLength+4] = byte(cnt >> 2)
	tmp[seedHalfLength+5] = byte(cnt >> 3)
	tmp[seedHalfLength+6] = byte(cnt >> 4)
	tmp[seedHalfLength+7] = byte(cnt >> 5)
	tmp[seedHalfLength+8] = byte(cnt >> 6)
	tmp[seedHalfLength+9] = byte(cnt >> 7)
	t := sha3.Sum512(tmp)
	copy(usedSeed[:halfLength], t[:])

	tmp = make([]byte, seedHalfLength+10)
	copy(tmp, seed[seedHalfLength:])
	tmp[seedHalfLength+0] = 'N'
	tmp[seedHalfLength+1] = 'o'
	tmp[seedHalfLength+2] = byte(cnt >> 0)
	tmp[seedHalfLength+3] = byte(cnt >> 1)
	tmp[seedHalfLength+4] = byte(cnt >> 2)
	tmp[seedHalfLength+5] = byte(cnt >> 3)
	tmp[seedHalfLength+6] = byte(cnt >> 4)
	tmp[seedHalfLength+7] = byte(cnt >> 5)
	tmp[seedHalfLength+8] = byte(cnt >> 6)
	tmp[seedHalfLength+9] = byte(cnt >> 7)
	t = sha3.Sum512(tmp)
	copy(usedSeed[halfLength:], t[:])
	return abecrypto.CryptoAddressKeyGen(usedSeed, abecryptoparam.CryptoSchemePQRingCT)
}
