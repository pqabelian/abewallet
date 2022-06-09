package waddrmgr

// DerivationPath represents a derivation path from a particular key manager's
// scope.  Each ScopedKeyManager starts key derivation from the end of their
// cointype hardened key: m/purpose'/cointype'. The fields in this struct allow
// further derivation to the next three child levels after the coin type key.
// This restriction is in the spriti of BIP0044 type derivation. We maintain a
// degree of coherency with the standard, but allow arbitrary derivations
// beyond the cointype key. The key derived using this path will be exactly:
// m/purpose'/cointype'/account/branch/index, where purpose' and cointype' are
// bound by the scope of a particular manager.

// KeyScope represents a restricted key scope from the primary root key within
// the HD chain. From the root manager (m/) we can create a nearly arbitrary
// number of ScopedKeyManagers of key derivation path: m/purpose'/cointype'.
// These scoped managers can then me managed indecently, as they house the
// encrypted cointype key and can derive any child keys from there on.

// ScopedIndex is a tuple of KeyScope and child Index. This is used to compactly
// identify a particular child key, when the account and branch can be inferred
// from context.

// String returns a human readable version describing the keypath encapsulated
// by the target key scope.

// ScopeAddrSchema is the address schema of a particular KeyScope. This will be
// persisted within the database, and will be consulted when deriving any keys
// for a particular scope to know how to encode the public keys as addresses.

// ScopedKeyManager is a sub key manager under the main root key manager. The
// root key manager will handle the root HD key (m/), while each sub scoped key
// manager will handle the cointype key for a particular key scope
// (m/purpose'/cointype'). This abstraction allows higher-level applications
// built upon the root key manager to perform their own arbitrary key
// derivation, while still being protected under the encryption of the root key
// manager.

// Scope returns the exact KeyScope of this scoped key manager.

// AddrSchema returns the set address schema for the target ScopedKeyManager.

// zeroSensitivePublicData performs a best try effort to remove and zero all
// sensitive public data associated with the address manager such as
// hierarchical deterministic extended public keys and the crypto public keys.

// Close cleanly shuts down the manager.  It makes a best try effort to remove
// and zero all private key and sensitive public key material associated with
// the address manager from memory.

// keyToManaged returns a new managed address for the provided derived key and
// its derivation path which consists of the account, branch, and index.
//
// The passed derivedKey is zeroed after the new address is created.
//
// This function MUST be called with the manager lock held for writes.

// deriveKey returns either a public or private derived extended key based on
// the private flag for the given an account info, branch, and index.

// loadAccountInfo attempts to load and cache information about the given
// account from the database.   This includes what is necessary to derive new
// keys for it and track the state of the internal and external branches.
//
// This function MUST be called with the manager lock held for writes.

// AccountProperties returns properties associated with the account, such as
// the account number, name, and the number of derived and imported keys.

// DeriveFromKeyPath attempts to derive a maximal child key (under the BIP0044
// scheme) from a given key path. If key derivation isn't possible, then an
// error will be returned.

// deriveKeyFromPath returns either a public or private derived extended key
// based on the private flag for the given an account, branch, and index.
//
// This function MUST be called with the manager lock held for writes.

// chainAddressRowToManaged returns a new managed address based on chained
// address data loaded from the database.
//
// This function MUST be called with the manager lock held for writes.

// importedAddressRowToManaged returns a new managed address based on imported
// address data loaded from the database.

// scriptAddressRowToManaged returns a new managed address based on script
// address data loaded from the database.

// rowInterfaceToManaged returns a new managed address based on the given
// address data loaded from the database.  It will automatically select the
// appropriate type.
//
// This function MUST be called with the manager lock held for writes.

// loadAndCacheAddress attempts to load the passed address from the database
// and caches the associated managed address.
//
// This function MUST be called with the manager lock held for writes.

// existsAddress returns whether or not the passed address is known to the
// address manager.
//
// This function MUST be called with the manager lock held for reads.

// Address returns a managed address given the passed address if it is known to
// the address manager.  A managed address differs from the passed address in
// that it also potentially contains extra information needed to sign
// transactions such as the associated private key for pay-to-pubkey and
// pay-to-pubkey-hash addresses and the script associated with
// pay-to-script-hash addresses.

// AddrAccount returns the account to which the given address belongs.

// nextAddresses returns the specified number of next chained address from the
// branch indicated by the internal flag.
//
// This function MUST be called with the manager lock held for writes.

// extendAddresses ensures that all addresses up to and including the lastIndex
// are derived for either an internal or external branch. If the child at
// lastIndex is invalid, this method will proceed until the next valid child is
// found. An error is returned if method failed to properly extend addresses
// up to the requested index.
//
// This function MUST be called with the manager lock held for writes.

// NextExternalAddresses returns the specified number of next chained addresses
// that are intended for external use from the address manager.

// NextInternalAddresses returns the specified number of next chained addresses
// that are intended for internal use such as change from the address manager.

// ExtendExternalAddresses ensures that all valid external keys through
// lastIndex are derived and stored in the wallet. This is used to ensure that
// wallet's persistent state catches up to a external child that was found
// during recovery.

// ExtendInternalAddresses ensures that all valid internal keys through
// lastIndex are derived and stored in the wallet. This is used to ensure that
// wallet's persistent state catches up to an internal child that was found
// during recovery.

// LastExternalAddress returns the most recently requested chained external
// address from calling NextExternalAddress for the given account.  The first
// external address for the account will be returned if none have been
// previously requested.
//
// This function will return an error if the provided account number is greater
// than the MaxAccountNum constant or there is no account information for the
// passed account.  Any other errors returned are generally unexpected.

// LastInternalAddress returns the most recently requested chained internal
// address from calling NextInternalAddress for the given account.  The first
// internal address for the account will be returned if none have been
// previously requested.
//
// This function will return an error if the provided account number is greater
// than the MaxAccountNum constant or there is no account information for the
// passed account.  Any other errors returned are generally unexpected.

// NewRawAccount creates a new account for the scoped manager. This method
// differs from the NewAccount method in that this method takes the account
// number *directly*, rather than taking a string name for the account, then
// mapping that to the next highest account number.

// NewRawAccountWatchingOnly creates a new watching only account for
// the scoped manager.  This method differs from the
// NewAccountWatchingOnly method in that this method takes the account
// number *directly*, rather than taking a string name for the
// account, then mapping that to the next highest account number.

// NewAccount creates and returns a new account stored in the manager based on
// the given account name.  If an account with the same name already exists,
// ErrDuplicateAccount will be returned.  Since creating a new account requires
// access to the cointype keys (from which extended account keys are derived),
// it requires the manager to be unlocked.

// newAccount is a helper function that derives a new precise account number,
// and creates a mapping from the passed name to the account number in the
// database.
//
// NOTE: This function MUST be called with the manager lock held for writes.

// NewAccountWatchingOnly is similar to NewAccount, but for watch-only wallets.

// newAccountWatchingOnly is similar to newAccount, but for watching-only wallets.
//
// NOTE: This function MUST be called with the manager lock held for writes.

// RenameAccount renames an account stored in the manager based on the given
// account number with the given name.  If an account with the same name
// already exists, ErrDuplicateAccount will be returned.

// ImportPrivateKey imports a WIF private key into the address manager.  The
// imported address is created using either a compressed or uncompressed
// serialized public key, depending on the CompressPubKey bool of the WIF.
//
// All imported addresses will be part of the account defined by the
// ImportedAddrAccount constant.
//
// NOTE: When the address manager is watching-only, the private key itself will
// not be stored or available since it is private data.  Instead, only the
// public key will be stored.  This means it is paramount the private key is
// kept elsewhere as the watching-only address manager will NOT ever have access
// to it.
//
// This function will return an error if the address manager is locked and not
// watching-only, or not for the same network as the key trying to be imported.
// It will also return an error if the address already exists.  Any other
// errors returned are generally unexpected.

// ImportScript imports a user-provided script into the address manager.  The
// imported script will act as a pay-to-script-hash address.
//
// All imported script addresses will be part of the account defined by the
// ImportedAddrAccount constant.
//
// When the address manager is watching-only, the script itself will not be
// stored or available since it is considered private data.
//
// This function will return an error if the address manager is locked and not
// watching-only, or the address already exists.  Any other errors returned are
// generally unexpected.

// lookupAccount loads account number stored in the manager for the given
// account name
//b
// This function MUST be called with the manager lock held for reads.

// LookupAccount loads account number stored in the manager for the given
// account name

// fetchUsed returns true if the provided address id was flagged used.

// MarkUsed updates the used flag for the provided address.

// ChainParams returns the chain parameters for this address manager.

// AccountName returns the account name for the given account number stored in
// the manager.

// ForEachAccount calls the given function with each account stored in the
// manager, breaking early on error.

// LastAccount returns the last account stored in the manager.
// If no accounts, returns twos-complement representation of -1

// ForEachAccountAddress calls the given function with each address of the
// given account stored in the manager, breaking early on error.

// ForEachActiveAccountAddress calls the given function with each active
// address of the given account stored in the manager, breaking early on error.
//

// ForEachActiveAddress calls the given function with each active address
// stored in the manager, breaking early on error.

// ForEachInternalActiveAddress invokes the given closure on each _internal_
// active address belonging to the scoped key manager, breaking early on error.
