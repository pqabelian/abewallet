package waddrmgr

import (
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abewallet/walletdb"
)

// AddressType represents the various address types waddrmgr is currently able
// to generate, and maintain.
//
// NOTE: These MUST be stable as they're used for scope address schema
// recognition within the database.
type AddressType uint8

const (
	// PubKeyHash is a regular p2pkh address.
	PubKeyHash AddressType = iota

	// Script reprints a raw script address.
	Script

	// RawPubKey is just raw public key to be used within scripts, This
	// type indicates that a scoped manager with this address type
	// shouldn't be consulted during historical rescans.
	RawPubKey

	// NestedWitnessPubKey represents a p2wkh output nested within a p2sh
	// output. Using this address type, the wallet can receive funds from
	// other wallet's which don't yet recognize the new segwit standard
	// output types. Receiving funds to this address maintains the
	// scalability, and malleability fixes due to segwit in a backwards
	// compatible manner.
	NestedWitnessPubKey

	// WitnessPubKey represents a p2wkh (pay-to-witness-key-hash) address
	// type.
	WitnessPubKey
)

// ManagedAddress is an interface that provides acces to information regarding
// an address managed by an address manager. Concrete implementations of this
// type may provide further fields to provide information specific to that type
// of address.
type ManagedAddress interface {
	// Account returns the account the address is associated with.
	Account() uint32

	// Address returns a btcutil.Address for the backing address.
	Address() abeutil.Address

	// AddrHash returns the key or script hash related to the address
	AddrHash() []byte

	// Imported returns true if the backing address was imported instead
	// of being part of an address chain.
	Imported() bool

	// Internal returns true if the backing address was created for internal
	// use such as a change output of a transaction.
	Internal() bool

	// Compressed returns true if the backing address is compressed.
	Compressed() bool

	// Used returns true if the backing address has been used in a transaction.
	Used(ns walletdb.ReadBucket) bool

	// AddrType returns the address type of the managed address. This can
	// be used to quickly discern the address type without further
	// processing
	AddrType() AddressType
}

// ManagedPubKeyAddress extends ManagedAddress and additionally provides the
// public and private keys for pubkey-based addresses.

// ManagedScriptAddress extends ManagedAddress and represents a pay-to-script-hash
// style of bitcoin addresses.  It additionally provides information about the
// script.

// managedAddress represents a public key address.  It also may or may not have
// the private key associated with the public key.

// Enforce managedAddress satisfies the ManagedPubKeyAddress interface.

// unlock decrypts and stores a pointer to the associated private key.  It will
// fail if the key is invalid or the encrypted private key is not available.
// The returned clear text private key will always be a copy that may be safely
// used by the caller without worrying about it being zeroed during an address
// lock.

// lock zeroes the associated clear text private key.

// Account returns the account number the address is associated with.
//
// This is part of the ManagedAddress interface implementation.

// AddrType returns the address type of the managed address. This can be used
// to quickly discern the address type without further processing
//
// This is part of the ManagedAddress interface implementation.

// Address returns the abeutil.Address which represents the managed address.
// This will be a pay-to-pubkey-hash address.
//
// This is part of the ManagedAddress interface implementation.

// AddrHash returns the public key hash for the address.
//
// This is part of the ManagedAddress interface implementation.

// Imported returns true if the address was imported instead of being part of an
// address chain.
//
// This is part of the ManagedAddress interface implementation.

// Internal returns true if the address was created for internal use such as a
// change output of a transaction.
//
// This is part of the ManagedAddress interface implementation.

// Compressed returns true if the address is compressed.
//
// This is part of the ManagedAddress interface implementation.

// Used returns true if the address has been used in a transaction.
//
// This is part of the ManagedAddress interface implementation.

// PubKey returns the public key associated with the address.
//
// This is part of the ManagedPubKeyAddress interface implementation.

// pubKeyBytes returns the serialized public key bytes for the managed address
// based on whether or not the managed address is marked as compressed.

// ExportPubKey returns the public key associated with the address
// serialized as a hex encoded string.
//
// This is part of the ManagedPubKeyAddress interface implementation.

// PrivKey returns the private key for the address.  It can fail if the address
// manager is watching-only or locked, or the address does not have any keys.
//
// This is part of the ManagedPubKeyAddress interface implementation.

// ExportPrivKey returns the private key associated with the address in Wallet
// Import Format (WIF).
//
// This is part of the ManagedPubKeyAddress interface implementation.

// Derivationinfo contains the information required to derive the key that
// backs the address via traditional methods from the HD root. For imported
// keys, the first value will be set to false to indicate that we don't know
// exactly how the key was derived.
//
// This is part of the ManagedPubKeyAddress interface implementation.

// newManagedAddressWithoutPrivKey returns a new managed address based on the
// passed account, public key, and whether or not the public key should be
// compressed.

// newManagedAddress returns a new managed address based on the passed account,
// private key, and whether or not the public key is compressed.  The managed
// address will have access to the private and public keys.

// newManagedAddressFromExtKey returns a new managed address based on the passed
// account and extended key.  The managed address will have access to the
// private and public keys if the provided extended key is private, otherwise it
// will only have access to the public key.

// scriptAddress represents a pay-to-script-hash address.

// Enforce scriptAddress satisfies the ManagedScriptAddress interface.

// unlock decrypts and stores the associated script.  It will fail if the key is
// invalid or the encrypted script is not available.  The returned clear text
// script will always be a copy that may be safely used by the caller without
// worrying about it being zeroed during an address lock.

// lock zeroes the associated clear text private key.

// Account returns the account the address is associated with.  This will always
// be the ImportedAddrAccount constant for script addresses.
//
// This is part of the ManagedAddress interface implementation.

// AddrType returns the address type of the managed address. This can be used
// to quickly discern the address type without further processing
//
// This is part of the ManagedAddress interface implementation.

// Address returns the abeutil.Address which represents the managed address.
// This will be a pay-to-script-hash address.
//
// This is part of the ManagedAddress interface implementation.

// AddrHash returns the script hash for the address.
//
// This is part of the ManagedAddress interface implementation.

// Imported always returns true since script addresses are always imported
// addresses and not part of any chain.
//
// This is part of the ManagedAddress interface implementation.

// Internal always returns false since script addresses are always imported
// addresses and not part of any chain in order to be for internal use.
//
// This is part of the ManagedAddress interface implementation.

// Compressed returns false since script addresses are never compressed.
//
// This is part of the ManagedAddress interface implementation.

// Used returns true if the address has been used in a transaction.
//
// This is part of the ManagedAddress interface implementation.

// Script returns the script associated with the address.
//
// This implements the ScriptAddress interface.

// newScriptAddress initializes and returns a new pay-to-script-hash address.
