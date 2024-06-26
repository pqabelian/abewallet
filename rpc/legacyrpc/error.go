package legacyrpc

import (
	"errors"
	"github.com/abesuite/abec/abejson"
)

// TODO(jrick): There are several error paths which 'replace' various errors
// with a more appropiate error from the btcjson package.  Create a map of
// these replacements so they can be handled once after an RPC handler has
// returned and before the error is marshaled.

// Error types to simplify the reporting of specific categories of
// errors, and their *btcjson.RPCError creation.
type (
	// DeserializationError describes a failed deserializaion due to bad
	// user input.  It corresponds to btcjson.ErrRPCDeserialization.
	DeserializationError struct {
		error
	}

	// InvalidParameterError describes an invalid parameter passed by
	// the user.  It corresponds to btcjson.ErrRPCInvalidParameter.
	InvalidParameterError struct {
		error
	}

	// ParseError describes a failed parse due to bad user input.  It
	// corresponds to btcjson.ErrRPCParse.
	ParseError struct {
		error
	}
)

// Errors variables that are defined once here to avoid duplication below.
var (
	ErrNeedPositiveAmount = InvalidParameterError{
		errors.New("amount must be positive"),
	}

	ErrNeedPositiveMinconf = InvalidParameterError{
		errors.New("minconf must be positive"),
	}

	ErrSpeicifiedUTXOWrong = InvalidParameterError{
		errors.New("specified utxo must be hex string (e.g. 0a2b12,180ac)"),
	}

	ErrAddressNotInWallet = abejson.RPCError{
		Code:    abejson.ErrRPCWallet,
		Message: "address not found in wallet",
	}

	ErrUnloadedWallet = abejson.RPCError{
		Code:    abejson.ErrRPCWallet,
		Message: "Request requires a wallet but wallet has not loaded yet",
	}

	ErrWalletUnlockNeeded = abejson.RPCError{
		Code:    abejson.ErrRPCWalletUnlockNeeded,
		Message: "Enter the wallet passphrase with walletpassphrase first",
	}

	ErrNoTransactionInfo = abejson.RPCError{
		Code:    abejson.ErrRPCNoTxInfo,
		Message: "No information for transaction",
	}
)
