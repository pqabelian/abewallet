// Package txrules provides transaction rules that should be followed by
// transaction authors for wide mempool acceptance and quick mining.

package txrules

import (
	"errors"
	"github.com/abesuite/abec/abecrypto/abepqringct"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/txscript"
	"github.com/abesuite/abec/wire"
)

// DefaultRelayFeePerKb is the default minimum relay fee policy for a mempool.
const DefaultRelayFeePerKb abeutil.Amount = 1e3

// GetDustThreshold is used to define the amount below which output will be
// determined as dust. Threshold is determined as 3 times the relay fee.
func GetDustThreshold(scriptSize int, relayFeePerKb abeutil.Amount) abeutil.Amount {
	// Calculate the total (estimated) cost to the network.  This is
	// calculated using the serialize size of the output plus the serial
	// size of a transaction input which redeems it.  The output is assumed
	// to be compressed P2PKH as this is the most common script type.  Use
	// the average size of a compressed P2PKH redeem input (148) rather than
	// the largest possible (txsizes.RedeemP2PKHInputSize).
	totalSize := 8 + wire.VarIntSerializeSize(uint64(scriptSize)) +
		scriptSize + 148

	byteFee := relayFeePerKb / 1000
	relayFee := abeutil.Amount(totalSize) * byteFee
	return 3 * relayFee
}

//	todo:AliceBob, 2021.06.15
/*
For change under the threshold, it will be regarded as fee, i.e., without change
*/
func GetChangeThreshold() abeutil.Amount {
	return abeutil.Amount(1000)
}

// IsDustAmount determines whether a transaction output value and script length would
// cause the output to be considered dust.  Transactions with dust outputs are
// not standard and are rejected by mempools with default policies.
func IsDustAmount(amount abeutil.Amount, scriptSize int, relayFeePerKb abeutil.Amount) bool {
	return amount < GetDustThreshold(scriptSize, relayFeePerKb)
}

// IsDustOutput determines whether a transaction output is considered dust.
// Transactions with dust outputs are not standard and are rejected by mempools
// with default policies.
func IsDustOutput(output *wire.TxOut, relayFeePerKb abeutil.Amount) bool {
	// Unspendable outputs which solely carry data are not checked for dust.
	if txscript.GetScriptClass(output.PkScript) == txscript.NullDataTy {
		return false
	}

	// All other unspendable outputs are considered dust.
	if txscript.IsUnspendable(output.PkScript) {
		return true
	}

	return IsDustAmount(abeutil.Amount(output.Value), len(output.PkScript),
		relayFeePerKb)
}
func IsDustOutputAbe(outputDesc *abepqringct.AbeTxOutDesc, relayFeePerKb abeutil.Amount) bool {
	// Unspendable outputs which solely carry data are not checked for dust.
	//if txscript.GetScriptClass(output.PkScript) == txscript.NullDataTy {
	//	return false
	//}

	// All other unspendable outputs are considered dust.
	//if txscript.IsUnspendable(output.PkScript) {
	//	return true
	//}

	//	return IsDustAmount(abeutil.Amount(output.ValueScript), len(output.AddressScript), relayFeePerKb)
	// todo(ABE): In ABE, the sizes of TXOs are the same.
	//	IsDust may be determined only by the value.
	return false
}

// Transaction rule violations
var (
	ErrAmountNegative   = errors.New("transaction output amount is negative")
	ErrAmountExceedsMax = errors.New("transaction output amount exceeds maximum value")
	ErrOutputIsDust     = errors.New("transaction output is dust")
)

// CheckOutput performs simple consensus and policy tests on a transaction
// output.
func CheckOutput(output *wire.TxOut, relayFeePerKb abeutil.Amount) error {
	if output.Value < 0 {
		return ErrAmountNegative
	}
	if output.Value > abeutil.MaxSatoshi {
		return ErrAmountExceedsMax
	}
	if IsDustOutput(output, relayFeePerKb) {
		return ErrOutputIsDust
	}
	return nil
}

func CheckOutputDescAbe(outputDesc *abepqringct.AbeTxOutDesc, relayFeePerKb abeutil.Amount) error {
	value := outputDesc.GetValue()

	if value < 0 {
		return ErrAmountNegative
	}
	if value > abeutil.MaxNeutrino {
		return ErrAmountExceedsMax
	}

	if IsDustOutputAbe(outputDesc, relayFeePerKb) {
		return ErrOutputIsDust
	}
	return nil
}

// FeeForSerializeSize calculates the required fee for a transaction of some
// arbitrary size given a mempool's relay fee policy.
func FeeForSerializeSize(relayFeePerKb abeutil.Amount, txSerializeSize int) abeutil.Amount {
	fee := relayFeePerKb * abeutil.Amount(txSerializeSize) / 1000

	if fee == 0 && relayFeePerKb > 0 {
		fee = relayFeePerKb
	}

	if fee < 0 || fee > abeutil.MaxSatoshi {
		fee = abeutil.MaxSatoshi
	}

	return fee
}

// TODO(abe):about the transaction fee we should design.
func FeeForSerializeSizeAbe(relayFeePerKb abeutil.Amount, txSerializeSize int) abeutil.Amount {
	fee := relayFeePerKb * abeutil.Amount(txSerializeSize) / 1000

	if fee == 0 && relayFeePerKb > 0 {
		fee = relayFeePerKb
	}

	if fee < 0 || fee > abeutil.MaxSatoshi {
		fee = abeutil.MaxSatoshi
	}

	return fee
}
