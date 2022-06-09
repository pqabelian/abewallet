package wallet

// MakeMultiSigScript creates a multi-signature script that can be redeemed with
// nRequired signatures of the passed keys and addresses.  If the address is a
// P2PKH address, the associated pubkey is looked up by the wallet if possible,
// otherwise an error is returned for a missing pubkey.
//
// This function only works with pubkeys and P2PKH addresses derived from them.

// ImportP2SHRedeemScript adds a P2SH redeem script to the wallet.
