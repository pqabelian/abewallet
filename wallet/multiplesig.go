package wallet

import (
	"errors"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/txscript"
	"github.com/abesuite/abewallet/waddrmgr"
	"github.com/abesuite/abewallet/walletdb"
)

// MakeMultiSigScript creates a multi-signature script that can be redeemed with
// nRequired signatures of the passed keys and addresses.  If the address is a
// P2PKH address, the associated pubkey is looked up by the wallet if possible,
// otherwise an error is returned for a missing pubkey.
//
// This function only works with pubkeys and P2PKH addresses derived from them.
func (w *Wallet) MakeMultiSigScript(addrs []abeutil.Address, nRequired int) ([]byte, error) {
	pubKeys := make([]*abeutil.AddressPubKey, len(addrs))

	var dbtx walletdb.ReadTx
	var addrmgrNs walletdb.ReadBucket
	defer func() {
		if dbtx != nil {
			dbtx.Rollback()
		}
	}()

	// The address list will made up either of addreseses (pubkey hash), for
	// which we need to look up the keys in wallet, straight pubkeys, or a
	// mixture of the two.
	for i, addr := range addrs {
		switch addr := addr.(type) {
		default:
			return nil, errors.New("cannot make multisig script for " +
				"a non-secp256k1 public key or P2PKH address")

		case *abeutil.AddressPubKey:
			pubKeys[i] = addr

		case *abeutil.AddressPubKeyHash:
			if dbtx == nil {
				var err error
				dbtx, err = w.db.BeginReadTx()
				if err != nil {
					return nil, err
				}
				addrmgrNs = dbtx.ReadBucket(waddrmgrNamespaceKey)
			}
			addrInfo, err := w.Manager.Address(addrmgrNs, addr)
			if err != nil {
				return nil, err
			}
			serializedPubKey := addrInfo.(waddrmgr.ManagedPubKeyAddress).
				PubKey().SerializeCompressed()

			pubKeyAddr, err := abeutil.NewAddressPubKey(
				serializedPubKey, w.chainParams)
			if err != nil {
				return nil, err
			}
			pubKeys[i] = pubKeyAddr
		}
	}

	return txscript.MultiSigScript(pubKeys, nRequired)
}

// ImportP2SHRedeemScript adds a P2SH redeem script to the wallet.
