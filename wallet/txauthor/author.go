package txauthor

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/abesuite/abec/abecrypto/abesalrs"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/txscript"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abewallet/waddrmgr"
	"github.com/abesuite/abewallet/wallet/txrules"
	"github.com/abesuite/abewallet/wallet/txsizes"
	"github.com/abesuite/abewallet/walletdb"
	"github.com/abesuite/abewallet/wtxmgr"
)

// SumOutputValues sums up the list of TxOuts and returns an Amount.
func SumOutputValues(outputs []*wire.TxOut) (totalOutput abeutil.Amount) {
	for _, txOut := range outputs {
		totalOutput += abeutil.Amount(txOut.Value)
	}
	return totalOutput
}
func SumOutputValuesAbe(outputs []*wire.TxOutAbe) (totalOutput abeutil.Amount) {
	for _, txOut := range outputs {
		totalOutput += abeutil.Amount(txOut.ValueScript)
	}
	return totalOutput
}

// InputSource provides transaction inputs referencing spendable outputs to
// construct a transaction outputting some target amount.  If the target amount
// can not be satisified, this can be signaled by returning a total amount less
// than the target or by returning a more detailed error implementing
// InputSourceError.
type InputSource func(target abeutil.Amount) (total abeutil.Amount, inputs []*wire.TxIn,
	inputValues []abeutil.Amount, scripts [][]byte, err error)
type InputSourceAbe func(target abeutil.Amount) (total abeutil.Amount, inputs []*wire.TxInAbe,
	inputValues []abeutil.Amount, scripts [][]byte,err error)

// InputSourceError describes the failure to provide enough input value from
// unspent transaction outputs to meet a target amount.  A typed error is used
// so input sources can provide their own implementations describing the reason
// for the error, for example, due to spendable policies or locked coins rather
// than the wallet not having enough available input value.
type InputSourceError interface {
	error
	InputSourceError()
}

// Default implementation of InputSourceError.
type insufficientFundsError struct{}

func (insufficientFundsError) InputSourceError() {}
func (insufficientFundsError) Error() string {
	return "insufficient funds available to construct transaction"
}

// AuthoredTx holds the state of a newly-created transaction and the change
// output (if one was added).
type AuthoredTx struct {
	Tx              *wire.MsgTx
	PrevScripts     [][]byte
	PrevInputValues []abeutil.Amount
	TotalInput      abeutil.Amount
	ChangeIndex     int // negative if no change
}

type AuthoredTxAbe struct {
	Tx              *wire.MsgTxAbe
	PrevScripts     [][]byte
	PrevInputValues []abeutil.Amount
	TotalInput      abeutil.Amount
	ChangeIndex     int // negative if no change
}
// ChangeSource provides P2PKH change output scripts for transaction creation.
type ChangeSource func() ([]byte, error)

// NewUnsignedTransaction creates an unsigned transaction paying to one or more
// non-change outputs.  An appropriate transaction fee is included based on the
// transaction size.
//
// Transaction inputs are chosen from repeated calls to fetchInputs with
// increasing targets amounts.
//
// If any remaining output value can be returned to the wallet via a change
// output without violating mempool dust rules, a P2WPKH change output is
// appended to the transaction outputs.  Since the change output may not be
// necessary, fetchChange is called zero or one times to generate this script.
// This function must return a P2WPKH script or smaller, otherwise fee estimation
// will be incorrect.
//
// If successful, the transaction, total input value spent, and all previous
// output scripts are returned.  If the input source was unable to provide
// enough input value to pay for every output and any necessary fees, an
// InputSourceError is returned.
//
// BUGS: Fee estimation may be off when redeeming non-compressed P2PKH outputs.
func NewUnsignedTransaction(outputs []*wire.TxOut, relayFeePerKb abeutil.Amount,
	fetchInputs InputSource, fetchChange ChangeSource) (*AuthoredTx, error) {

	targetAmount := SumOutputValues(outputs)
	estimatedSize := txsizes.EstimateVirtualSize(0, 1, 0, outputs, true)
	targetFee := txrules.FeeForSerializeSize(relayFeePerKb, estimatedSize)

	for {
		inputAmount, inputs, inputValues, scripts, err := fetchInputs(targetAmount + targetFee)
		if err != nil {
			return nil, err
		}
		if inputAmount < targetAmount+targetFee {
			return nil, insufficientFundsError{}
		}

		// We count the types of inputs, which we'll use to estimate
		// the vsize of the transaction.
		var nested, p2wpkh, p2pkh int
		for _, pkScript := range scripts {
			switch {
			// If this is a p2sh output, we assume this is a
			// nested P2WKH.
			case txscript.IsPayToScriptHash(pkScript):
				nested++
			case txscript.IsPayToWitnessPubKeyHash(pkScript):
				p2wpkh++
			default:
				p2pkh++
			}
		}

		maxSignedSize := txsizes.EstimateVirtualSize(p2pkh, p2wpkh,
			nested, outputs, true)
		maxRequiredFee := txrules.FeeForSerializeSize(relayFeePerKb, maxSignedSize)
		remainingAmount := inputAmount - targetAmount
		if remainingAmount < maxRequiredFee {
			targetFee = maxRequiredFee
			continue
		}

		unsignedTransaction := &wire.MsgTx{
			Version:  wire.TxVersion,
			TxIn:     inputs,
			TxOut:    outputs,
			LockTime: 0,
		}
		changeIndex := -1
		changeAmount := inputAmount - targetAmount - maxRequiredFee
		if changeAmount != 0 && !txrules.IsDustAmount(changeAmount,
			txsizes.P2WPKHPkScriptSize, relayFeePerKb) {
			changeScript, err := fetchChange()
			if err != nil {
				return nil, err
			}
			if len(changeScript) > txsizes.P2WPKHPkScriptSize {
				return nil, errors.New("fee estimation requires change " +
					"scripts no larger than P2WPKH output scripts")
			}
			change := wire.NewTxOut(int64(changeAmount), changeScript)
			l := len(outputs)
			unsignedTransaction.TxOut = append(outputs[:l:l], change)
			changeIndex = l
		}

		return &AuthoredTx{
			Tx:              unsignedTransaction,
			PrevScripts:     scripts,
			PrevInputValues: inputValues,
			TotalInput:      inputAmount,
			ChangeIndex:     changeIndex,
		}, nil
	}
}
//TODO(abe):the logic of this function need to be verified
func NewUnsignedTransactionAbe(outputs []*wire.TxOutAbe, relayFeePerKb abeutil.Amount,
	fetchInputs InputSourceAbe, fetchChange ChangeSource) (*AuthoredTxAbe, error) {

	targetAmount := SumOutputValuesAbe(outputs)
	estimatedSize := txsizes.EstimateVirtualSizeAbe(nil,outputs, true) //TODO(abe):about the tx fee, we can assign a value for testing
	targetFee := txrules.FeeForSerializeSizeAbe(relayFeePerKb, estimatedSize)      // to compute the required tx fee

	for {
		inputAmount, inputs, inputValues, scripts , err := fetchInputs(targetAmount + targetFee)
		if err != nil {
			return nil, err
		}
		if inputAmount < targetAmount+targetFee {
			return nil, insufficientFundsError{}
		}

		// We count the types of inputs, which we'll use to estimate
		// the vsize of the transaction.
		//TODO(abe):there should add a input size and output size
		maxSignedSize := txsizes.EstimateVirtualSizeAbe(inputs,outputs, true)
		maxRequiredFee := txrules.FeeForSerializeSizeAbe(relayFeePerKb, maxSignedSize)
		remainingAmount := inputAmount - targetAmount
		if remainingAmount < maxRequiredFee {
			targetFee = maxRequiredFee
			continue
		}

		unsignedTransaction := &wire.MsgTxAbe{
			Version:  wire.TxVersion,
			TxIns:     inputs,
			TxOuts:    outputs,
			TxFee: int64(maxRequiredFee),
			TxWitness: &wire.TxWitnessAbe{
				Witnesses: []wire.Witness{},
			},
		}
		changeIndex := -1
		changeAmount := inputAmount - targetAmount - maxRequiredFee
		if changeAmount != 0 && !txrules.IsDustAmount(changeAmount,
			txsizes.P2WPKHPkScriptSize, relayFeePerKb) {
			changeScript, err := fetchChange()
			if err != nil {
				return nil, err
			}
			// this value should be decided according the max block size
			if len(changeScript) > txsizes.P2WPKHPkScriptSize {
				return nil, errors.New("fee estimation requires change " +
					"scripts no larger than P2WPKH output scripts")
			}
			change := wire.NewTxOutAbe(int64(changeAmount), changeScript)
			l := len(outputs)
			unsignedTransaction.TxOuts = append(outputs[:l:l], change)
			changeIndex = l
		}

		return &AuthoredTxAbe{
			Tx:              unsignedTransaction,
			PrevScripts:     scripts,
			PrevInputValues: inputValues,
			TotalInput:      inputAmount,
			ChangeIndex:     changeIndex,
		}, nil
	}
}
// RandomizeOutputPosition randomizes the position of a transaction's output by
// swapping it with a random output.  The new index is returned.  This should be
// done before signing.
func RandomizeOutputPosition(outputs []*wire.TxOut, index int) int {
	r := cprng.Int31n(int32(len(outputs)))
	outputs[r], outputs[index] = outputs[index], outputs[r]
	return int(r)
}
func RandomizeOutputAbePosition(outputs []*wire.TxOutAbe, index int) int {
	r := cprng.Int31n(int32(len(outputs)))
	outputs[r], outputs[index] = outputs[index], outputs[r]
	return int(r)
}

// RandomizeChangePosition randomizes the position of an authored transaction's
// change output.  This should be done before signing.
func (tx *AuthoredTx) RandomizeChangePosition() {
	tx.ChangeIndex = RandomizeOutputPosition(tx.Tx.TxOut, tx.ChangeIndex)
}
func (tx *AuthoredTxAbe) RandomizeChangePosition() {
	tx.ChangeIndex = RandomizeOutputAbePosition(tx.Tx.TxOuts, tx.ChangeIndex)
}
// SecretsSource provides private keys and redeem scripts necessary for
// constructing transaction input signatures.  Secrets are looked up by the
// corresponding Address for the previous output script.  Addresses for lookup
// are created using the source's blockchain parameters and means a single
// SecretsSource can only manage secrets for a single chain.
//
// TODO: Rewrite this interface to look up private keys and redeem scripts for
// pubkeys, pubkey hashes, script hashes, etc. as separate interface methods.
// This would remove the ChainParams requirement of the interface and could
// avoid unnecessary conversions from previous output scripts to Addresses.
// This can not be done without modifications to the txscript package.
// TODO(abe): this SecretSource would be deleted, we will ignore it because we do not generate a dsk, we just generate
//  a signature via mpk, msvk, mssk
type SecretsSource interface {
	txscript.KeyDB
	txscript.ScriptDB
	ChainParams() *chaincfg.Params
}

// AddAllInputScripts modifies a transaction by adding inputs
// scripts for each input.  Previous output scripts being redeemed by each input
// are passed in prevPkScripts and the slice length must match the number of
// inputs.  Private keys and redeem scripts are looked up using a SecretsSource
// based on the previous output script.
func AddAllInputScripts(tx *wire.MsgTx, prevPkScripts [][]byte, inputValues []abeutil.Amount,
	secrets SecretsSource) error {

	inputs := tx.TxIn
	hashCache := txscript.NewTxSigHashes(tx)
	chainParams := secrets.ChainParams()

	if len(inputs) != len(prevPkScripts) {
		return errors.New("tx.TxIn and prevPkScripts slices must " +
			"have equal length")
	}

	for i := range inputs {
		pkScript := prevPkScripts[i]

		switch {
		// If this is a p2sh output, who's script hash pre-image is a
		// witness program, then we'll need to use a modified signing
		// function which generates both the sigScript, and the witness
		// script.
		case txscript.IsPayToScriptHash(pkScript):
			err := spendNestedWitnessPubKeyHash(inputs[i], pkScript,
				int64(inputValues[i]), chainParams, secrets,
				tx, hashCache, i)
			if err != nil {
				return err
			}
		case txscript.IsPayToWitnessPubKeyHash(pkScript):
			err := spendWitnessKeyHash(inputs[i], pkScript,
				int64(inputValues[i]), chainParams, secrets,
				tx, hashCache, i)
			if err != nil {
				return err
			}
		default:
			sigScript := inputs[i].SignatureScript
			script, err := txscript.SignTxOutput(chainParams, tx, i,
				pkScript, txscript.SigHashAll, secrets, secrets,
				sigScript)
			if err != nil {
				return err
			}
			inputs[i].SignatureScript = script
		}
	}

	return nil
}

// spendWitnessKeyHash generates, and sets a valid witness for spending the
// passed pkScript with the specified input amount. The input amount *must*
// correspond to the output value of the previous pkScript, or else verification
// will fail since the new sighash digest algorithm defined in BIP0143 includes
// the input value in the sighash.
func spendWitnessKeyHash(txIn *wire.TxIn, pkScript []byte,
	inputValue int64, chainParams *chaincfg.Params, secrets SecretsSource,
	tx *wire.MsgTx, hashCache *txscript.TxSigHashes, idx int) error {

	// First obtain the key pair associated with this p2wkh address.
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript,
		chainParams)
	if err != nil {
		return err
	}
	privKey, compressed, err := secrets.GetKey(addrs[0])
	if err != nil {
		return err
	}
	pubKey := privKey.PubKey()

	// Once we have the key pair, generate a p2wkh address type, respecting
	// the compression type of the generated key.
	var pubKeyHash []byte
	if compressed {
		pubKeyHash = abeutil.Hash160(pubKey.SerializeCompressed())
	} else {
		pubKeyHash = abeutil.Hash160(pubKey.SerializeUncompressed())
	}
	p2wkhAddr, err := abeutil.NewAddressWitnessPubKeyHash(pubKeyHash, chainParams)
	if err != nil {
		return err
	}

	// With the concrete address type, we can now generate the
	// corresponding witness program to be used to generate a valid witness
	// which will allow us to spend this output.
	witnessProgram, err := txscript.PayToAddrScript(p2wkhAddr)
	if err != nil {
		return err
	}
	witnessScript, err := txscript.WitnessSignature(tx, hashCache, idx,
		inputValue, witnessProgram, txscript.SigHashAll, privKey, true)
	if err != nil {
		return err
	}

	txIn.Witness = witnessScript

	return nil
}

// spendNestedWitnessPubKey generates both a sigScript, and valid witness for
// spending the passed pkScript with the specified input amount. The generated
// sigScript is the version 0 p2wkh witness program corresponding to the queried
// key. The witness stack is identical to that of one which spends a regular
// p2wkh output. The input amount *must* correspond to the output value of the
// previous pkScript, or else verification will fail since the new sighash
// digest algorithm defined in BIP0143 includes the input value in the sighash.
func spendNestedWitnessPubKeyHash(txIn *wire.TxIn, pkScript []byte,
	inputValue int64, chainParams *chaincfg.Params, secrets SecretsSource,
	tx *wire.MsgTx, hashCache *txscript.TxSigHashes, idx int) error {

	// First we need to obtain the key pair related to this p2sh output.
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript,
		chainParams)
	if err != nil {
		return err
	}
	privKey, compressed, err := secrets.GetKey(addrs[0])
	if err != nil {
		return err
	}
	pubKey := privKey.PubKey()

	var pubKeyHash []byte
	if compressed {
		pubKeyHash = abeutil.Hash160(pubKey.SerializeCompressed())
	} else {
		pubKeyHash = abeutil.Hash160(pubKey.SerializeUncompressed())
	}

	// Next, we'll generate a valid sigScript that'll allow us to spend
	// the p2sh output. The sigScript will contain only a single push of
	// the p2wkh witness program corresponding to the matching public key
	// of this address.
	p2wkhAddr, err := abeutil.NewAddressWitnessPubKeyHash(pubKeyHash, chainParams)
	if err != nil {
		return err
	}
	witnessProgram, err := txscript.PayToAddrScript(p2wkhAddr)
	if err != nil {
		return err
	}
	bldr := txscript.NewScriptBuilder()
	bldr.AddData(witnessProgram)
	sigScript, err := bldr.Script()
	if err != nil {
		return err
	}
	txIn.SignatureScript = sigScript

	// With the sigScript in place, we'll next generate the proper witness
	// that'll allow us to spend the p2wkh output.
	witnessScript, err := txscript.WitnessSignature(tx, hashCache, idx,
		inputValue, witnessProgram, txscript.SigHashAll, privKey, compressed)
	if err != nil {
		return err
	}

	txIn.Witness = witnessScript

	return nil
}

// AddAllInputScripts modifies an authored transaction by adding inputs scripts
// for each input of an authored transaction.  Private keys and redeem scripts
// are looked up using a SecretsSource based on the previous output script.
func (tx *AuthoredTx) AddAllInputScripts(secrets SecretsSource) error {
	return AddAllInputScripts(tx.Tx, tx.PrevScripts, tx.PrevInputValues, secrets)
}
func (tx *AuthoredTxAbe) AddAllInputScripts(msg []byte,m *waddrmgr.ManagerAbe, waddrmgrNs walletdb.ReadWriteBucket,wtxmgrNs walletdb.ReadWriteBucket) error {
	// acquire the key
	//TODO(abe): this process of acquire master key will be abstract to a interface
	if m.IsLocked() {
		return fmt.Errorf("the wallet is locked")
	}
	mpkEncBytes, msvkEncBytes, msskEncBytes, err := m.FetchMasterKeyEncAbe(waddrmgrNs)
	if err!=nil {
		return err
	}
	msskBytes, err := m.Decrypt(waddrmgr.CKTPrivate, msskEncBytes)
	if err!=nil {
		return err
	}
	msvkBytes, err := m.Decrypt(waddrmgr.CKTPublic, msvkEncBytes)   //TODO(abe):zero the master key byte
	if err!=nil {
		return err
	}
	mpkBytes, err := m.Decrypt(waddrmgr.CKTPublic, mpkEncBytes)
	if err!=nil {
		return err
	}
	mssk, err := abesalrs.DeseralizeMasterSecretSignKey(msskBytes)
	if err!=nil {
		return err
	}
	msvk,err:=abesalrs.DeseralizeMasterSecretViewKey(msvkBytes)
	if err!=nil {
		return err
	}
	mpk,err:=abesalrs.DeseralizeMasterPubKey(mpkBytes)
	if err!=nil {
		return err
	}
	for i:=0;i<len(tx.Tx.TxIns);i++{
		//TODO(abe):when signature, what is the message?  temporary, it uses "this is a test"
		//TODO(abe):1-get the all and own dpk from script
		ringHash:=tx.Tx.TxIns[i].PreviousOutPointRing.Hash()
		//utxoRing, err := wtxmgr.FetchUTXORing(waddrmgrNs, ringHash[:])
		ring, err := wtxmgr.FetchRingDetails(waddrmgrNs, ringHash[:])
		if err!=nil{
			return err
		}
		dpkRing:=new(abesalrs.DpkRing)
		dpkRing.R=len(ring.TxHashes)
		mydpk:=new(abesalrs.DerivedPubKey)
		for j:=0;j<len(ring.AddrScript);j++{
			derivedAddr, err := txscript.ExtractAddressFromScriptAbe(ring.AddrScript[i])
			if err!=nil{
				return err
			}
			dpk := derivedAddr.DerivedPubKey()
			dpkRing.Dpks=append(dpkRing.Dpks,*dpk)
			if bytes.Equal(ring.AddrScript[i],tx.PrevScripts[i]) {
				mydpk=dpk
			}
		}
		if mydpk !=nil{
			sig, err :=abesalrs.Sign(msg,dpkRing,mydpk,mpk,msvk,mssk)
			if err!=nil{
				return err
			}
			tx.Tx.TxWitness.Witnesses[i]=sig.Serialize()
			k,b,err:=abesalrs.Verify(msg,dpkRing,sig)
			if !b||err!=nil{
				return fmt.Errorf("error in generating the key image:%v",err)
			}
			tx.Tx.TxIns[i].SerialNumber=chainhash.DoubleHashH(k.Serialize())
			//TODO(abe):need to update the database such as utxoRing and unspentTxo...
		}else{
			return fmt.Errorf("the tx input do not contain a output belonging to wallet")
		}
	}

	return nil
}
