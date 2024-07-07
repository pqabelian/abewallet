package wallet

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abecrypto/abecryptoparam"
	"github.com/abesuite/abec/abecryptox"
	"github.com/abesuite/abec/abecryptox/abecryptoxkey"
	"github.com/abesuite/abec/abecryptox/abecryptoxparam"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/aut"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/txscript"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abewallet/waddrmgr"
	"github.com/abesuite/abewallet/wallet/txauthor"
	"github.com/abesuite/abewallet/walletdb"
	"github.com/abesuite/abewallet/wtxmgr"
	"math"
	"math/big"
	"sort"
	"strings"
)

const (
	ChangeThreshold    abeutil.Amount = 1000
	WitnessScaleFactor                = 10
)

// byAmount defines the methods needed to satisify sort.Interface to
// sort credits by their output amount.

type byAmount []wtxmgr.UnspentUTXO

func (s byAmount) Len() int { return len(s) }
func (s byAmount) Less(i, j int) bool {
	if s[i].Version < s[j].Version {
		return true
	} else if s[i].Version > s[j].Version {
		return false
	} else {
		return s[i].Amount < s[j].Amount
	}
}
func (s byAmount) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

type byAUTCoinValue []*wtxmgr.AUTCoin

func (s byAUTCoinValue) Len() int { return len(s) }
func (s byAUTCoinValue) Less(i, j int) bool {
	if s[i].Spent && !s[j].Spent {
		return true
	}
	if s[i].Spent && s[j].Spent {
		return false
	}
	if s[j].Spent {
		return false
	}
	return s[i].AUTCoinValue < s[j].AUTCoinValue
}
func (s byAUTCoinValue) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

/*func makeInputSourceAbe(eligible []wtxmgr.UnspentUTXO, rings map[chainhash.Hash]*wtxmgr.Ring) txauthor.InputSourceAbe {
	// Pick largest outputs first.  This is only done for compatibility with
	// previous tx creation code, not because it's a good idea.
	sort.Sort(sort.Reverse(byAmount(eligible)))

	// Current inputs and their total value.  These are closed over by the
	// returned input source and reused across multiple calls.
	currentTotal := abeutil.Amount(0)                        // total amount
	currentInputs := make([]*wire.TxInAbe, 0, len(eligible)) //Inputs
	currentScripts := make([][]byte, 0, len(eligible))
	currentInputValues := make([]abeutil.Amount, 0, len(eligible)) //input value

	return func(target abeutil.Amount) (abeutil.Amount, []*wire.TxInAbe,
		[]abeutil.Amount, [][]byte, error) {
		//TODO(abe): Add a serialNumber to NewTXInAbe
		for currentTotal < target && len(eligible) != 0 {
			nextUTXO := &eligible[0]
			eligible = eligible[1:]
			// TODO(abe):delete it due to we must use dpk ring to generate script, so we do not get the index
			//index:=0
			//for ;index<len(rings[nextUTXO.RingHash].TxHashes);index++{
			//	if rings[nextUTXO.RingHash].TxHashes[index].IsEqual(&nextUTXO.TxOutput.TxHash) &&
			//		rings[nextUTXO.RingHash].Index[index]==nextUTXO.TxOutput.Index{
			//		break
			//	}
			//}
			nextInput := wire.NewTxInAbe(&chainhash.Hash{}, &wire.OutPointRing{ // the outpoint index has be put in the serialNumber field
				BlockHashs: []*chainhash.Hash{},
				OutPoints:  []*wire.OutPointAbe{},
			})
			index := -1
			for i := 0; i < len(rings[nextUTXO.RingHash].BlockHashes); i++ { // fill up the blockhashes field
				nextInput.PreviousOutPointRing.BlockHashs = append(nextInput.PreviousOutPointRing.BlockHashs, &rings[nextUTXO.RingHash].BlockHashes[i])
			}
			for i := 0; i < len(rings[nextUTXO.RingHash].TxHashes); i++ { //fill up the outpoint field
				nextInput.PreviousOutPointRing.OutPoints = append(nextInput.PreviousOutPointRing.OutPoints, &wire.OutPointAbe{
					TxHash: rings[nextUTXO.RingHash].TxHashes[i],
					Index:  rings[nextUTXO.RingHash].Index[i],
				})
				//which input in ring is spent
				if rings[nextUTXO.RingHash].TxHashes[i] == nextUTXO.TxOutput.TxHash && rings[nextUTXO.RingHash].Index[i] == nextUTXO.TxOutput.Index {
					currentScripts = append(currentScripts, rings[nextUTXO.RingHash].AddrScript[i])
					index = i
				}
			}
			currentTotal += abeutil.Amount(nextUTXO.Amount)
			nextInput.SerialNumber[0] = byte(index) //index is set
			currentInputs = append(currentInputs, nextInput)
			amount, _ := abeutil.NewAmountAbe(float64(nextUTXO.Amount))
			currentInputValues = append(currentInputValues, amount)
		}
		return currentTotal, currentInputs, currentInputValues, currentScripts, nil
	}
}*/

//	todo: written by AliceBobScorpio on 2021.06.14, need to be confirm-ed
//func makeInputSourceAbe(eligible []wtxmgr.UnspentUTXO) txauthor.InputSourceAbe {
//	// Pick largest outputs first.  This is only done for compatibility with
//	// previous tx creation code, not because it's a good idea.
//	sort.Sort(sort.Reverse(byAmount(eligible)))
//
//	// Current inputs and their total value.  These are closed over by the
//	// returned input source and reused across multiple calls.
//	currentTotal := abeutil.Amount(0)                        // total amount
//	currentInputs := make([]*wire.TxInAbe, 0, len(eligible)) //Inputs
//	currentScripts := make([][]byte, 0, len(eligible))
//	currentInputValues := make([]abeutil.Amount, 0, len(eligible)) //input value
//
//	return func(target abeutil.Amount) (abeutil.Amount, []*wire.TxIn,
//		[]abeutil.Amount, [][]byte, error) {
//
//		for currentTotal < target && len(eligible) != 0 {
//			nextCredit := &eligible[0]
//			eligible = eligible[1:]
//			nextInput := wire.NewTxIn(&nextCredit.OutPoint, nil, nil)
//			currentTotal += nextCredit.Amount
//			currentInputs = append(currentInputs, nextInput)
//			currentScripts = append(currentScripts, nextCredit.PkScript)
//			currentInputValues = append(currentInputValues, nextCredit.Amount)
//		}
//		return currentTotal, currentInputs, currentInputValues, currentScripts, nil
//	}
//
//	/*	return func(target abeutil.Amount) (abeutil.Amount, []*wire.TxInAbe,
//		[]abeutil.Amount, [][]byte, error) {
//		//TODO(abe): Add a serialNumber to NewTXInAbe
//		for currentTotal < target && len(eligible) != 0 {
//			nextUTXO := &eligible[0]
//			eligible = eligible[1:]
//			// TODO(abe):delete it due to we must use dpk ring to generate script, so we do not get the index
//			//index:=0
//			//for ;index<len(rings[nextUTXO.RingHash].TxHashes);index++{
//			//	if rings[nextUTXO.RingHash].TxHashes[index].IsEqual(&nextUTXO.TxOutput.TxHash) &&
//			//		rings[nextUTXO.RingHash].Index[index]==nextUTXO.TxOutput.Index{
//			//		break
//			//	}
//			//}
//			nextInput := wire.NewTxInAbe(&chainhash.Hash{}, &wire.OutPointRing{ // the outpoint index has be put in the serialNumber field
//				BlockHashs: []*chainhash.Hash{},
//				OutPoints:  []*wire.OutPointAbe{},
//			})
//			index := -1
//			for i := 0; i < len(rings[nextUTXO.RingHash].BlockHashes); i++ { // fill up the blockhashes field
//				nextInput.PreviousOutPointRing.BlockHashs = append(nextInput.PreviousOutPointRing.BlockHashs, &rings[nextUTXO.RingHash].BlockHashes[i])
//			}
//			for i := 0; i < len(rings[nextUTXO.RingHash].TxHashes); i++ { //fill up the outpoint field
//				nextInput.PreviousOutPointRing.OutPoints = append(nextInput.PreviousOutPointRing.OutPoints, &wire.OutPointAbe{
//					TxHash: rings[nextUTXO.RingHash].TxHashes[i],
//					Index:  rings[nextUTXO.RingHash].Index[i],
//				})
//				//which input in ring is spent
//				if rings[nextUTXO.RingHash].TxHashes[i] == nextUTXO.TxOutput.TxHash && rings[nextUTXO.RingHash].Index[i] == nextUTXO.TxOutput.Index {
//					currentScripts = append(currentScripts, rings[nextUTXO.RingHash].AddrScript[i])
//					index = i
//				}
//			}
//			currentTotal += abeutil.Amount(nextUTXO.Amount)
//			nextInput.SerialNumber[0] = byte(index) //index is set
//			currentInputs = append(currentInputs, nextInput)
//			amount, _ := abeutil.NewAmountAbe(float64(nextUTXO.Amount))
//			currentInputValues = append(currentInputValues, amount)
//		}
//		return currentTotal, currentInputs, currentInputValues, currentScripts, nil
//	}*/
//}

// secretSource is an implementation of txauthor.SecretSource for the wallet's
// address manager.

//type secretSourceAbe struct {
//	*waddrmgr.Manager
//	addrmgrNs walletdb.ReadBucket
//}
//func (s secretSourceAbe) GetKey(addr abeutil.Address) (*btcec.PrivateKey, bool, error) {
//	ma, err := s.Address(s.addrmgrNs, addr)
//	if err != nil {
//		return nil, false, err
//	}
//
//	mpka, ok := ma.(waddrmgr.ManagedPubKeyAddress)
//	if !ok {
//		e := fmt.Errorf("managed address type for %v is `%T` but "+
//			"want waddrmgr.ManagedPubKeyAddress", addr, ma)
//		return nil, false, e
//	}
//	privKey, err := mpka.PrivKey()
//	if err != nil {
//		return nil, false, err
//	}
//	return privKey, ma.Compressed(), nil
//}

//func (s secretSourceAbe) GetScript(addr abeutil.Address) ([]byte, error) {
//	ma, err := s.Address(s.addrmgrNs, addr)
//	if err != nil {
//		return nil, err
//	}
//
//	msa, ok := ma.(waddrmgr.ManagedScriptAddress)
//	if !ok {
//		e := fmt.Errorf("managed address type for %v is `%T` but "+
//			"want waddrmgr.ManagedScriptAddress", addr, ma)
//		return nil, e
//	}
//	return msa.Script()
//}

// txToOutputs creates a signed transaction which includes each output from
// outputs.  Previous outputs to reedeem are chosen from the passed account's
// UTXO set and minconf policy. An additional output may be added to return
// change to the wallet.  An appropriate fee is included based on the wallet's
// current relay fee.  The wallet must be unlocked to create the transaction.
//
// NOTE: The dryRun argument can be set true to create a tx that doesn't alter
// the database. A tx created with this set to true will intentionally have no
// input scripts added and SHOULD NOT be broadcasted.

//func (w *Wallet) txAbeToOutputs(txOutDescs []*abepqringct.AbeTxOutDesc, minconf int32, feeSatPerKb abeutil.Amount, dryRun bool) (
//	unsignedTx *txauthor.AuthoredTxAbe, err error) {
//
//	chainClient, err := w.requireChainClient()
//	if err != nil {
//		return nil, err
//	}
//	bs, err := chainClient.BlockStamp()
//	if err != nil {
//		return nil, err
//	}
//	// TODO(abe):should use a db.View to spend, if successful, use db.Update
//	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
//		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
//		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
//		eligible, rings, err := w.findEligibleOutputsAbe(txmgrNs, minconf, bs)
//		if err != nil {
//			return err
//		}
//		inputSource := makeInputSourceAbe(eligible, rings)
//		changeSource := func() ([]byte, error) {
//			// Derive the change output script. We'll use the default key
//			// scope responsible for P2WPKH addresses to do so. As a hack to
//			// allow spending from the imported account, change addresses
//			// are created from account 0.
//			return w.Manager.NewChangeAddress(addrmgrNs)
//		}
//		unsignedTx, err = txauthor.NewUnsignedTransactionAbe(txOutDescs, feeSatPerKb,
//			inputSource, changeSource)
//		if err != nil {
//			return err
//		}
//		return nil
//	})
//	if err != nil {
//		return nil, err
//	}
//	// Get current block's height and hash.
//	//bs:=w.Manager.SyncedTo()
//
//	// use db.View to spent coins, if successful, use db.Update to update the database
//
//	// get the unspent transaction output
//
//	// Randomize change position, if change exists, before signing.  This
//	// doesn't affect the serialize size, so the change amount will still
//	// be valid.
//	if unsignedTx.ChangeIndex >= 0 {
//		unsignedTx.RandomizeChangePosition()
//	}
//
//	// If a dry run was requested, we return now before adding the input
//	// scripts, and don't commit the database transaction. The DB will be
//	// rolled back when this method returns to ensure the dry run didn't
//	// alter the DB in any way.
//	if dryRun {
//		return unsignedTx, nil
//	}
//
//	// TODO(abe):refresh the utxo ring
//	//   todo
//	// TODO(abe):need to get serialNumber and signature for all input in new transaction
//	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
//		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
//		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)
//		// TODO 20210520: the signed message will be the hash of the transaction information without signature
//		err = unsignedTx.AddAllInputScripts([]byte("this is a test"), w.Manager, addrmgrNs, txmgrNs)
//		if err != nil {
//			return nil
//		}
//		return nil
//	})
//	if err != nil {
//		return nil, err
//	}
//	//	todo(ABE): Is this necessary?
//	// TODO(osy): temporary ignore it
//	//err = validateMsgTx(tx.Tx, tx.PrevScripts, tx.PrevInputValues)
//	//if err != nil {
//	//	return nil, err
//	//}
//
//	// TODO(abe):up to here, the transaction will be successful created, so the spent utxo should be marked used and move to SpentButUmined Bucket.
//	//   and modify the utxo ring bucket.
//
//	//txRecordAbe, err := wtxmgr.NewTxRecordAbeFromMsgTxAbe(unsignedTx.Tx, time.Now())
//	//if err != nil {
//	//	return nil, err
//	//}
//	//
//	//err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
//	//	txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)
//	//	err = w.TxStore.InsertTx(txmgrNs, txRecordAbe, nil)
//	//	if err != nil {
//	//		return err
//	//	}
//	//	return nil
//	//})
//	//if err!=nil{
//	//	return nil,err
//	//}
//	return unsignedTx, nil
//	//return unsignedTx, nil
//	//
//	//if err := dbtx.Commit(); err != nil {
//	//	return nil, err
//	//}
//	//
//	////if tx.ChangeIndex >= 0 && account == waddrmgr.ImportedAddrAccount {
//	////	changeAmount := abeutil.Amount(tx.Tx.TxOuts[tx.ChangeIndex].ValueScript)
//	////	log.Warnf("Spend from imported account produced change: moving"+
//	////		" %v from imported account into default account.", changeAmount)
//	////}
//	//
//	//// Finally, we'll request the backend to notify us of the transaction
//	//// that pays to the change address, if there is one, when it confirms.
//	////TODO(abe): this process will be ignore, because we can not spend this change output before this transaction is mined into the chain
//	////if tx.ChangeIndex >= 0 {
//	////	changePkScript := tx.Tx.TxOuts[tx.ChangeIndex].AddressScript
//	////	_, addrs, _, err := txscript.ExtractPkScriptAddrs(
//	////		changePkScript, w.chainParams,
//	////	)
//	////	if err != nil {
//	////		return nil, err
//	////	}
//	////	if err := chainClient.NotifyReceived(addrs); err != nil {
//	////		return nil, err
//	////	}
//	////}
//	//
//	//return tx, nil
//}

func createTransferTxAbeMsgTemplateMLP(txIn []*wire.TxInAbe, txOutNum int, txMemo []byte, fee uint64) (*wire.MsgTxAbe, error) {
	// TODO(MLP) Abewallet would be generate transaction with latest version
	msgTx := &wire.MsgTxAbe{
		Version:   wire.TxVersion,
		TxIns:     nil,
		TxOuts:    make([]*wire.TxOutAbe, txOutNum),
		TxFee:     fee,
		TxMemo:    txMemo,
		TxWitness: []byte{}, // will be fulfill
	}

	msgTx.TxIns = txIn

	for i := 0; i < txOutNum; i++ {
		msgTx.TxOuts[i] = &wire.TxOutAbe{
			Version:   msgTx.Version,
			TxoScript: []byte{}, // will be fulfill
		}
	}

	return msgTx, nil
}

func createTransferTxAbeMsgTemplate(txIn []*wire.TxInAbe, txOutNum int, txMemo []byte, fee uint64) (*wire.MsgTxAbe, error) {
	// TODO(MLP) Abewallet would be generate transaction with latest version
	msgTx := &wire.MsgTxAbe{
		Version:   wire.TxVersion_Height_0,
		TxIns:     nil,
		TxOuts:    make([]*wire.TxOutAbe, txOutNum),
		TxFee:     fee,
		TxMemo:    txMemo,
		TxWitness: []byte{}, // will be fulfill
	}

	msgTx.TxIns = txIn

	for i := 0; i < txOutNum; i++ {
		msgTx.TxOuts[i] = &wire.TxOutAbe{
			Version:   msgTx.Version,
			TxoScript: []byte{}, // will be fulfill
		}
	}

	return msgTx, nil
}

func PrintConsumedUTXOs(selectedTxos []*wtxmgr.UnspentUTXO) {
	log.Infof("Consumed utxos: ")
	for idx, txo := range selectedTxos {
		log.Infof("(%d) Value %v at height %d, version %08x, utxoHash: %s (From Coinbase: %t)",
			idx, float64(txo.Amount)/math.Pow10(7), txo.Height, txo.Version, txo.Hash().String(), txo.FromCoinBase)
	}
}

func PrintNewUTXOs(txOutDescs []*abecrypto.AbeTxOutputDesc, hasChange bool, fee abeutil.Amount) {
	log.Infof("New utxos: ")
	for idx, txo := range txOutDescs {
		if idx != len(txOutDescs)-1 {
			log.Infof("(%d) Value %v", idx, float64(txo.GetValue())/math.Pow10(7))
		} else if hasChange {
			log.Infof("(%d) Value %v (Change)", idx, float64(txo.GetValue())/math.Pow10(7))
		} else {
			log.Infof("(%d) Value %v", idx, float64(txo.GetValue())/math.Pow10(7))
		}
	}
	log.Infof("TxFee: %v\n", fee.ToABE())
}

func CalculateFee(txConSize uint32, witnessSize uint32, feePerKbSpecified abeutil.Amount) (abeutil.Amount, error) {
	fee, err := abeutil.NewAmountAbe(float64(txConSize+witnessSize/uint32(WitnessScaleFactor)) * feePerKbSpecified.ToUnit(abeutil.AmountNeutrino) / 1000.0)
	if err != nil {
		return 0, err
	}
	return fee, nil
}

func fetchSpecifiedUTXO(eligible []wtxmgr.UnspentUTXO, utxoSpecified []string) ([]*wtxmgr.UnspentUTXO, error) {
	selected := make([]*wtxmgr.UnspentUTXO, 0)
	utxoSpecifiedLen := len(utxoSpecified)
	eligibleLen := len(eligible)
	for i := 0; i < utxoSpecifiedLen; i++ {
		var currSelected *wtxmgr.UnspentUTXO = nil
		for j := 0; j < eligibleLen; j++ {
			if strings.HasPrefix(eligible[j].Hash().String(), utxoSpecified[i]) {
				currSelected = &eligible[j]
				break
			}
		}
		if currSelected == nil {
			return nil, errors.New(fmt.Sprintf("cannot find specified utxo %s", utxoSpecified[i]))
		}
		selected = append(selected, currSelected)
	}
	return selected, nil
}

func fetchUTXOForAUT(eligible []wtxmgr.UnspentUTXO, eligibleAUT []*wtxmgr.AUTCoin, utxoSpecified []string) ([]wtxmgr.UnspentUTXO, map[string]wtxmgr.UnspentUTXO, error) {
	utxoSpecifiedMapping := map[string]struct{}{}
	for i := 0; i < len(utxoSpecified); i++ {
		utxoSpecifiedMapping[utxoSpecified[i]] = struct{}{}
	}
	specified := len(utxoSpecified) != 0
	outputStrs := make(map[string]struct{}, len(eligibleAUT))
	for i := 0; i < len(eligibleAUT); i++ {
		outputStrs[eligibleAUT[i].TxOutput.String()] = struct{}{}
	}

	remainUTXOs := make([]wtxmgr.UnspentUTXO, 0)
	utxosforAUT := make(map[string]wtxmgr.UnspentUTXO, len(eligibleAUT))

	for i := 0; i < len(eligible); i++ {
		if _, ok := outputStrs[eligible[i].TxOutput.String()]; ok {
			if _, exist := utxoSpecifiedMapping[eligible[i].Hash().String()]; specified && !exist {
				continue
			}
			utxosforAUT[eligible[i].TxOutput.String()] = eligible[i]
		} else {
			remainUTXOs = append(remainUTXOs, eligible[i])
		}
	}
	return remainUTXOs, utxosforAUT, nil
}

func (w *Wallet) txPqringCTToOutputsMLP(txOutDescs []*abecryptox.AbeTxOutputDesc, minconf int32,
	feePerKbSpecified abeutil.Amount, feeSpecified abeutil.Amount, utxoSpecified []string, dryRun bool) (
	unsignedTx *txauthor.AuthoredTxAbe, err error) {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}
	if !w.isDevEnv() {
		log.Debug("Waiting for chain backend to sync to tip")
		if err := w.waitUntilBackendSynced(chainClient); err != nil {
			return nil, err
		}
		log.Debug("Chain backend synced to tip!")
	}
	bs, err := chainClient.BlockStamp()
	if err != nil {
		return nil, err
	}

	txVersion := wire.TxVersion
	//	todo: Amount seems useless
	targetValue := abeutil.Amount(0)
	outForRing := 0
	outputPublic := int64(0)
	outputCoinAddresses := make([][]byte, len(txOutDescs))
	for i := 0; i < len(txOutDescs); i++ {
		privacyLevel, coinAddress, _, err := abecryptoxkey.CryptoAddressParse(txOutDescs[i].CryptoAddress())
		if err != nil {
			return nil, err
		}
		outputCoinAddresses[i] = coinAddress
		if privacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYM {
			outputPublic += int64(txOutDescs[i].Value())
		} else if privacyLevel == abecryptoxkey.PrivacyLevelRINGCTPre || privacyLevel == abecryptoxkey.PrivacyLevelRINGCT {
			outForRing++
		} else {
			return nil, errors.New("un-supported address")
		}
		targetValue += abeutil.Amount(txOutDescs[i].Value())
	}

	if targetValue < 0 || targetValue > abeutil.Amount(abeutil.MaxNeutrino) {
		return nil, fmt.Errorf("target output value %v exceeds the maximum allowd value %v", targetValue, abeutil.MaxNeutrino)
	}
	maxOutputNum, err := abecryptoxparam.GetTxOutputMaxNum(txVersion)
	if err != nil {
		return nil, err
	}
	if len(txOutDescs) >= maxOutputNum {
		return nil, errors.New("transfer too many utxo")
	}

	maxNumOutputForRing, err := abecryptoxparam.GetTxOutputMaxNumForRing(txVersion)
	if err != nil {
		return nil, err
	}
	if outForRing > maxNumOutputForRing {
		return nil, fmt.Errorf("transfer too many utxo for ring, max allow %d but get %d", maxNumOutputForRing, outForRing)
	}

	maxNumOutputForSingle, err := abecryptoxparam.GetTxOutputMaxNumForSingle(txVersion)
	if err != nil {
		return nil, err
	}
	if len(txOutDescs)-outForRing > maxNumOutputForSingle {
		return nil, fmt.Errorf("transfer too many utxo for single, max allow %d but get %d", maxNumOutputForSingle, len(txOutDescs)-outForRing)
	}

	//var addrBytes, vskBytes, aSkSpBytes []byte
	//var addrBytes, aSkSpBytes []byte
	needChangeFlag := false //whether need to make a change
	var eligible []wtxmgr.UnspentUTXO
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		//eligible, rings, err := w.findEligibleOutputsAbe(txmgrNs, minconf, bs)
		eligible, err = w.findEligibleTxosAbe(txmgrNs, minconf, bs)
		return err

	})
	if err != nil {
		return nil, err
	}
	if len(eligible) == 0 {
		return nil, errors.New("not Enough")
	}
	sort.Sort(sort.Reverse(byAmount(eligible)))
	log.Tracef("Find eligible: ")
	for idx, txo := range eligible {
		log.Tracef("(%d) Height: %d, Value: %v", idx, txo.Height, float64(txo.Amount)/math.Pow10(7))
	}

	privacyLevel := w.Manager.GetPrivacyLevel()

	selectedTxos := make([]*wtxmgr.UnspentUTXO, 0, len(eligible))
	inputRingVersionsForAll := make([]uint32, 0, len(eligible))
	inRingSizesForAll := make([]uint8, 0, len(eligible))
	inputRingVersionsForRing := make([]uint32, 0, len(eligible))
	inRingSizesForRing := make([]uint8, 0, len(eligible))
	inputPublic := uint64(0)
	inForSingleDistinct := uint8(0) // TODO distinguish input address
	inForRing := uint8(0)
	var currentTotal abeutil.Amount
	var txFee abeutil.Amount

	// specified the fee
	if feeSpecified > 0 && utxoSpecified == nil {
		for i := 0; i < len(eligible); i++ {
			currentUtxo := &eligible[i]

			selectedTxos = append(selectedTxos, currentUtxo)
			if privacyLevel == abecryptoxkey.PrivacyLevelRINGCT || privacyLevel == abecryptoxkey.PrivacyLevelRINGCTPre {
				inForRing++
				inputRingVersionsForRing = append(inputRingVersionsForRing, currentUtxo.Version)
				inRingSizesForRing = append(inRingSizesForRing, currentUtxo.RingSize)
			} else if privacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYM {
				inputPublic += currentUtxo.Amount
			}

			inputRingVersionsForAll = append(inputRingVersionsForAll, currentUtxo.Version)
			inRingSizesForAll = append(inRingSizesForAll, currentUtxo.RingSize)
			currentTotal = currentTotal + abeutil.Amount(currentUtxo.Amount)
			if currentTotal >= targetValue+feeSpecified {
				break
			}
		}
	}
	if feeSpecified > 0 && utxoSpecified != nil {
		log.Infof("create transaction for specified utxo %s", utxoSpecified)
		selectedTxos, err = fetchSpecifiedUTXO(eligible, utxoSpecified)
		if err != nil {
			log.Errorf("can not create transaction for specified utxo %s due to %s", utxoSpecified, err)
			return nil, err
		}
		for _, txo := range selectedTxos {
			currentTotal = currentTotal + abeutil.Amount(txo.Amount)

			if privacyLevel == abecryptoxkey.PrivacyLevelRINGCT || privacyLevel == abecryptoxkey.PrivacyLevelRINGCTPre {
				inForRing++
				inputRingVersionsForRing = append(inputRingVersionsForRing, txo.Version)
				inRingSizesForRing = append(inRingSizesForRing, txo.RingSize)
			} else if privacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYM {
				inputPublic += txo.Amount
			}

			inputRingVersionsForAll = append(inputRingVersionsForAll, txo.Version)
			inRingSizesForAll = append(inRingSizesForAll, txo.RingSize)

		}
		log.Infof("utxoSpecified: targetValue %d, feeSpecified %d, currentTotal %d", targetValue, feeSpecified, currentTotal)
		if currentTotal < targetValue+feeSpecified {
			log.Errorf("can not create transaction for specified utxo %s due to %s", utxoSpecified, err)
			return nil, errors.New("specified utxos do not have enough amount")
		}
	}
	if feeSpecified > 0 {
		txFee = feeSpecified
		if currentTotal > targetValue+feeSpecified {
			// the remain less than threshold so giving it to transaction fee
			if currentTotal-targetValue-feeSpecified < ChangeThreshold {
				txFee = currentTotal - targetValue
				needChangeFlag = false
			} else {
				txFee = feeSpecified
				needChangeFlag = true
			}
		}
	}

	computeFee := func(txVersion uint32,
		inputRingVersionForAll []uint32, inRingSizesForAll []uint8, // all inputs
		inputRingVersionsForRing []uint32, inRingSizeForRing []uint8, // ring inputs
		inForRing uint8, inForSingleDistinct uint8,
		vPublic int64) (abeutil.Amount, error) {
		txConSize, err := wire.PrecomputeTrTxConSizeMLP(txVersion, inputRingVersionForAll, inRingSizesForAll, outputCoinAddresses, abecryptoxparam.MaxAllowedTxMemoSize)
		if err != nil {
			return 0, err
		}
		// force v Public to 0
		if privacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYM {
			// all input would be pseudonym
			// when outputs may contain full-privacy, vPublic must less than 0
			// otherwise must be 0 to meet the requirement of underlying crypto scheme
			if outForRing == 0 {
				vPublic = 0
			}
		}
		witnessSize, err := abecryptox.GetTrTxWitnessSerializeSizeApprox(txVersion, inForRing, inForSingleDistinct, inRingSizeForRing, uint8(outForRing), vPublic)
		if err != nil {
			return 0, err
		}
		fee, err := CalculateFee(txConSize, uint32(witnessSize), feePerKbSpecified)
		if err != nil {
			return 0, err
		}
		return fee, nil
	}
	if feeSpecified == 0 && feePerKbSpecified > 0 && utxoSpecified == nil {
		nextUTXOIdx := 0
		for nextUTXOIdx < len(eligible) {
			currentUtxo := &eligible[nextUTXOIdx]
			nextUTXOIdx++

			if privacyLevel == abecryptoxkey.PrivacyLevelRINGCT || privacyLevel == abecryptoxkey.PrivacyLevelRINGCTPre {
				inForRing++
				inputRingVersionsForRing = append(inputRingVersionsForRing, currentUtxo.Version)
				inRingSizesForRing = append(inRingSizesForRing, currentUtxo.RingSize)
			} else if privacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYM {
				inputPublic += currentUtxo.Amount
				inForSingleDistinct++
			}
			inputRingVersionsForAll = append(inputRingVersionsForAll, currentUtxo.Version)
			inRingSizesForAll = append(inRingSizesForAll, currentUtxo.RingSize)

			selectedTxos = append(selectedTxos, currentUtxo)
			currentTotal = currentTotal + abeutil.Amount(currentUtxo.Amount)
			if currentTotal < targetValue {
				continue
			}
			fee, err := computeFee(txVersion,
				inputRingVersionsForAll, inRingSizesForAll,
				inputRingVersionsForRing, inRingSizesForRing, inForRing,
				inForSingleDistinct,
				outputPublic-int64(inputPublic),
			)
			if err != nil {
				return nil, err
			}
			if currentTotal < targetValue+fee {
				continue
			}
			if currentTotal >= targetValue+fee+ChangeThreshold {
				// need to make a change
				needChangeFlag = true
				txFee = fee
			} else {
				needChangeFlag = false
				txFee = currentTotal - targetValue
			}
			break
		}
	}
	if feeSpecified == 0 && feePerKbSpecified > 0 && utxoSpecified != nil {
		selectedTxos, err = fetchSpecifiedUTXO(eligible, utxoSpecified)
		if err != nil {
			return nil, err
		}
		for _, txo := range selectedTxos {
			if privacyLevel == abecryptoxkey.PrivacyLevelRINGCT || privacyLevel == abecryptoxkey.PrivacyLevelRINGCTPre {
				inForRing++
				inputRingVersionsForRing = append(inputRingVersionsForRing, txo.Version)
				inRingSizesForRing = append(inRingSizesForRing, txo.RingSize)
			} else if privacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYM {
				inputPublic += txo.Amount
				inForSingleDistinct++
			}

			inputRingVersionsForAll = append(inputRingVersionsForAll, txo.Version)
			inRingSizesForAll = append(inRingSizesForAll, txo.RingSize)
			currentTotal = currentTotal + abeutil.Amount(txo.Amount)
		}
		if currentTotal < targetValue {
			return nil, errors.New("please specify enough amount to transfer: input < output")
		}
		maxInputNum, err := abecryptoxparam.GetTxInputMaxNum(txVersion)
		if err != nil {
			return nil, err
		}
		if len(selectedTxos) >= maxInputNum {
			return nil, errors.New("select too many utxo to transfer, basically it means: input + fee < output ")
		}

		maxNumInputForRing, err := abecryptoxparam.GetTxInputMaxNumForRing(txVersion)
		if err != nil {
			return nil, err
		}
		if int(inForRing) > maxNumInputForRing {
			return nil, errors.New("select too many utxo for ring, basically it means: input + fee < output ")
		}

		maxNumInputForSingle, err := abecryptoxparam.GetTxInputMaxNumForSingle(txVersion)
		if err != nil {
			return nil, err
		}
		if len(selectedTxos)-int(inForRing) > maxNumInputForSingle {
			return nil, errors.New("select too many utxo for single, basically it means: input + fee < output ")
		}

		fee, err := computeFee(wire.TxVersion,
			inputRingVersionsForAll, inRingSizesForAll,
			inputRingVersionsForRing, inRingSizesForRing, inForRing,
			inForSingleDistinct,
			outputPublic-int64(inputPublic),
		)
		if err != nil {
			return nil, err
		}
		if targetValue+fee > currentTotal {
			return nil, errors.New("please specify enough amount to transfer: input + fee < output ")
		}
		if currentTotal >= targetValue+fee+ChangeThreshold {
			// need to make a change
			needChangeFlag = true
			txFee = fee
		} else {
			needChangeFlag = false
			txFee = currentTotal - targetValue
		}
	}

	if targetValue+txFee > currentTotal {
		return nil, errors.New("please specify enough amount to transfer: input + fee < output ")
	}

	selectedRings := make(map[chainhash.Hash]*wtxmgr.Ring)
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		for _, txo := range selectedTxos {
			_, ok := selectedRings[txo.RingHash]
			if !ok {
				ring, err := wtxmgr.FetchRingDetails(txmgrNs, txo.RingHash[:])
				if err != nil {
					return err
				}
				selectedRings[txo.RingHash] = ring
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	cryptoScheme := w.Manager.GetCryptoScheme()
	if cryptoScheme == abecryptoxparam.CryptoSchemePQRingCT && privacyLevel == abecryptoxkey.PrivacyLevelRINGCTPre {
		return w.createTransactionMLPByKeys(selectedTxos, txOutDescs, []byte{}, txFee, needChangeFlag, true)
	}
	if cryptoScheme == abecryptoxparam.CryptoSchemePQRingCTX &&
		(privacyLevel == abecryptoxkey.PrivacyLevelRINGCT || privacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYM) {
		return w.createTransactionMLPByRootSeeds(selectedTxos, txOutDescs, []byte{}, txFee, needChangeFlag, true)
	}
	return nil, errors.New("unsupported (crypto scheme, privacy level)")
	// If a dry run was requested, we return now before adding the input
	// scripts, and don't commit the database transaction. The DB will be
	// rolled back when this method returns to ensure the dry run didn't
	// alter the DB in any way.

	//if dryRun {
	//	return unsignedTx, nil
	//}

	//// Finally, we'll request the backend to notify us of the transaction
	//// that pays to the change address, if there is one, when it confirms.
}

func (w *Wallet) txPqringCTToOutputsMLPAUT(autTransaction aut.Transaction, txOutDescs []*abecryptox.AbeTxOutputDesc,
	minconf int32, feePerKbSpecified abeutil.Amount, autIssueTokenThreshold uint8, autIssueUpdateThreshold uint8,
	utxoSpecified []string) (unsignedTx *txauthor.AuthoredTxAbe, err error) {
	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}
	if !w.isDevEnv() {
		log.Debug("Waiting for chain backend to sync to tip")
		if err := w.waitUntilBackendSynced(chainClient); err != nil {
			return nil, err
		}
		log.Debug("Chain backend synced to tip!")
	}
	bs, err := chainClient.BlockStamp()
	if err != nil {
		return nil, err
	}

	// AUT Layer
	targetAUTValue := uint64(0)
	// Abelian layer
	txVersion := wire.TxVersion
	targetValue := abeutil.Amount(0)
	outputPublic := int64(0)
	outForRing := 0
	var autChangeAddress []byte
	if autTransaction.Type() == aut.Transfer {
		autChangeAddress = txOutDescs[len(txOutDescs)-1].CryptoAddress()
		txOutDescs = txOutDescs[:len(txOutDescs)-1]
		autTx := autTransaction.(*aut.TransferTx)
		autTx.TxoAUTValues = autTx.TxoAUTValues[:len(autTx.TxoAUTValues)-1]
	}

	outputCoinAddresses := make([][]byte, len(txOutDescs))

	for i := 0; i < len(txOutDescs); i++ {
		privacyLevel, coinAddress, _, err := abecryptoxkey.CryptoAddressParse(txOutDescs[i].CryptoAddress())
		if err != nil {
			return nil, err
		}
		outputCoinAddresses[i] = coinAddress
		if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYM {
			return nil, errors.New("unsupported address type for aut")
		}
		outputPublic += int64(txOutDescs[i].Value())
		targetValue += abeutil.Amount(1)
		targetAUTValue += autTransaction.ValueAt(uint8(i))
	}

	if targetValue < 0 || targetValue > abeutil.Amount(abeutil.MaxNeutrino) {
		return nil, fmt.Errorf("target output value %v exceeds the maximum allowd value %v", targetValue, abeutil.MaxNeutrino)
	}
	maxOutputNum, err := abecryptoxparam.GetTxOutputMaxNum(txVersion)
	if err != nil {
		return nil, err
	}
	if len(txOutDescs) >= maxOutputNum {
		return nil, errors.New("transfer too many utxo")
	}

	maxNumOutputForRing, err := abecryptoxparam.GetTxOutputMaxNumForRing(txVersion)
	if err != nil {
		return nil, err
	}
	if outForRing > maxNumOutputForRing {
		return nil, fmt.Errorf("transfer too many utxo for ring, max allow %d but get %d", maxNumOutputForRing, outForRing)
	}

	maxNumOutputForSingle, err := abecryptoxparam.GetTxOutputMaxNumForSingle(txVersion)
	if err != nil {
		return nil, err
	}
	if len(txOutDescs)-outForRing > maxNumOutputForSingle {
		return nil, fmt.Errorf("transfer too many utxo for single, max allow %d but get %d", maxNumOutputForSingle, len(txOutDescs)-outForRing)
	}

	var eligibleAUT []*wtxmgr.AUTCoin
	if autTransaction.Type() != aut.Registration {
		err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
			txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
			eligibleAUT, err = w.findEligibleTxosAbeAUT(txmgrNs, minconf, bs, autTransaction.AUTIdentifier())
			return err
		})
		if err != nil {
			return nil, err
		}
		if len(eligibleAUT) == 0 {
			return nil, errors.New("not enough AUT coin to spend")
		}
		sort.Sort(sort.Reverse(byAUTCoinValue(eligibleAUT)))
		log.Tracef("Find AUT (Name %s) eligibleAUT: ", autTransaction.AUTIdentifier())
		for idx, txo := range eligibleAUT {
			log.Tracef("(%d) AUT Coin (%s:%d) Value: %v", idx, txo.TxOutput.TxHash, txo.TxOutput.Index, txo.AUTCoinValue)
		}
	}

	var eligible []wtxmgr.UnspentUTXO
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		//eligible, rings, err := w.findEligibleOutputsAbe(txmgrNs, minconf, bs)
		eligible, err = w.findEligibleTxosAbe(txmgrNs, minconf, bs)
		return err
	})
	if err != nil {
		return nil, err
	}
	// filter with AUT coin
	eligible, eligibleForAUTMapping, err := fetchUTXOForAUT(eligible, eligibleAUT, utxoSpecified)
	if err != nil {
		return nil, errors.New("can not filter AUT coin")
	}
	if len(eligible) == 0 {
		return nil, errors.New("not Enough")
	}

	sort.Sort(sort.Reverse(byAmount(eligible)))
	log.Tracef("Find eligible: ")
	for idx, txo := range eligible {
		log.Tracef("(%d) Height: %d, Value: %v", idx, txo.Height, float64(txo.Amount)/math.Pow10(7))
	}

	privacyLevel := w.Manager.GetPrivacyLevel()
	if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYM {
		return nil, errors.New("non-pseudonym wallet is not support for aut")
	}

	selectedTxos := make([]*wtxmgr.UnspentUTXO, 0, len(eligible))
	inputRingVersionsForAll := make([]uint32, 0, len(eligible))
	inRingSizesForAll := make([]uint8, 0, len(eligible))

	//inputRingVersionsForRing := make([]uint32, 0, len(eligible))
	//inRingSizesForRing := make([]uint8, 0, len(eligible))

	inputPublic := uint64(0)
	inForSingleDistinct := uint8(0) // TODO distinguish input address
	//inForRing := uint8(0)

	var currentTotal abeutil.Amount
	var txFee abeutil.Amount

	switch autTx := autTransaction.(type) {
	case *aut.RegistrationTx:
		// nothing
	case *aut.MintTx:
		// select the aut root coin
		nextAUTCoinIdx := 0
		// TODO How to check the issuer token threshold
		existIssuerToken := map[string]struct{}{}
		for nextAUTCoinIdx < len(eligibleAUT) {
			currentUtxo := eligibleAUT[nextAUTCoinIdx]
			nextAUTCoinIdx++

			if !currentUtxo.IsAUTRootCoin {
				continue
			}
			if _, ok := existIssuerToken[hex.EncodeToString(currentUtxo.AddrKey)]; ok {
				continue
			}

			if unspentUTXO, ok := eligibleForAUTMapping[currentUtxo.TxOutput.String()]; ok {
				inputPublic += unspentUTXO.Amount
				inForSingleDistinct++

				inputRingVersionsForAll = append(inputRingVersionsForAll, unspentUTXO.Version)
				inRingSizesForAll = append(inRingSizesForAll, unspentUTXO.RingSize)

				// todo check address
				selectedTxos = append(selectedTxos, &unspentUTXO)
				currentTotal += +abeutil.Amount(unspentUTXO.Amount)

				autTx.InAutRootCoinNum++

				existIssuerToken[hex.EncodeToString(currentUtxo.AddrKey)] = struct{}{}
				if len(existIssuerToken) >= int(autIssueTokenThreshold) {
					break
				}
			}
		}
		if len(existIssuerToken) < int(autIssueTokenThreshold) {
			return nil, errors.New("exist AUT coin can not reach the issue token threshold")
		}

	case *aut.TransferTx:
		var currentAUTTotal uint64
		// select the aut root coin
		nextAUTUTXOIdx := 0
		// TODO How to check the issuer token threshold
		//existIssuerToken := map[string]struct{}{}
		for nextAUTUTXOIdx < len(eligibleAUT) {
			currentAUTUtxo := eligibleAUT[nextAUTUTXOIdx]
			nextAUTUTXOIdx++
			if currentAUTUtxo.IsAUTRootCoin {
				continue
			}
			if currentAUTUtxo.Spent {
				continue
			}

			if unspentUTXO, ok := eligibleForAUTMapping[currentAUTUtxo.TxOutput.String()]; ok {
				inputPublic += unspentUTXO.Amount
				inForSingleDistinct++

				inputRingVersionsForAll = append(inputRingVersionsForAll, unspentUTXO.Version)
				inRingSizesForAll = append(inRingSizesForAll, unspentUTXO.RingSize)

				// todo check address
				selectedTxos = append(selectedTxos, &unspentUTXO)
				currentTotal += abeutil.Amount(unspentUTXO.Amount)

				autTx.InAutCoinNum++
				currentAUTTotal += currentAUTUtxo.AUTCoinValue
				if currentAUTTotal >= targetAUTValue {
					break
				}
			}
		}

		if currentAUTTotal < targetAUTValue {
			return nil, errors.New("exist AUT coins can not reach the target aut value")
		} else if currentAUTTotal == targetAUTValue {
			// remove the aut change address

		} else { // currentAUTTotal > targetAUTValue
			txOutDescs = append(txOutDescs, abecryptox.NewAbeTxOutDesc(autChangeAddress, 1))
			privacyLevel, coinAddress, _, err := abecryptoxkey.CryptoAddressParse(autChangeAddress)
			if err != nil {
				return nil, err
			}
			outputCoinAddresses = append(outputCoinAddresses, coinAddress)
			if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYM {
				return nil, errors.New("unsupported address type for aut")
			}
			outputPublic += int64(1)
			targetValue += abeutil.Amount(1)
			autTx.TxoAUTValues = append(autTx.TxoAUTValues, currentAUTTotal-targetAUTValue)
			autTx.OutAutCoinNum++
			targetAUTValue += currentAUTTotal
		}
	case *aut.ReRegistrationTx:
		// select the aut root coin
		nextAUTCoinIdx := 0
		// TODO How to check the issuer update threshold
		existIssuerToken := map[string]struct{}{}
		for nextAUTCoinIdx < len(eligibleAUT) {
			currentAUTCoin := eligibleAUT[nextAUTCoinIdx]
			nextAUTCoinIdx++

			if !currentAUTCoin.IsAUTRootCoin {
				continue
			}
			if _, ok := existIssuerToken[hex.EncodeToString(currentAUTCoin.AddrKey)]; ok {
				continue
			}

			if unspentUTXO, ok := eligibleForAUTMapping[currentAUTCoin.TxOutput.String()]; ok {
				inputPublic += unspentUTXO.Amount
				inForSingleDistinct++

				inputRingVersionsForAll = append(inputRingVersionsForAll, unspentUTXO.Version)
				inRingSizesForAll = append(inRingSizesForAll, unspentUTXO.RingSize)

				// todo check address
				selectedTxos = append(selectedTxos, &unspentUTXO)
				currentTotal += +abeutil.Amount(unspentUTXO.Amount)

				autTx.InAutRootCoinNum++

				existIssuerToken[hex.EncodeToString(currentAUTCoin.AddrKey)] = struct{}{}
				if len(existIssuerToken) >= int(autIssueUpdateThreshold) {
					break
				}
			}
		}
		if len(existIssuerToken) < int(autIssueUpdateThreshold) {
			return nil, errors.New("exist AUT coins can not reach the update threshold")
		}
	case *aut.BurnTx:
		utxoSpecifiedMapping := map[string]struct{}{}
		for i := 0; i < len(utxoSpecified); i++ {
			utxoSpecifiedMapping[utxoSpecified[i]] = struct{}{}
		}

		// select the aut root coin
		nextAUTCoinIdx := 0
		for nextAUTCoinIdx < len(eligibleAUT) {
			currentAUTCoin := eligibleAUT[nextAUTCoinIdx]
			nextAUTCoinIdx++

			if unspentUTXO, ok := eligibleForAUTMapping[currentAUTCoin.TxOutput.String()]; ok {
				if _, specified := utxoSpecifiedMapping[unspentUTXO.Hash().String()]; specified {
					if currentAUTCoin.IsAUTRootCoin {
						return nil, errors.New("burn transaction can not operate root coin")
					}

					inputPublic += unspentUTXO.Amount
					inForSingleDistinct++

					inputRingVersionsForAll = append(inputRingVersionsForAll, unspentUTXO.Version)
					inRingSizesForAll = append(inRingSizesForAll, unspentUTXO.RingSize)

					// todo check address
					selectedTxos = append(selectedTxos, &unspentUTXO)
					currentTotal += +abeutil.Amount(unspentUTXO.Amount)

					autTx.InAutCoinNum++
				}
			}
		}

		// compare the specified with selected
		if len(utxoSpecified) != len(selectedTxos) {
			return nil, errors.New("not all specified AUT coins can be selected for generate burn transaction")
		}

	default:
		return nil, errors.New("unsupported aut type")
	}

	nextUTXOIdx := 0
	for nextUTXOIdx < len(eligible) {
		currentUtxo := &eligible[nextUTXOIdx]
		nextUTXOIdx++

		inputPublic += currentUtxo.Amount
		inForSingleDistinct++

		inputRingVersionsForAll = append(inputRingVersionsForAll, currentUtxo.Version)
		inRingSizesForAll = append(inRingSizesForAll, currentUtxo.RingSize)

		selectedTxos = append(selectedTxos, currentUtxo)

		currentTotal = currentTotal + abeutil.Amount(currentUtxo.Amount)
		if currentTotal < targetValue {
			continue
		}

		txConSize, err := wire.PrecomputeTrTxConSizeMLP(txVersion, inputRingVersionsForAll, inRingSizesForAll, outputCoinAddresses, abecryptoxparam.MaxAllowedTxMemoSize)
		if err != nil {
			return nil, err
		}
		witnessSize, err := abecryptox.GetTrTxWitnessSerializeSizeApprox(txVersion, 0, inForSingleDistinct, nil, 0 /*outputPublic-int64(inputPublic)*/, 0)
		if err != nil {
			return nil, err
		}
		txFee, err = CalculateFee(txConSize, uint32(witnessSize), feePerKbSpecified)
		if err != nil {
			return nil, err
		}
		if currentTotal >= targetValue+txFee {
			break
		}
	}

	memo, err := autTransaction.Serialize()
	if err != nil {
		return nil, errors.New("can not serialize the aut transaction")
	}

	return w.createTransactionMLPByRootSeeds(selectedTxos, txOutDescs, memo, txFee, true, false)
}

func (w *Wallet) createTransactionMLPByRootSeeds(
	selectedUTXOs []*wtxmgr.UnspentUTXO, txOutDescs []*abecryptox.AbeTxOutputDesc,
	memo []byte, txFee abeutil.Amount,
	needChangeFlag bool, randomOutput bool) (unsignedTx *txauthor.AuthoredTxAbe, err error) {
	selectedRings := make(map[chainhash.Hash]*wtxmgr.Ring)
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		for _, txo := range selectedUTXOs {
			_, ok := selectedRings[txo.RingHash]
			if !ok {
				ring, err := wtxmgr.FetchRingDetails(txmgrNs, txo.RingHash[:])
				if err != nil {
					return err
				}
				selectedRings[txo.RingHash] = ring
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	PrintConsumedUTXOs(selectedUTXOs)

	if w.Manager.IsLocked() {
		return nil, errors.New("wallet is locked")
	}
	var coinSpendKeyRootSeed []byte
	var coinSerialNumberKeyRootSeed []byte
	var coinValueKeyRootSeed []byte
	var coinDetectorRootKey []byte
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		coinSpendKeyRootSeed, coinSerialNumberKeyRootSeed, coinValueKeyRootSeed, coinDetectorRootKey, err = w.Manager.FetchProtectedRootSeeds(addrmgrNs)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	currentTotal := abeutil.Amount(0)
	abeTxInputDescs := make([]*abecryptox.AbeTxInputDescByRootSeeds, 0, len(selectedUTXOs))
	txIns := make([]*wire.TxInAbe, len(selectedUTXOs))
	for i := 0; i < len(selectedUTXOs); i++ {
		currentTotal += abeutil.Amount(selectedUTXOs[i].Amount)

		txIns[i] = &wire.TxInAbe{
			SerialNumber: nil,
			PreviousOutPointRing: wire.OutPointRing{
				Version:    selectedRings[selectedUTXOs[i].RingHash].Version,
				BlockHashs: make([]*chainhash.Hash, len(selectedRings[selectedUTXOs[i].RingHash].BlockHashes)),
				OutPoints:  make([]*wire.OutPointAbe, len(selectedRings[selectedUTXOs[i].RingHash].TxHashes)),
			},
		}
		for j := 0; j < len(selectedRings[selectedUTXOs[i].RingHash].BlockHashes); j++ {
			txIns[i].PreviousOutPointRing.BlockHashs[j] = &selectedRings[selectedUTXOs[i].RingHash].BlockHashes[j]
		}

		for j := 0; j < len(selectedRings[selectedUTXOs[i].RingHash].TxHashes); j++ {
			txIns[i].PreviousOutPointRing.OutPoints[j] = &wire.OutPointAbe{
				TxHash: selectedRings[selectedUTXOs[i].RingHash].TxHashes[j],
				Index:  selectedRings[selectedUTXOs[i].RingHash].Index[j],
			}
		}

		serializedTxoLists := make([]*wire.TxOutAbe, 0, len(selectedRings[selectedUTXOs[i].RingHash].Index))
		for j := 0; j < len(selectedRings[selectedUTXOs[i].RingHash].Index); j++ {
			serializedTxoLists = append(serializedTxoLists, &wire.TxOutAbe{
				Version:   selectedRings[selectedUTXOs[i].RingHash].Version,
				TxoScript: selectedRings[selectedUTXOs[i].RingHash].TxoScripts[j],
			})
		}
		txoRing := &wire.TxoRing{
			Version:         selectedUTXOs[i].Version,
			RingBlockHeight: selectedUTXOs[i].Height, // Ring Height
			OutPointRing:    &txIns[i].PreviousOutPointRing,
			TxOuts:          serializedTxoLists,
			IsCoinbase:      selectedUTXOs[i].FromCoinBase,
		}

		abeTxInputDescs = append(abeTxInputDescs, abecryptox.NewAbeTxInputDescByRootSeeds(
			txoRing,
			selectedUTXOs[i].Index,
			w.Manager.GetCryptoScheme(),
			w.Manager.GetPrivacyLevel(),
			coinSpendKeyRootSeed,
			coinSerialNumberKeyRootSeed,
			coinValueKeyRootSeed,
			coinDetectorRootKey,
			selectedUTXOs[i].Amount,
		))
	}

	targetValue := abeutil.Amount(0)
	for i := 0; i < len(txOutDescs); i++ {
		output := txOutDescs[i]
		targetValue += abeutil.Amount(output.Value())
	}
	if targetValue+txFee > currentTotal {
		return nil, errors.New("please specify enough amount to transfer: input + fee < output ")
	}

	usedCntNum := ^uint64(0)
	if needChangeFlag {
		var addrBytes []byte
		// fetch a free address if possible
		usedCntNum, addrBytes, err = w.FetchChangeAddress(true)
		if err != nil {
			// fetch a change address for the change
			_, usedCntNum, addrBytes, err = w.NewAddressKey(true)
			if err != nil {
				return nil, err
			}
			log.Infof("No.%d would be used as change address when generating a transaction", usedCntNum)
		} else {
			log.Infof("No.%d would be used as change address when generating a transaction", usedCntNum)
		}

		txOutDescs = append(txOutDescs, abecryptox.NewAbeTxOutDesc(addrBytes, uint64(currentTotal-txFee-targetValue)))
		if randomOutput {
			// random the outputs
			r, err := rand.Int(rand.Reader, big.NewInt(int64(len(txOutDescs))))
			if err != nil {
				return nil, err
			}
			index := r.Int64()
			txOutDescs[len(txOutDescs)-1], txOutDescs[index] = txOutDescs[index], txOutDescs[len(txOutDescs)-1]
		}
	}

	//TODO(abe) 20210627: to sure the txmemo?
	transferTxTemplate, err := createTransferTxAbeMsgTemplateMLP(txIns, len(txOutDescs), memo, uint64(txFee))
	if err != nil {
		return nil, errors.New("error for creating a transfer transaction template ")
	}

	// adjust the order of output descs
	sort.SliceStable(txOutDescs, func(i, j int) bool {
		outputIAddressPrivacyLevel, _, _, _ := abecryptoxkey.CryptoAddressParse(txOutDescs[i].CryptoAddress())
		outputJAddressPrivacyLevel, _, _, _ := abecryptoxkey.CryptoAddressParse(txOutDescs[j].CryptoAddress())
		if outputIAddressPrivacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYM && outputJAddressPrivacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYM {
			return true
		}
		return false
	})

	transferTx, err := abecryptox.TransferTxGenByRootSeeds(abeTxInputDescs, txOutDescs, transferTxTemplate)
	if err != nil {
		return nil, err
	}
	resTx := &txauthor.AuthoredTxAbe{
		Tx:              transferTx,
		ChangeAddressNo: usedCntNum,
	}
	return resTx, nil
}
func (w *Wallet) createTransactionMLPByKeys(
	selectedUTXOs []*wtxmgr.UnspentUTXO, txOutDescs []*abecryptox.AbeTxOutputDesc,
	memo []byte, txFee abeutil.Amount,
	needChangeFlag bool, randomOutput bool) (unsignedTx *txauthor.AuthoredTxAbe, err error) {
	selectedRings := make(map[chainhash.Hash]*wtxmgr.Ring)
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		for _, txo := range selectedUTXOs {
			_, ok := selectedRings[txo.RingHash]
			if !ok {
				ring, err := wtxmgr.FetchRingDetails(txmgrNs, txo.RingHash[:])
				if err != nil {
					return err
				}
				selectedRings[txo.RingHash] = ring
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	PrintConsumedUTXOs(selectedUTXOs)

	serializeAddressBytes := make([][]byte, len(selectedUTXOs))
	serializedAskspBytes := make([][]byte, len(selectedUTXOs))
	serializedAsksnBytes := make([][]byte, len(selectedUTXOs))
	serializedVskBytes := make([][]byte, len(selectedUTXOs))
	detectorKeys := make([][]byte, len(selectedUTXOs))
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		var serializedAddressEnc, serializedAskspEnc, serializedAsksnEnc, serializedVskEnc, detectorKeyEnc []byte
		for i := 0; i < len(selectedUTXOs); i++ {
			coinAddr, err := abecryptox.ExtractCoinAddressFromTxo(&wire.TxOutAbe{
				Version:   selectedUTXOs[i].Version,
				TxoScript: selectedRings[selectedUTXOs[i].RingHash].TxoScripts[selectedUTXOs[i].Index],
			})
			if err != nil {
				return err
			}
			serializedAddressEnc, serializedAskspEnc, serializedAsksnEnc, serializedVskEnc, _, detectorKeyEnc, err = w.Manager.FetchAddressKeyEnc(addrmgrNs, coinAddr)
			if err != nil {
				return err
			}
			serializeAddressBytes[i], serializedAskspBytes[i], serializedAsksnBytes[i], serializedVskBytes[i], detectorKeys[i], err = w.Manager.DecryptAddressKey(serializedAddressEnc, serializedAskspEnc, serializedAsksnEnc, serializedVskEnc, detectorKeyEnc)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	currentTotal := abeutil.Amount(0)
	abeTxInputDescs := make([]*abecryptox.AbeTxInputDescByKeys, 0, len(selectedUTXOs))
	txIns := make([]*wire.TxInAbe, len(selectedUTXOs))
	for i := 0; i < len(selectedUTXOs); i++ {
		currentTotal += abeutil.Amount(selectedUTXOs[i].Amount)

		txIns[i] = &wire.TxInAbe{
			SerialNumber: nil,
			PreviousOutPointRing: wire.OutPointRing{
				Version:    selectedRings[selectedUTXOs[i].RingHash].Version,
				BlockHashs: make([]*chainhash.Hash, len(selectedRings[selectedUTXOs[i].RingHash].BlockHashes)),
				OutPoints:  make([]*wire.OutPointAbe, len(selectedRings[selectedUTXOs[i].RingHash].TxHashes)),
			},
		}
		for j := 0; j < len(selectedRings[selectedUTXOs[i].RingHash].BlockHashes); j++ {
			txIns[i].PreviousOutPointRing.BlockHashs[j] = &selectedRings[selectedUTXOs[i].RingHash].BlockHashes[j]
		}

		for j := 0; j < len(selectedRings[selectedUTXOs[i].RingHash].TxHashes); j++ {
			txIns[i].PreviousOutPointRing.OutPoints[j] = &wire.OutPointAbe{
				TxHash: selectedRings[selectedUTXOs[i].RingHash].TxHashes[j],
				Index:  selectedRings[selectedUTXOs[i].RingHash].Index[j],
			}
		}

		serializedTxoLists := make([]*wire.TxOutAbe, 0, len(selectedRings[selectedUTXOs[i].RingHash].Index))
		for j := 0; j < len(selectedRings[selectedUTXOs[i].RingHash].Index); j++ {
			serializedTxoLists = append(serializedTxoLists, &wire.TxOutAbe{
				Version:   selectedRings[selectedUTXOs[i].RingHash].Version,
				TxoScript: selectedRings[selectedUTXOs[i].RingHash].TxoScripts[j],
			})
		}
		txoRing := &wire.TxoRing{
			Version:         selectedUTXOs[i].Version,
			RingBlockHeight: selectedUTXOs[i].Height, // Ring Height
			OutPointRing:    &txIns[i].PreviousOutPointRing,
			TxOuts:          serializedTxoLists,
			IsCoinbase:      selectedUTXOs[i].FromCoinBase,
		}
		// fetch the aSkSpByte from manager
		var copyedVskBytes []byte
		if serializedVskBytes[i] != nil {
			copyedVskBytes = make([]byte, len(serializedVskBytes[i]))
			copy(copyedVskBytes, serializedVskBytes[i])
		}

		abeTxInputDescs = append(abeTxInputDescs, abecryptox.NewAbeTxInputDescByKeys(
			txoRing,
			selectedUTXOs[i].Index,
			serializeAddressBytes[i],
			serializedAskspBytes[i],
			serializedAsksnBytes[i],
			copyedVskBytes,
			detectorKeys[i],
			selectedUTXOs[i].Amount))
	}

	targetValue := abeutil.Amount(0)
	for i := 0; i < len(txOutDescs); i++ {
		output := txOutDescs[i]
		targetValue += abeutil.Amount(output.Value())
	}
	if targetValue+txFee > currentTotal {
		return nil, errors.New("please specify enough amount to transfer: input + fee < output ")
	}

	usedCntNum := ^uint64(0)
	if needChangeFlag {
		var addrBytes []byte
		// fetch a free address if possible
		usedCntNum, addrBytes, err = w.FetchChangeAddress(true)
		if err != nil {
			// fetch a change address for the change
			_, usedCntNum, addrBytes, err = w.NewAddressKey(true)
			if err != nil {
				return nil, err
			}
			log.Infof("No.%d would be used as change address when generating a transaction", usedCntNum)
		} else {
			log.Infof("No.%d would be used as change address when generating a transaction", usedCntNum)
		}

		txOutDescs = append(txOutDescs, abecryptox.NewAbeTxOutDesc(addrBytes, uint64(currentTotal-txFee-targetValue)))
		if randomOutput {
			// random the outputs
			r, err := rand.Int(rand.Reader, big.NewInt(int64(len(txOutDescs))))
			if err != nil {
				return nil, err
			}
			index := r.Int64()
			txOutDescs[len(txOutDescs)-1], txOutDescs[index] = txOutDescs[index], txOutDescs[len(txOutDescs)-1]
		}
	}

	//TODO(abe) 20210627: to sure the txmemo?
	transferTxTemplate, err := createTransferTxAbeMsgTemplateMLP(txIns, len(txOutDescs), memo, uint64(txFee))
	if err != nil {
		return nil, errors.New("error for creating a transfer transaction template ")
	}

	// adjust the order of output descs
	sort.SliceStable(txOutDescs, func(i, j int) bool {
		outputIAddressPrivacyLevel, _, _, _ := abecryptoxkey.CryptoAddressParse(txOutDescs[i].CryptoAddress())
		outputJAddressPrivacyLevel, _, _, _ := abecryptoxkey.CryptoAddressParse(txOutDescs[j].CryptoAddress())
		if outputIAddressPrivacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYM && outputJAddressPrivacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYM {
			return true
		}
		return false
	})

	transferTx, err := abecryptox.TransferTxGenByKeys(abeTxInputDescs, txOutDescs, transferTxTemplate)
	if err != nil {
		return nil, err
	}
	resTx := &txauthor.AuthoredTxAbe{
		Tx:              transferTx,
		ChangeAddressNo: usedCntNum,
	}
	return resTx, nil
}

// txPqringCTToOutputs would be removed
func (w *Wallet) txPqringCTToOutputs(txOutDescs []*abecrypto.AbeTxOutputDesc, minconf int32, feePerKbSpecified abeutil.Amount, feeSpecified abeutil.Amount, utxoSpecified []string, dryRun bool) (
	unsignedTx *txauthor.AuthoredTxAbe, err error) {

	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}
	if !w.isDevEnv() {
		log.Debug("Waiting for chain backend to sync to tip")
		if err := w.waitUntilBackendSynced(chainClient); err != nil {
			return nil, err
		}
		log.Debug("Chain backend synced to tip!")
	}
	bs, err := chainClient.BlockStamp()
	if err != nil {
		return nil, err
	}

	//	todo: Amount seems useless
	targetValue := abeutil.Amount(0)
	for i := 0; i < len(txOutDescs); i++ {
		targetValue += abeutil.Amount(txOutDescs[i].GetValue())
	}

	if targetValue < 0 || targetValue > abeutil.Amount(abeutil.MaxNeutrino) {
		return nil, fmt.Errorf("target output value %v exceeds the maximum allowd value %v", targetValue, abeutil.MaxNeutrino)
	}
	var selectedTxos []*wtxmgr.UnspentUTXO
	var currentTotal abeutil.Amount
	var selectedRings map[chainhash.Hash]*wtxmgr.Ring
	var inputRingVersions []uint32
	var txFee abeutil.Amount
	//var addrBytes, vskBytes, aSkSpBytes []byte
	//var addrBytes, aSkSpBytes []byte
	needChangeFlag := false //whether need to make a change
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		//eligible, rings, err := w.findEligibleOutputsAbe(txmgrNs, minconf, bs)
		eligible, err := w.findEligibleTxosAbe(txmgrNs, minconf, bs)
		log.Tracef("Find eligible: ")
		for idx, txo := range eligible {
			log.Tracef("(%d) Height: %d, Value: %v", idx, txo.Height, float64(txo.Amount)/math.Pow10(7))
		}
		if err != nil {
			return err
		}

		if len(eligible) == 0 {
			return errors.New("not Enough")
		}
		// todo_DONE: order by version-then-amount
		//	pick utxos to spend
		sort.Sort(sort.Reverse(byAmount(eligible)))
		//TODO check the feeSpecified and feePerKbSpecified
		// fix the transaction fee
		if feeSpecified > 0 {
			currentVersion := eligible[0].Version
			selectedTxos = make([]*wtxmgr.UnspentUTXO, 0, len(eligible))
			currentTotal = abeutil.Amount(0) // total amount
			selectedRingSizes := make([]uint8, 0, len(eligible))

			if utxoSpecified != nil {
				log.Infof("create transaction for specified utxo %s", utxoSpecified)
				selectedTxos, err = fetchSpecifiedUTXO(eligible, utxoSpecified)
				if err != nil {
					log.Errorf("can not create transaction for specified utxo %s due to %s", utxoSpecified, err)
					return err
				}
				for _, txo := range selectedTxos {
					currentTotal = currentTotal + abeutil.Amount(txo.Amount)
					inputRingVersions = append(inputRingVersions, txo.Version)
					selectedRingSizes = append(selectedRingSizes, txo.RingSize)
				}
				log.Infof("utxoSpecified: targetValue %d, feeSpecified %d, currentTotal %d", targetValue, feeSpecified, currentTotal)
				if currentTotal >= targetValue+feeSpecified {
					txFee = feeSpecified
					if currentTotal > targetValue+feeSpecified {
						// the remain less than threshold so giving it to transaction fee
						if currentTotal-targetValue-feeSpecified < ChangeThreshold {
							txFee = currentTotal - targetValue
							needChangeFlag = false
						} else {
							txFee = feeSpecified
							needChangeFlag = true
						}
					}
				} else {
					return errors.New("not Enough")
				}
			} else {
				for len(eligible) != 0 {
					nextUtxo := &eligible[0]
					if nextUtxo.Version != currentVersion {
						currentVersion = nextUtxo.Version
						selectedTxos = make([]*wtxmgr.UnspentUTXO, 0, len(eligible))
						currentTotal = abeutil.Amount(0)
						selectedRingSizes = make([]uint8, 0, len(eligible))
						continue
					}
					eligible = eligible[1:]
					currentTotal = currentTotal + abeutil.Amount(nextUtxo.Amount)
					selectedTxos = append(selectedTxos, nextUtxo)
					inputRingVersions = append(inputRingVersions, nextUtxo.Version)
					selectedRingSizes = append(selectedRingSizes, nextUtxo.RingSize)

					if currentTotal >= targetValue+feeSpecified {
						txFee = feeSpecified
						if currentTotal > targetValue+feeSpecified {
							// the remain less than threshold so giving it to transaction fee
							if currentTotal-targetValue-feeSpecified < ChangeThreshold {
								txFee = currentTotal - targetValue
								needChangeFlag = false
							} else {
								txFee = feeSpecified
								needChangeFlag = true
							}
						}
						break
					}
				}
			}
			selectedRings = make(map[chainhash.Hash]*wtxmgr.Ring)
			for _, txo := range selectedTxos {
				_, ok := selectedRings[txo.RingHash]
				if !ok {
					ring, err := wtxmgr.FetchRingDetails(txmgrNs, txo.RingHash[:])
					if err != nil {
						return err
					}
					selectedRings[txo.RingHash] = ring
				}
			}
		} else if feePerKbSpecified > 0 {
			currentVersion := eligible[0].Version
			selectedTxos = make([]*wtxmgr.UnspentUTXO, 0, len(eligible))
			currentTotal = abeutil.Amount(0) // total amount
			selectedRingSizes := make([]int, 0, len(eligible))

			if utxoSpecified != nil {
				selectedTxos, err = fetchSpecifiedUTXO(eligible, utxoSpecified)
				if err != nil {
					return err
				}
				for _, txo := range selectedTxos {
					currentTotal = currentTotal + abeutil.Amount(txo.Amount)
					inputRingVersions = append(inputRingVersions, txo.Version)
					selectedRingSizes = append(selectedRingSizes, int(txo.RingSize))
				}

				txVersion := wire.TxVersion
				txConSize, err := wire.PrecomputeTrTxConSize(uint32(txVersion), inputRingVersions, selectedRingSizes, uint8(len(txOutDescs)+1), abecryptoparam.MaxAllowedTxMemoSize)
				if err != nil {
					return err
				}
				witnessSize, err := abecryptoparam.GetTrTxWitnessSerializeSizeApprox(uint32(txVersion), currentVersion, selectedRingSizes, (len(txOutDescs))+1)
				if err != nil {
					return err
				}
				fee, err := CalculateFee(txConSize, uint32(witnessSize), feePerKbSpecified)
				if err != nil {
					return err
				}

				if currentTotal >= targetValue+fee {
					txFee = fee
					if currentTotal > targetValue+fee {
						// the remain less than threshold so giving it to transaction fee
						if currentTotal-targetValue-fee < ChangeThreshold {
							txFee = currentTotal - targetValue
							needChangeFlag = false
						} else {
							txFee = fee
							needChangeFlag = true
						}
					}
				} else {
					txConSize, err := wire.PrecomputeTrTxConSize(uint32(txVersion), inputRingVersions, selectedRingSizes, uint8(len(txOutDescs)), abecryptoparam.MaxAllowedTxMemoSize)
					if err != nil {
						return err
					}
					witnessSize, err := abecryptoparam.GetTrTxWitnessSerializeSizeApprox(uint32(txVersion), currentVersion, selectedRingSizes, (len(txOutDescs)))
					if err != nil {
						return err
					}
					fee, err := CalculateFee(txConSize, uint32(witnessSize), feePerKbSpecified)
					if err != nil {
						return err
					}
					if currentTotal >= targetValue+fee {
						txFee = currentTotal - targetValue
						needChangeFlag = false
					} else {
						return errors.New("not Enough")
					}
				}
			} else {
				for len(eligible) != 0 {
					nextUtxo := &eligible[0]

					if nextUtxo.Version != currentVersion {
						currentVersion = nextUtxo.Version
						selectedTxos = make([]*wtxmgr.UnspentUTXO, 0, len(eligible))
						currentTotal = abeutil.Amount(0)
						selectedRingSizes = make([]int, 0, len(eligible))
						continue
					}

					eligible = eligible[1:]

					currentTotal = currentTotal + abeutil.Amount(nextUtxo.Amount)
					selectedTxos = append(selectedTxos, nextUtxo)
					inputRingVersions = append(inputRingVersions, nextUtxo.Version)
					selectedRingSizes = append(selectedRingSizes, int(nextUtxo.RingSize))

					// todo: compute tx size and witness, computes the fee, check amount, compare with changeThreshold

					if currentTotal > targetValue {
						txVersion := wire.TxVersion
						// compute the tx size with witness
						txConSize, err := wire.PrecomputeTrTxConSize(uint32(txVersion), inputRingVersions, selectedRingSizes, uint8(len(txOutDescs)), abecryptoparam.MaxAllowedTxMemoSize)
						if err != nil {
							return err
						}
						witnessSize, err := abecryptoparam.GetTrTxWitnessSerializeSizeApprox(uint32(txVersion), currentVersion, selectedRingSizes, len(txOutDescs))
						if err != nil {
							return err
						}
						fee, err := CalculateFee(txConSize, uint32(witnessSize), feePerKbSpecified)
						if err != nil {
							return err
						}
						txFee = fee
						if targetValue+fee < currentTotal {
							if currentTotal-targetValue-fee < ChangeThreshold {
								txFee = currentTotal - targetValue
								needChangeFlag = false
							} else {
								// need to make a change
								needChangeFlag = true
								txConSize, err := wire.PrecomputeTrTxConSize(uint32(txVersion), inputRingVersions, selectedRingSizes, uint8(len(txOutDescs)+1), abecryptoparam.MaxAllowedTxMemoSize)
								if err != nil {
									return err
								}
								witnessSize, err = abecryptoparam.GetTrTxWitnessSerializeSizeApprox(uint32(txVersion), currentVersion, selectedRingSizes, len(txOutDescs)+1)
								if err != nil {
									return err
								}
								fee, err := CalculateFee(txConSize, uint32(witnessSize), feePerKbSpecified)
								if err != nil {
									return err
								}
								if targetValue+fee < currentTotal {
									if currentTotal-targetValue < ChangeThreshold {
										txFee = currentTotal - targetValue
										needChangeFlag = false
									} else {
										txFee = fee
										needChangeFlag = true
									}
								} else {
									continue
								}
							}
							break
						}
					}
				}
			}
			selectedRings = make(map[chainhash.Hash]*wtxmgr.Ring)
			for _, txo := range selectedTxos {
				_, ok := selectedRings[txo.RingHash]
				if !ok {
					ring, err := wtxmgr.FetchRingDetails(txmgrNs, txo.RingHash[:])
					if err != nil {
						return err
					}
					selectedRings[txo.RingHash] = ring
				}
			}
		}
		if targetValue+txFee <= currentTotal {
			return nil
		}
		return errors.New("not Enough")
	})
	if err != nil {
		return nil, err
	}
	// Get current block's height and hash.
	//bs:=w.Manager.SyncedTo()

	// use db.View to spent coins, if successful, use db.Update to update the database

	// get the unspent transaction output

	// Randomize change position, if change exists, before signing.  This
	// doesn't affect the serialize size, so the change amount will still
	// be valid.

	PrintConsumedUTXOs(selectedTxos)

	serializeAddressBytes := make([][]byte, len(selectedTxos))
	serializedAskspBytes := make([][]byte, len(selectedTxos))
	serializedAsksnBytes := make([][]byte, len(selectedTxos))
	serializedVskBytes := make([][]byte, len(selectedTxos))
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		var serializedAddressEnc, serializedAskspEnc, serializedAsksnEnc, serializedVskEnc []byte
		for i := 0; i < len(selectedTxos); i++ {
			coinAddr, err := abecrypto.ExtractCoinAddressFromTxoScript(selectedRings[selectedTxos[i].RingHash].TxoScripts[selectedTxos[i].Index], abecryptoparam.CryptoSchemePQRingCT)
			if err != nil {
				return err
			}
			serializedAddressEnc, serializedAskspEnc, serializedAsksnEnc, serializedVskEnc, _, _, err = w.Manager.FetchAddressKeyEnc(addrmgrNs, coinAddr)
			if err != nil {
				return err
			}
			serializeAddressBytes[i], serializedAskspBytes[i], serializedAsksnBytes[i], serializedVskBytes[i], _, err = w.Manager.DecryptAddressKey(serializedAddressEnc, serializedAskspEnc, serializedAsksnEnc, serializedVskEnc, nil)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	abeTxInputDescs := make([]*abecrypto.AbeTxInputDesc, 0, len(selectedTxos))
	txIns := make([]*wire.TxInAbe, len(selectedTxos))
	for i := 0; i < len(selectedTxos); i++ {
		txIns[i] = &wire.TxInAbe{
			SerialNumber: nil,
			PreviousOutPointRing: wire.OutPointRing{
				Version:    selectedRings[selectedTxos[i].RingHash].Version,
				BlockHashs: make([]*chainhash.Hash, len(selectedRings[selectedTxos[i].RingHash].BlockHashes)),
				OutPoints:  make([]*wire.OutPointAbe, len(selectedRings[selectedTxos[i].RingHash].TxHashes)),
			},
		}
		for j := 0; j < len(selectedRings[selectedTxos[i].RingHash].BlockHashes); j++ {
			txIns[i].PreviousOutPointRing.BlockHashs[j] = &selectedRings[selectedTxos[i].RingHash].BlockHashes[j]
		}

		for j := 0; j < len(selectedRings[selectedTxos[i].RingHash].TxHashes); j++ {
			txIns[i].PreviousOutPointRing.OutPoints[j] = &wire.OutPointAbe{
				TxHash: selectedRings[selectedTxos[i].RingHash].TxHashes[j],
				Index:  selectedRings[selectedTxos[i].RingHash].Index[j],
			}
		}
		serializedTxoLists := make([]*wire.TxOutAbe, 0, len(selectedRings[selectedTxos[i].RingHash].Index))
		for j := 0; j < len(selectedRings[selectedTxos[i].RingHash].Index); j++ {
			serializedTxoLists = append(serializedTxoLists, &wire.TxOutAbe{
				Version:   selectedRings[selectedTxos[i].RingHash].Version,
				TxoScript: selectedRings[selectedTxos[i].RingHash].TxoScripts[j],
			})
		}
		// fetch the aSkSpByte from manager
		copyedVskBytes := make([]byte, len(serializedVskBytes[i]))
		copy(copyedVskBytes, serializedVskBytes[i])
		abeTxInputDescs = append(abeTxInputDescs, abecrypto.NewAbeTxInputDesc(
			selectedTxos[i].RingHash,
			serializedTxoLists,
			selectedTxos[i].Index,
			serializeAddressBytes[i],
			serializedAskspBytes[i],
			serializedAsksnBytes[i],
			copyedVskBytes,
			selectedTxos[i].Amount))
	}
	usedCntNum := ^uint64(0)
	if needChangeFlag {
		var addrBytes []byte
		// fetch a free address if possible
		usedCntNum, addrBytes, err = w.FetchChangeAddress(true)
		if err != nil {
			// fetch a change address for the change
			_, usedCntNum, addrBytes, err = w.NewAddressKey(true)
			if err != nil {
				return nil, err
			}
			log.Infof("No.%d would be used as change address when generating a transaction", usedCntNum)
		} else {
			log.Infof("No.%d would be used as change address when generating a transaction", usedCntNum)
		}

		txOutDescs = append(txOutDescs, abecrypto.NewAbeTxOutDesc(addrBytes, uint64(currentTotal-txFee-targetValue)))
		// random the outputs
		r, err := rand.Int(rand.Reader, big.NewInt(int64(len(txOutDescs))))
		if err != nil {
			return nil, err
		}
		index := r.Int64()
		txOutDescs[len(txOutDescs)-1], txOutDescs[index] = txOutDescs[index], txOutDescs[len(txOutDescs)-1]
	}

	//PrintNewUTXOs(txOutDescs, needChangeFlag, txFee)

	//TODO(abe) 20210627: to sure the txmemo?
	transferTxTemplate, err := createTransferTxAbeMsgTemplate(txIns, len(txOutDescs), []byte{}, uint64(txFee))
	if err != nil {
		return nil, errors.New("error for creating a transfer transaction template ")
	}
	transferTx, err := abecrypto.TransferTxGen(abeTxInputDescs, txOutDescs, transferTxTemplate)
	if err != nil {
		return nil, err
	}
	resTx := &txauthor.AuthoredTxAbe{
		Tx:              transferTx,
		ChangeAddressNo: usedCntNum,
	}
	return resTx, nil

	// If a dry run was requested, we return now before adding the input
	// scripts, and don't commit the database transaction. The DB will be
	// rolled back when this method returns to ensure the dry run didn't
	// alter the DB in any way.

	//if dryRun {
	//	return unsignedTx, nil
	//}

	//// Finally, we'll request the backend to notify us of the transaction
	//// that pays to the change address, if there is one, when it confirms.
}

// TODO(abe):we should request the unspent transaction output from tx manager
func (w *Wallet) findEligibleOutputsAbe(txmgrNs walletdb.ReadBucket, minconf int32, bs *waddrmgr.BlockStamp) ([]wtxmgr.UnspentUTXO, map[chainhash.Hash]*wtxmgr.Ring, error) {
	unspent, err := w.TxStore.UnspentOutputs(txmgrNs) // In ABE, this result will be spendable for the logic of store
	if err != nil {
		return nil, nil, err
	}
	// TODO: Eventually all of these filters (except perhaps output locking)
	// should be handled by the call to UnspentOutputs (or similar).
	// Because one of these filters requires matching the output script to
	// the desired account, this change depends on making wtxmgr a waddrmgr
	// dependancy and requesting unspent outputs for a single account.
	eligible := make([]wtxmgr.UnspentUTXO, 0, len(unspent))
	for i := range unspent {
		output := unspent[i]

		// Only include this output if it meets the required number of
		// confirmations.  Coinbase transactions must have have reached
		// maturity before their outputs may be spent.
		if !confirmed(minconf, output.Height, bs.Height) {
			// if the utxo.height<current height, it can not spend.
			continue
		}
		if output.FromCoinBase {
			target := int32(w.chainParams.CoinbaseMaturity)
			if !confirmed(target, output.Height, bs.Height) {
				continue
			}
		}
		eligible = append(eligible, output)
	}
	rings := make(map[chainhash.Hash]*wtxmgr.Ring)

	for i := 0; i < len(eligible); i++ {
		// Due to logic of storing, the ringhash of output can't be zerohash
		//if chainhash.ZeroHash.IsEqual(&eligible[i].RingHash) { //if the hash is zero, it means that this output is unspentable
		//	eligible = append(eligible[:i], eligible[i+1:]...)
		//	i--
		//	continue
		//}
		_, ok := rings[eligible[i].RingHash]
		if !ok {
			ring, err := wtxmgr.FetchRingDetails(txmgrNs, eligible[i].RingHash[:])
			if ring == nil && err == fmt.Errorf("the pair is not exist") { // it means that this outpoint is not contained in a ring
				continue
			} else if err != nil {
				return nil, nil, err
			}
			rings[eligible[i].RingHash] = ring
		}
	}
	return eligible, rings, nil
}

// todo (AliceBob): This method just read the eligible Txos from WalletDB
func (w *Wallet) findEligibleTxosAbe(txmgrNs walletdb.ReadBucket, minconf int32, bs *waddrmgr.BlockStamp) ([]wtxmgr.UnspentUTXO, error) {
	unspent, err := w.TxStore.UnspentOutputs(txmgrNs) // In ABE, this result will be spendable for the logic of store
	if err != nil {
		return nil, err
	}
	// TODO: Eventually all of these filters (except perhaps output locking)
	// should be handled by the call to UnspentOutputs (or similar).
	// Because one of these filters requires matching the output script to
	// the desired account, this change depends on making wtxmgr a waddrmgr
	// dependancy and requesting unspent outputs for a single account.
	eligible := make([]wtxmgr.UnspentUTXO, 0, len(unspent))
	for i := range unspent {
		output := unspent[i]

		// Only include this output if it meets the required number of
		// confirmations.  Coinbase transactions must have have reached
		// maturity before their outputs may be spent.
		if !confirmed(minconf, output.Height, bs.Height) {
			// if the utxo.height<current height, it can not spend.
			continue
		}
		if output.FromCoinBase {
			target := int32(w.chainParams.CoinbaseMaturity)
			if !confirmed(target, output.Height, bs.Height) {
				continue
			}
		}
		eligible = append(eligible, output)
	}
	//	todo: confirm that will not read the rings
	/*	rings := make(map[chainhash.Hash]*wtxmgr.Ring)

		for i := 0; i < len(eligible); i++ {
			// Due to logic of storing, the ringhash of output can't be zerohash
			//if chainhash.ZeroHash.IsEqual(&eligible[i].RingHash) { //if the hash is zero, it means that this output is unspentable
			//	eligible = append(eligible[:i], eligible[i+1:]...)
			//	i--
			//	continue
			//}
			_, ok := rings[eligible[i].RingHash]
			if !ok {
				ring, err := wtxmgr.FetchRingDetails(txmgrNs, eligible[i].RingHash[:])
				if ring == nil && err == fmt.Errorf("the pair is not exist") { // it means that this outpoint is not contained in a ring
					continue
				} else if err != nil {
					return nil, nil, err
				}
				rings[eligible[i].RingHash] = ring
			}
		}
		return eligible, rings, nil*/
	return eligible, nil
}

func (w *Wallet) findEligibleTxosAbeAUT(txmgrNs walletdb.ReadBucket, minconf int32, bs *waddrmgr.BlockStamp, autName []byte) ([]*wtxmgr.AUTCoin, error) {
	unspent, _, err := w.TxStore.UnspentOutputsAUT(txmgrNs, autName, false) // In ABE, this result will be spendable for the logic of store
	if err != nil {
		return nil, err
	}

	// TODO: Eventually all of these filters (except perhaps output locking)
	// should be handled by the call to UnspentOutputs (or similar).
	// Because one of these filters requires matching the output script to
	// the desired account, this change depends on making wtxmgr a waddrmgr
	// dependancy and requesting unspent outputs for a single account.
	eligible := make([]*wtxmgr.AUTCoin, 0, len(unspent))
	for i := range unspent {
		output := unspent[i]

		if output.Spent {
			continue
		}

		eligible = append(eligible, output)
	}
	return eligible, nil
}

// validateMsgTx verifies transaction input scripts for tx.  All previous output
// scripts from outputs redeemed by the transaction, in the same order they are
// spent, must be passed in the prevScripts slice.
func validateMsgTx(tx *wire.MsgTx, prevScripts [][]byte, inputValues []abeutil.Amount) error {
	hashCache := txscript.NewTxSigHashes(tx)
	for i, prevScript := range prevScripts {
		vm, err := txscript.NewEngine(prevScript, tx, i,
			txscript.StandardVerifyFlags, nil, hashCache, int64(inputValues[i]))
		if err != nil {
			return fmt.Errorf("cannot create script engine: %s", err)
		}
		err = vm.Execute()
		if err != nil {
			return fmt.Errorf("cannot validate transaction: %s", err)
		}
	}
	return nil
}
