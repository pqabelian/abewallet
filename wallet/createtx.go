package wallet

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abecrypto/abecryptoparam"
	"github.com/abesuite/abec/abeutil"
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

func createTransferTxAbeMsgTemplate(txIn []*wire.TxInAbe, txOutNum int, txMemo []byte, fee uint64) (*wire.MsgTxAbe, error) {
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

func PrintConsumedUTXOs(selectedTxos []*wtxmgr.UnspentUTXO) {
	log.Infof("Consumed utxos: ")
	for idx, txo := range selectedTxos {
		log.Infof("(%d) Value %v at height %d, utxoHash: %s (From Coinbase: %t)",
			idx, float64(txo.Amount)/math.Pow10(7), txo.Height, txo.Hash().String(), txo.FromCoinBase)
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
			serializedAddressEnc, serializedAskspEnc, serializedAsksnEnc, serializedVskEnc, _, err = w.Manager.FetchAddressKeyEnc(addrmgrNs, coinAddr)
			if err != nil {
				return err
			}
			serializeAddressBytes[i], serializedAskspBytes[i], serializedAsksnBytes[i], serializedVskBytes[i], err = w.Manager.DecryptAddressKey(serializedAddressEnc, serializedAskspEnc, serializedAsksnEnc, serializedVskEnc)
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
		usedCntNum, addrBytes, err = w.FetchFreeAddress(true)
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
