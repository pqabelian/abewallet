package wallet

import (
	"fmt"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/btcec"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/txscript"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abewallet/waddrmgr"
	"github.com/abesuite/abewallet/wallet/txauthor"
	"github.com/abesuite/abewallet/walletdb"
	"github.com/abesuite/abewallet/wtxmgr"
	"sort"
)

// byAmount defines the methods needed to satisify sort.Interface to
// sort credits by their output amount.
type byAmount []wtxmgr.Credit

func (s byAmount) Len() int           { return len(s) }
func (s byAmount) Less(i, j int) bool { return s[i].Amount < s[j].Amount }
func (s byAmount) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

type byAmountAbe []wtxmgr.UnspentUTXO

func (s byAmountAbe) Len() int           { return len(s) }
func (s byAmountAbe) Less(i, j int) bool { return s[i].Amount < s[j].Amount }
func (s byAmountAbe) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func makeInputSource(eligible []wtxmgr.Credit) txauthor.InputSource {
	// Pick largest outputs first.  This is only done for compatibility with
	// previous tx creation code, not because it's a good idea.
	sort.Sort(sort.Reverse(byAmount(eligible)))

	// Current inputs and their total value.  These are closed over by the
	// returned input source and reused across multiple calls.
	currentTotal := abeutil.Amount(0)
	currentInputs := make([]*wire.TxIn, 0, len(eligible))
	currentScripts := make([][]byte, 0, len(eligible))
	currentInputValues := make([]abeutil.Amount, 0, len(eligible))

	return func(target abeutil.Amount) (abeutil.Amount, []*wire.TxIn,
		[]abeutil.Amount, [][]byte, error) {

		for currentTotal < target && len(eligible) != 0 {
			nextCredit := &eligible[0]
			eligible = eligible[1:]
			nextInput := wire.NewTxIn(&nextCredit.OutPoint, nil, nil)
			currentTotal += nextCredit.Amount
			currentInputs = append(currentInputs, nextInput)
			currentScripts = append(currentScripts, nextCredit.PkScript)
			currentInputValues = append(currentInputValues, nextCredit.Amount)
		}
		return currentTotal, currentInputs, currentInputValues, currentScripts, nil
	}
}
func makeInputSourceAbe(eligible []wtxmgr.UnspentUTXO, rings map[chainhash.Hash]*wtxmgr.Ring) txauthor.InputSourceAbe {
	// Pick largest outputs first.  This is only done for compatibility with
	// previous tx creation code, not because it's a good idea.
	sort.Sort(sort.Reverse(byAmountAbe(eligible)))

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
			nextInput := wire.NewTxInAbe(&chainhash.Hash{}, &wire.OutPointRing{ // the outpoint index has be put in the seriaalNummber field
				BlockHashs: []*chainhash.Hash{},
				OutPoints:  []*wire.OutPointAbe{},
			})
			index:=-1
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
					index=i
				}
			}
			currentTotal += abeutil.Amount(nextUTXO.Amount)
			nextInput.SerialNumber[0]=byte(index)
			currentInputs = append(currentInputs, nextInput)
			amount, _ := abeutil.NewAmount(float64(nextUTXO.Amount))
			currentInputValues = append(currentInputValues, amount)
		}
		return currentTotal, currentInputs, currentInputValues, currentScripts, nil
	}
}

// secretSource is an implementation of txauthor.SecretSource for the wallet's
// address manager.
type secretSource struct {
	*waddrmgr.Manager
	addrmgrNs walletdb.ReadBucket
}

func (s secretSource) GetKey(addr abeutil.Address) (*btcec.PrivateKey, bool, error) {
	ma, err := s.Address(s.addrmgrNs, addr)
	if err != nil {
		return nil, false, err
	}

	mpka, ok := ma.(waddrmgr.ManagedPubKeyAddress)
	if !ok {
		e := fmt.Errorf("managed address type for %v is `%T` but "+
			"want waddrmgr.ManagedPubKeyAddress", addr, ma)
		return nil, false, e
	}
	privKey, err := mpka.PrivKey()
	if err != nil {
		return nil, false, err
	}
	return privKey, ma.Compressed(), nil
}

func (s secretSource) GetScript(addr abeutil.Address) ([]byte, error) {
	ma, err := s.Address(s.addrmgrNs, addr)
	if err != nil {
		return nil, err
	}

	msa, ok := ma.(waddrmgr.ManagedScriptAddress)
	if !ok {
		e := fmt.Errorf("managed address type for %v is `%T` but "+
			"want waddrmgr.ManagedScriptAddress", addr, ma)
		return nil, e
	}
	return msa.Script()
}

//type secretSourceAbe struct {
//	*waddrmgr.ManagerAbe
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
//	todo(ABE.2)
func (w *Wallet) txToOutputs(outputs []*wire.TxOut, account uint32,
	minconf int32, feeSatPerKb abeutil.Amount, dryRun bool) (
	tx *txauthor.AuthoredTx, err error) {

	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}

	dbtx, err := w.db.BeginReadWriteTx()
	if err != nil {
		return nil, err
	}
	defer dbtx.Rollback()

	addrmgrNs := dbtx.ReadWriteBucket(waddrmgrNamespaceKey)

	// Get current block's height and hash.
	bs, err := chainClient.BlockStamp()
	if err != nil {
		return nil, err
	}

	eligible, err := w.findEligibleOutputs(dbtx, account, minconf, bs)
	if err != nil {
		return nil, err
	}

	inputSource := makeInputSource(eligible)
	changeSource := func() ([]byte, error) {
		// Derive the change output script. We'll use the default key
		// scope responsible for P2WPKH addresses to do so. As a hack to
		// allow spending from the imported account, change addresses
		// are created from account 0.
		var changeAddr abeutil.Address
		var err error
		changeKeyScope := waddrmgr.KeyScopeBIP0084
		if account == waddrmgr.ImportedAddrAccount {
			changeAddr, err = w.newChangeAddress(
				addrmgrNs, 0, changeKeyScope,
			)
		} else {
			changeAddr, err = w.newChangeAddress(
				addrmgrNs, account, changeKeyScope,
			)
		}
		if err != nil {
			return nil, err
		}
		return txscript.PayToAddrScript(changeAddr)
	}
	tx, err = txauthor.NewUnsignedTransaction(outputs, feeSatPerKb,
		inputSource, changeSource)
	if err != nil {
		return nil, err
	}

	// Randomize change position, if change exists, before signing.  This
	// doesn't affect the serialize size, so the change amount will still
	// be valid.
	if tx.ChangeIndex >= 0 {
		tx.RandomizeChangePosition()
	}

	// If a dry run was requested, we return now before adding the input
	// scripts, and don't commit the database transaction. The DB will be
	// rolled back when this method returns to ensure the dry run didn't
	// alter the DB in any way.
	if dryRun {
		return tx, nil
	}

	err = tx.AddAllInputScripts(secretSource{w.Manager, addrmgrNs})
	if err != nil {
		return nil, err
	}

	//	todo(ABE): Is this necessary?
	err = validateMsgTx(tx.Tx, tx.PrevScripts, tx.PrevInputValues)
	if err != nil {
		return nil, err
	}

	if err := dbtx.Commit(); err != nil {
		return nil, err
	}

	if tx.ChangeIndex >= 0 && account == waddrmgr.ImportedAddrAccount {
		changeAmount := abeutil.Amount(tx.Tx.TxOut[tx.ChangeIndex].Value)
		log.Warnf("Spend from imported account produced change: moving"+
			" %v from imported account into default account.", changeAmount)
	}

	// Finally, we'll request the backend to notify us of the transaction
	// that pays to the change address, if there is one, when it confirms.
	if tx.ChangeIndex >= 0 {
		changePkScript := tx.Tx.TxOut[tx.ChangeIndex].PkScript
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			changePkScript, w.chainParams,
		)
		if err != nil {
			return nil, err
		}
		if err := chainClient.NotifyReceived(addrs); err != nil {
			return nil, err
		}
	}

	return tx, nil
}

// TODO(abe): compute the transaction fee
func (w *Wallet) txAbeToOutputs(outputs []*wire.TxOutAbe, minconf int32, feeSatPerKb abeutil.Amount, dryRun bool) (
	unsignedTx *txauthor.AuthoredTxAbe, err error) {

	chainClient, err := w.requireChainClient()
	if err != nil {
		return nil, err
	}
	bs, err := chainClient.BlockStamp()
	if err != nil {
		return nil, err
	}
	// TODO(abe):should use a db.View to spend, if successful, use db.Update
	err = walletdb.View(w.db, func(tx walletdb.ReadTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadBucket(wtxmgrNamespaceKey)
		eligible, rings, err := w.findEligibleOutputsAbe(txmgrNs, minconf, bs)
		if err != nil {
			return err
		}
		inputSource := makeInputSourceAbe(eligible, rings)
		changeSource := func() ([]byte, error) {
			// Derive the change output script. We'll use the default key
			// scope responsible for P2WPKH addresses to do so. As a hack to
			// allow spending from the imported account, change addresses
			// are created from account 0.
			return w.ManagerAbe.NewChangeAddress(addrmgrNs)
		}
		unsignedTx, err = txauthor.NewUnsignedTransactionAbe(outputs, feeSatPerKb,
			inputSource, changeSource)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Get current block's height and hash.
	//bs:=w.ManagerAbe.SyncedTo()

	// use db.View to spent coins, if successful, use db.Update to update the database

	// get the unspent transaction output

	// Randomize change position, if change exists, before signing.  This
	// doesn't affect the serialize size, so the change amount will still
	// be valid.
	if unsignedTx.ChangeIndex >= 0 {
		unsignedTx.RandomizeChangePosition()
	}

	// If a dry run was requested, we return now before adding the input
	// scripts, and don't commit the database transaction. The DB will be
	// rolled back when this method returns to ensure the dry run didn't
	// alter the DB in any way.
	if dryRun {
		return unsignedTx, nil
	}

	// TODO(abe):refresh the utxo ring
	//   todo
	// TODO(abe):need to get serialNumber and signature for all input in new transaction
	err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
		addrmgrNs := tx.ReadBucket(waddrmgrNamespaceKey)
		txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)
		err = unsignedTx.AddAllInputScripts([]byte("this is a test"), w.ManagerAbe, addrmgrNs, txmgrNs)
		if err != nil {
			return nil
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	//	todo(ABE): Is this necessary?
	// TODO(osy): temporary ignore it
	//err = validateMsgTx(tx.Tx, tx.PrevScripts, tx.PrevInputValues)
	//if err != nil {
	//	return nil, err
	//}

	// TODO(abe):up to here, the transaction will be successful created, so the spent utxo should be marked used and move to SpentButUmined Bucket.
	//   and modify the utxo ring bucket.

	//txRecordAbe, err := wtxmgr.NewTxRecordAbeFromMsgTxAbe(unsignedTx.Tx, time.Now())
	//if err != nil {
	//	return nil, err
	//}
	//
	//err = walletdb.Update(w.db, func(tx walletdb.ReadWriteTx) error {
	//	txmgrNs := tx.ReadWriteBucket(wtxmgrNamespaceKey)
	//	err = w.TxStore.InsertTxAbe(txmgrNs, txRecordAbe, nil)
	//	if err != nil {
	//		return err
	//	}
	//	return nil
	//})
	//if err!=nil{
	//	return nil,err
	//}
	return unsignedTx,nil
	//return unsignedTx, nil
	//
	//if err := dbtx.Commit(); err != nil {
	//	return nil, err
	//}
	//
	////if tx.ChangeIndex >= 0 && account == waddrmgr.ImportedAddrAccount {
	////	changeAmount := abeutil.Amount(tx.Tx.TxOuts[tx.ChangeIndex].ValueScript)
	////	log.Warnf("Spend from imported account produced change: moving"+
	////		" %v from imported account into default account.", changeAmount)
	////}
	//
	//// Finally, we'll request the backend to notify us of the transaction
	//// that pays to the change address, if there is one, when it confirms.
	////TODO(abe): this process will be ignore, because we can not spend this change output before this transaction is mined into the chain
	////if tx.ChangeIndex >= 0 {
	////	changePkScript := tx.Tx.TxOuts[tx.ChangeIndex].AddressScript
	////	_, addrs, _, err := txscript.ExtractPkScriptAddrs(
	////		changePkScript, w.chainParams,
	////	)
	////	if err != nil {
	////		return nil, err
	////	}
	////	if err := chainClient.NotifyReceived(addrs); err != nil {
	////		return nil, err
	////	}
	////}
	//
	//return tx, nil
}

func (w *Wallet) findEligibleOutputs(dbtx walletdb.ReadTx, account uint32, minconf int32, bs *waddrmgr.BlockStamp) ([]wtxmgr.Credit, error) {
	addrmgrNs := dbtx.ReadBucket(waddrmgrNamespaceKey)
	txmgrNs := dbtx.ReadBucket(wtxmgrNamespaceKey)

	unspent, err := w.TxStore.UnspentOutputs(txmgrNs)
	if err != nil {
		return nil, err
	}

	// TODO: Eventually all of these filters (except perhaps output locking)
	// should be handled by the call to UnspentOutputs (or similar).
	// Because one of these filters requires matching the output script to
	// the desired account, this change depends on making wtxmgr a waddrmgr
	// dependancy and requesting unspent outputs for a single account.
	eligible := make([]wtxmgr.Credit, 0, len(unspent))
	for i := range unspent {
		output := &unspent[i]

		// Only include this output if it meets the required number of
		// confirmations.  Coinbase transactions must have have reached
		// maturity before their outputs may be spent.
		if !confirmed(minconf, output.Height, bs.Height) {
			continue
		}
		if output.FromCoinBase {
			target := int32(w.chainParams.CoinbaseMaturity)
			if !confirmed(target, output.Height, bs.Height) {
				continue
			}
		}

		// Locked unspent outputs are skipped.
		if w.LockedOutpoint(output.OutPoint) {
			continue
		}

		// Only include the output if it is associated with the passed
		// account.
		//
		// TODO: Handle multisig outputs by determining if enough of the
		// addresses are controlled.
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			output.PkScript, w.chainParams)
		if err != nil || len(addrs) != 1 {
			continue
		}
		_, addrAcct, err := w.Manager.AddrAccount(addrmgrNs, addrs[0])
		if err != nil || addrAcct != account {
			continue
		}
		eligible = append(eligible, *output)
	}
	return eligible, nil
}

// TODO(abe):we should request the unspent transaction output from tx manager
func (w *Wallet) findEligibleOutputsAbe(txmgrNs walletdb.ReadBucket, minconf int32, bs *waddrmgr.BlockStamp) ([]wtxmgr.UnspentUTXO, map[chainhash.Hash]*wtxmgr.Ring, error) {
	unspent, err := w.TxStore.UnspentOutputsAbe(txmgrNs)
	if err != nil {
		return nil, nil, err
	}
	// TODO: Eventually all of these filters (except perhaps output locking)
	// should be handled by the call to UnspentOutputs (or similar).
	// Because one of these filters requires matching the output script to
	// the desired account, this change depends on making wtxmgr a waddrmgr
	// dependancy and requesting unspent outputs for a single account.
	eligible := make([]wtxmgr.UnspentUTXO, 0, len(*unspent))
	for i := range *unspent {
		output := (*unspent)[i]

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
		if chainhash.ZeroHash.IsEqual(&eligible[i].RingHash) { //if the hash is zero, it means that this output is unspentable
			eligible = append(eligible[:i], eligible[i+1:]...)
			i--
			continue
		}
		_, ok := rings[eligible[i].RingHash]
		if !ok {
			ring, err := wtxmgr.FetchRingDetails(txmgrNs, eligible[i].RingHash[:])
			if ring==nil && err.Error()=="the pair is not exist"{     // it means that this outpoint is not contained in a ring
				continue
			}else if err!=nil{
				return nil,nil,err
			}
			rings[eligible[i].RingHash] = ring
		}
	}
	return eligible, rings, nil
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
