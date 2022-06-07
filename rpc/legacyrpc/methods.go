package legacyrpc

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abejson"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abewallet/wallet/txrules"
	"github.com/abesuite/abewallet/wtxmgr"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/abesuite/abec/btcec"
	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/rpcclient"
	"github.com/abesuite/abec/txscript"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abewallet/chain"
	"github.com/abesuite/abewallet/waddrmgr"
	"github.com/abesuite/abewallet/wallet"
)

// confirmed checks whether a transaction at height txHeight has met minconf
// confirmations for a blockchain at height curHeight.
func confirmed(minconf, txHeight, curHeight int32) bool {
	return confirms(txHeight, curHeight) >= minconf
}

// confirms returns the number of confirmations for a transaction in a block at
// height txHeight (or -1 for an unconfirmed tx) given the chain height
// curHeight.
func confirms(txHeight, curHeight int32) int32 {
	switch {
	case txHeight == -1, txHeight > curHeight:
		return 0
	default:
		return curHeight - txHeight + 1
	}
}

// requestHandler is a handler function to handle an unmarshaled and parsed
// request into a marshalable response.  If the error is a *btcjson.RPCError
// or any of the above special error classes, the server will respond with
// the JSON-RPC appropiate error code.  All other errors use the wallet
// catch-all error code, btcjson.ErrRPCWallet.
type requestHandler func(interface{}, *wallet.Wallet) (interface{}, error)

// requestHandlerChain is a requestHandler that also takes a parameter for
type requestHandlerChainRequired func(interface{}, *wallet.Wallet, *chain.RPCClient) (interface{}, error)

var rpcHandlers = map[string]struct {
	handler          requestHandler
	handlerWithChain requestHandlerChainRequired

	// Function variables cannot be compared against anything but nil, so
	// use a boolean to record whether help generation is necessary.  This
	// is used by the tests to ensure that help can be generated for every
	// implemented method.
	//
	// A single map and this bool is here is used rather than several maps
	// for the unimplemented handlers so every method has exactly one
	// handler function.
	noHelp bool
}{
	//	todo(ABE): The supported RPC requests are here. We need to remove some that are not supported any more.
	// Reference implementation wallet methods (implemented)
	"addmultisigaddress": {handler: addMultiSigAddress},
	//"addpayee":              {handler: addPayee},
	"createmultisig":        {handler: createMultiSig},
	"dumpprivkey":           {handler: dumpPrivKey},
	"getaccount":            {handler: getAccount},
	"getaccountaddress":     {handler: getAccountAddress},
	"getaddressesbyaccount": {handler: getAddressesByAccount},
	//"getbalance":            {handler: getBalance},
	"getbalances":          {handler: getBalance},
	"getdetailedutxos":     {handler: getDetailedUtxos},
	"getbestblockhash":     {handler: getBestBlockHash},
	"getblockcount":        {handler: getBlockCount},
	"getinfo":              {handlerWithChain: getInfo},
	"getnewaddress":        {handler: getNewAddress},
	"getrawchangeaddress":  {handler: getRawChangeAddress},
	"getreceivedbyaccount": {handler: getReceivedByAccount},
	"getreceivedbyaddress": {handler: getReceivedByAddress},
	"gettransaction":       {handler: getTransaction},
	"help":                 {handler: helpNoChainRPC, handlerWithChain: helpWithChainRPC},
	"importprivkey":        {handler: importPrivKey},
	"keypoolrefill":        {handler: keypoolRefill},
	//"listaccounts":           {handler: listAccounts},
	"listlockunspent":        {handler: listLockUnspent},
	"listreceivedbyaccount":  {handler: listReceivedByAccount},
	"listreceivedbyaddress":  {handler: listReceivedByAddress},
	"listsinceblock":         {handlerWithChain: listSinceBlock},
	"listtransactions":       {handler: listTransactions},
	"listunspent":            {handler: listUnspent},
	"listallutxoabe":         {handler: listAllUTXOAbe},
	"listunmaturedabe":       {handler: listUnmaturedUTXOAbe},
	"listunspentabe":         {handler: listUnspentAbe},
	"listspentbutunminedabe": {handler: listSpentButUnminedAbe},
	"listspentandminedabe":   {handler: listSpentAndMinedAbe},
	"lockunspent":            {handler: lockUnspent},
	//"sendfrom":               {handlerWithChain: sendFrom},
	//"sendmany":               {handler: sendMany},
	"sendtoaddressesabe": {handler: sendToAddressesAbe},
	"generateaddressabe": {handler: generateAddressAbe},
	//"sendtoaddress":          {handler: sendToAddress},
	"sendtopayee":            {handler: sendToPayees},
	"settxfee":               {handler: setTxFee},
	"signmessage":            {handler: signMessage},
	"signrawtransaction":     {handlerWithChain: signRawTransaction},
	"validateaddress":        {handler: validateAddress},
	"verifymessage":          {handler: verifyMessage},
	"walletlock":             {handler: walletLock},
	"freshen":                {handler: freshen},
	"walletpassphrase":       {handler: walletPassphrase},
	"walletpassphrasechange": {handler: walletPassphraseChange},

	// Reference implementation methods (still unimplemented)
	"backupwallet":         {handler: unimplemented, noHelp: true},
	"dumpwallet":           {handler: unimplemented, noHelp: true},
	"getwalletinfo":        {handler: unimplemented, noHelp: true},
	"importwallet":         {handler: unimplemented, noHelp: true},
	"listaddressgroupings": {handler: unimplemented, noHelp: true},

	// Reference methods which can't be implemented by btcwallet due to
	// design decision differences
	"encryptwallet": {handler: unsupported, noHelp: true},
	"move":          {handler: unsupported, noHelp: true},
	"setaccount":    {handler: unsupported, noHelp: true},

	// Extensions to the reference client JSON-RPC API
	"createnewaccount": {handler: createNewAccount},
	"getbestblock":     {handler: getBestBlock},
	// This was an extension but the reference implementation added it as
	// well, but with a different API (no account parameter).  It's listed
	// here because it hasn't been update to use the reference
	// implemenation's API.
	"getunconfirmedbalance":   {handler: getUnconfirmedBalance},
	"listaddresstransactions": {handler: listAddressTransactions},
	"listalltransactions":     {handler: listAllTransactions},
	"renameaccount":           {handler: renameAccount},
	"walletislocked":          {handler: walletIsLocked},
}

// unimplemented handles an unimplemented RPC request with the
// appropiate error.
func unimplemented(interface{}, *wallet.Wallet) (interface{}, error) {
	return nil, &abejson.RPCError{
		Code:    abejson.ErrRPCUnimplemented,
		Message: "Method unimplemented",
	}
}

// unsupported handles a standard bitcoind RPC request which is
// unsupported by btcwallet due to design differences.
func unsupported(interface{}, *wallet.Wallet) (interface{}, error) {
	return nil, &abejson.RPCError{
		Code:    -1,
		Message: "Request unsupported by abewallet",
	}
}

// lazyHandler is a closure over a requestHandler or passthrough request with
// the RPC server's wallet and chain server variables as part of the closure
// context.
type lazyHandler func() (interface{}, *abejson.RPCError)

// lazyApplyHandler looks up the best request handler func for the method,
// returning a closure that will execute it with the (required) wallet and
// (optional) consensus RPC server.  If no handlers are found and the
// chainClient is not nil, the returned handler performs RPC passthrough.
func lazyApplyHandler(request *abejson.Request, w *wallet.Wallet, chainClient chain.Interface) lazyHandler {
	handlerData, ok := rpcHandlers[request.Method]
	if ok && handlerData.handlerWithChain != nil && w != nil && chainClient != nil { // if this handle need helps of chain
		return func() (interface{}, *abejson.RPCError) {
			cmd, err := abejson.UnmarshalCmd(request)
			if err != nil {
				return nil, abejson.ErrRPCInvalidRequest
			}
			switch client := chainClient.(type) {
			case *chain.RPCClient:
				resp, err := handlerData.handlerWithChain(cmd,
					w, client)
				if err != nil {
					return nil, jsonError(err)
				}
				return resp, nil
			default:
				return nil, &abejson.RPCError{
					Code:    -1,
					Message: "Chain RPC is inactive",
				}
			}
		}
	}
	if ok && handlerData.handler != nil && w != nil { //just wallet can handle with this request
		return func() (interface{}, *abejson.RPCError) {
			cmd, err := abejson.UnmarshalCmd(request)
			if err != nil {
				return nil, abejson.ErrRPCInvalidRequest
			}
			resp, err := handlerData.handler(cmd, w)
			if err != nil {
				return nil, jsonError(err)
			}
			return resp, nil
		}
	}

	// Fallback to RPC passthrough
	return func() (interface{}, *abejson.RPCError) {
		if chainClient == nil {
			return nil, &abejson.RPCError{
				Code:    -1,
				Message: "Chain RPC is inactive",
			}
		}
		switch client := chainClient.(type) {
		case *chain.RPCClient:
			resp, err := client.RawRequest(request.Method,
				request.Params)
			if err != nil {
				return nil, jsonError(err)
			}
			return &resp, nil
		default:
			return nil, &abejson.RPCError{
				Code:    -1,
				Message: "Chain RPC is inactive",
			}
		}
	}
}

// makeResponse makes the JSON-RPC response struct for the result and error
// returned by a requestHandler.  The returned response is not ready for
// marshaling and sending off to a client, but must be
func makeResponse(id, result interface{}, err error) abejson.Response {
	idPtr := idPointer(id)
	if err != nil {
		return abejson.Response{
			ID:    idPtr,
			Error: jsonError(err),
		}
	}
	resultBytes, err := json.Marshal(result)
	if err != nil {
		return abejson.Response{
			ID: idPtr,
			Error: &abejson.RPCError{
				Code:    abejson.ErrRPCInternal.Code,
				Message: "Unexpected error marshalling result",
			},
		}
	}
	return abejson.Response{
		ID:     idPtr,
		Result: json.RawMessage(resultBytes),
	}
}

// jsonError creates a JSON-RPC error from the Go error.
func jsonError(err error) *abejson.RPCError {
	if err == nil {
		return nil
	}

	code := abejson.ErrRPCWallet
	switch e := err.(type) {
	case abejson.RPCError:
		return &e
	case *abejson.RPCError:
		return e
	case DeserializationError:
		code = abejson.ErrRPCDeserialization
	case InvalidParameterError:
		code = abejson.ErrRPCInvalidParameter
	case ParseError:
		code = abejson.ErrRPCParse.Code
	case waddrmgr.ManagerError:
		switch e.ErrorCode {
		case waddrmgr.ErrWrongPassphrase:
			code = abejson.ErrRPCWalletPassphraseIncorrect
		}
	}
	return &abejson.RPCError{
		Code:    code,
		Message: err.Error(),
	}
}

// makeMultiSigScript is a helper function to combine common logic for
// AddMultiSig and CreateMultiSig.
func makeMultiSigScript(w *wallet.Wallet, keys []string, nRequired int) ([]byte, error) {
	keysesPrecious := make([]*abeutil.AddressPubKey, len(keys))

	// The address list will made up either of addreseses (pubkey hash), for
	// which we need to look up the keys in wallet, straight pubkeys, or a
	// mixture of the two.
	for i, a := range keys {
		// try to parse as pubkey address
		a, err := decodeAddress(a, w.ChainParams())
		if err != nil {
			return nil, err
		}

		switch addr := a.(type) {
		case *abeutil.AddressPubKey:
			keysesPrecious[i] = addr
		default:
			pubKey, err := w.PubKeyForAddress(addr)
			if err != nil {
				return nil, err
			}
			pubKeyAddr, err := abeutil.NewAddressPubKey(
				pubKey.SerializeCompressed(), w.ChainParams())
			if err != nil {
				return nil, err
			}
			keysesPrecious[i] = pubKeyAddr
		}
	}

	return txscript.MultiSigScript(keysesPrecious, nRequired)
}

// addMultiSigAddress handles an addmultisigaddress request by adding a
// multisig address to the given wallet.
func addMultiSigAddress(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.AddMultisigAddressCmd)

	// If an account is specified, ensure that is the imported account.
	if cmd.Account != nil && *cmd.Account != waddrmgr.ImportedAddrAccountName {
		return nil, &ErrNotImportedAccount
	}

	secp256k1Addrs := make([]abeutil.Address, len(cmd.Keys))
	for i, k := range cmd.Keys {
		addr, err := decodeAddress(k, w.ChainParams())
		if err != nil {
			return nil, ParseError{err}
		}
		secp256k1Addrs[i] = addr
	}

	script, err := w.MakeMultiSigScript(secp256k1Addrs, cmd.NRequired)
	if err != nil {
		return nil, err
	}

	p2shAddr, err := w.ImportP2SHRedeemScript(script)
	if err != nil {
		return nil, err
	}

	return p2shAddr.EncodeAddress(), nil
}
func addPayee(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.AddPayeeCmd)
	// check whether the parameter have right format
	if cmd.Name == "" {
		return nil, errors.New("the name is empty")
	}
	err := w.AddPayee(cmd.Name, cmd.MasterPubKey)
	if err != nil {
		return err.Error(), err
	}
	return fmt.Sprintf("successful!"), nil
}

// createMultiSig handles an createmultisig request by returning a
// multisig address for the given inputs.
func createMultiSig(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.CreateMultisigCmd)

	script, err := makeMultiSigScript(w, cmd.Keys, cmd.NRequired)
	if err != nil {
		return nil, ParseError{err}
	}

	address, err := abeutil.NewAddressScriptHash(script, w.ChainParams())
	if err != nil {
		// above is a valid script, shouldn't happen.
		return nil, err
	}

	return abejson.CreateMultiSigResult{
		Address:      address.EncodeAddress(),
		RedeemScript: hex.EncodeToString(script),
	}, nil
}

// dumpPrivKey handles a dumpprivkey request with the private key
// for a single address, or an appropiate error if the wallet
// is locked.
func dumpPrivKey(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.DumpPrivKeyCmd)

	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		return nil, err
	}

	key, err := w.DumpWIFPrivateKey(addr)
	if waddrmgr.IsError(err, waddrmgr.ErrLocked) {
		// Address was found, but the private key isn't
		// accessible.
		return nil, &ErrWalletUnlockNeeded
	}
	return key, err
}

// dumpWallet handles a dumpwallet request by returning  all private
// keys in a wallet, or an appropiate error if the wallet is locked.
// TODO: finish this to match bitcoind by writing the dump to a file.
func dumpWallet(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	keys, err := w.DumpPrivKeys()
	if waddrmgr.IsError(err, waddrmgr.ErrLocked) {
		return nil, &ErrWalletUnlockNeeded
	}

	return keys, err
}

// getAddressesByAccount handles a getaddressesbyaccount request by returning
// all addresses for an account, or an error if the requested account does
// not exist.
func getAddressesByAccount(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.GetAddressesByAccountCmd)

	account, err := w.AccountNumber(waddrmgr.KeyScopeBIP0044, cmd.Account)
	if err != nil {
		return nil, err
	}

	addrs, err := w.AccountAddresses(account)
	if err != nil {
		return nil, err
	}

	addrStrs := make([]string, len(addrs))
	for i, a := range addrs {
		addrStrs[i] = a.EncodeAddress()
	}
	return addrStrs, nil
}

// getBalance handles a getbalance request by returning the balance for an
// account (wallet), or an error if the requested account does not
// exist.
func getBalance(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.GetBalancesAbeCmd)

	currentTime := time.Now().String()
	bs := w.ManagerAbe.SyncedTo()
	var balances []abeutil.Amount
	//var needUpdateNum int
	var err error
	balances, err = w.CalculateBalanceAbe(int32(*cmd.Minconf))
	if err != nil {
		return nil, err
	}
	type tt struct {
		CurrentTime      string  `json:"current_time,omitempty"`
		CurrentHeight    int32   `json:"current_height,omitempty"`
		CurrentBlockHash string  `json:"current_block_hash,omitempty"`
		TotalBalance     float64 `json:"total_balance,omitempty"`
		SpendableBalance float64 `json:"spendable_balance,omitempty"`
		FreezeBalance    float64 `json:"freeze_balance,omitempty"`
		LockedBalance    float64 `json:"locked_balance,omitempty"`
	}
	res := &tt{
		CurrentTime:      currentTime,
		CurrentHeight:    bs.Height,
		CurrentBlockHash: bs.Hash.String(),
		TotalBalance:     balances[0].ToABE(),
		SpendableBalance: balances[1].ToABE(),
		FreezeBalance:    balances[2].ToABE(),
		LockedBalance:    balances[3].ToABE(),
	}
	marshal, err := json.Marshal(res)
	if err != nil {
		return nil, err
	}
	return string(marshal), nil
}

// getDetailedUtxos is a temporary command for convenience of test.
// will be deleted or modified in the future
func getDetailedUtxos(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.GetDetailedUtxosCmd)
	res, err := w.FetchDetailedUtxos(int32(*cmd.Minconf))
	if err != nil {
		return nil, err
	}
	return res, nil
}

// getBestBlock handles a getbestblock request by returning a JSON object
// with the height and hash of the most recently processed block.
// TODO(abe): this function can be reused for abelian
func getBestBlock(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	//blk := w.Manager.SyncedTo()
	blk := w.ManagerAbe.SyncedTo()
	result := &abejson.GetBestBlockResult{
		Hash:   blk.Hash.String(),
		Height: blk.Height,
	}
	return result, nil
}

// getBestBlockHash handles a getbestblockhash request by returning the hash
// of the most recently processed block.
// TODO(abe): this function can be reused for abelian
func getBestBlockHash(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	//blk := w.Manager.SyncedTo()
	blk := w.ManagerAbe.SyncedTo()
	return blk.Hash.String(), nil
}

// getBlockCount handles a getblockcount request by returning the chain height
// of the most recently processed block.
// TODO(abe): this function can be reused for abelian
func getBlockCount(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	//blk := w.Manager.SyncedTo()
	blk := w.ManagerAbe.SyncedTo()
	return blk.Height, nil
}

// getInfo handles a getinfo request by returning the a structure containing
// information about the current state of btcwallet.
// exist.
// TODO(abe): this function needs to be redesigned for abelian
func getInfo(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	// Call down to btcd for all of the information in this command known
	// by them.
	info, err := chainClient.GetInfo()
	if err != nil {
		return nil, err
	}
	// TODO(abe):need add the update number into result struct
	//bal, err := w.CalculateBalance(1)  // switch to calculateBalanceAbe
	bal, err := w.CalculateBalanceAbe(1)
	if err != nil {
		return nil, err
	}

	// TODO(davec): This should probably have a database version as opposed
	// to using the manager version.
	info.WalletVersion = int32(waddrmgr.LatestMgrVersion)
	info.Balance = bal[1].ToABE()
	info.PaytxFee = float64(txrules.DefaultRelayFeePerKb)
	// We don't set the following since they don't make much sense in the
	// wallet architecture:
	//  - unlocked_until
	//  - errors

	return info, nil
}

func decodeAddress(s string, params *chaincfg.Params) (abeutil.Address, error) {
	addr, err := abeutil.DecodeAddress(s, params)
	if err != nil {
		msg := fmt.Sprintf("Invalid address %q: decode failed with %#q", s, err)
		return nil, &abejson.RPCError{
			Code:    abejson.ErrRPCInvalidAddressOrKey,
			Message: msg,
		}
	}
	if !addr.IsForNet(params) {
		msg := fmt.Sprintf("Invalid address %q: not intended for use on %s",
			addr, params.Name)
		return nil, &abejson.RPCError{
			Code:    abejson.ErrRPCInvalidAddressOrKey,
			Message: msg,
		}
	}
	return addr, nil
}

// getAccount handles a getaccount request by returning the account name
// associated with a single address.
// TODO(abe): In ABE, we do not support the "account"
func getAccount(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.GetAccountCmd)

	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		return nil, err
	}

	// Fetch the associated account
	account, err := w.AccountOfAddress(addr)
	if err != nil {
		return nil, &ErrAddressNotInWallet
	}

	acctName, err := w.AccountName(waddrmgr.KeyScopeBIP0044, account)
	if err != nil {
		return nil, &ErrAccountNameNotFound
	}
	return acctName, nil
}

// getAccountAddress handles a getaccountaddress by returning the most
// recently-created chained address that has not yet been used (does not yet
// appear in the blockchain, or any tx that has arrived in the btcd mempool).
// If the most recently-requested address has been used, a new address (the
// next chained address in the keypool) is used.  This can fail if the keypool
// runs out (and will return abejson.ErrRPCWalletKeypoolRanOut if that happens).
// TODO(abe): In ABE, we do not support the "account"
// TODO(abe): we need to show the payees
func getAccountAddress(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.GetAccountAddressCmd)

	account, err := w.AccountNumber(waddrmgr.KeyScopeBIP0044, cmd.Account)
	if err != nil {
		return nil, err
	}
	addr, err := w.CurrentAddress(account, waddrmgr.KeyScopeBIP0044)
	if err != nil {
		return nil, err
	}

	return addr.EncodeAddress(), err
}

// getUnconfirmedBalance handles a getunconfirmedbalance extension request
// by returning the current unconfirmed balance of an account.
func getUnconfirmedBalance(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.GetUnconfirmedBalanceCmd)

	acctName := "default"
	if cmd.Account != nil {
		acctName = *cmd.Account
	}
	account, err := w.AccountNumber(waddrmgr.KeyScopeBIP0044, acctName)
	if err != nil {
		return nil, err
	}
	bals, err := w.CalculateAccountBalances(account, 1)
	if err != nil {
		return nil, err
	}

	return (bals.Total - bals.Spendable).ToABE(), nil
}

// importPrivKey handles an importprivkey request by parsing
// a WIF-encoded private key and adding it to an account.
func importPrivKey(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.ImportPrivKeyCmd)

	// Ensure that private keys are only imported to the correct account.
	//
	// Yes, Label is the account name.
	if cmd.Label != nil && *cmd.Label != waddrmgr.ImportedAddrAccountName {
		return nil, &ErrNotImportedAccount
	}

	wif, err := abeutil.DecodeWIF(cmd.PrivKey)
	if err != nil {
		return nil, &abejson.RPCError{
			Code:    abejson.ErrRPCInvalidAddressOrKey,
			Message: "WIF decode failed: " + err.Error(),
		}
	}
	if !wif.IsForNet(w.ChainParams()) {
		return nil, &abejson.RPCError{
			Code:    abejson.ErrRPCInvalidAddressOrKey,
			Message: "Key is not intended for " + w.ChainParams().Name,
		}
	}

	// Import the private key, handling any errors.
	_, err = w.ImportPrivateKey(waddrmgr.KeyScopeBIP0044, wif, nil, *cmd.Rescan)
	switch {
	case waddrmgr.IsError(err, waddrmgr.ErrDuplicateAddress):
		// Do not return duplicate key errors to the client.
		return nil, nil
	case waddrmgr.IsError(err, waddrmgr.ErrLocked):
		return nil, &ErrWalletUnlockNeeded
	}

	return nil, err
}

// keypoolRefill handles the keypoolrefill command. Since we handle the keypool
// automatically this does nothing since refilling is never manually required.
func keypoolRefill(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	return nil, nil
}

// createNewAccount handles a createnewaccount request by creating and
// returning a new account. If the last account has no transaction history
// as per BIP 0044 a new account cannot be created so an error will be returned.
func createNewAccount(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.CreateNewAccountCmd)

	// The wildcard * is reserved by the rpc server with the special meaning
	// of "all accounts", so disallow naming accounts to this string.
	if cmd.Account == "*" {
		return nil, &ErrReservedAccountName
	}

	_, err := w.NextAccount(waddrmgr.KeyScopeBIP0044, cmd.Account)
	if waddrmgr.IsError(err, waddrmgr.ErrLocked) {
		return nil, &abejson.RPCError{
			Code: abejson.ErrRPCWalletUnlockNeeded,
			Message: "Creating an account requires the wallet to be unlocked. " +
				"Enter the wallet passphrase with walletpassphrase to unlock",
		}
	}
	return nil, err
}

// renameAccount handles a renameaccount request by renaming an account.
// If the account does not exist an appropiate error will be returned.
func renameAccount(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.RenameAccountCmd)

	// The wildcard * is reserved by the rpc server with the special meaning
	// of "all accounts", so disallow naming accounts to this string.
	if cmd.NewAccount == "*" {
		return nil, &ErrReservedAccountName
	}

	// Check that given account exists
	account, err := w.AccountNumber(waddrmgr.KeyScopeBIP0044, cmd.OldAccount)
	if err != nil {
		return nil, err
	}
	return nil, w.RenameAccount(waddrmgr.KeyScopeBIP0044, account, cmd.NewAccount)
}

// getNewAddress handles a getnewaddress request by returning a new
// address for an account.  If the account does not exist an appropiate
// error is returned.
// TODO: Follow BIP 0044 and warn if number of unused addresses exceeds
// the gap limit.
func getNewAddress(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.GetNewAddressCmd)

	acctName := "default"
	if cmd.Account != nil {
		acctName = *cmd.Account
	}
	account, err := w.AccountNumber(waddrmgr.KeyScopeBIP0044, acctName)
	if err != nil {
		return nil, err
	}
	addr, err := w.NewAddress(account, waddrmgr.KeyScopeBIP0044)
	if err != nil {
		return nil, err
	}

	// Return the new payment address string.
	return addr.EncodeAddress(), nil
}

// getRawChangeAddress handles a getrawchangeaddress request by creating
// and returning a new change address for an account.
//
// Note: bitcoind allows specifying the account as an optional parameter,
// but ignores the parameter.
func getRawChangeAddress(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.GetRawChangeAddressCmd)

	acctName := "default"
	if cmd.Account != nil {
		acctName = *cmd.Account
	}
	account, err := w.AccountNumber(waddrmgr.KeyScopeBIP0044, acctName)
	if err != nil {
		return nil, err
	}
	addr, err := w.NewChangeAddress(account, waddrmgr.KeyScopeBIP0044)
	if err != nil {
		return nil, err
	}

	// Return the new payment address string.
	return addr.EncodeAddress(), nil
}

// getReceivedByAccount handles a getreceivedbyaccount request by returning
// the total amount received by addresses of an account.
func getReceivedByAccount(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.GetReceivedByAccountCmd)

	account, err := w.AccountNumber(waddrmgr.KeyScopeBIP0044, cmd.Account)
	if err != nil {
		return nil, err
	}

	// TODO: This is more inefficient that it could be, but the entire
	// algorithm is already dominated by reading every transaction in the
	// wallet's history.
	results, err := w.TotalReceivedForAccounts(
		waddrmgr.KeyScopeBIP0044, int32(*cmd.MinConf),
	)
	if err != nil {
		return nil, err
	}
	acctIndex := int(account)
	if account == waddrmgr.ImportedAddrAccount {
		acctIndex = len(results) - 1
	}
	return results[acctIndex].TotalReceived.ToABE(), nil
}

// getReceivedByAddress handles a getreceivedbyaddress request by returning
// the total amount received by a single address.
func getReceivedByAddress(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.GetReceivedByAddressCmd)

	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		return nil, err
	}
	total, err := w.TotalReceivedForAddr(addr, int32(*cmd.MinConf))
	if err != nil {
		return nil, err
	}

	return total.ToABE(), nil
}

// getTransaction handles a gettransaction request by returning details about
// a single transaction saved by wallet.
func getTransaction(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.GetTransactionCmd)

	txHash, err := chainhash.NewHashFromStr(cmd.Txid)
	if err != nil {
		return nil, &abejson.RPCError{
			Code:    abejson.ErrRPCDecodeHexString,
			Message: "Transaction hash string decode failed: " + err.Error(),
		}
	}

	details, err := wallet.UnstableAPI(w).TxDetails(txHash)
	if err != nil {
		return nil, err
	}
	if details == nil {
		return nil, &ErrNoTransactionInfo
	}

	syncBlock := w.Manager.SyncedTo()

	// TODO: The serialized transaction is already in the DB, so
	// reserializing can be avoided here.
	var txBuf bytes.Buffer
	txBuf.Grow(details.MsgTx.SerializeSize())
	err = details.MsgTx.Serialize(&txBuf)
	if err != nil {
		return nil, err
	}

	// TODO: Add a "generated" field to this result type.  "generated":true
	// is only added if the transaction is a coinbase.
	ret := abejson.GetTransactionResult{
		TxID:            cmd.Txid,
		Hex:             hex.EncodeToString(txBuf.Bytes()),
		Time:            details.Received.Unix(),
		TimeReceived:    details.Received.Unix(),
		WalletConflicts: []string{}, // Not saved
		//Generated:     blockchain.IsCoinBaseTx(&details.MsgTx),
	}

	if details.Block.Height != -1 {
		ret.BlockHash = details.Block.Hash.String()
		ret.BlockTime = details.Block.Time.Unix()
		ret.Confirmations = int64(confirms(details.Block.Height, syncBlock.Height))
	}

	var (
		debitTotal  abeutil.Amount
		creditTotal abeutil.Amount // Excludes change
		fee         abeutil.Amount
		feeF64      float64
	)
	for _, deb := range details.Debits {
		debitTotal += deb.Amount
	}
	for _, cred := range details.Credits {
		if !cred.Change {
			creditTotal += cred.Amount
		}
	}
	// Fee can only be determined if every input is a debit.
	if len(details.Debits) == len(details.MsgTx.TxIn) {
		var outputTotal abeutil.Amount
		for _, output := range details.MsgTx.TxOut {
			outputTotal += abeutil.Amount(output.Value)
		}
		fee = debitTotal - outputTotal
		//feeF64 = fee.ToBTC()
		feeF64 = fee.ToABE()
	}

	if len(details.Debits) == 0 {
		// Credits must be set later, but since we know the full length
		// of the details slice, allocate it with the correct cap.
		ret.Details = make([]abejson.GetTransactionDetailsResult, 0, len(details.Credits))
	} else {
		ret.Details = make([]abejson.GetTransactionDetailsResult, 1, len(details.Credits)+1)

		ret.Details[0] = abejson.GetTransactionDetailsResult{
			// Fields left zeroed:
			//   InvolvesWatchOnly
			//   Account
			//   Address
			//   Vout
			//
			// TODO(jrick): Address and Vout should always be set,
			// but we're doing the wrong thing here by not matching
			// core.  Instead, gettransaction should only be adding
			// details for transaction outputs, just like
			// listtransactions (but using the short result format).
			Category: "send",
			Amount:   (-debitTotal).ToABE(), // negative since it is a send
			Fee:      &feeF64,
		}
		ret.Fee = feeF64
	}

	credCat := wallet.RecvCategory(details, syncBlock.Height, w.ChainParams()).String()
	for _, cred := range details.Credits {
		// Change is ignored.
		if cred.Change {
			continue
		}

		var address string
		var accountName string
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(
			details.MsgTx.TxOut[cred.Index].PkScript, w.ChainParams())
		if err == nil && len(addrs) == 1 {
			addr := addrs[0]
			address = addr.EncodeAddress()
			account, err := w.AccountOfAddress(addr)
			if err == nil {
				name, err := w.AccountName(waddrmgr.KeyScopeBIP0044, account)
				if err == nil {
					accountName = name
				}
			}
		}

		ret.Details = append(ret.Details, abejson.GetTransactionDetailsResult{
			// Fields left zeroed:
			//   InvolvesWatchOnly
			//   Fee
			Account:  accountName,
			Address:  address,
			Category: credCat,
			Amount:   cred.Amount.ToABE(),
			Vout:     cred.Index,
		})
	}

	ret.Amount = creditTotal.ToABE()
	return ret, nil
}

// These generators create the following global variables in this package:
//
//   var localeHelpDescs map[string]func() map[string]string
//   var requestUsages string
//
// localeHelpDescs maps from locale strings (e.g. "en_US") to a function that
// builds a map of help texts for each RPC server method.  This prevents help
// text maps for every locale map from being rooted and created during init.
// Instead, the appropiate function is looked up when help text is first needed
// using the current locale and saved to the global below for futher reuse.
//
// requestUsages contains single line usages for every supported request,
// separated by newlines.  It is set during init.  These usages are used for all
// locales.
//
//go:generate go run ../../internal/rpchelp/genrpcserverhelp.go legacyrpc
//go:generate gofmt -w rpcserverhelp.go

var helpDescs map[string]string
var helpDescsMu sync.Mutex // Help may execute concurrently, so synchronize access.

// helpWithChainRPC handles the help request when the RPC server has been
// associated with a consensus RPC client.  The additional RPC client is used to
// include help messages for methods implemented by the consensus server via RPC
// passthrough.
func helpWithChainRPC(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	return help(icmd, w, chainClient)
}

// helpNoChainRPC handles the help request when the RPC server has not been
// associated with a consensus RPC client.  No help messages are included for
// passthrough requests.
func helpNoChainRPC(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	return help(icmd, w, nil)
}

// help handles the help request by returning one line usage of all available
// methods, or full help for a specific method.  The chainClient is optional,
// and this is simply a helper function for the HelpNoChainRPC and
// HelpWithChainRPC handlers.
func help(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	cmd := icmd.(*abejson.HelpCmd)

	// btcd returns different help messages depending on the kind of
	// connection the client is using.  Only methods availble to HTTP POST
	// clients are available to be used by wallet clients, even though
	// wallet itself is a websocket client to btcd.  Therefore, create a
	// POST client as needed.
	//
	// Returns nil if chainClient is currently nil or there is an error
	// creating the client.
	//
	// This is hacky and is probably better handled by exposing help usage
	// texts in a non-internal btcd package.
	postClient := func() *rpcclient.Client {
		if chainClient == nil {
			return nil
		}
		c, err := chainClient.POSTClient()
		if err != nil {
			return nil
		}
		return c
	}
	if cmd.Command == nil || *cmd.Command == "" {
		// Prepend chain server usage if it is available.
		usages := requestUsages
		client := postClient()
		if client != nil {
			rawChainUsage, err := client.RawRequest("help", nil)
			var chainUsage string
			if err == nil {
				_ = json.Unmarshal([]byte(rawChainUsage), &chainUsage)
			}
			if chainUsage != "" {
				usages = "Chain server usage:\n\n" + chainUsage + "\n\n" +
					"Wallet server usage (overrides chain requests):\n\n" +
					requestUsages
			}
		}
		return usages, nil
	}

	defer helpDescsMu.Unlock()
	helpDescsMu.Lock()

	if helpDescs == nil {
		// TODO: Allow other locales to be set via config or detemine
		// this from environment variables.  For now, hardcode US
		// English.
		helpDescs = localeHelpDescs["en_US"]()
	}

	helpText, ok := helpDescs[*cmd.Command]
	if ok {
		return helpText, nil
	}

	// Return the chain server's detailed help if possible.
	var chainHelp string
	client := postClient()
	if client != nil {
		param := make([]byte, len(*cmd.Command)+2)
		param[0] = '"'
		copy(param[1:], *cmd.Command)
		param[len(param)-1] = '"'
		rawChainHelp, err := client.RawRequest("help", []json.RawMessage{param})
		if err == nil {
			_ = json.Unmarshal([]byte(rawChainHelp), &chainHelp)
		}
	}
	if chainHelp != "" {
		return chainHelp, nil
	}
	return nil, &abejson.RPCError{
		Code:    abejson.ErrRPCInvalidParameter,
		Message: fmt.Sprintf("No help for method '%s'", *cmd.Command),
	}
}

// listAccounts handles a listaccounts request by returning a map of account
// names to their balances.
func listAccounts(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.ListAccountsCmd)

	accountBalances := map[string]float64{}
	results, err := w.AccountBalances(waddrmgr.KeyScopeBIP0044, int32(*cmd.MinConf))
	if err != nil {
		return nil, err
	}
	for _, result := range results {
		//accountBalances[result.AccountName] = result.AccountBalance.ToBTC()
		accountBalances[result.AccountName] = result.AccountBalance.ToABE()
	}
	// Return the map.  This will be marshaled into a JSON object.
	return accountBalances, nil
}

// listLockUnspent handles a listlockunspent request by returning an slice of
// all locked outpoints.
func listLockUnspent(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	return w.LockedOutpoints(), nil
}

// listReceivedByAccount handles a listreceivedbyaccount request by returning
// a slice of objects, each one containing:
//  "account": the receiving account;
//  "amount": total amount received by the account;
//  "confirmations": number of confirmations of the most recent transaction.
// It takes two parameters:
//  "minconf": minimum number of confirmations to consider a transaction -
//             default: one;
//  "includeempty": whether or not to include addresses that have no transactions -
//                  default: false.
func listReceivedByAccount(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.ListReceivedByAccountCmd)

	results, err := w.TotalReceivedForAccounts(
		waddrmgr.KeyScopeBIP0044, int32(*cmd.MinConf),
	)
	if err != nil {
		return nil, err
	}

	jsonResults := make([]abejson.ListReceivedByAccountResult, 0, len(results))
	for _, result := range results {
		jsonResults = append(jsonResults, abejson.ListReceivedByAccountResult{
			Account:       result.AccountName,
			Amount:        result.TotalReceived.ToABE(),
			Confirmations: uint64(result.LastConfirmation),
		})
	}
	return jsonResults, nil
}

// listReceivedByAddress handles a listreceivedbyaddress request by returning
// a slice of objects, each one containing:
//  "account": the account of the receiving address;
//  "address": the receiving address;
//  "amount": total amount received by the address;
//  "confirmations": number of confirmations of the most recent transaction.
// It takes two parameters:
//  "minconf": minimum number of confirmations to consider a transaction -
//             default: one;
//  "includeempty": whether or not to include addresses that have no transactions -
//                  default: false.
func listReceivedByAddress(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.ListReceivedByAddressCmd)

	// Intermediate data for each address.
	type AddrData struct {
		// Total amount received.
		amount abeutil.Amount
		// Number of confirmations of the last transaction.
		confirmations int32
		// Hashes of transactions which include an output paying to the address
		tx []string
		// Account which the address belongs to
		account string
	}

	syncBlock := w.Manager.SyncedTo()

	// Intermediate data for all addresses.
	allAddrData := make(map[string]AddrData)
	// Create an AddrData entry for each active address in the account.
	// Otherwise we'll just get addresses from transactions later.
	sortedAddrs, err := w.SortedActivePaymentAddresses()
	if err != nil {
		return nil, err
	}
	for _, address := range sortedAddrs {
		// There might be duplicates, just overwrite them.
		allAddrData[address] = AddrData{}
	}

	minConf := *cmd.MinConf
	var endHeight int32
	if minConf == 0 {
		endHeight = -1
	} else {
		endHeight = syncBlock.Height - int32(minConf) + 1
	}
	err = wallet.UnstableAPI(w).RangeTransactions(0, endHeight, func(details []wtxmgr.TxDetails) (bool, error) {
		confirmations := confirms(details[0].Block.Height, syncBlock.Height)
		for _, tx := range details {
			for _, cred := range tx.Credits {
				pkScript := tx.MsgTx.TxOut[cred.Index].PkScript
				_, addrs, _, err := txscript.ExtractPkScriptAddrs(
					pkScript, w.ChainParams())
				if err != nil {
					// Non standard script, skip.
					continue
				}
				for _, addr := range addrs {
					addrStr := addr.EncodeAddress()
					addrData, ok := allAddrData[addrStr]
					if ok {
						addrData.amount += cred.Amount
						// Always overwrite confirmations with newer ones.
						addrData.confirmations = confirmations
					} else {
						addrData = AddrData{
							amount:        cred.Amount,
							confirmations: confirmations,
						}
					}
					addrData.tx = append(addrData.tx, tx.Hash.String())
					allAddrData[addrStr] = addrData
				}
			}
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}

	// Massage address data into output format.
	numAddresses := len(allAddrData)
	ret := make([]abejson.ListReceivedByAddressResult, numAddresses, numAddresses)
	idx := 0
	for address, addrData := range allAddrData {
		ret[idx] = abejson.ListReceivedByAddressResult{
			Address:       address,
			Amount:        addrData.amount.ToABE(),
			Confirmations: uint64(addrData.confirmations),
			TxIDs:         addrData.tx,
		}
		idx++
	}
	return ret, nil
}

// listSinceBlock handles a listsinceblock request by returning an array of maps
// with details of sent and received wallet transactions since the given block.
func listSinceBlock(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	cmd := icmd.(*abejson.ListSinceBlockCmd)

	syncBlock := w.Manager.SyncedTo()
	targetConf := int64(*cmd.TargetConfirmations)

	// For the result we need the block hash for the last block counted
	// in the blockchain due to confirmations. We send this off now so that
	// it can arrive asynchronously while we figure out the rest.
	gbh := chainClient.GetBlockHashAsync(int64(syncBlock.Height) + 1 - targetConf)

	var start int32
	if cmd.BlockHash != nil {
		hash, err := chainhash.NewHashFromStr(*cmd.BlockHash)
		if err != nil {
			return nil, DeserializationError{err}
		}
		block, err := chainClient.GetBlockVerboseTx(hash)
		if err != nil {
			return nil, err
		}
		start = int32(block.Height) + 1
	}

	txInfoList, err := w.ListSinceBlock(start, -1, syncBlock.Height)
	if err != nil {
		return nil, err
	}

	// Done with work, get the response.
	blockHash, err := gbh.Receive()
	if err != nil {
		return nil, err
	}

	res := abejson.ListSinceBlockResult{
		Transactions: txInfoList,
		LastBlock:    blockHash.String(),
	}
	return res, nil
}

// listTransactions handles a listtransactions request by returning an
// array of maps with details of sent and recevied wallet transactions.
func listTransactions(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.ListTransactionsCmd)

	// TODO: ListTransactions does not currently understand the difference
	// between transactions pertaining to one account from another.  This
	// will be resolved when wtxmgr is combined with the waddrmgr namespace.

	if cmd.Account != nil && *cmd.Account != "*" {
		// For now, don't bother trying to continue if the user
		// specified an account, since this can't be (easily or
		// efficiently) calculated.
		return nil, &abejson.RPCError{
			Code:    abejson.ErrRPCWallet,
			Message: "Transactions are not yet grouped by account",
		}
	}

	return w.ListTransactions(*cmd.From, *cmd.Count)
}

// listAddressTransactions handles a listaddresstransactions request by
// returning an array of maps with details of spent and received wallet
// transactions.  The form of the reply is identical to listtransactions,
// but the array elements are limited to transaction details which are
// about the addresess included in the request.
func listAddressTransactions(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.ListAddressTransactionsCmd)

	if cmd.Account != nil && *cmd.Account != "*" {
		return nil, &abejson.RPCError{
			Code:    abejson.ErrRPCInvalidParameter,
			Message: "Listing transactions for addresses may only be done for all accounts",
		}
	}

	// Decode addresses.
	hash160Map := make(map[string]struct{})
	for _, addrStr := range cmd.Addresses {
		addr, err := decodeAddress(addrStr, w.ChainParams())
		if err != nil {
			return nil, err
		}
		hash160Map[string(addr.ScriptAddress())] = struct{}{}
	}

	return w.ListAddressTransactions(hash160Map)
}

// listAllTransactions handles a listalltransactions request by returning
// a map with details of sent and recevied wallet transactions.  This is
// similar to ListTransactions, except it takes only a single optional
// argument for the account name and replies with all transactions.
func listAllTransactions(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.ListAllTransactionsCmd)

	if cmd.Account != nil && *cmd.Account != "*" {
		return nil, &abejson.RPCError{
			Code:    abejson.ErrRPCInvalidParameter,
			Message: "Listing all transactions may only be done for all accounts",
		}
	}

	return w.ListAllTransactions()
}

// listUnspent handles the listunspent command.
func listUnspent(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.ListUnspentCmd)

	var addresses map[string]struct{}
	if cmd.Addresses != nil {
		addresses = make(map[string]struct{})
		// confirm that all of them are good:
		for _, as := range *cmd.Addresses {
			a, err := decodeAddress(as, w.ChainParams())
			if err != nil {
				return nil, err
			}
			addresses[a.EncodeAddress()] = struct{}{}
		}
	}

	return w.ListUnspent(int32(*cmd.MinConf), int32(*cmd.MaxConf), addresses)
}

// For test
type utxo struct {
	RingHash     string
	TxHash       string
	Index        uint8
	FromCoinbase bool
	Amount       uint64
	Height       int32
}
type utxoset []utxo

func (u *utxoset) Len() int {
	return len(*u)
}

func (u *utxoset) Less(i, j int) bool {
	return (*u)[i].Height < (*u)[j].Height
}

func (u *utxoset) Swap(i, j int) {
	(*u)[i], (*u)[j] = (*u)[j], (*u)[i]
}
func listAllUTXOAbe(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	_ = icmd.(*abejson.ListAllUnspentAbeCmd)
	utxos, err := w.FetchUnspentUTXOSet()
	if err != nil {
		return nil, err
	}
	unmatureds, err := w.FetchUnmatruedUTXOSet()
	if err != nil {
		return nil, err
	}
	res := make([]utxo, 0, len(utxos)+len(unmatureds))
	for i := 0; i < len(utxos); i++ {
		res = append(res, utxo{
			RingHash:     utxos[i].RingHash.String(),
			TxHash:       utxos[i].TxOutput.TxHash.String(),
			Index:        utxos[i].TxOutput.Index,
			FromCoinbase: utxos[i].FromCoinBase,
			Amount:       utxos[i].Amount,
			Height:       utxos[i].Height,
		})
	}
	for i := 0; i < len(unmatureds); i++ {
		res = append(res, utxo{
			RingHash:     unmatureds[i].RingHash.String(),
			TxHash:       unmatureds[i].TxOutput.TxHash.String(),
			Index:        unmatureds[i].TxOutput.Index,
			FromCoinbase: unmatureds[i].FromCoinBase,
			Amount:       unmatureds[i].Amount,
			Height:       unmatureds[i].Height,
		})
	}
	t := utxoset(res)
	sort.Sort(&t)
	return res, nil
}
func listUnmaturedUTXOAbe(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	_ = icmd.(*abejson.ListUnmaturedAbeCmd)
	unmatureds, err := w.FetchUnmatruedUTXOSet()
	if err != nil {
		return nil, err
	}
	res := make([]utxo, 0, len(unmatureds))
	for i := 0; i < len(unmatureds); i++ {
		res = append(res, utxo{
			RingHash:     unmatureds[i].RingHash.String(),
			TxHash:       unmatureds[i].TxOutput.TxHash.String(),
			Index:        unmatureds[i].TxOutput.Index,
			FromCoinbase: unmatureds[i].FromCoinBase,
			Amount:       unmatureds[i].Amount,
			Height:       unmatureds[i].Height,
		})
	}
	t := utxoset(res)
	sort.Sort(&t)
	return res, nil
}

func listUnspentAbe(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	_ = icmd.(*abejson.ListUnspentAbeCmd)
	utxos, err := w.FetchUnspentUTXOSet()
	if err != nil {
		return nil, err
	}
	res := make([]utxo, 0, len(utxos))
	for i := 0; i < len(utxos); i++ {
		res = append(res, utxo{
			RingHash:     utxos[i].RingHash.String(),
			TxHash:       utxos[i].TxOutput.TxHash.String(),
			Index:        utxos[i].TxOutput.Index,
			FromCoinbase: utxos[i].FromCoinBase,
			Amount:       utxos[i].Amount,
			Height:       utxos[i].Height,
		})
	}
	t := utxoset(res)
	sort.Sort(&t)
	return res, nil
}
func listSpentButUnminedAbe(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	_ = icmd.(*abejson.ListSpentButUnminedAbeCmd)
	sbutxos, err := w.FetchSpentButUnminedTXOSet()
	if err != nil {
		return nil, err
	}
	res := make([]utxo, 0, len(sbutxos))
	for i := 0; i < len(sbutxos); i++ {
		res = append(res, utxo{
			RingHash:     sbutxos[i].RingHash.String(),
			TxHash:       sbutxos[i].TxOutput.TxHash.String(),
			Index:        sbutxos[i].TxOutput.Index,
			FromCoinbase: sbutxos[i].FromCoinBase,
			Amount:       sbutxos[i].Amount,
			Height:       sbutxos[i].Height,
		})
	}
	t := utxoset(res)
	sort.Sort(&t)
	return res, nil
}
func listSpentAndMinedAbe(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	_ = icmd.(*abejson.ListSpentAndMinedAbeCmd)
	sctxos, err := w.FetchSpentAndConfirmedTXOSet()
	if err != nil {
		return nil, err
	}
	res := make([]utxo, 0, len(sctxos))
	for i := 0; i < len(sctxos); i++ {
		res = append(res, utxo{
			RingHash:     sctxos[i].RingHash.String(),
			TxHash:       sctxos[i].TxOutput.TxHash.String(),
			Index:        sctxos[i].TxOutput.Index,
			FromCoinbase: sctxos[i].FromCoinBase,
			Amount:       sctxos[i].Amount,
			Height:       sctxos[i].Height,
		})
	}
	t := utxoset(res)
	sort.Sort(&t)
	return res, nil
}

// lockUnspent handles the lockunspent command.
func lockUnspent(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.LockUnspentCmd)

	switch {
	case cmd.Unlock && len(cmd.Transactions) == 0:
		w.ResetLockedOutpoints()
	default:
		for _, input := range cmd.Transactions {
			txHash, err := chainhash.NewHashFromStr(input.Txid)
			if err != nil {
				return nil, ParseError{err}
			}
			op := wire.OutPoint{Hash: *txHash, Index: input.Vout}
			if cmd.Unlock {
				w.UnlockOutpoint(op)
			} else {
				w.LockOutpoint(op)
			}
		}
	}
	return true, nil
}

// makeOutputs creates a slice of transaction outputs from a pair of address
// strings to amounts.  This is used to create the outputs to include in newly
// created transactions from a JSON object describing the output destinations
// and amounts.
// TODO(abe): we must use payee to send some coin
func makeOutputs(pairs map[string]abeutil.Amount, chainParams *chaincfg.Params) ([]*wire.TxOut, error) {
	outputs := make([]*wire.TxOut, 0, len(pairs))
	for addrStr, amt := range pairs {
		addr, err := abeutil.DecodeAddress(addrStr, chainParams)
		if err != nil {
			return nil, fmt.Errorf("cannot decode address: %s", err)
		}

		pkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, fmt.Errorf("cannot create txout script: %s", err)
		}

		outputs = append(outputs, wire.NewTxOut(int64(amt), pkScript))
	}
	return outputs, nil
}

//TODO(abe):add the chainPramas into the decoding of address
func makeOutputsAbe(w *wallet.Wallet, pairs map[string]abeutil.Amount, chainParams *chaincfg.Params) ([]*wire.TxOutAbe, error) {
	outputs := make([]*wire.TxOutAbe, 0, len(pairs))
	//coinValues := []int64{500, 200, 100, 50, 20, 10, 5, 2, 1}
	for name, amt := range pairs {
		payeeManager, err := w.FetchPayeeManager(name)
		if payeeManager == nil {
			return nil, err
		}
		addr, err := payeeManager.ChooseMAddr()
		if err != nil {
			return nil, fmt.Errorf("cannot get an address from given payee: %s", err)
		}
		targetAmount := uint64(amt)
		abecrypto.NewAbeTxOutDesc(addr, targetAmount)
	}
	return outputs, nil
}

// checkValidAddress checks whether the given address meets the requirement,
// including netID and verification hash
func checkValidAddress(addr []byte, chainParams *chaincfg.Params) error {
	if len(addr) < 33 {
		return errors.New("the length of address is incorrect")
	}

	// Check netID
	netID := addr[0]
	if netID != chainParams.PQRingCTID {
		return errors.New("address verification fails: the netID of address does not match the active net")
	}

	// Check verification hash
	verifyBytes := addr[:len(addr)-32]
	dstHash0 := addr[len(addr)-32:]
	dstHash, _ := chainhash.NewHash(dstHash0)
	realHash := chainhash.DoubleHashH(verifyBytes)
	if !dstHash.IsEqual(&realHash) {
		return errors.New("address verification fails: verification hash does not match")
	}
	return nil
}

func makeOutputDescsForPairs(w *wallet.Wallet, pairs []abejson.Pair, chainParams *chaincfg.Params) ([]*abecrypto.AbeTxOutputDesc, error) {
	outputDescs := make([]*abecrypto.AbeTxOutputDesc, 0, len(pairs))
	for i := 0; i < len(pairs); i++ {
		addr, err := hex.DecodeString(pairs[i].Address)
		if err != nil {
			return nil, err
		}
		err = checkValidAddress(addr, chainParams)
		if err != nil {
			return nil, err
		}
		targetAmount := uint64(pairs[i].Amount)
		addr = addr[1 : len(addr)-32]
		outputDesc := abecrypto.NewAbeTxOutDesc(addr, targetAmount)

		outputDescs = append(outputDescs, outputDesc)
	}
	return outputDescs, nil
}

func makeOutputDescs(w *wallet.Wallet, pairs map[string]abeutil.Amount, chainParams *chaincfg.Params) ([]*abecrypto.AbeTxOutputDesc, error) {
	outputDescs := make([]*abecrypto.AbeTxOutputDesc, 0, len(pairs))
	for addrStr, amt := range pairs {
		//payeeManager, err := w.FetchPayeeManager(name)
		//if payeeManager == nil {
		//	return nil, err
		//}
		//addr, err := payeeManager.ChooseMAddr()
		//if err != nil {
		//	return nil, fmt.Errorf("cannot get an address from given payee: %s", err)
		//}
		addr, err := hex.DecodeString(addrStr)
		if err != nil {
			return nil, err
		}
		targetAmount := uint64(amt)
		// TODO: check the net ID and the check hash
		// discard the heading net ID and tailing hash in address
		addr = addr[1 : len(addr)-32]
		outputDesc := abecrypto.NewAbeTxOutDesc(addr, targetAmount)

		outputDescs = append(outputDescs, outputDesc)
	}
	return outputDescs, nil
}

// sendPairs creates and sends payment transactions.
// It returns the transaction hash in string format upon success
// All errors are returned in abejson.RPCError format

func isNilOrEmpty(s *string) bool {
	return s == nil || *s == ""
}

func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for _, ch := range s {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return false
		}
	}
	return true
}

//	todo: to confirm : modified by AliceBob on 15 June
/*func sendPairsAbe(w *wallet.Wallet, amounts map[string]abeutil.Amount,
	minconf int32, feeSatPerKb abeutil.Amount) (string, error) {

	//outputs, err := makeOutputsAbe(w, amounts, w.ChainParams())
	outputDescs, err := makeOutputDescs(w, amounts, w.ChainParams())
	if err != nil {
		return "", err
	}
	tx, err := w.SendOutputsAbe(outputDescs, minconf, feeSatPerKb, "") // TODO(abe): what's label?
	if err != nil {
		if err == txrules.ErrAmountNegative {
			return "", ErrNeedPositiveAmount
		}
		if waddrmgr.IsError(err, waddrmgr.ErrLocked) {
			return "", &ErrWalletUnlockNeeded
		}
		switch err.(type) {
		case abejson.RPCError:
			return "", err
		}

		return "", &abejson.RPCError{
			Code:    abejson.ErrRPCInternal.Code,
			Message: err.Error(),
		}
	}

	txHashStr := tx.TxHash().String()
	log.Infof("Successfully sent transaction %v", txHashStr)
	return txHashStr, nil
}*/

func sendAddressAbe(w *wallet.Wallet, amounts []abejson.Pair,
	minconf int32, feePerKbSpecified abeutil.Amount, feeSpecified abeutil.Amount, utxoSpecified []string) (string, error) {

	outputDescs, err := makeOutputDescsForPairs(w, amounts, w.ChainParams())
	if err != nil {
		return "", err
	}
	tx, err := w.SendOutputsAbe(outputDescs, minconf, feePerKbSpecified, feeSpecified, utxoSpecified, "") // TODO(abe): what's label?
	if err != nil {
		if err == txrules.ErrAmountNegative {
			return "", ErrNeedPositiveAmount
		}
		if waddrmgr.IsError(err, waddrmgr.ErrLocked) {
			return "", &ErrWalletUnlockNeeded
		}
		switch err.(type) {
		case abejson.RPCError:
			return "", err
		}

		return "", &abejson.RPCError{
			Code:    abejson.ErrRPCInternal.Code,
			Message: err.Error(),
		}
	}

	txHashStr := tx.TxHash().String()
	log.Infof("Successfully sent transaction %v", txHashStr)
	return txHashStr, nil
}

func sendPairsAbe(w *wallet.Wallet, amounts map[string]abeutil.Amount,
	minconf int32, feePerKbSpecified abeutil.Amount, feeSpecified abeutil.Amount, utxoSpecified []string) (string, error) {

	//outputs, err := makeOutputsAbe(w, amounts, w.ChainParams())
	outputDescs, err := makeOutputDescs(w, amounts, w.ChainParams())
	if err != nil {
		return "", err
	}
	tx, err := w.SendOutputsAbe(outputDescs, minconf, feePerKbSpecified, feeSpecified, utxoSpecified, "") // TODO(abe): what's label?
	if err != nil {
		if err == txrules.ErrAmountNegative {
			return "", ErrNeedPositiveAmount
		}
		if waddrmgr.IsError(err, waddrmgr.ErrLocked) {
			return "", &ErrWalletUnlockNeeded
		}
		switch err.(type) {
		case abejson.RPCError:
			return "", err
		}

		return "", &abejson.RPCError{
			Code:    abejson.ErrRPCInternal.Code,
			Message: err.Error(),
		}
	}

	txHashStr := tx.TxHash().String()
	log.Infof("Successfully sent transaction %v", txHashStr)
	return txHashStr, nil
}

func sendToPayees(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.SendToPayeesCmd)

	// Transaction comments are not yet supported.  Error instead of
	// pretending to save them.
	if !isNilOrEmpty(cmd.Comment) {
		return nil, &abejson.RPCError{
			Code:    abejson.ErrRPCUnimplemented,
			Message: "Transaction comments are not yet supported",
		}
	}

	// Check that minconf is positive.
	minConf := int32(*cmd.MinConf)
	if minConf < 0 {
		return nil, ErrNeedPositiveMinconf
	}

	// Recreate address/amount pairs, using abeutil.Amount.
	pairs := make(map[string]abeutil.Amount, len(cmd.Amounts))
	for k, v := range cmd.Amounts {
		amt, err := abeutil.NewAmountAbe(v)
		if err != nil {
			return nil, err
		}
		pairs[k] = amt
	}

	//	todo: the fee policy
	feeSatPerKb := txrules.DefaultRelayFeePerKb // todo: AliceBobScorpio, should use the feeSatPerKb received from abec
	scaleToFeeSatPerKb := *cmd.ScaleToFeeSatPerKb
	feeSpecified, err := abeutil.NewAmountAbe(*cmd.FeeSpecified)
	if err != nil {
		return nil, err
	}

	if scaleToFeeSatPerKb != 1 {
		// set the scaleToFeeSatPerKb
		feeSatPerKb = feeSatPerKb.MulF64(scaleToFeeSatPerKb)
		feeSpecified = abeutil.Amount(0)
	} else if feeSpecified != 0 && scaleToFeeSatPerKb == 1 {
		//	if neither scaleToFeeSatPerKb or feeSpecified is specified, the use scaleToFeeSatPerKb = 1
		//	feeSatPerKb = feeSatPerKb
		//	feeSpecified = 0
		//	i.e. nothing to do
	}

	var utxoSpecified []string = nil
	if cmd.UTXOSpecified != nil {
		utxoSpecified = strings.Split(*cmd.UTXOSpecified, ",")
		utxoNum := len(utxoSpecified)
		for i := 0; i < utxoNum; i++ {
			utxoSpecified[i] = strings.TrimSpace(utxoSpecified[i])
			if !isHexString(utxoSpecified[i]) {
				return nil, ErrSpeicifiedUTXOWrong
			}
		}
	}

	// return sendPairsAbe(w, pairs, minConf, txrules.DefaultRelayFeePerKb)
	//	todo: AliceBobScorpio, should use the feeSatPerKb received from abec
	return sendPairsAbe(w, pairs, minConf, feeSatPerKb, feeSpecified, utxoSpecified)
}

// sendFrom handles a sendfrom RPC request by creating a new transaction
// spending unspent transaction outputs for a wallet to another payment
// address.  Leftover inputs not sent to the payment address or a fee for
// the miner are sent back to a new address in the wallet.  Upon success,
// the TxID for the created transaction is returned.

// sendMany handles a sendmany RPC request by creating a new transaction
// spending unspent transaction outputs for a wallet to any number of
// payment addresses.  Leftover inputs not sent to the payment address
// or a fee for the miner are sent back to a new address in the wallet.
// Upon success, the TxID for the created transaction is returned.

func generateAddressAbe(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	_ = icmd.(*abejson.GenerateAddressCmd)

	var err error
	var numberOrder uint64
	var address []byte
	numberOrder, address, err = w.NewAddressKeyAbe()
	if err != nil {
		return nil, err
	}
	b := make([]byte, len(address)+1)
	// TODO: How to know the active net?
	b[0] = chaincfg.MainNetParams.PQRingCTID
	copy(b[1:], address)
	// generate the hash of (abecrypto.CryptoSchemePQRINGCT || serialized address)
	hash := chainhash.DoubleHashB(b)
	b = append(b, hash...)
	type tt struct {
		No_  uint64 `json:"No,omitempty"`
		Addr string `json:"addr,omitempty"`
	}
	return &tt{
		No_:  numberOrder,
		Addr: hex.EncodeToString(b),
	}, nil
}
func freshen(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	_ = icmd.(*abejson.FreshenCmd)

	flag, err := w.Refresh()
	return flag, err
}

func sendToAddressesAbe(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.SendToAddressAbeCmd)

	// Transaction comments are not yet supported.  Error instead of
	// pretending to save them.
	if !isNilOrEmpty(cmd.Comment) {
		return nil, &abejson.RPCError{
			Code:    abejson.ErrRPCUnimplemented,
			Message: "Transaction comments are not yet supported",
		}
	}

	// Check that minconf is positive.
	minConf := int32(*cmd.MinConf)
	if minConf < 0 {
		return nil, ErrNeedPositiveMinconf
	}

	//	todo: the fee policy
	feeSatPerKb := txrules.DefaultRelayFeePerKb // todo: AliceBobScorpio, should use the feeSatPerKb received from abec
	scaleToFeeSatPerKb := *cmd.ScaleToFeeSatPerKb
	feeSpecified, err := abeutil.NewAmountAbe(*cmd.FeeSpecified)
	if err != nil {
		return nil, err
	}

	if scaleToFeeSatPerKb != 1 {
		// set the scaleToFeeSatPerKb
		feeSatPerKb = feeSatPerKb.MulF64(scaleToFeeSatPerKb)
		feeSpecified = abeutil.Amount(0)
	} else if feeSpecified != 0 && scaleToFeeSatPerKb == 1 {
		//	if neither scaleToFeeSatPerKb or feeSpecified is specified, the use scaleToFeeSatPerKb = 1
		//	feeSatPerKb = feeSatPerKb
		//	feeSpecified = 0
		//	i.e. nothing to do
	}

	var utxoSpecified []string = nil
	if cmd.UTXOSpecified != nil {
		utxoSpecified = strings.Split(*cmd.UTXOSpecified, ",")
		utxoNum := len(utxoSpecified)
		for i := 0; i < utxoNum; i++ {
			utxoSpecified[i] = strings.TrimSpace(utxoSpecified[i])
			if !isHexString(utxoSpecified[i]) {
				return nil, ErrSpeicifiedUTXOWrong
			}
		}
	}

	return sendAddressAbe(w, cmd.Amounts, minConf, feeSatPerKb, feeSpecified, utxoSpecified)
}

// sendToAddress handles a sendtoaddress RPC request by creating a new
// transaction spending unspent transaction outputs for a wallet to another
// payment address.  Leftover inputs not sent to the payment address or a fee
// for the miner are sent back to a new address in the wallet.  Upon success,
// the TxID for the created transaction is returned.

// setTxFee sets the transaction fee per kilobyte added to transactions.
func setTxFee(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.SetTxFeeCmd)

	// Check that amount is not negative.
	if cmd.Amount < 0 {
		return nil, ErrNeedPositiveAmount
	}

	// A boolean true result is returned upon success.
	return true, nil
}

// signMessage signs the given message with the private key for the given
// address
func signMessage(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.SignMessageCmd)

	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		return nil, err
	}

	privKey, err := w.PrivKeyForAddress(addr)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	wire.WriteVarString(&buf, 0, "Bitcoin Signed Message:\n")
	wire.WriteVarString(&buf, 0, cmd.Message)
	messageHash := chainhash.DoubleHashB(buf.Bytes())
	sigbytes, err := btcec.SignCompact(btcec.S256(), privKey,
		messageHash, true)
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.EncodeToString(sigbytes), nil
}

// signRawTransaction handles the signrawtransaction command.
func signRawTransaction(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	cmd := icmd.(*abejson.SignRawTransactionCmd)

	serializedTx, err := decodeHexStr(cmd.RawTx)
	if err != nil {
		return nil, err
	}
	var tx wire.MsgTx
	err = tx.Deserialize(bytes.NewBuffer(serializedTx))
	if err != nil {
		e := errors.New("TX decode failed")
		return nil, DeserializationError{e}
	}

	var hashType txscript.SigHashType
	switch *cmd.Flags {
	case "ALL":
		hashType = txscript.SigHashAll
	case "NONE":
		hashType = txscript.SigHashNone
	case "SINGLE":
		hashType = txscript.SigHashSingle
	case "ALL|ANYONECANPAY":
		hashType = txscript.SigHashAll | txscript.SigHashAnyOneCanPay
	case "NONE|ANYONECANPAY":
		hashType = txscript.SigHashNone | txscript.SigHashAnyOneCanPay
	case "SINGLE|ANYONECANPAY":
		hashType = txscript.SigHashSingle | txscript.SigHashAnyOneCanPay
	default:
		e := errors.New("Invalid sighash parameter")
		return nil, InvalidParameterError{e}
	}

	// TODO: really we probably should look these up with btcd anyway to
	// make sure that they match the blockchain if present.
	inputs := make(map[wire.OutPoint][]byte)
	scripts := make(map[string][]byte)
	var cmdInputs []abejson.RawTxInput
	if cmd.Inputs != nil {
		cmdInputs = *cmd.Inputs
	}
	for _, rti := range cmdInputs {
		inputHash, err := chainhash.NewHashFromStr(rti.Txid)
		if err != nil {
			return nil, DeserializationError{err}
		}

		script, err := decodeHexStr(rti.ScriptPubKey)
		if err != nil {
			return nil, err
		}

		// redeemScript is only actually used iff the user provided
		// private keys. In which case, it is used to get the scripts
		// for signing. If the user did not provide keys then we always
		// get scripts from the wallet.
		// Empty strings are ok for this one and hex.DecodeString will
		// DTRT.
		if cmd.PrivKeys != nil && len(*cmd.PrivKeys) != 0 {
			redeemScript, err := decodeHexStr(rti.RedeemScript)
			if err != nil {
				return nil, err
			}

			addr, err := abeutil.NewAddressScriptHash(redeemScript,
				w.ChainParams())
			if err != nil {
				return nil, DeserializationError{err}
			}
			scripts[addr.String()] = redeemScript
		}
		inputs[wire.OutPoint{
			Hash:  *inputHash,
			Index: rti.Vout,
		}] = script
	}

	// Now we go and look for any inputs that we were not provided by
	// querying btcd with getrawtransaction. We queue up a bunch of async
	// requests and will wait for replies after we have checked the rest of
	// the arguments.
	requested := make(map[wire.OutPoint]rpcclient.FutureGetTxOutResult)
	for _, txIn := range tx.TxIn {
		// Did we get this outpoint from the arguments?
		if _, ok := inputs[txIn.PreviousOutPoint]; ok {
			continue
		}

		// Asynchronously request the output script.
		requested[txIn.PreviousOutPoint] = chainClient.GetTxOutAsync(
			&txIn.PreviousOutPoint.Hash, txIn.PreviousOutPoint.Index,
			true)
	}

	// Parse list of private keys, if present. If there are any keys here
	// they are the keys that we may use for signing. If empty we will
	// use any keys known to us already.
	var keys map[string]*abeutil.WIF
	if cmd.PrivKeys != nil {
		keys = make(map[string]*abeutil.WIF)

		for _, key := range *cmd.PrivKeys {
			wif, err := abeutil.DecodeWIF(key)
			if err != nil {
				return nil, DeserializationError{err}
			}

			if !wif.IsForNet(w.ChainParams()) {
				s := "key network doesn't match wallet's"
				return nil, DeserializationError{errors.New(s)}
			}

			addr, err := abeutil.NewAddressPubKey(wif.SerializePubKey(),
				w.ChainParams())
			if err != nil {
				return nil, DeserializationError{err}
			}
			keys[addr.EncodeAddress()] = wif
		}
	}

	// We have checked the rest of the args. now we can collect the async
	// txs. TODO: If we don't mind the possibility of wasting work we could
	// move waiting to the following loop and be slightly more asynchronous.
	for outPoint, resp := range requested {
		result, err := resp.Receive()
		if err != nil {
			return nil, err
		}
		script, err := hex.DecodeString(result.ScriptPubKey.Hex)
		if err != nil {
			return nil, err
		}
		inputs[outPoint] = script
	}

	// All args collected. Now we can sign all the inputs that we can.
	// `complete' denotes that we successfully signed all outputs and that
	// all scripts will run to completion. This is returned as part of the
	// reply.
	signErrs, err := w.SignTransaction(&tx, hashType, inputs, keys, scripts)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	buf.Grow(tx.SerializeSize())

	// All returned errors (not OOM, which panics) encounted during
	// bytes.Buffer writes are unexpected.
	if err = tx.Serialize(&buf); err != nil {
		panic(err)
	}

	signErrors := make([]abejson.SignRawTransactionError, 0, len(signErrs))
	for _, e := range signErrs {
		input := tx.TxIn[e.InputIndex]
		signErrors = append(signErrors, abejson.SignRawTransactionError{
			TxID:      input.PreviousOutPoint.Hash.String(),
			Vout:      input.PreviousOutPoint.Index,
			ScriptSig: hex.EncodeToString(input.SignatureScript),
			Sequence:  input.Sequence,
			Error:     e.Error.Error(),
		})
	}

	return abejson.SignRawTransactionResult{
		Hex:      hex.EncodeToString(buf.Bytes()),
		Complete: len(signErrors) == 0,
		Errors:   signErrors,
	}, nil
}

//TODO(abe): we sign a transaction just when the wallet creates a unsigned transaction
func signRawTransactionAbe(icmd interface{}, w *wallet.Wallet, chainClient *chain.RPCClient) (interface{}, error) {
	cmd := icmd.(*abejson.SignRawTransactionCmd)

	serializedTx, err := decodeHexStr(cmd.RawTx)
	if err != nil {
		return nil, err
	}
	var tx wire.MsgTx
	err = tx.Deserialize(bytes.NewBuffer(serializedTx))
	if err != nil {
		e := errors.New("TX decode failed")
		return nil, DeserializationError{e}
	}

	var hashType txscript.SigHashType
	switch *cmd.Flags {
	case "ALL":
		hashType = txscript.SigHashAll
	case "NONE":
		hashType = txscript.SigHashNone
	case "SINGLE":
		hashType = txscript.SigHashSingle
	case "ALL|ANYONECANPAY":
		hashType = txscript.SigHashAll | txscript.SigHashAnyOneCanPay
	case "NONE|ANYONECANPAY":
		hashType = txscript.SigHashNone | txscript.SigHashAnyOneCanPay
	case "SINGLE|ANYONECANPAY":
		hashType = txscript.SigHashSingle | txscript.SigHashAnyOneCanPay
	default:
		e := errors.New("Invalid sighash parameter")
		return nil, InvalidParameterError{e}
	}

	// TODO: really we probably should look these up with btcd anyway to
	// make sure that they match the blockchain if present.
	inputs := make(map[wire.OutPoint][]byte)
	scripts := make(map[string][]byte)
	var cmdInputs []abejson.RawTxInput
	if cmd.Inputs != nil {
		cmdInputs = *cmd.Inputs
	}
	for _, rti := range cmdInputs {
		inputHash, err := chainhash.NewHashFromStr(rti.Txid)
		if err != nil {
			return nil, DeserializationError{err}
		}

		script, err := decodeHexStr(rti.ScriptPubKey)
		if err != nil {
			return nil, err
		}

		// redeemScript is only actually used iff the user provided
		// private keys. In which case, it is used to get the scripts
		// for signing. If the user did not provide keys then we always
		// get scripts from the wallet.
		// Empty strings are ok for this one and hex.DecodeString will
		// DTRT.
		if cmd.PrivKeys != nil && len(*cmd.PrivKeys) != 0 {
			redeemScript, err := decodeHexStr(rti.RedeemScript)
			if err != nil {
				return nil, err
			}

			addr, err := abeutil.NewAddressScriptHash(redeemScript,
				w.ChainParams())
			if err != nil {
				return nil, DeserializationError{err}
			}
			scripts[addr.String()] = redeemScript
		}
		inputs[wire.OutPoint{
			Hash:  *inputHash,
			Index: rti.Vout,
		}] = script
	}

	// Now we go and look for any inputs that we were not provided by
	// querying btcd with getrawtransaction. We queue up a bunch of async
	// requests and will wait for replies after we have checked the rest of
	// the arguments.
	requested := make(map[wire.OutPoint]rpcclient.FutureGetTxOutResult)
	for _, txIn := range tx.TxIn {
		// Did we get this outpoint from the arguments?
		if _, ok := inputs[txIn.PreviousOutPoint]; ok {
			continue
		}

		// Asynchronously request the output script.
		requested[txIn.PreviousOutPoint] = chainClient.GetTxOutAsync(
			&txIn.PreviousOutPoint.Hash, txIn.PreviousOutPoint.Index,
			true)
	}

	// Parse list of private keys, if present. If there are any keys here
	// they are the keys that we may use for signing. If empty we will
	// use any keys known to us already.
	var keys map[string]*abeutil.WIF
	if cmd.PrivKeys != nil {
		keys = make(map[string]*abeutil.WIF)

		for _, key := range *cmd.PrivKeys {
			wif, err := abeutil.DecodeWIF(key)
			if err != nil {
				return nil, DeserializationError{err}
			}

			if !wif.IsForNet(w.ChainParams()) {
				s := "key network doesn't match wallet's"
				return nil, DeserializationError{errors.New(s)}
			}

			addr, err := abeutil.NewAddressPubKey(wif.SerializePubKey(),
				w.ChainParams())
			if err != nil {
				return nil, DeserializationError{err}
			}
			keys[addr.EncodeAddress()] = wif
		}
	}

	// We have checked the rest of the args. now we can collect the async
	// txs. TODO: If we don't mind the possibility of wasting work we could
	// move waiting to the following loop and be slightly more asynchronous.
	for outPoint, resp := range requested {
		result, err := resp.Receive()
		if err != nil {
			return nil, err
		}
		script, err := hex.DecodeString(result.ScriptPubKey.Hex)
		if err != nil {
			return nil, err
		}
		inputs[outPoint] = script
	}

	// All args collected. Now we can sign all the inputs that we can.
	// `complete' denotes that we successfully signed all outputs and that
	// all scripts will run to completion. This is returned as part of the
	// reply.
	signErrs, err := w.SignTransaction(&tx, hashType, inputs, keys, scripts)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	buf.Grow(tx.SerializeSize())

	// All returned errors (not OOM, which panics) encounted during
	// bytes.Buffer writes are unexpected.
	if err = tx.Serialize(&buf); err != nil {
		panic(err)
	}

	signErrors := make([]abejson.SignRawTransactionError, 0, len(signErrs))
	for _, e := range signErrs {
		input := tx.TxIn[e.InputIndex]
		signErrors = append(signErrors, abejson.SignRawTransactionError{
			TxID:      input.PreviousOutPoint.Hash.String(),
			Vout:      input.PreviousOutPoint.Index,
			ScriptSig: hex.EncodeToString(input.SignatureScript),
			Sequence:  input.Sequence,
			Error:     e.Error.Error(),
		})
	}

	return abejson.SignRawTransactionResult{
		Hex:      hex.EncodeToString(buf.Bytes()),
		Complete: len(signErrors) == 0,
		Errors:   signErrors,
	}, nil
}

// validateAddress handles the validateaddress command.
func validateAddress(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.ValidateAddressCmd)

	result := abejson.ValidateAddressWalletResult{}
	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		// Use result zero value (IsValid=false).
		return result, nil
	}

	// We could put whether or not the address is a script here,
	// by checking the type of "addr", however, the reference
	// implementation only puts that information if the script is
	// "ismine", and we follow that behaviour.
	result.Address = addr.EncodeAddress()
	result.IsValid = true

	ainfo, err := w.AddressInfo(addr)
	if err != nil {
		if waddrmgr.IsError(err, waddrmgr.ErrAddressNotFound) {
			// No additional information available about the address.
			return result, nil
		}
		return nil, err
	}

	// The address lookup was successful which means there is further
	// information about it available and it is "mine".
	result.IsMine = true
	acctName, err := w.AccountName(waddrmgr.KeyScopeBIP0044, ainfo.Account())
	if err != nil {
		return nil, &ErrAccountNameNotFound
	}
	result.Account = acctName

	switch ma := ainfo.(type) {
	case waddrmgr.ManagedPubKeyAddress:
		result.IsCompressed = ma.Compressed()
		result.PubKey = ma.ExportPubKey()

	case waddrmgr.ManagedScriptAddress:
		result.IsScript = true

		// The script is only available if the manager is unlocked, so
		// just break out now if there is an error.
		script, err := ma.Script()
		if err != nil {
			break
		}
		result.Hex = hex.EncodeToString(script)

		// This typically shouldn't fail unless an invalid script was
		// imported.  However, if it fails for any reason, there is no
		// further information available, so just set the script type
		// a non-standard and break out now.
		class, addrs, reqSigs, err := txscript.ExtractPkScriptAddrs(
			script, w.ChainParams())
		if err != nil {
			result.Script = txscript.NonStandardTy.String()
			break
		}

		addrStrings := make([]string, len(addrs))
		for i, a := range addrs {
			addrStrings[i] = a.EncodeAddress()
		}
		result.Addresses = addrStrings

		// Multi-signature scripts also provide the number of required
		// signatures.
		result.Script = class.String()
		if class == txscript.MultiSigTy {
			result.SigsRequired = int32(reqSigs)
		}
	}

	return result, nil
}

// verifyMessage handles the verifymessage command by verifying the provided
// compact signature for the given address and message.
func verifyMessage(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.VerifyMessageCmd)

	addr, err := decodeAddress(cmd.Address, w.ChainParams())
	if err != nil {
		return nil, err
	}

	// decode base64 signature
	sig, err := base64.StdEncoding.DecodeString(cmd.Signature)
	if err != nil {
		return nil, err
	}

	// Validate the signature - this just shows that it was valid at all.
	// we will compare it with the key next.
	var buf bytes.Buffer
	wire.WriteVarString(&buf, 0, "Bitcoin Signed Message:\n")
	wire.WriteVarString(&buf, 0, cmd.Message)
	expectedMessageHash := chainhash.DoubleHashB(buf.Bytes())
	pk, wasCompressed, err := btcec.RecoverCompact(btcec.S256(), sig,
		expectedMessageHash)
	if err != nil {
		return nil, err
	}

	var serializedPubKey []byte
	if wasCompressed {
		serializedPubKey = pk.SerializeCompressed()
	} else {
		serializedPubKey = pk.SerializeUncompressed()
	}
	// Verify that the signed-by address matches the given address
	switch checkAddr := addr.(type) {
	case *abeutil.AddressPubKeyHash: // ok
		return bytes.Equal(abeutil.Hash160(serializedPubKey), checkAddr.Hash160()[:]), nil
	case *abeutil.AddressPubKey: // ok
		return string(serializedPubKey) == checkAddr.String(), nil
	default:
		return nil, errors.New("address type not supported")
	}
}

// walletIsLocked handles the walletislocked extension request by
// returning the current lock state (false for unlocked, true for locked)
// of an account.
func walletIsLocked(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	return w.Locked(), nil
}

// walletLock handles a walletlock request by locking the all account
// wallets, returning an error if any wallet is not encrypted (for example,
// a watching-only wallet).
func walletLock(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	w.Lock()
	return nil, nil
}

// walletPassphrase responds to the walletpassphrase request by unlocking
// the wallet.  The decryption key is saved in the wallet until timeout
// seconds expires, after which the wallet is locked.
func walletPassphrase(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.WalletPassphraseCmd)

	timeout := time.Second * time.Duration(cmd.Timeout)
	var unlockAfter <-chan time.Time
	if timeout != 0 {
		unlockAfter = time.After(timeout)
	}
	err := w.Unlock([]byte(cmd.Passphrase), unlockAfter)
	return nil, err
}

// walletPassphraseChange responds to the walletpassphrasechange request
// by unlocking all accounts with the provided old passphrase, and
// re-encrypting each private key with an AES key derived from the new
// passphrase.
//
// If the old passphrase is correct and the passphrase is changed, all
// wallets will be immediately locked.
func walletPassphraseChange(icmd interface{}, w *wallet.Wallet) (interface{}, error) {
	cmd := icmd.(*abejson.WalletPassphraseChangeCmd)

	err := w.ChangePrivatePassphrase([]byte(cmd.OldPassphrase),
		[]byte(cmd.NewPassphrase))
	if waddrmgr.IsError(err, waddrmgr.ErrWrongPassphrase) {
		return nil, &abejson.RPCError{
			Code:    abejson.ErrRPCWalletPassphraseIncorrect,
			Message: "Incorrect passphrase",
		}
	}
	return nil, err
}

// decodeHexStr decodes the hex encoding of a string, possibly prepending a
// leading '0' character if there is an odd number of bytes in the hex string.
// This is to prevent an error for an invalid hex string when using an odd
// number of bytes when calling hex.Decode.
func decodeHexStr(hexStr string) ([]byte, error) {
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, &abejson.RPCError{
			Code:    abejson.ErrRPCDecodeHexString,
			Message: "Hex string decode failed: " + err.Error(),
		}
	}
	return decoded, nil
}
