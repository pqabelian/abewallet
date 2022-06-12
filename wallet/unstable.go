package wallet

// unstableAPI is reserved to keep for experiment API although the APIs of abewallet is not stable
type unstableAPI struct {
	w *Wallet
}

// UnstableAPI exposes additional unstable public APIs for a Wallet.  These APIs
// may be changed or removed at any time.  Currently this type exists to ease
// the transation (particularly for the legacy JSON-RPC server) from using
// exported manager packages to a unified wallet package that exposes all
// functionality by itself.  New code should not be written using this API.
func UnstableAPI(w *Wallet) unstableAPI { return unstableAPI{w} }

// TxDetails calls wtxmgr.Store.TxDetails under a single database view transaction.

// RangeTransactions calls wtxmgr.Store.RangeTransactions under a single
// database view tranasction.
