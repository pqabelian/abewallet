package wtxmgr

import (
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abewallet/walletdb"
)

// CreditRecord contains metadata regarding a transaction credit for a known
// transaction.  Further details may be looked up by indexing a wire.MsgTx.TxOut
// with the Index field.

// DebitRecord contains metadata regarding a transaction debit for a known
// transaction.  Further details may be looked up by indexing a wire.MsgTx.TxIn
// with the Index field.

// TxDetails is intended to provide callers with access to rich details
// regarding a relevant transaction and which inputs and outputs are credit or
// debits.

// minedTxDetails fetches the TxDetails for the mined transaction with hash
// txHash and the passed tx record key and value.

// unminedTxDetails fetches the TxDetails for the unmined transaction with the
// hash txHash and the passed unmined record value.

// TxLabel looks up a transaction label for the txHash provided. If the store
// has no labels in it, or the specific txHash does not have a label, an empty
// string and no error are returned.
func (s *Store) TxLabel(ns walletdb.ReadBucket, txHash chainhash.Hash) (string,
	error) {

	label, err := FetchTxLabel(ns, txHash)
	switch err {
	// If there are no saved labels yet (the bucket has not been created) or
	// there is not a label for this particular tx, we ignore the error.
	case ErrNoLabelBucket:
		fallthrough
	case ErrTxLabelNotFound:
		return "", nil

	// If we found the label, we return it.
	case nil:
		return label, nil
	}

	// Otherwise, another error occurred while looking uo the label, so we
	// return it.
	return "", err
}

// TxDetails looks up all recorded details regarding a transaction with some
// hash.  In case of a hash collision, the most recent transaction with a
// matching hash is returned.
//
// Not finding a transaction with this hash is not an error.  In this case,
// a nil TxDetails is returned.

// UniqueTxDetails looks up all recorded details for a transaction recorded
// mined in some particular block, or an unmined transaction if block is nil.
//
// Not finding a transaction with this hash from this block is not an error.  In
// this case, a nil TxDetails is returned.

// rangeUnminedTransactions executes the function f with TxDetails for every
// unmined transaction.  f is not executed if no unmined transactions exist.
// Error returns from f (if any) are propigated to the caller.  Returns true
// (signaling breaking out of a RangeTransactions) iff f executes and returns
// true.

// rangeBlockTransactions executes the function f with TxDetails for every block
// between heights begin and end (reverse order when end > begin) until f
// returns true, or the transactions from block is processed.  Returns true iff
// f executes and returns true.

// RangeTransactions runs the function f on all transaction details between
// blocks on the best chain over the height range [begin,end].  The special
// height -1 may be used to also include unmined transactions.  If the end
// height comes before the begin height, blocks are iterated in reverse order
// and unmined transactions (if any) are processed first.
//
// The function f may return an error which, if non-nil, is propagated to the
// caller.  Additionally, a boolean return value allows exiting the function
// early without reading any additional transactions early when true.
//
// All calls to f are guaranteed to be passed a slice with more than zero
// elements.  The slice may be reused for multiple blocks, so it is not safe to
// use it after the loop iteration it was acquired.

// PreviousPkScripts returns a slice of previous output scripts for each credit
// output this transaction record debits from.
