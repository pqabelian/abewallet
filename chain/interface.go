package chain

import (
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abewallet/waddrmgr"
	"github.com/abesuite/abewallet/wtxmgr"
	"time"
)

// isCurrentDelta is the delta duration we'll use from the present time to
// determine if a backend is considered "current", i.e. synced to the tip of
// the chain.
const isCurrentDelta = 2 * time.Hour

// BackEnds returns a list of the available back ends.
// When there are more than one backend, it should transfer
// into a driver and use dynamic registration.
func BackEnds() []string {
	return []string{
		"abec",
	}
}

// Interface allows more than one backing blockchain source, such as a
// btcd RPC chain server, or an SPV library, as long as we write a driver for
// it.
type Interface interface {
	Start() error
	Stop()
	WaitForShutdown()
	GetBestBlock() (*chainhash.Hash, int32, error)               // request the best block height and hash
	GetBlockAbe(hash *chainhash.Hash) (*wire.MsgBlockAbe, error) // request the origin block by given hash
	GetBlockHash(int64) (*chainhash.Hash, error)                 //request the hash given height
	GetBlockHeader(*chainhash.Hash) (*wire.BlockHeader, error)   // request the block height given hash
	IsCurrent() bool
	BlockStamp() (*waddrmgr.BlockStamp, error)
	SendRawTransactionAbe(*wire.MsgTxAbe, bool) (*chainhash.Hash, error)
	RescanAbe(*chainhash.Hash) error
	NotifyBlocks() error
	Notifications() <-chan interface{} // receive the notification from block chain
	BackEnd() string
}

// Notification types.  These are defined here and processed from from reading
// a notificationChan to avoid handling these notifications directly in
// rpcclient callbacks, which isn't very Go-like and doesn't allow
// blocking client calls.
type (
	// ClientConnected is a notification for when a client connection is
	// opened or reestablished to the chain server.
	ClientConnected struct{}

	// BlockConnected is a notification for a newly-attached block to the
	// best chain.

	BlockAbeConnected wtxmgr.BlockMeta

	// FilteredBlockConnected is an alternate notification that contains
	// both block and relevant transaction information in one struct, which
	// allows atomic updates.

	// FilterBlocksRequest specifies a range of blocks and the set of
	// internal and external addresses of interest, indexed by corresponding
	// scoped-index of the child address. A global set of watched outpoints
	// is also included to monitor for spends.

	// FilterBlocksResponse reports the set of all internal and external
	// addresses found in response to a FilterBlockRequest, any outpoints
	// found that correspond to those addresses, as well as the relevant
	// transactions that can modify the wallet's balance. The index of the
	// block within the FilterBlocksRequest is returned, such that the
	// caller can reinitiate a request for the subsequent block after
	// updating the addresses of interest.

	// BlockDisconnected is a notifcation that the block described by the
	// BlockStamp was reorganized out of the best chain.

	BlockAbeDisconnected wtxmgr.BlockMeta
)
