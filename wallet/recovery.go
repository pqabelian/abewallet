package wallet

import (
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abewallet/wtxmgr"
	"time"
)

// RecoveryManager maintains the state required to recover previously used
// addresses, and coordinates batched processing of the blocks to search.
// TODO: this struct is reserved for recovery address but now is useless.
type RecoveryManager struct {
	// recoveryWindow defines the key-derivation lookahead used when
	// attempting to recover the set of used addresses.
	recoveryWindow uint32

	// started is true after the first block has been added to the batch.
	started bool

	// blockBatch contains a list of blocks that have not yet been searched
	// for recovered addresses.
	blockBatch []wtxmgr.BlockMeta

	// state encapsulates and allocates the necessary recovery state for all
	// key scopes and subsidiary derivation paths.
	state *RecoveryState

	// chainParams are the parameters that describe the chain we're trying
	// to recover funds on.
	chainParams *chaincfg.Params
}

// NewRecoveryManager initializes a new RecoveryManager with a derivation
// look-ahead of `recoveryWindow` child indexes, and pre-allocates a backing
// array for `batchSize` blocks to scan at once.
func NewRecoveryManager(recoveryWindow, batchSize uint32,
	chainParams *chaincfg.Params) *RecoveryManager {

	return &RecoveryManager{
		recoveryWindow: recoveryWindow,
		blockBatch:     make([]wtxmgr.BlockMeta, 0, batchSize),
		chainParams:    chainParams,
		state:          NewRecoveryState(recoveryWindow),
	}
}

// Resurrect restores all known addresses for the provided scopes that can be
// found in the walletdb namespace, in addition to restoring all outpoints that
// have been previously found. This method ensures that the recovery state's
// horizons properly start from the last found address of a prior recovery
// attempt.

// AddToBlockBatch appends the block information, consisting of hash and height,
// to the batch of blocks to be searched.
func (rm *RecoveryManager) AddToBlockBatch(hash *chainhash.Hash, height int32,
	timestamp time.Time) {

	if !rm.started {
		log.Infof("Seed birthday surpassed, starting recovery "+
			"of wallet from height=%d hash=%v with "+
			"recovery-window=%d", height, *hash, rm.recoveryWindow)
		rm.started = true
	}

	block := wtxmgr.BlockMeta{
		Block: wtxmgr.Block{
			Hash:   *hash,
			Height: height,
		},
		Time: timestamp,
	}
	rm.blockBatch = append(rm.blockBatch, block)
}

// BlockBatch returns a buffer of blocks that have not yet been searched.
func (rm *RecoveryManager) BlockBatch() []wtxmgr.BlockMeta {
	return rm.blockBatch
}

// ResetBlockBatch resets the internal block buffer to conserve memory.
func (rm *RecoveryManager) ResetBlockBatch() {
	rm.blockBatch = rm.blockBatch[:0]
}

// State returns the current RecoveryState.
func (rm *RecoveryManager) State() *RecoveryState {
	return rm.state
}

// RecoveryState manages the initialization and lookup of ScopeRecoveryStates
// for any actively used key scopes.
//
// In order to ensure that all addresses are properly recovered, the window
// should be sized as the sum of maximum possible inter-block and intra-block
// gap between used addresses of a particular branch.
//
// These are defined as:
//   - Inter-Block Gap: The maximum difference between the derived child indexes
//       of the last addresses used in any block and the next address consumed
//       by a later block.
//   - Intra-Block Gap: The maximum difference between the derived child indexes
//       of the first address used in any block and the last address used in the
//       same block.
type RecoveryState struct {
	// recoveryWindow defines the key-derivation lookahead used when
	// attempting to recover the set of used addresses. This value will be
	// used to instantiate a new RecoveryState for each requested scope.
	recoveryWindow uint32

	// scopes maintains a map of each requested key scope to its active
	// RecoveryState.

	// watchedOutPoints contains the set of all outpoints known to the
	// wallet. This is updated iteratively as new outpoints are found during
	// a rescan.
	watchedOutPoints map[wire.OutPoint]abeutil.Address
}

// NewRecoveryState creates a new RecoveryState using the provided
// recoveryWindow. Each RecoveryState that is subsequently initialized for a
// particular key scope will receive the same recoveryWindow.
func NewRecoveryState(recoveryWindow uint32) *RecoveryState {

	return &RecoveryState{
		recoveryWindow:   recoveryWindow,
		watchedOutPoints: make(map[wire.OutPoint]abeutil.Address),
	}
}

// StateForScope returns a ScopeRecoveryState for the provided key scope. If one
// does not already exist, a new one will be generated with the RecoveryState's
// recoveryWindow.
func (rs *RecoveryState) StateForScope() *ScopeRecoveryState {
	// TODO delete
	return nil
}

// WatchedOutPoints returns the global set of outpoints that are known to belong
// to the wallet during recovery.
func (rs *RecoveryState) WatchedOutPoints() map[wire.OutPoint]abeutil.Address {
	return rs.watchedOutPoints
}

// AddWatchedOutPoint updates the recovery state's set of known outpoints that
// we will monitor for spends during recovery.
func (rs *RecoveryState) AddWatchedOutPoint(outPoint *wire.OutPoint,
	addr abeutil.Address) {

	rs.watchedOutPoints[*outPoint] = addr
}

// ScopeRecoveryState is used to manage the recovery of addresses generated
// under a particular BIP32 account. Each account tracks both an external and
// internal branch recovery state, both of which use the same recovery window.
type ScopeRecoveryState struct {
	// ExternalBranch is the recovery state of addresses generated for
	// external use, i.e. receiving addresses.
	ExternalBranch *BranchRecoveryState

	// InternalBranch is the recovery state of addresses generated for
	// internal use, i.e. change addresses.
	InternalBranch *BranchRecoveryState
}

// NewScopeRecoveryState initializes an ScopeRecoveryState with the chosen
// recovery window.
func NewScopeRecoveryState(recoveryWindow uint32) *ScopeRecoveryState {
	return &ScopeRecoveryState{
		ExternalBranch: NewBranchRecoveryState(recoveryWindow),
		InternalBranch: NewBranchRecoveryState(recoveryWindow),
	}
}

// BranchRecoveryState maintains the required state in-order to properly
// recover addresses derived from a particular account's internal or external
// derivation branch.
//
// A branch recovery state supports operations for:
//  - Expanding the look-ahead horizon based on which indexes have been found.
//  - Registering derived addresses with indexes within the horizon.
//  - Reporting an invalid child index that falls into the horizon.
//  - Reporting that an address has been found.
//  - Retrieving all currently derived addresses for the branch.
//  - Looking up a particular address by its child index.
type BranchRecoveryState struct {
	// recoveryWindow defines the key-derivation lookahead used when
	// attempting to recover the set of addresses on this branch.
	recoveryWindow uint32

	// horizion records the highest child index watched by this branch.
	horizon uint32

	// nextUnfound maintains the child index of the successor to the highest
	// index that has been found during recovery of this branch.
	nextUnfound uint32

	// addresses is a map of child index to address for all actively watched
	// addresses belonging to this branch.
	addresses map[uint32]abeutil.Address

	// invalidChildren records the set of child indexes that derive to
	// invalid keys.
	invalidChildren map[uint32]struct{}
}

// NewBranchRecoveryState creates a new BranchRecoveryState that can be used to
// track either the external or internal branch of an account's derivation path.
func NewBranchRecoveryState(recoveryWindow uint32) *BranchRecoveryState {
	return &BranchRecoveryState{
		recoveryWindow:  recoveryWindow,
		addresses:       make(map[uint32]abeutil.Address),
		invalidChildren: make(map[uint32]struct{}),
	}
}

// ExtendHorizon returns the current horizon and the number of addresses that
// must be derived in order to maintain the desired recovery window.
func (brs *BranchRecoveryState) ExtendHorizon() (uint32, uint32) {

	// Compute the new horizon, which should surpass our last found address
	// by the recovery window.
	curHorizon := brs.horizon

	nInvalid := brs.NumInvalidInHorizon()
	minValidHorizon := brs.nextUnfound + brs.recoveryWindow + nInvalid

	// If the current horizon is sufficient, we will not have to derive any
	// new keys.
	if curHorizon >= minValidHorizon {
		return curHorizon, 0
	}

	// Otherwise, the number of addresses we should derive corresponds to
	// the delta of the two horizons, and we update our new horizon.
	delta := minValidHorizon - curHorizon
	brs.horizon = minValidHorizon

	return curHorizon, delta
}

// AddAddr adds a freshly derived address from our lookahead into the map of
// known addresses for this branch.
func (brs *BranchRecoveryState) AddAddr(index uint32, addr abeutil.Address) {
	brs.addresses[index] = addr
}

// GetAddr returns the address derived from a given child index.
func (brs *BranchRecoveryState) GetAddr(index uint32) abeutil.Address {
	return brs.addresses[index]
}

// ReportFound updates the last found index if the reported index exceeds the
// current value.
func (brs *BranchRecoveryState) ReportFound(index uint32) {
	if index >= brs.nextUnfound {
		brs.nextUnfound = index + 1

		// Prune all invalid child indexes that fall below our last
		// found index. We don't need to keep these entries any longer,
		// since they will not affect our required look-ahead.
		for childIndex := range brs.invalidChildren {
			if childIndex < index {
				delete(brs.invalidChildren, childIndex)
			}
		}
	}
}

// MarkInvalidChild records that a particular child index results in deriving an
// invalid address. In addition, the branch's horizon is increment, as we expect
// the caller to perform an additional derivation to replace the invalid child.
// This is used to ensure that we are always have the proper lookahead when an
// invalid child is encountered.
func (brs *BranchRecoveryState) MarkInvalidChild(index uint32) {
	brs.invalidChildren[index] = struct{}{}
	brs.horizon++
}

// NextUnfound returns the child index of the successor to the highest found
// child index.
func (brs *BranchRecoveryState) NextUnfound() uint32 {
	return brs.nextUnfound
}

// Addrs returns a map of all currently derived child indexes to the their
// corresponding addresses.
func (brs *BranchRecoveryState) Addrs() map[uint32]abeutil.Address {
	return brs.addresses
}

// NumInvalidInHorizon computes the number of invalid child indexes that lie
// between the last found and current horizon. This informs how many additional
// indexes to derive in order to maintain the proper number of valid addresses
// within our horizon.
func (brs *BranchRecoveryState) NumInvalidInHorizon() uint32 {
	var nInvalid uint32
	for childIndex := range brs.invalidChildren {
		if brs.nextUnfound <= childIndex && childIndex < brs.horizon {
			nInvalid++
		}
	}

	return nInvalid
}
