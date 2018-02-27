package mempool

type LockPoints struct {
	// Will be set to the blockchain height and median time past values that
	// would be necessary to satisfy all relative locktime constraints (BIP68)
	// of this tx given our view of block chain history
	Height int
	Time   int64
	//maxInputBlock *blockchain.BlockIndex
}

func NewLockPoints() *LockPoints {
	lockPoints := LockPoints{}
	return &lockPoints
}
