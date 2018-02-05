package utxo

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"testing"

	"github.com/astaxie/beego/logs"
	"github.com/btcboost/copernicus/btcutil"
	"github.com/btcboost/copernicus/model"
	"github.com/btcboost/copernicus/utils"
	"gopkg.in/fatih/set.v0"
)

const NumSimulationIterations = 4000

type CoinsViewCacheTest struct {
	CoinsViewCache
}

func newCoinsViewCacheTest() *CoinsViewCacheTest {
	return &CoinsViewCacheTest{
		CoinsViewCache: CoinsViewCache{
			cacheCoins: make(CacheCoins),
		},
	}
}

// Store of all necessary tx and undo data for next test
type undoTx struct {
	tx   model.Tx
	undo []Coin // undo information for all txins
	coin Coin
}

// backed store
type CoinsViewTest struct {
	hashBestBlock utils.Hash
	coinMap       map[OutPoint]*Coin
}

func newCoinsViewTest() *CoinsViewTest {
	return &CoinsViewTest{
		coinMap: make(map[OutPoint]*Coin),
	}
}

func (coinsViewTest *CoinsViewTest) GetCoin(outPoint *OutPoint, coin *Coin) bool {
	c, ok := coinsViewTest.coinMap[*outPoint]
	if !ok {
		return false
	}
	tmp := DeepCopyCoin(c)
	coin.TxOut = tmp.TxOut
	coin.HeightAndIsCoinBase = tmp.HeightAndIsCoinBase
	if coin.IsSpent() && InsecureRandBool() {
		return false
	}
	return true
}

func (coinsViewTest *CoinsViewTest) HaveCoin(point *OutPoint) bool {
	var coin *Coin
	return coinsViewTest.GetCoin(point, coin)
}

func (coinsViewTest *CoinsViewTest) GetBestBlock() utils.Hash {
	return coinsViewTest.hashBestBlock
}
func (coinsViewTest *CoinsViewTest) EstimateSize() uint64 {
	return 0
}

func (coinsViewTest *CoinsViewTest) BatchWrite(cacheCoins CacheCoins, hashBlock *utils.Hash) bool {
	for outPoint, entry := range cacheCoins {
		if entry.Flags&DIRTY != 0 {
			// Same optimization used in CCoinsViewDB is to only write dirty entries.
			tmp := DeepCopyCoin(entry.Coin)
			coinsViewTest.coinMap[outPoint] = &tmp
			if entry.Coin.IsSpent() && InsecureRand32()%3 == 0 {
				// Randomly delete empty entries on write.
				delete(coinsViewTest.coinMap, outPoint)
			}
		}
	}
	cacheCoins = make(CacheCoins)
	if !hashBlock.IsNull() {
		coinsViewTest.hashBestBlock = *hashBlock
	}

	return true
}

func (coinsViewCacheTest *CoinsViewCacheTest) SelfTest() {
	// Manually recompute the dynamic usage of the whole data, and compare it.
	var ret int64
	var count int
	for _, entry := range coinsViewCacheTest.cacheCoins {
		ret += entry.Coin.DynamicMemoryUsage()
		count++
	}
	if len(coinsViewCacheTest.cacheCoins) != count {
		panic("count error")
	}

	if coinsViewCacheTest.cachedCoinsUsage != ret {
		panic("calculate memory usage error")
	}
}

func IsEqualCoin(c1 *Coin, c2 *Coin) bool {
	if c1.IsSpent() && c2.IsSpent() {
		return true
	}
	return c1.HeightAndIsCoinBase == c2.HeightAndIsCoinBase && IsEqualTxOut(c1.TxOut, c2.TxOut)
}

func IsEqualTxOut(o1 *model.TxOut, o2 *model.TxOut) bool {
	if o1.Script == nil && o2.Script == nil {
		return o1.Value == o2.Value
	}

	if o1.Script != nil && o2.Script != nil {
		bytes1 := o1.Script.GetScriptByte()
		bytes2 := o2.Script.GetScriptByte()
		if o1.Value != o2.Value || len(bytes1) != len(bytes2) {
			return false
		}
		for i := 0; i < len(bytes1); i++ {
			if bytes1[i] != bytes2[i] {
				return false
			}
		}
		return true
	}

	return false
}

// This is a large randomized insert/remove simulation test on a variable-size
// stack of caches on top of CCoinsViewTest.
//
// It will randomly create/update/delete Coin entries to a tip of caches, with
// txids picked from a limited list of random 256-bit hashes. Occasionally, a
// new tip is added to the stack of caches, or the tip is flushed and removed.
//
// During the process, booleans are kept to make sure that the randomized
// operation hits all branches.
func TestCoinsCacheSimulation(t *testing.T) {
	// Various coverage trackers.
	removedAllCaches := false
	reached4Caches := false
	addedAnEntry := false
	addedAnUnspendableEntry := false
	removedAnEntry := false
	updatedAnEntry := false
	foundAnEntry := false
	missedAnEntry := false
	unCachedAnEntry := false

	// A simple map to track what we expect the cache stack to represent.
	result := make(map[OutPoint]*Coin)

	// The cache stack.
	// A stack of CCoinsViewCaches on top.
	stack := make([]*CoinsViewCacheTest, 0)
	// A backed store instance
	backed := newCoinsViewTest()
	// A stack of CCoinsViewCaches on top.
	item := newCoinsViewCacheTest()
	item.base = backed
	// Start with one cache.
	stack = append(stack, item)

	// Use a limited set of random transaction ids, so we do test overwriting entries.
	var txids [NumSimulationIterations / 8]utils.Hash
	for i := 0; i < NumSimulationIterations/8; i++ {
		txids[i] = *GetRandHash()
	}

	for i := 0; i < NumSimulationIterations; i++ {
		{
			// Do a random modification.
			randomNum := InsecureRandRange(uint64(len(txids) - 1))
			// txid we're going to modify in this iteration.
			txid := txids[randomNum]
			coin, ok := result[OutPoint{Hash: txid, Index: 0}]

			if !ok {
				coin = NewEmptyCoin()
				result[OutPoint{Hash: txid, Index: 0}] = coin
			}

			randNum := InsecureRandRange(50)
			var entry *Coin
			if randNum == 0 {
				entry = AccessByTxid(&stack[len(stack)-1].CoinsViewCache, &txid)
			} else {
				entry = stack[len(stack)-1].AccessCoin(&OutPoint{Hash: txid, Index: 0})
			}

			if !IsEqualCoin(entry, coin) {
				t.Error("the coin should be equal to entry from cacheCoins or coinMap")
			}

			if InsecureRandRange(5) == 0 || coin.IsSpent() {
				var newTxOut model.TxOut
				newTxOut.Value = int64(InsecureRand32())
				if InsecureRandRange(16) == 0 && coin.IsSpent() {
					newTxOut.Script = model.NewScriptRaw(bytes.Repeat([]byte{byte(model.OP_RETURN)}, int(InsecureRandBits(6)+1)))
					if !newTxOut.Script.IsUnspendable() {
						t.Error("error IsUnspendable")
					}
					addedAnUnspendableEntry = true
				} else {
					// Random sizes so we can test memory usage accounting
					randomBytes := bytes.Repeat([]byte{0}, int(InsecureRandBits(6)+1))
					newTxOut.Script = model.NewScriptRaw(randomBytes)
					if coin.IsSpent() {
						addedAnEntry = true
					} else {
						updatedAnEntry = true
					}
					*result[OutPoint{Hash: txid, Index: 0}] = DeepCopyCoin(&Coin{TxOut: &newTxOut, HeightAndIsCoinBase: 2})
				}
				newCoin := Coin{TxOut: &newTxOut, HeightAndIsCoinBase: 2}
				newnewCoin := DeepCopyCoin(&newCoin)
				stack[len(stack)-1].AddCoin(&OutPoint{Hash: txid, Index: 0}, newnewCoin, !coin.IsSpent() || (InsecureRand32()&1 != 0))
			} else {
				removedAnEntry = true
				result[OutPoint{Hash: txid, Index: 0}].Clear()
				stack[len(stack)-1].SpendCoin(&OutPoint{Hash: txid, Index: 0}, nil)
			}
		}

		// One every 10 iterations, remove a random entry from the cache
		if InsecureRandRange(11) != 0 {
			cacheID := int(InsecureRand32()) % (len(stack))
			hashID := int(InsecureRand32()) % len(txids)
			out := OutPoint{Hash: txids[hashID], Index: 0}
			stack[cacheID].UnCache(&out)
			if !stack[cacheID].HaveCoinInCache(&out) {
				unCachedAnEntry = true
			}
		}

		// Once every 1000 iterations and at the end, verify the full cache.
		//if InsecureRandRange(2) == 1 || i == NumSimulationIterations-1 {
		if i == 200 || i == NumSimulationIterations-1 {
			for out, entry := range result {
				have := stack[len(stack)-1].HaveCoin(&out)
				coin := stack[len(stack)-1].AccessCoin(&out)
				if have == coin.IsSpent() {
					t.Error("the coin should be different from have in IsSpent")
				}

				if !IsEqualCoin(coin, entry) {
					t.Error("the coin should be equal to entry from cacheCoins or coinMap")
				}
				if coin.IsSpent() {
					missedAnEntry = true
				} else {
					if !stack[len(stack)-1].HaveCoinInCache(&out) {
						t.Error("error HaveCoinInCache")
					}
					foundAnEntry = true
				}
			}
			for _, test := range stack {
				test.SelfTest()
			}
		}

		// Every 100 iterations, flush an intermediate cache
		if InsecureRandRange(100) == 1000 {
			// Every 100 iterations, flush an intermediate cache
			if len(stack) > 1 && InsecureRandBool() {
				flushIndex := InsecureRandRange(uint64(len(stack) - 1))
				for out, item := range stack[0].cacheCoins {
					fmt.Println(out.Hash.ToString(), item.Coin.TxOut.Value, item.Coin.HeightAndIsCoinBase, item.Flags)
				}
				stack[flushIndex].Flush()
			}
		}

		if InsecureRandRange(100) == 0 {
			// Every 100 iterations, change the cache stack.
			length := len(stack)
			if length > 0 && InsecureRandBool() {
				//Remove the top cache
				stack[len(stack)-1].Flush()
				stack = stack[:length-1]
			}

			if len(stack) == 0 || len(stack) < 4 && InsecureRandBool() {
				//Add a new cache
				tip := newCoinsViewCacheTest()
				if len(stack) > 0 {
					tip.base = stack[len(stack)-1]
				} else {
					tip.base = backed
					removedAllCaches = true
				}

				stack = append(stack, tip)
				if len(stack) == 4 {
					reached4Caches = true
				}
			}
		}
	}

	// Clean up the stack.
	stack = nil

	// Verify coverage.
	if !removedAllCaches {
		t.Error("removedAllCaches should be true")
	}
	if !reached4Caches {
		t.Error("reached4Caches should be true")
	}
	if !addedAnEntry {
		t.Error("addedAnEntry should be true")
	}
	if !addedAnUnspendableEntry {
		t.Error("addedAnUnspendableEntry should be true")
	}
	if !removedAnEntry {
		t.Error("removedAnEntry should be true")
	}
	if !updatedAnEntry {
		t.Error("updatedAnEntry should be true")
	}
	if !foundAnEntry {
		t.Error("foundAnEntry should be true")
	}
	if !missedAnEntry {
		t.Error("missedAnEntry should be true")
	}
	if !unCachedAnEntry {
		t.Error("uncachedAnEntry should be true")
	}
}

var utxoData map[OutPoint]undoTx

func lowerBound(a OutPoint, b OutPoint) bool {
	tmp := a.Hash.Cmp(&b.Hash)
	return tmp < 0 || (tmp == 0 && a.Index < b.Index)
}

func findRandomFrom(utxoSet *set.Set) (OutPoint, undoTx) {
	if utxoSet.Size() == 0 {
		panic("utxoSet is empty")
	}

	randOutPoint := OutPoint{Hash: *GetRandHash(), Index: 0}
	utxoList := utxoSet.List()

	var utxoSetIt OutPoint
	for _, it := range utxoList {
		out := it.(*model.OutPoint)
		outpoint := OutPoint{Hash: *out.Hash, Index: out.Index}
		if !lowerBound(outpoint, randOutPoint) {
			break
		}
	}
	if &utxoSetIt.Hash == nil {
		utxoSetIt = utxoList[0].(OutPoint)
	}
	utxoDataIt, ok := utxoData[utxoSetIt]
	if ok {
		log.Error("this utxoSetIt should be in utxoData")
	}
	return utxoSetIt, utxoDataIt
}

var log = logs.NewLogger()

func TestUpdateCoinsSimulation(t *testing.T) {
	spentDuplicateCoinbase := false
	//A simple map to track what we expect the cache stack to represent.
	result := make(map[OutPoint]*Coin)

	stack := make([]*CoinsViewCacheTest, 0)
	backed := newCoinsViewTest()
	item := newCoinsViewCacheTest()
	item.base = backed
	// Start with one cache.
	stack = append(stack, item)

	// Track the txIds we've used in various sets
	coinBaseCoins := set.New()
	disconnectedCoins := set.New()
	duplicateCoins := set.New()
	utxoSet := set.New()

	for i := 0; i < NumSimulationIterations; i++ {
		randiter := InsecureRand32()
		//19/20 txs add a new transaction
		if (randiter % 20) < 19 {
			tx1 := model.NewTx()
			tx1.Ins = make([]*model.TxIn, 0)
			outpoint := model.OutPoint{Hash: GetRandHash(), Index: 0}
			tx1.Ins = append(tx1.Ins, &model.TxIn{PreviousOutPoint: &outpoint})
			tx1.Outs = make([]*model.TxOut, 1)
			tx1.Outs[0] = model.NewTxOut(int64(i), bytes.Repeat([]byte{0}, int(InsecureRand32())&0x3F))
			height := InsecureRand32()
			//var oldCoin *Coin

			// 2/20 times create a new coinbase
			if (randiter%20) < 2 || coinBaseCoins.Size() < 10 {
				// 1/10 of those times create a duplicate coinBase
				if InsecureRandRange(10) == 0 && coinBaseCoins.Size() > 0 {
					outKey, undoData := findRandomFrom(coinBaseCoins)
					tx1 = &undoData.tx
					disconnectedCoins.Remove(outKey)
					duplicateCoins.Add(outKey)
				} else {
					out := &model.OutPoint{Hash: &tx1.Hash, Index: 0}
					coinBaseCoins.Add(out)
				}
				if tx1.IsCoinBase() {
					log.Error("tx1 can't is coinBase.")
				}
			} else {
				// 17/20 times reconnect previous or add a regular tx
				// 1/20 times reconnect a previously disconnected tx
				var prevOut OutPoint
				if (randiter%20 == 2) && (disconnectedCoins.Size() > 0) {
					out, _ := findRandomFrom(disconnectedCoins)
					tmp := tx1.Ins[0].PreviousOutPoint
					prevOut.Hash = *tmp.Hash
					prevOut.Index = tmp.Index
					if !tx1.IsCoinBase() && !utxoSet.Has(prevOut) {
						disconnectedCoins.Remove(out)
						continue
					}
					// If this tx is already IN the UTXO, then it must be a coinBase, and it must be a duplicate
					if utxoSet.Has(out) {
						if tx1.IsCoinBase() {
							log.Error("tx1 can't is coinBase..")
						}
						if !duplicateCoins.Has(out) {
							log.Error("duplicate coins should have outpoint.")
						}
						disconnectedCoins.Remove(out)
					}
				} else {
					// 16/20 times create a regular tx
					out, _ := findRandomFrom(utxoSet)
					prevOut = out
					tx1.Ins[0] = model.NewTxIn(&model.OutPoint{Hash: &out.Hash, Index: out.Index}, []byte{0})
					if tx1.IsCoinBase() {
						log.Error("tx1 can't is coinBase...")
					}
				}
				// In this simple test coins only have two states, spent or
				// unspent, save the unspent state to restore
				// Update the expected result of prevouthash to know these coins
				// are spent
				utxoSet.Remove(prevOut)

				// The test is designed to ensure spending a duplicate coinbase
				// will work properly if that ever happens and not resurrect the
				// previously overwritten coinbase
				if duplicateCoins.Has(prevOut) {
					spentDuplicateCoinbase = true
				}
			}
			// Update the expected result to know about the new output coins
			if len(tx1.Outs) != 1 {
				log.Error("the tx out size isn't 1 .")
			}
			outPoint := model.NewOutPoint(&tx1.Hash, 0)
			tx1.Outs = make([]*model.TxOut, 0)
			tx1.Outs = append(tx1.Outs, model.NewTxOut(int64(i), bytes.Repeat([]byte{0}, int(InsecureRand32())&0x3F)))
			result[OutPoint{Hash: *outPoint.Hash, Index: outPoint.Index}] = NewCoin(tx1.Outs[0], height, tx1.IsCoinBase())

			// Update the utxo set for future spends
			utxoSet.Add(outPoint)

			// Track this tx and undo info to use later
			//utxoData[OutPoint{Hash: *outPoint.Hash, Index: 0}] = undo
		} else if utxoSet.Size() > 0 {
			// 1/20 times undo a previous transaction
			outKey, utxoData := findRandomFrom(utxoSet)

			tx1 := &utxoData.tx
			tx1.Ins = make([]*model.TxIn, 0)
			tx1.Ins = append(tx1.Ins, model.NewTxIn(&model.OutPoint{Hash: &outKey.Hash, Index: outKey.Index}, []byte{0}))
			tx1.Ins[0] = model.NewTxIn(&model.OutPoint{Hash: &outKey.Hash, Index: outKey.Index}, []byte{0})
			origCoin := &utxoData.coin

			// If not coinbase restore prevout
			if !(tx1.IsCoinBase()) {
				tmp := tx1.Ins[0].PreviousOutPoint
				outKey.Hash = *tmp.Hash
				outKey.Index = tmp.Index
				result[outKey] = origCoin
			}
			// Disconnect the tx from the current UTXO
			// See code in DisconnectBlock
			// remove outputs
			stack[len(stack)-1].CoinsViewCache.SpendCoin(&outKey, nil)

			// restore inputs
			if !(tx1.IsCoinBase()) {
				tmp := tx1.Ins[0].PreviousOutPoint
				outKey.Hash = *tmp.Hash
				outKey.Index = tmp.Index

				//UndoCoinSpend(nil, &stack[len(stack)-1].CoinsViewCache, &outKey)
			}
			// Store as a candidate for reconnection
			tmp := model.OutPoint{Hash: &outKey.Hash, Index: outKey.Index}
			disconnectedCoins.Add(&tmp)

			// Update the utxoset
			utxoSet.Remove(outKey)
			if !(tx1.IsCoinBase()) {
				utxoSet.Add(tx1.Ins[0].PreviousOutPoint)
			}
		}

		//Once every 1000 iterations and at the end, verify the full cache.
		if (InsecureRandRange(1000) == 1) || (i == NumSimulationIterations-1) {
			for itKey, itValue := range result {
				have := stack[len(stack)-1].CoinsViewCache.HaveCoin(&itKey)
				coin := stack[len(stack)-1].CoinsViewCache.AccessCoin(&itKey)
				if have == !coin.IsSpent() {
					log.Error("the coin not is spent")
				}
				if coin == itValue {
					log.Error("the coin not equal")
				}
			}
		}

		// One every 10 iterations, remove a random entry from the cache
		if (utxoSet.Size() > 1) && (InsecureRandRange(30)) > 0 {
			utxoset, _ := findRandomFrom(utxoSet)
			stack[InsecureRand32()%uint32(len(stack))].CoinsViewCache.UnCache(&utxoset)
		}
		if (disconnectedCoins.Size() > 1) && (InsecureRandRange(30) > 0) {
			disconnectedcoins, _ := findRandomFrom(disconnectedCoins)
			stack[InsecureRand32()%uint32(len(stack))].CoinsViewCache.UnCache(&disconnectedcoins)
		}
		if (duplicateCoins.Size() > 1) && (InsecureRandRange(30) > 0) {
			duplicatecoins, _ := findRandomFrom(disconnectedCoins)
			stack[InsecureRand32()%uint32(len(stack))].CoinsViewCache.UnCache(&duplicatecoins)
		}
		if InsecureRandRange(100) == 0 {
			// Every 100 iterations, flush an intermediate cache
			if len(stack) > 1 && InsecureRand32() == 0 {
				flushIndex := InsecureRandRange(uint64(len(stack)) - 1)
				stack[flushIndex].CoinsViewCache.Flush()
			}
		}
		if InsecureRandRange(100) == 0 {
			//Every 100 iterations, change the cache stack.
			if len(stack) > 0 && InsecureRand32() == 0 {
				stack[len(stack)-1].CoinsViewCache.Flush()
				stack = nil
			}
			if len(stack) == 0 || len(stack) < 4 && InsecureRandBool() {
				tip := newCoinsViewCacheTest()
				if len(stack) > 0 {
					tip = stack[len(stack)-1]
					stack = append(stack, tip)
				}
			}
		}
	}
	//Clean up the stack.
	stack = nil

	//Verify coverage.
	if spentDuplicateCoinbase {
		log.Error("the duplicate coinBase is spent.")
	}
}

type DisconnectResult int

const (
	DISCONNECT_OK DisconnectResult = iota
	DISCONNECT_UNCLEAN
	DISCONNECT_FAILED
)

func UndoCoinSpend(undo *Coin, view *CoinsViewCache, out *OutPoint) DisconnectResult {
	fClean := true
	if view.HaveCoin(out) {
		fClean = false
	}
	if undo.GetHeight() == 0 {
		alternate := AccessByTxid(view, &out.Hash)
		if alternate.IsSpent() {
			return DISCONNECT_FAILED
		}
		undo = NewCoin(undo.TxOut, alternate.GetHeight(), alternate.IsCoinBase())
	}
	view.AddCoin(out, *undo, undo.IsCoinBase())
	if fClean {
		return DISCONNECT_OK
	}
	return DISCONNECT_UNCLEAN
}

func UpdateCoins(tx model.Tx, inputs CoinsViewCache, txUndo undoTx, nHeight int) {
	if !(tx.IsCoinBase()) {
		for _, txin := range tx.Ins {
			var out OutPoint
			tmp := txin.PreviousOutPoint
			out.Hash = *tmp.Hash
			out.Index = tmp.Index
			isSpent := inputs.SpendCoin(&out, nil)
			if isSpent {
				panic("the coin is spent ..")
			}
		}
	}
	AddCoins(inputs, tx, nHeight, true)
}

var OUTPOINT = OutPoint{Hash: utils.HashZero, Index: math.MaxUint32}

const (
	PRUNED   btcutil.Amount = -1
	ABSENT   btcutil.Amount = -2
	FAIL     btcutil.Amount = -3
	VALUE1   btcutil.Amount = 100
	VALUE2   btcutil.Amount = 200
	VALUE3   btcutil.Amount = 300
	DIRTY                   = COIN_ENTRY_DIRTY
	FRESH                   = COIN_ENTRY_FRESH
	NO_ENTRY                = -1
)

type SingleEntryCacheTest struct {
	root  CoinsView
	base  *CoinsViewCacheTest
	cache *CoinsViewCacheTest
}

func NewSingleEntryCacheTest(baseValue btcutil.Amount, cacheValue btcutil.Amount, cacheFlags int) *SingleEntryCacheTest {
	root := newCoinsViewTest()
	base := newCoinsViewCacheTest()
	base.base = root
	cache := newCoinsViewCacheTest()
	cache.base = base
	if baseValue == ABSENT {
		WriteCoinViewEntry(base, baseValue, NO_ENTRY)
	} else {
		WriteCoinViewEntry(base, baseValue, DIRTY)
	}
	cache.cachedCoinsUsage += InsertCoinMapEntry(cache.cacheCoins, cacheValue, cacheFlags)
	return &SingleEntryCacheTest{
		root:  root,
		base:  base,
		cache: cache,
	}
}

func WriteCoinViewEntry(view CoinsView, value btcutil.Amount, flags int) {
	cacheCoins := make(CacheCoins)
	InsertCoinMapEntry(cacheCoins, value, flags)
	view.BatchWrite(cacheCoins, &utils.Hash{})
}

func InsertCoinMapEntry(cacheCoins CacheCoins, value btcutil.Amount, flags int) int64 {
	if value == ABSENT {
		if flags != NO_ENTRY {
			panic("input flags should be NO_ENTRY")
		}
		return 0
	}
	if flags == NO_ENTRY {
		panic("input flags should not be NO_ENTRY")
	}
	coin := NewEmptyCoin()
	SetCoinValue(value, coin)
	coinsCacheEntry := NewCoinsCacheEntry(coin)
	coinsCacheEntry.Flags = uint8(flags)
	_, ok := cacheCoins[OUTPOINT]
	if ok {
		panic("add CoinsCacheEntry should success")
	}
	cacheCoins[OUTPOINT] = coinsCacheEntry
	return coinsCacheEntry.Coin.DynamicMemoryUsage()
}

func SetCoinValue(value btcutil.Amount, coin *Coin) {
	if value == ABSENT {
		panic("input value should not be equal to ABSENT")
	}
	coin.Clear()
	if !coin.IsSpent() {
		panic("coin should have spent after calling Clear() function")
	}
	if value != PRUNED {
		coin.TxOut = &model.TxOut{Value: int64(value)}
		coin.HeightAndIsCoinBase = (1 << 1) | 0
	}
}

func GetCoinMapEntry(cacheCoins CacheCoins) (btcutil.Amount, int) {
	entry, ok := cacheCoins[OUTPOINT]
	var resultValue btcutil.Amount
	var resultFlags int
	if !ok {
		resultValue = ABSENT
		resultFlags = NO_ENTRY
	} else {
		if entry.Coin.IsSpent() {
			resultValue = PRUNED
		} else {
			resultValue = btcutil.Amount(entry.Coin.TxOut.Value)
		}
		resultFlags = int(entry.Flags)
		if resultFlags == NO_ENTRY {
			panic("result_flags should not be equal to NO_ENTRY")
		}
	}
	return resultValue, resultFlags
}

func CheckAccessCoin(baseValue btcutil.Amount, cacheValue btcutil.Amount, expectedValue btcutil.Amount, cacheFlags int, expectedFlags int) {
	singleEntryCacheTest := NewSingleEntryCacheTest(baseValue, cacheValue, cacheFlags)
	var (
		resultValue btcutil.Amount
		resultFlags int
	)
	singleEntryCacheTest.cache.AccessCoin(&OUTPOINT)
	singleEntryCacheTest.cache.SelfTest()
	resultValue, resultFlags = GetCoinMapEntry(singleEntryCacheTest.cache.cacheCoins)

	if resultValue != expectedValue {
		panic("expectedValue should be equal to resultValue")
	}

	if resultFlags != expectedFlags {
		panic("expectedFlags should be equal to resultFlags")
	}
}

func TestCoinAccess(t *testing.T) {
	CheckAccessCoin(ABSENT, ABSENT, ABSENT, NO_ENTRY, NO_ENTRY)
	CheckAccessCoin(ABSENT, PRUNED, PRUNED, 0, 0)
	CheckAccessCoin(ABSENT, PRUNED, PRUNED, FRESH, FRESH)
	CheckAccessCoin(ABSENT, PRUNED, PRUNED, DIRTY, DIRTY)
	CheckAccessCoin(ABSENT, PRUNED, PRUNED, DIRTY|FRESH, DIRTY|FRESH)
	CheckAccessCoin(ABSENT, VALUE2, VALUE2, 0, 0)
	CheckAccessCoin(ABSENT, VALUE2, VALUE2, FRESH, FRESH)
	CheckAccessCoin(ABSENT, VALUE2, VALUE2, DIRTY, DIRTY)
	CheckAccessCoin(ABSENT, VALUE2, VALUE2, DIRTY|FRESH, DIRTY|FRESH)
	CheckAccessCoin(PRUNED, ABSENT, PRUNED, NO_ENTRY, FRESH)
	CheckAccessCoin(PRUNED, PRUNED, PRUNED, 0, 0)
	CheckAccessCoin(PRUNED, PRUNED, PRUNED, FRESH, FRESH)
	CheckAccessCoin(PRUNED, PRUNED, PRUNED, DIRTY, DIRTY)
	CheckAccessCoin(PRUNED, PRUNED, PRUNED, DIRTY|FRESH, DIRTY|FRESH)
	CheckAccessCoin(PRUNED, VALUE2, VALUE2, 0, 0)
	CheckAccessCoin(PRUNED, VALUE2, VALUE2, FRESH, FRESH)
	CheckAccessCoin(PRUNED, VALUE2, VALUE2, DIRTY, DIRTY)
	CheckAccessCoin(PRUNED, VALUE2, VALUE2, DIRTY|FRESH, DIRTY|FRESH)
	CheckAccessCoin(VALUE1, ABSENT, VALUE1, NO_ENTRY, 0)
	CheckAccessCoin(VALUE1, PRUNED, PRUNED, 0, 0)
	CheckAccessCoin(VALUE1, PRUNED, PRUNED, FRESH, FRESH)
	CheckAccessCoin(VALUE1, PRUNED, PRUNED, DIRTY, DIRTY)
	CheckAccessCoin(VALUE1, PRUNED, PRUNED, DIRTY|FRESH, DIRTY|FRESH)
	CheckAccessCoin(VALUE1, VALUE2, VALUE2, 0, 0)
	CheckAccessCoin(VALUE1, VALUE2, VALUE2, FRESH, FRESH)
	CheckAccessCoin(VALUE1, VALUE2, VALUE2, DIRTY, DIRTY)
	CheckAccessCoin(VALUE1, VALUE2, VALUE2, DIRTY|FRESH, DIRTY|FRESH)
}

func CheckSpendCoin(baseValue btcutil.Amount, cacheValue btcutil.Amount, expectedValue btcutil.Amount, cacheFlags int, expectedFlags int) {
	singleEntryCacheTest := NewSingleEntryCacheTest(baseValue, cacheValue, int(cacheFlags))
	singleEntryCacheTest.cache.SpendCoin(&OUTPOINT, nil)
	singleEntryCacheTest.cache.SelfTest()

	resultValue, resultFlags := GetCoinMapEntry(singleEntryCacheTest.cache.cacheCoins)
	if expectedValue != resultValue {
		panic("expectedValue should be equal to resultValue")
	}
	if expectedFlags != resultFlags {
		panic("expectedFlags should be equal to resultFlags")
	}
}

func TestCoinSpeed(t *testing.T) {
	/**
	 * Check SpendCoin behavior, requesting a coin from a cache view layered on
	 * top of a base view, spending, and then checking the resulting entry in
	 * the cache after the modification.
	 *
	 *              Base    	Cache   	Result  		Cache        Result
	 *              Value   	Value   	Value   		Flags        Flags
	 */

	CheckSpendCoin(ABSENT, ABSENT, ABSENT, NO_ENTRY, NO_ENTRY)
	CheckSpendCoin(ABSENT, PRUNED, PRUNED, 0, DIRTY)
	CheckSpendCoin(ABSENT, PRUNED, ABSENT, FRESH, NO_ENTRY)
	CheckSpendCoin(ABSENT, PRUNED, PRUNED, DIRTY, DIRTY)
	CheckSpendCoin(ABSENT, PRUNED, ABSENT, DIRTY|FRESH, NO_ENTRY)
	CheckSpendCoin(ABSENT, VALUE2, PRUNED, 0, DIRTY)
	CheckSpendCoin(ABSENT, VALUE2, ABSENT, FRESH, NO_ENTRY)
	CheckSpendCoin(ABSENT, VALUE2, PRUNED, DIRTY, DIRTY)
	CheckSpendCoin(ABSENT, VALUE2, ABSENT, DIRTY|FRESH, NO_ENTRY)
	CheckSpendCoin(PRUNED, ABSENT, ABSENT, NO_ENTRY, NO_ENTRY)
	CheckSpendCoin(PRUNED, PRUNED, PRUNED, 0, DIRTY)
	CheckSpendCoin(PRUNED, PRUNED, ABSENT, FRESH, NO_ENTRY)
	CheckSpendCoin(PRUNED, PRUNED, PRUNED, DIRTY, DIRTY)
	CheckSpendCoin(PRUNED, PRUNED, ABSENT, DIRTY|FRESH, NO_ENTRY)
	CheckSpendCoin(PRUNED, VALUE2, PRUNED, 0, DIRTY)
	CheckSpendCoin(PRUNED, VALUE2, ABSENT, FRESH, NO_ENTRY)
	CheckSpendCoin(PRUNED, VALUE2, PRUNED, DIRTY, DIRTY)
	CheckSpendCoin(PRUNED, VALUE2, ABSENT, DIRTY|FRESH, NO_ENTRY)
	CheckSpendCoin(VALUE1, ABSENT, PRUNED, NO_ENTRY, DIRTY)
	CheckSpendCoin(VALUE1, PRUNED, PRUNED, 0, DIRTY)
	CheckSpendCoin(VALUE1, PRUNED, ABSENT, FRESH, NO_ENTRY)
	CheckSpendCoin(VALUE1, PRUNED, PRUNED, DIRTY, DIRTY)
	CheckSpendCoin(VALUE1, PRUNED, ABSENT, DIRTY|FRESH, NO_ENTRY)
	CheckSpendCoin(VALUE1, VALUE2, PRUNED, 0, DIRTY)
	CheckSpendCoin(VALUE1, VALUE2, ABSENT, FRESH, NO_ENTRY)
	CheckSpendCoin(VALUE1, VALUE2, PRUNED, DIRTY, DIRTY)
	CheckSpendCoin(VALUE1, VALUE2, ABSENT, DIRTY|FRESH, NO_ENTRY)
}

func CheckAddCoinBase(baseValue btcutil.Amount, cacheValue btcutil.Amount, modifyValue btcutil.Amount, expectedValue btcutil.Amount, cacheFlags int, expectedFlags int, isCoinbase bool) {
	singleEntryCacheTest := NewSingleEntryCacheTest(baseValue, cacheValue, int(cacheFlags))

	var resultValue btcutil.Amount
	var resultFlags int
	defer func() {
		if r := recover(); r != nil {
			resultValue = FAIL
			resultFlags = NO_ENTRY
			if resultValue != expectedValue {
				panic("expectedValue should be equal to resultValue")
			}
			if resultFlags != expectedFlags {
				panic("expectedFlags should be equal to resultFlags")
			}
		} else {
			if resultValue != expectedValue {
				panic("expectedValue should be equal to resultValue")
			}
			if resultFlags != expectedFlags {
				panic("expectedFlags should be equal to resultFlags")
			}
		}
	}()

	txOut := model.NewTxOut(int64(modifyValue), []byte{})
	coin := NewCoin(txOut, 1, isCoinbase)
	singleEntryCacheTest.cache.AddCoin(&OUTPOINT, *coin, isCoinbase)
	singleEntryCacheTest.cache.SelfTest()
	resultValue, resultFlags = GetCoinMapEntry(singleEntryCacheTest.cache.cacheCoins)
}

func CheckAddCoin(cacheValue btcutil.Amount, modifyValue btcutil.Amount, expectedValue btcutil.Amount, cacheFlags int, expectedFlags int, isCoinbase bool) {
	for _, arg := range [3]btcutil.Amount{ABSENT, PRUNED, VALUE1} {
		CheckAddCoinBase(arg, cacheValue, modifyValue, expectedValue, cacheFlags, expectedFlags, isCoinbase)
	}
}

func TestCoinAdd(t *testing.T) {
	/**
	 * Check AddCoin behavior, requesting a new coin from a cache view, writing
	 * a modification to the coin, and then checking the resulting entry in the
	 * cache after the modification. Verify behavior with the with the AddCoin
	 * potential_overwrite argument set to false, and to true.
	 *
	 * Cache   Write   Result  Cache        Result       potential_overwrite
	 * Value   Value   Value   Flags        Flags
	 */
	CheckAddCoin(ABSENT, VALUE3, VALUE3, NO_ENTRY, DIRTY|FRESH, false)
	CheckAddCoin(ABSENT, VALUE3, VALUE3, NO_ENTRY, DIRTY, true)
	CheckAddCoin(PRUNED, VALUE3, VALUE3, 0, DIRTY|FRESH, false)
	CheckAddCoin(PRUNED, VALUE3, VALUE3, 0, DIRTY, true)
	CheckAddCoin(PRUNED, VALUE3, VALUE3, FRESH, DIRTY|FRESH, false)
	CheckAddCoin(PRUNED, VALUE3, VALUE3, FRESH, DIRTY|FRESH, true)
	CheckAddCoin(PRUNED, VALUE3, VALUE3, DIRTY, DIRTY, false)
	CheckAddCoin(PRUNED, VALUE3, VALUE3, DIRTY, DIRTY, true)
	CheckAddCoin(PRUNED, VALUE3, VALUE3, DIRTY|FRESH, DIRTY|FRESH, false)
	CheckAddCoin(PRUNED, VALUE3, VALUE3, DIRTY|FRESH, DIRTY|FRESH, true)
	CheckAddCoin(VALUE2, VALUE3, FAIL, 0, NO_ENTRY, false)
	CheckAddCoin(VALUE2, VALUE3, VALUE3, 0, DIRTY, true)
	CheckAddCoin(VALUE2, VALUE3, FAIL, FRESH, NO_ENTRY, false)
	CheckAddCoin(VALUE2, VALUE3, VALUE3, FRESH, DIRTY|FRESH, true)
	CheckAddCoin(VALUE2, VALUE3, FAIL, DIRTY, NO_ENTRY, false)
	CheckAddCoin(VALUE2, VALUE3, VALUE3, DIRTY, DIRTY, true)
	CheckAddCoin(VALUE2, VALUE3, FAIL, DIRTY|FRESH, NO_ENTRY, false)
	CheckAddCoin(VALUE2, VALUE3, VALUE3, DIRTY|FRESH, DIRTY|FRESH, true)
}

func CheckWriteCoin(parentValue btcutil.Amount, childValue btcutil.Amount, expectedValue btcutil.Amount, parentFlags int, childFlags int, expectedFlags int) {
	singleEntryCacheTest := NewSingleEntryCacheTest(ABSENT, parentValue, parentFlags)
	var (
		resultValue btcutil.Amount
		resultFlags int
	)
	defer func() {
		if r := recover(); r != nil {
			resultValue = FAIL
			resultFlags = NO_ENTRY
			if resultValue != expectedValue {
				panic("expectedValue should be equal to resultValue")
			}
			if resultFlags != expectedFlags {
				panic("expectedFlags should be equal to resultFlags")
			}
		} else {
			if resultValue != expectedValue {
				panic("expectedValue should be equal to resultValue")
			}
			if resultFlags != expectedFlags {
				panic("expectedFlags should be equal to resultFlags")
			}
		}
	}()
	WriteCoinViewEntry(singleEntryCacheTest.cache, childValue, childFlags)
	singleEntryCacheTest.cache.SelfTest()
	resultValue, resultFlags = GetCoinMapEntry(singleEntryCacheTest.cache.cacheCoins)
}

func TestWriteCoin(t *testing.T) {
	/* Check BatchWrite behavior, flushing one entry from a child cache to a
	 * parent cache, and checking the resulting entry in the parent cache
	 * after the write.
	 *
	 *              Parent  Child   Result  Parent       Child        Result
	 *              Value   Value   Value   Flags        Flags        Flags
	 */
	CheckWriteCoin(ABSENT, ABSENT, ABSENT, NO_ENTRY, NO_ENTRY, NO_ENTRY)
	CheckWriteCoin(ABSENT, PRUNED, PRUNED, NO_ENTRY, DIRTY, DIRTY)
	CheckWriteCoin(ABSENT, PRUNED, ABSENT, NO_ENTRY, DIRTY|FRESH, NO_ENTRY)
	CheckWriteCoin(ABSENT, VALUE2, VALUE2, NO_ENTRY, DIRTY, DIRTY)
	CheckWriteCoin(ABSENT, VALUE2, VALUE2, NO_ENTRY, DIRTY|FRESH, DIRTY|FRESH)
	CheckWriteCoin(PRUNED, ABSENT, PRUNED, 0, NO_ENTRY, 0)
	CheckWriteCoin(PRUNED, ABSENT, PRUNED, FRESH, NO_ENTRY, FRESH)
	CheckWriteCoin(PRUNED, ABSENT, PRUNED, DIRTY, NO_ENTRY, DIRTY)
	CheckWriteCoin(PRUNED, ABSENT, PRUNED, DIRTY|FRESH, NO_ENTRY, DIRTY|FRESH)
	CheckWriteCoin(PRUNED, PRUNED, PRUNED, 0, DIRTY, DIRTY)
	CheckWriteCoin(PRUNED, PRUNED, PRUNED, 0, DIRTY|FRESH, DIRTY)
	CheckWriteCoin(PRUNED, PRUNED, ABSENT, FRESH, DIRTY, NO_ENTRY)
	CheckWriteCoin(PRUNED, PRUNED, ABSENT, FRESH, DIRTY|FRESH, NO_ENTRY)
	CheckWriteCoin(PRUNED, PRUNED, PRUNED, DIRTY, DIRTY, DIRTY)
	CheckWriteCoin(PRUNED, PRUNED, PRUNED, DIRTY, DIRTY|FRESH, DIRTY)
	CheckWriteCoin(PRUNED, PRUNED, ABSENT, DIRTY|FRESH, DIRTY, NO_ENTRY)
	CheckWriteCoin(PRUNED, PRUNED, ABSENT, DIRTY|FRESH, DIRTY|FRESH, NO_ENTRY)
	CheckWriteCoin(PRUNED, VALUE2, VALUE2, 0, DIRTY, DIRTY)
	CheckWriteCoin(PRUNED, VALUE2, VALUE2, 0, DIRTY|FRESH, DIRTY)
	CheckWriteCoin(PRUNED, VALUE2, VALUE2, FRESH, DIRTY, DIRTY|FRESH)
	CheckWriteCoin(PRUNED, VALUE2, VALUE2, FRESH, DIRTY|FRESH, DIRTY|FRESH)
	CheckWriteCoin(PRUNED, VALUE2, VALUE2, DIRTY, DIRTY, DIRTY)
	CheckWriteCoin(PRUNED, VALUE2, VALUE2, DIRTY, DIRTY|FRESH, DIRTY)
	CheckWriteCoin(PRUNED, VALUE2, VALUE2, DIRTY|FRESH, DIRTY, DIRTY|FRESH)
	CheckWriteCoin(PRUNED, VALUE2, VALUE2, DIRTY|FRESH, DIRTY|FRESH, DIRTY|FRESH)
	CheckWriteCoin(VALUE1, ABSENT, VALUE1, 0, NO_ENTRY, 0)
	CheckWriteCoin(VALUE1, ABSENT, VALUE1, FRESH, NO_ENTRY, FRESH)
	CheckWriteCoin(VALUE1, ABSENT, VALUE1, DIRTY, NO_ENTRY, DIRTY)
	CheckWriteCoin(VALUE1, ABSENT, VALUE1, DIRTY|FRESH, NO_ENTRY, DIRTY|FRESH)
	CheckWriteCoin(VALUE1, PRUNED, PRUNED, 0, DIRTY, DIRTY)
	CheckWriteCoin(VALUE1, PRUNED, FAIL, 0, DIRTY|FRESH, NO_ENTRY)
	CheckWriteCoin(VALUE1, PRUNED, ABSENT, FRESH, DIRTY, NO_ENTRY)
	CheckWriteCoin(VALUE1, PRUNED, FAIL, FRESH, DIRTY|FRESH, NO_ENTRY)
	CheckWriteCoin(VALUE1, PRUNED, PRUNED, DIRTY, DIRTY, DIRTY)
	CheckWriteCoin(VALUE1, PRUNED, FAIL, DIRTY, DIRTY|FRESH, NO_ENTRY)
	CheckWriteCoin(VALUE1, PRUNED, ABSENT, DIRTY|FRESH, DIRTY, NO_ENTRY)
	CheckWriteCoin(VALUE1, PRUNED, FAIL, DIRTY|FRESH, DIRTY|FRESH, NO_ENTRY)
	CheckWriteCoin(VALUE1, VALUE2, VALUE2, 0, DIRTY, DIRTY)
	CheckWriteCoin(VALUE1, VALUE2, FAIL, 0, DIRTY|FRESH, NO_ENTRY)
	CheckWriteCoin(VALUE1, VALUE2, VALUE2, FRESH, DIRTY, DIRTY|FRESH)
	CheckWriteCoin(VALUE1, VALUE2, FAIL, FRESH, DIRTY|FRESH, NO_ENTRY)
	CheckWriteCoin(VALUE1, VALUE2, VALUE2, DIRTY, DIRTY, DIRTY)
	CheckWriteCoin(VALUE1, VALUE2, FAIL, DIRTY, DIRTY|FRESH, NO_ENTRY)
	CheckWriteCoin(VALUE1, VALUE2, VALUE2, DIRTY|FRESH, DIRTY, DIRTY|FRESH)
	CheckWriteCoin(VALUE1, VALUE2, FAIL, DIRTY|FRESH, DIRTY|FRESH, NO_ENTRY)
}

// new a insecure rand creator from crypto/rand seed
func newInsecureRand() []byte {
	randByte := make([]byte, 32)
	_, err := rand.Read(randByte)
	if err != nil {
		panic("init rand number creator failed...")
	}
	return randByte
}

// GetRandHash create a random Hash(utils.Hash)
func GetRandHash() *utils.Hash {
	tmpStr := hex.EncodeToString(newInsecureRand())
	return utils.HashFromString(tmpStr)
}

// InsecureRandRange create a random number in [0, limit]
func InsecureRandRange(limit uint64) uint64 {
	if limit == 0 {
		fmt.Println("param 0 will be insignificant")
		return 0
	}
	r := newInsecureRand()
	return binary.LittleEndian.Uint64(r) % (limit + 1)
}

// InsecureRand32 create a random number in [0 math.MaxUint32]
func InsecureRand32() uint32 {
	r := newInsecureRand()
	return binary.LittleEndian.Uint32(r)
}

// InsecureRandBits create a random number following  specified bit count
func InsecureRandBits(bit uint8) uint64 {
	r := newInsecureRand()
	maxNum := uint64(((1<<(bit-1))-1)*2 + 1 + 1)
	return binary.LittleEndian.Uint64(r) % maxNum
}

// InsecureRandBool create true or false randomly
func InsecureRandBool() bool {
	r := newInsecureRand()
	remainder := binary.LittleEndian.Uint16(r) % 2
	return remainder == 1
}

func TestRandomFunction(t *testing.T) {
	trueCount := 0
	falseCount := 0

	for i := 0; i < 10000; i++ {
		NumUint64 := InsecureRandRange(100)
		if NumUint64 > 100 {
			t.Error("InsecureRandRange() create a random number bigger than 10000")
		}

		NumUint32 := InsecureRand32()
		if NumUint32 > math.MaxUint32 {
			t.Error("InsecureRand32() creates a random number bigger than math.MaxUint32")
		}

		NumFromRandBit := InsecureRandBits(6)
		if NumFromRandBit > (((1<<(6-1))-1)*2 + 1) {
			t.Error("InsecureRandBits() creates a random numner bigger than bit-specific MaxNumber")
		}

		BoolFromRandFunc := InsecureRandBool()
		if BoolFromRandFunc {
			trueCount++
		} else {
			falseCount++
		}
	}

	if trueCount == 0 || falseCount == 0 {
		t.Error("InsecureRandBool() maybe needed to check")
	}
}
