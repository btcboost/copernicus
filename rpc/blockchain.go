package rpc

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/btcboost/copernicus/blockchain"
	"github.com/btcboost/copernicus/btcjson"
	"github.com/btcboost/copernicus/core"
	"github.com/btcboost/copernicus/net/msg"
	"github.com/btcboost/copernicus/policy"
	"github.com/btcboost/copernicus/utils"
	"github.com/pkg/errors"
)

var blockchainHandlers = map[string]commandHandler{
	"getblockchaininfo":     handleGetBlockChainInfo,
	"getbestblockhash":      handleGetBestBlockHash, // complete
	"getblockcount":         handleGetBlockCount,    // complete
	"getblock":              handleGetBlock,
	"getblockhash":          handleGetBlockHash,   // complete
	"getblockheader":        handleGetBlockHeader, // complete
	"getchaintips":          handleGetChainTips,
	"getdifficulty":         handleGetDifficulty, //complete
	"getmempoolancestors":   handleGetMempoolAncestors,
	"getmempooldescendants": handleGetMempoolDescendants,
	"getmempoolinfo":        handleGetMempoolInfo, // complete
	"getrawmempool":         handleGetRawMempool,
	"gettxout":              handleGetTxOut,
	"gettxoutsetinfo":       handleGetTxoutSetInfo,
	"pruneblockchain":       handlePruneBlockChain, //complete
	"verifychain":           handleVerifyChain,     //complete
	"preciousblock":         handlePreciousblock,   //complete

	/*not shown in help*/
	"invalidateblock":    handlInvalidateBlock,
	"reconsiderblock":    handleReconsiderBlock,
	"waitfornewblock":    handleWaitForNewBlock,
	"waitforblock":       handleWaitForBlock,
	"waitforblockheight": handleWaitForBlockHeight,
}

func handleGetBlockChainInfo(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {

	/*	// Obtain a snapshot of the current best known blockchain state. We'll
		// populate the response to this call primarily from this snapshot.
		var headers int32
		if blockchain.GIndexBestHeader != nil {
			headers = int32(blockchain.GIndexBestHeader.Height)
		} else {
			headers = -1
		}


		tip := blockchain.GChainActive.Tip()
		chainInfo := &btcjson.GetBlockChainInfoResult{
			//Chain:         Params().NetworkingIDString(),            // TODO
			Blocks:        int32(blockchain.GChainActive.Height()),
			Headers:       headers,
			BestBlockHash: tip.GetBlockHash().ToString(),
			Difficulty:    getDifficulty(tip),
			MedianTime:    tip.GetMedianTimePast(),
			//VerificationProgress: blockchain.GuessVerificationProgress(Params().TxData(),
			//	blockchain.GChainActive.Tip())            // TODO
			ChainWork:     tip.ChainWork.String(),
			Pruned:        false,
			Bip9SoftForks: make(map[string]*btcjson.Bip9SoftForkDescription),
		}

		// Next, populate the response with information describing the current
		// status of soft-forks deployed via the super-majority block
		// signalling mechanism.
		height := chainSnapshot.Height
		chainInfo.SoftForks = []*btcjson.SoftForkDescription{
			{
				ID:      "bip34",
				Version: 2,
				Reject: struct {
					Status bool `json:"status"`
				}{
					Status: height >= params.BIP0034Height,
				},
			},
			{
				ID:      "bip66", f
				Version: 3,
				Reject: struct {
					Status bool `json:"status"`
				}{
					Status: height >= params.BIP0066Height,
				},
			},
			{
				ID:      "bip65",
				Version: 4,
				Reject: struct {
					Status bool `json:"status"`
				}{
					Status: height >= params.BIP0065Height,
				},
			},
		}

		// Finally, query the BIP0009 version bits state for all currently
		// defined BIP0009 soft-fork deployments.
		for deployment, deploymentDetails := range params.Deployments {
			// Map the integer deployment ID into a human readable
			// fork-name.
			var forkName string
			switch deployment {
			case chaincfg.DeploymentTestDummy:
				forkName = "dummy"

			case chaincfg.DeploymentCSV:
				forkName = "csv"

			case chaincfg.DeploymentSegwit:
				forkName = "segwit"

			default:
				return nil, &btcjson.RPCError{
					Code: btcjson.ErrRPCInternal.Code,
					Message: fmt.Sprintf("Unknown deployment %v "+
						"detected", deployment),
				}
			}

			// Query the chain for the current status of the deployment as
			// identified by its deployment ID.
			deploymentStatus, err := chain.ThresholdState(uint32(deployment))
			if err != nil {
				context := "Failed to obtain deployment status"
				return nil, internalRPCError(err.Error(), context)
			}

			// Attempt to convert the current deployment status into a
			// human readable string. If the status is unrecognized, then a
			// non-nil error is returned.
			statusString, err := softForkStatus(deploymentStatus)
			if err != nil {
				return nil, &btcjson.RPCError{
					Code: btcjson.ErrRPCInternal.Code,
					Message: fmt.Sprintf("unknown deployment status: %v",
						deploymentStatus),
				}
			}

			// Finally, populate the soft-fork description with all the
			// information gathered above.
			chainInfo.Bip9SoftForks[forkName] = &btcjson.Bip9SoftForkDescription{
				Status:    strings.ToLower(statusString),
				Bit:       deploymentDetails.BitNumber,
				StartTime: int64(deploymentDetails.StartTime),
				Timeout:   int64(deploymentDetails.ExpireTime),
			}
		}

		return chainInfo, nil
	*/
	return nil, nil
}

func handleGetBestBlockHash(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return blockchain.GChainActive.Tip().GetBlockHash().ToString(), nil
}

func handleGetBlockCount(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return blockchain.GChainActive.Height(), nil
}

// createTxRawResult converts the passed transaction and associated parameters
// to a raw transaction JSON object.
/*func createTxRawResult(chainParams *chaincfg.Params, mtx *wire.MsgTx,
	txHash string, blkHeader *wire.BlockHeader, blkHash string,
	blkHeight int32, chainHeight int32) (*btcjson.TxRawResult, error) {

	mtxHex, err := messageToHex(mtx)
	if err != nil {
		return nil, err
	}

	txReply := &btcjson.TxRawResult{
		Hex:      mtxHex,
		Txid:     txHash,
		Hash:     mtx.WitnessHash().String(),
		Size:     int32(mtx.SerializeSize()),
		Vsize:    int32(mempool.GetTxVirtualSize(btcutil.NewTx(mtx))),
		Vin:      createVinList(mtx),
		Vout:     createVoutList(mtx, chainParams, nil),
		Version:  mtx.Version,
		LockTime: mtx.LockTime,
	}

	if blkHeader != nil {
		// This is not a typo, they are identical in bitcoind as well.
		txReply.Time = blkHeader.Timestamp.Unix()
		txReply.Blocktime = blkHeader.Timestamp.Unix()
		txReply.BlockHash = blkHash
		txReply.Confirmations = uint64(1 + chainHeight - blkHeight)
	}

	return txReply, nil
}*/

// createVoutList returns a slice of JSON objects for the outputs of the passed
// transaction.
//func createVoutList(mtx *wire.MsgTx, chainParams *chaincfg.Params, filterAddrMap map[string]struct{}) []btcjson.Vout {
//	voutList := make([]btcjson.Vout, 0, len(mtx.TxOut))
//	for i, v := range mtx.TxOut {
//		// The disassembled string will contain [error] inline if the
//		// script doesn't fully parse, so ignore the error here.
//		disbuf, _ := txscript.DisasmString(v.PkScript)
//
//		// Ignore the error here since an error means the script
//		// couldn't parse and there is no additional information about
//		// it anyways.
//		scriptClass, addrs, reqSigs, _ := txscript.ExtractPkScriptAddrs(
//			v.PkScript, chainParams)
//
//		// Encode the addresses while checking if the address passes the
//		// filter when needed.
//		passesFilter := len(filterAddrMap) == 0
//		encodedAddrs := make([]string, len(addrs))
//		for j, addr := range addrs {
//			encodedAddr := addr.EncodeAddress()
//			encodedAddrs[j] = encodedAddr
//
//			// No need to check the map again if the filter already
//			// passes.
//			if passesFilter {
//				continue
//			}
//			if _, exists := filterAddrMap[encodedAddr]; exists {
//				passesFilter = true
//			}
//		}
//
//		if !passesFilter {
//			continue
//		}
//
//		var vout btcjson.Vout
//		vout.N = uint32(i)
//		vout.Value = btcutil.Amount(v.Value).ToBTC()
//		vout.ScriptPubKey.Addresses = encodedAddrs
//		vout.ScriptPubKey.Asm = disbuf
//		vout.ScriptPubKey.Hex = hex.EncodeToString(v.PkScript)
//		vout.ScriptPubKey.Type = scriptClass.String()
//		vout.ScriptPubKey.ReqSigs = int32(reqSigs)
//
//		voutList = append(voutList, vout)
//	}
//
//	return voutList
//}

// createVinList returns a slice of JSON objects for the inputs of the passed
// transaction.
//func createVinList(mtx *wire.MsgTx) []btcjson.Vin {
//	// Coinbase transactions only have a single txin by definition.
//	vinList := make([]btcjson.Vin, len(mtx.TxIn))
//	if blockchain.IsCoinBaseTx(mtx) {
//		txIn := mtx.TxIn[0]
//		vinList[0].Coinbase = hex.EncodeToString(txIn.SignatureScript)
//		vinList[0].Sequence = txIn.Sequence
//		return vinList
//	}
//
//	for i, txIn := range mtx.TxIn {
//		// The disassembled string will contain [error] inline
//		// if the script doesn't fully parse, so ignore the
//		// error here.
//		disbuf, _ := txscript.DisasmString(txIn.SignatureScript)
//
//		vinEntry := &vinList[i]
//		vinEntry.Txid = txIn.PreviousOutPoint.Hash.String()
//		vinEntry.Vout = txIn.PreviousOutPoint.Index
//		vinEntry.Sequence = txIn.Sequence
//		vinEntry.ScriptSig = &btcjson.ScriptSig{
//			Asm: disbuf,
//			Hex: hex.EncodeToString(txIn.SignatureScript),
//		}
//	}
//
//	return vinList
//}

func handleGetBlock(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {

	c := cmd.(*btcjson.GetBlockCmd)

	// Load the raw block bytes from the database.
	hash, err := utils.GetHashFromStr(c.Hash)
	if err != nil {
		return nil, rpcDecodeHexError(c.Hash)
	}

	verbose := *c.Verbose
	if len(blockchain.MapBlockIndex.Data) == 0 {
		return false, &btcjson.RPCError{
			Code:    btcjson.ErrRPCInvalidAddressOrKey,
			Message: "Block not found",
		}
	}
	blk := core.Block{}
	bIndex := blockchain.MapBlockIndex.Data[*hash]

	if blockchain.GHavePruned && (bIndex.Status&8) != 0 && bIndex.TxCount > 0 {
		return false, &btcjson.RPCError{
			Code:    btcjson.ErrRPCMisc,
			Message: "Block not available (pruned data)",
		}
	}

	/*if blockchain.ReadBlockFromDisk() {
		return false, &btcjson.RPCError{
			Code:    btcjson.ErrRPCMisc,
			Message: "Block not found on disk",
		}
	}*/             //TODO

	if !verbose {
		writer := bytes.NewBuffer(nil)
		blk.Serialize(writer)
		strHex := hex.EncodeToString(writer.Bytes())
		return strHex, nil
	}

	// blockToJSON()          // TODO
	return nil, nil
}

func handleGetBlockHash(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {

	c := cmd.(*btcjson.GetBlockHashCmd)

	height := c.Height
	if height < 0 || height > blockchain.GChainActive.Height() {
		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCOutOfRange,
			Message: "Block number out of range",
		}
	}

	blockIndex := blockchain.GChainActive.GetSpecIndex(height)

	return blockIndex.GetBlockHash().ToString(), nil
}

func handleGetBlockHeader(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	c := cmd.(*btcjson.GetBlockHeaderCmd)

	// Fetch the header from chain.
	hash, err := utils.GetHashFromStr(c.Hash)
	if err != nil {
		return nil, rpcDecodeHexError(c.Hash)
	}
	blockIndex := blockchain.GChainActive.FetchBlockIndexByHash(hash) // todo realise: get BlockIndex by hash

	if blockIndex == nil {
		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCBlockNotFound,
			Message: "Block not found",
		}
	}

	// When the verbose flag is set false
	if c.Verbose != nil && !*c.Verbose {
		var headerBuf bytes.Buffer
		err := blockIndex.Header.Serialize(&headerBuf)
		if err != nil {
			context := "Failed to serialize block header"
			return nil, internalRPCError(err.Error(), context)
		}
		return hex.EncodeToString(headerBuf.Bytes()), nil
	}

	//best := s.cfg.Chain.BestSnapshot()
	best := blockchain.GChainActive.Tip()
	confirmations := -1
	// Only report confirmations if the block is on the main chain
	if blockchain.GChainActive.Contains(blockIndex) {
		confirmations = best.Height - blockIndex.Height + 1
	}

	var previousblockhash string
	if blockIndex.Prev != nil {
		previousblockhash = blockIndex.Prev.BlockHash.ToString()
	}

	var nextblockhash string
	next := blockchain.GChainActive.Next(blockIndex)
	if next != nil {
		nextblockhash = next.BlockHash.ToString()
	}

	blockHeaderReply := btcjson.GetBlockHeaderVerboseResult{
		Hash:          c.Hash,
		Confirmations: uint64(confirmations),
		Height:        int32(blockIndex.Height),
		Version:       blockIndex.Header.Version,
		VersionHex:    fmt.Sprintf("%08x", blockIndex.Header.Version),
		MerkleRoot:    blockIndex.Header.MerkleRoot.ToString(),
		Time:          blockIndex.Header.Time,
		Mediantime:    blockIndex.GetMedianTimePast(),
		Nonce:         uint64(blockIndex.Header.Nonce),
		Bits:          fmt.Sprintf("%8x", blockIndex.Header.Bits),
		Difficulty:    getDifficulty(blockIndex),
		Chainwork:     blockIndex.ChainWork.Text(16),
		PreviousHash:  previousblockhash,
		NextHash:      nextblockhash,
	}
	return blockHeaderReply, nil
}

func handleGetChainTips(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func getDifficulty(bi *core.BlockIndex) float64 {
	if bi == nil {
		return 1.0
	}
	return getDifficultyFromBits(bi.GetBlockHeader().Bits)
}

// getDifficultyRatio returns the proof-of-work difficulty as a multiple of the
// minimum difficulty using the passed bits field from the header of a block.
func getDifficultyFromBits(bits uint32) float64 {
	shift := bits >> 24 & 0xff
	diff := 0x0000ffff / float64(bits&0x00ffffff)

	for shift < 29 {
		diff *= 256
		shift++
	}

	for shift > 29 {
		diff /= 256
		shift--
	}

	return diff
}

func handleGetDifficulty(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	best := blockchain.GChainActive.Tip()
	return getDifficulty(best), nil
}

func handleGetMempoolAncestors(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func handleGetMempoolDescendants(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func handleGetMempoolInfo(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	maxMempool := utils.GetArg("-maxmempool", int64(policy.DefaultMaxMemPoolSize))
	ret := &btcjson.GetMempoolInfoResult{
		Size:       len(blockchain.GMemPool.PoolData),
		Bytes:      blockchain.GMemPool.TotalTxSize,
		Usage:      blockchain.GMemPool.GetCacheUsage(),
		MaxMempool: maxMempool,
		//MempoolMinFee: valueFromAmount(mempool.GetMinFee(maxMempool)),		// todo realise
	}

	return ret, nil
}

func valueFromAmount(sizeLimit int64) string {
	sign := sizeLimit < 0
	var nAbs int64
	if sign {
		nAbs = -sizeLimit
	} else {
		nAbs = sizeLimit
	}

	quotient := nAbs / utils.COIN
	remainder := nAbs % utils.COIN

	if sign {
		return fmt.Sprintf("-%d.%08d", quotient, remainder)
	}
	return fmt.Sprintf("%d.%08d", quotient, remainder)
}

func handleGetRawMempool(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func handleGetTxOut(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {

	/*	c := cmd.(*btcjson.GetTxOutCmd)

		// Convert the provided transaction hash hex to a Hash.
		txHash, err := utils.GetHashFromStr(c.Txid)
		if err != nil {
			return nil, rpcDecodeHexError(c.Txid)
		}

		vout := c.Vout
		out := core.OutPoint{Hash:*txHash, Index:vout}
		includeMempool := true
		if c.IncludeMempool != nil {
			includeMempool = *c.IncludeMempool
		}

		coin := utxo.Coin{}
		if includeMempool {

		}

		//// TODO: This is racy.  It should attempt to fetch it directly and check
		//// the error.
		//if includeMempool && s.cfg.TxMemPool.HaveTransaction(txHash) {
		//	tx, err := s.cfg.TxMemPool.FetchTransaction(txHash)
		//	if err != nil {
		//		return nil, rpcNoTxInfoError(txHash)
		//	}
		//
		//	mtx := tx.MsgTx()
		//	if c.Vout > uint32(len(mtx.TxOut)-1) {
		//		return nil, &btcjson.RPCError{
		//			Code: btcjson.ErrRPCInvalidTxVout,
		//			Message: "Output index number (vout) does not " +
		//				"exist for transaction.",
		//		}
		//	}
		//
		//	txOut := mtx.TxOut[c.Vout]
		//	if txOut == nil {
		//		errStr := fmt.Sprintf("Output index: %d for txid: %s "+
		//			"does not exist", c.Vout, txHash)
		//		return nil, internalRPCError(errStr, "")
		//	}
		//
		//	best := s.cfg.Chain.BestSnapshot()
		//	bestBlockHash = best.Hash.String()
		//	confirmations = 0
		//	txVersion = mtx.Version
		//	value = txOut.Value
		//	pkScript = txOut.PkScript
		//	isCoinbase = blockchain.IsCoinBaseTx(mtx)
		//} else {
		//	entry, err := s.cfg.Chain.FetchUtxoEntry(txHash)
		//	if err != nil {
		//		return nil, rpcNoTxInfoError(txHash)
		//	}
		//
		//	// To match the behavior of the reference client, return nil
		//	// (JSON null) if the transaction output is spent by another
		//	// transaction already in the main chain.  Mined transactions
		//	// that are spent by a mempool transaction are not affected by
		//	// this.
		//	if entry == nil || entry.IsOutputSpent(c.Vout) {
		//		return nil, nil
		//	}
		//
		//	best := s.cfg.Chain.BestSnapshot()
		//	bestBlockHash = best.Hash.String()
		//	confirmations = 1 + best.Height - entry.BlockHeight()
		//	txVersion = entry.Version()
		//	value = entry.AmountByIndex(c.Vout)
		//	pkScript = entry.PkScriptByIndex(c.Vout)
		//	isCoinbase = entry.IsCoinBase()
		//}

		// Disassemble script into single line printable format.
		// The disassembled string will contain [error] inline if the script
		// doesn't fully parse, so ignore the error here.
		disbuf, _ := txscript.DisasmString(pkScript)

		// Get further info about the script.
		// Ignore the error here since an error means the script couldn't parse
		// and there is no additional information about it anyways.
		scriptClass, addrs, reqSigs, _ := txscript.ExtractPkScriptAddrs(pkScript,
			s.cfg.ChainParams)
		addresses := make([]string, len(addrs))
		for i, addr := range addrs {
			addresses[i] = addr.EncodeAddress()
		}

		txOutReply := &btcjson.GetTxOutResult{
			BestBlock:     bestBlockHash,
			Confirmations: int64(confirmations),
			Value:         btcutil.Amount(value).ToBTC(),
			Version:       txVersion,
			ScriptPubKey: btcjson.ScriptPubKeyResult{
				Asm:       disbuf,
				Hex:       hex.EncodeToString(pkScript),
				ReqSigs:   int32(reqSigs),
				Type:      scriptClass.String(),
				Addresses: addresses,
			},
			Coinbase: isCoinbase,
		}
		return txOutReply, nil*/

	return nil, nil
}

func handleGetTxoutSetInfo(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func getPrunMode() (bool, error) {
	pruneArg := utils.GetArg("-prune", 0)
	if pruneArg < 0 {
		return false, errors.New("Prune cannot be configured with a negative value")
	}
	return true, nil
}

func handlePruneBlockChain(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	pruneMode, err := getPrunMode()

	if err != nil && !pruneMode {
		return false, &btcjson.RPCError{
			Code:    btcjson.ErrRPCType,
			Message: fmt.Sprintf("Cannot prune blocks because node is not in prune mode."),
		}
	}

	c := cmd.(*btcjson.PruneBlockChainCmd)
	height := c.Height
	if *height < 0 {
		return false, &btcjson.RPCError{
			Code:    btcjson.ErrRPCType,
			Message: fmt.Sprintf("Negative block height."),
		}
	}

	if *height > 1000000000 {
		var index *core.BlockIndex
		index = blockchain.GChainActive.FindEarliestAtLeast(int64(*height - 72000))
		if index != nil {
			return false, &btcjson.RPCError{
				Code:    btcjson.ErrRPCType,
				Message: fmt.Sprintf("Could not find block with at least the specified timestamp."),
			}
		}
		height = &index.Height
	}

	h := *height
	var chainHeight int
	chainHeight = blockchain.GChainActive.Height()
	if chainHeight < msg.ActiveNetParams.PruneAfterHeight {
		return false, &btcjson.RPCError{
			Code:    btcjson.ErrRPCMisc,
			Message: fmt.Sprintf("Blockchain is too short for pruning."),
		}
	} else if h > chainHeight {
		return false, &btcjson.RPCError{
			Code:    btcjson.ErrRPCInvalidParameter,
			Message: fmt.Sprintf("Blockchain is shorter than the attempted prune height."),
		}
	} /*else if h > chainHeight - MIN_BLOCKS_TO_KEEP {
		h = chainHeight - MIN_BLOCKS_TO_KEEP
	}*/// TODO realise

	blockchain.PruneBlockFilesManual(*height)
	return uint64(*height), nil
}

// handleVerifyChain implements the verifychain command.
func handleVerifyChain(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {

	/*	c := cmd.(*btcjson.VerifyChainCmd)

		var checkLevel, checkDepth int32
		if c.CheckLevel != nil {
			checkLevel = *c.CheckLevel
		}
		if c.CheckDepth != nil {
			checkDepth = *c.CheckDepth
		}

		err := verifyChain(s, checkLevel, checkDepth)

		return err == nil, nil*/// TODO realise
	return nil, nil
}

func handlePreciousblock(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	c := cmd.(*btcjson.PreciousBlockCmd)
	hash, err := utils.GetHashFromStr(c.BlockHash)
	if err != nil {
		return nil, err
	}
	blockIndex := blockchain.GChainActive.FetchBlockIndexByHash(hash)
	if blockIndex == nil {
		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCBlockNotFound,
			Message: "Block not found",
		}
	}
	state := core.ValidationState{}
	blockchain.PreciousBlock(msg.ActiveNetParams, &state, blockIndex)
	if !state.IsValid() {

	}
	return nil, nil
}

func handlInvalidateBlock(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	//c := cmd.(*btcjson.InvalidateBlockCmd)
	//hash, _ := utils.GetHashFromStr(c.BlockHash)
	state := core.ValidationState{}

	if len(blockchain.MapBlockIndex.Data) == 0 {
		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCInvalidAddressOrKey,
			Message: "Block not found",
		}

		//blkIndex := blockchain.MapBlockIndex.Data[*hash]
		//blockchain.InvalidateBlock()                  // TODO
	}
	if state.IsValid() {
		//blockchain.ActivateBestChain()        // TODO
	}

	if state.IsInvalid() {
		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCDatabase,
			Message: state.GetRejectReason(),
		}
	}

	return nil, nil
}

func handleReconsiderBlock(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	c := cmd.(*btcjson.ReconsiderBlockCmd)
	hash, _ := utils.GetHashFromStr(c.BlockHash)

	if len(blockchain.MapBlockIndex.Data) == 0 {
		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCInvalidAddressOrKey,
			Message: "Block not found",
		}

		blkIndex := blockchain.MapBlockIndex.Data[*hash]
		blockchain.ResetBlockFailureFlags(blkIndex)
	}

	state := core.ValidationState{}
	//blockchain.ActivateBestChain()             //TODO

	if state.IsInvalid() {
		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCDatabase,
			Message: state.GetRejectReason(),
		}
	}
	return nil, nil
}

func handleWaitForNewBlock(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func handleWaitForBlock(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func handleWaitForBlockHeight(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func registerBlockchainRPCCommands() {
	for name, handler := range blockchainHandlers {
		appendCommand(name, handler)
	}
}
