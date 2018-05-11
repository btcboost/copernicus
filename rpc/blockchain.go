package rpc

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/btcboost/copernicus/blockchain"
	"github.com/btcboost/copernicus/btcjson"
	"github.com/btcboost/copernicus/core"
	"github.com/btcboost/copernicus/net/msg"
	"github.com/btcboost/copernicus/utils"
)

var blockchainHandlers = map[string]commandHandler{
	"getblockchaininfo":     handleGetBlockChainInfo,
	"getbestblockhash":      handleGetBestBlockHash,
	"getblockcount":         handleGetBlockCount,
	"getblock":              handleGetBlock,
	"getblockhash":          handleGetBlockHash,
	"getblockheader":        handleGetblockheader, // complete
	"getchaintips":          handleGetchaintips,
	"getdifficulty":         handleGetdifficulty, //complete
	"getmempoolancestors":   handleGetmempoolancestors,
	"getmempooldescendants": handleGetmempooldescendants,
	"getmempoolinfo":        handleGetmempoolinfo,
	"getrawmempool":         handleGetrawmempool,
	"gettxout":              handleGetTxOut,
	"gettxoutsetinfo":       handleGettxoutsetinfo,
	"pruneblockchain":       handlePruneblockchain,
	"verifychain":           handleVerifychain,
	"preciousblock":         handlePreciousblock,

	/*not shown in help*/
	"invalidateblock":    handlenvalidateblock,
	"reconsiderblock":    handleReconsiderblock,
	"waitfornewblock":    handleWaitfornewblock,
	"waitforblock":       handleWaitforblock,
	"waitforblockheight": handleWaitforblockheight,
}

func handleGetBlockChainInfo(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	/*
		// Obtain a snapshot of the current best known blockchain state. We'll
		// populate the response to this call primarily from this snapshot.
		params := s.cfg.ChainParams
		chain := s.cfg.Chain
		chainSnapshot := chain.BestSnapshot()

		chainInfo := &btcjson.GetBlockChainInfoResult{
			Chain:         params.Name,
			Blocks:        chainSnapshot.Height,
			Headers:       chainSnapshot.Height,
			BestBlockHash: chainSnapshot.Hash.String(),
			Difficulty:    getDifficultyRatio(chainSnapshot.Bits, params),
			MedianTime:    chainSnapshot.MedianTime.Unix(),
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
				ID:      "bip66",f
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
	/*
		best := s.cfg.Chain.BestSnapshot()
		return best.Hash.String(), nil
	*/
	return nil, nil
}

func handleGetBlockCount(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	/*
		best := s.cfg.Chain.BestSnapshot()
		return int64(best.Height), nil
	*/
	return nil, nil
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
	/*
		c := cmd.(*btcjson.GetBlockCmd)

		// Load the raw block bytes from the database.
		hash, err := chainhash.NewHashFromStr(c.Hash)
		if err != nil {
			return nil, rpcDecodeHexError(c.Hash)
		}
		var blkBytes []byte
		err = s.cfg.DB.View(func(dbTx database.Tx) error {
			var err error
			blkBytes, err = dbTx.FetchBlock(hash)
			return err
		})
		if err != nil {
			return nil, &btcjson.RPCError{
				Code:    btcjson.ErrRPCBlockNotFound,
				Message: "Block not found",
			}
		}

		// When the verbose flag isn't set, simply return the serialized block
		// as a hex-encoded string.
		if c.Verbose != nil && !*c.Verbose {
			return hex.EncodeToString(blkBytes), nil
		}

		// The verbose flag is set, so generate the JSON object and return it.

		// Deserialize the block.
		blk, err := btcutil.NewBlockFromBytes(blkBytes)
		if err != nil {
			context := "Failed to deserialize block"
			return nil, internalRPCError(err.Error(), context)
		}

		// Get the block height from chain.
		blockHeight, err := s.cfg.Chain.BlockHeightByHash(hash)
		if err != nil {
			context := "Failed to obtain block height"
			return nil, internalRPCError(err.Error(), context)
		}
		blk.SetHeight(blockHeight)
		best := s.cfg.Chain.BestSnapshot()

		// Get next block hash unless there are none.
		var nextHashString string
		if blockHeight < best.Height {
			nextHash, err := s.cfg.Chain.BlockHashByHeight(blockHeight + 1)
			if err != nil {
				context := "No next block"
				return nil, internalRPCError(err.Error(), context)
			}
			nextHashString = nextHash.String()
		}

		params := s.cfg.ChainParams
		blockHeader := &blk.MsgBlock().Header
		blockReply := btcjson.GetBlockVerboseResult{
			Hash:          c.Hash,
			Version:       blockHeader.Version,
			VersionHex:    fmt.Sprintf("%08x", blockHeader.Version),
			MerkleRoot:    blockHeader.MerkleRoot.String(),
			PreviousHash:  blockHeader.PrevBlock.String(),
			Nonce:         blockHeader.Nonce,
			Time:          blockHeader.Timestamp.Unix(),
			Confirmations: uint64(1 + best.Height - blockHeight),
			Height:        int64(blockHeight),
			Size:          int32(len(blkBytes)),
			StrippedSize:  int32(blk.MsgBlock().SerializeSizeStripped()),
			Weight:        int32(blockchain.GetBlockWeight(blk)),
			Bits:          strconv.FormatInt(int64(blockHeader.Bits), 16),
			Difficulty:    getDifficultyRatio(blockHeader.Bits, params),
			NextHash:      nextHashString,
		}

		if c.VerboseTx == nil || !*c.VerboseTx {
			transactions := blk.Transactions()
			txNames := make([]string, len(transactions))
			for i, tx := range transactions {
				txNames[i] = tx.Hash().String()
			}

			blockReply.Tx = txNames
		} else {
			txns := blk.Transactions()
			rawTxns := make([]btcjson.TxRawResult, len(txns))
			for i, tx := range txns {
				rawTxn, err := createTxRawResult(params, tx.MsgTx(),
					tx.Hash().String(), blockHeader, hash.String(),
					blockHeight, best.Height)
				if err != nil {
					return nil, err
				}
				rawTxns[i] = *rawTxn
			}
			blockReply.RawTx = rawTxns
		}

		return blockReply, nil
	*/
	return nil, nil
}

func handleGetBlockHash(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	/*
		c := cmd.(*btcjson.GetBlockHashCmd)
		hash, err := s.cfg.Chain.BlockHashByHeight(int32(c.Index))
		if err != nil {
			return nil, &btcjson.RPCError{
				Code:    btcjson.ErrRPCOutOfRange,
				Message: "Block number out of range",
			}
		}

		return hash.String(), nil
	*/
	return nil, nil
}

func handleGetblockheader(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
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

func handleGetchaintips(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func handleGetdifficulty(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	best := blockchain.GChainActive.Tip()
	return getDifficulty(best), nil
}

func handleGetmempoolancestors(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func handleGetmempooldescendants(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func handleGetmempoolinfo(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	/*
		mempoolTxns := s.cfg.TxMemPool.TxDescs()

		var numBytes int64
		for _, txD := range mempoolTxns {
			numBytes += int64(txD.Tx.MsgTx().SerializeSize())
		}

		ret := &btcjson.GetMempoolInfoResult{
			Size:  int64(len(mempoolTxns)),
			Bytes: numBytes,
		}

		return ret, nil
	*/
	return nil, nil
}

func handleGetrawmempool(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func handleGetTxOut(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	/*
		c := cmd.(*btcjson.GetTxOutCmd)

		// Convert the provided transaction hash hex to a Hash.
		txHash, err := chainhash.NewHashFromStr(c.Txid)
		if err != nil {
			return nil, rpcDecodeHexError(c.Txid)
		}

		// If requested and the tx is available in the mempool try to fetch it
		// from there, otherwise attempt to fetch from the block database.
		var bestBlockHash string
		var confirmations int32
		var txVersion int32
		var value int64
		var pkScript []byte
		var isCoinbase bool
		includeMempool := true
		if c.IncludeMempool != nil {
			includeMempool = *c.IncludeMempool
		}
		// TODO: This is racy.  It should attempt to fetch it directly and check
		// the error.
		if includeMempool && s.cfg.TxMemPool.HaveTransaction(txHash) {
			tx, err := s.cfg.TxMemPool.FetchTransaction(txHash)
			if err != nil {
				return nil, rpcNoTxInfoError(txHash)
			}

			mtx := tx.MsgTx()
			if c.Vout > uint32(len(mtx.TxOut)-1) {
				return nil, &btcjson.RPCError{
					Code: btcjson.ErrRPCInvalidTxVout,
					Message: "Output index number (vout) does not " +
						"exist for transaction.",
				}
			}

			txOut := mtx.TxOut[c.Vout]
			if txOut == nil {
				errStr := fmt.Sprintf("Output index: %d for txid: %s "+
					"does not exist", c.Vout, txHash)
				return nil, internalRPCError(errStr, "")
			}

			best := s.cfg.Chain.BestSnapshot()
			bestBlockHash = best.Hash.String()
			confirmations = 0
			txVersion = mtx.Version
			value = txOut.Value
			pkScript = txOut.PkScript
			isCoinbase = blockchain.IsCoinBaseTx(mtx)
		} else {
			entry, err := s.cfg.Chain.FetchUtxoEntry(txHash)
			if err != nil {
				return nil, rpcNoTxInfoError(txHash)
			}

			// To match the behavior of the reference client, return nil
			// (JSON null) if the transaction output is spent by another
			// transaction already in the main chain.  Mined transactions
			// that are spent by a mempool transaction are not affected by
			// this.
			if entry == nil || entry.IsOutputSpent(c.Vout) {
				return nil, nil
			}

			best := s.cfg.Chain.BestSnapshot()
			bestBlockHash = best.Hash.String()
			confirmations = 1 + best.Height - entry.BlockHeight()
			txVersion = entry.Version()
			value = entry.AmountByIndex(c.Vout)
			pkScript = entry.PkScriptByIndex(c.Vout)
			isCoinbase = entry.IsCoinBase()
		}

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
		return txOutReply, nil
	*/
	return nil, nil
}

func handleGettxoutsetinfo(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func handlePruneblockchain(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

/*func verifyChain(s *Server, level, depth int32) error {
	best := s.cfg.Chain.BestSnapshot()
	finishHeight := best.Height - depth
	if finishHeight < 0 {
		finishHeight = 0
	}
	logs.Info("Verifying chain for %d blocks at level %d",
		best.Height-finishHeight, level)

	for height := best.Height; height > finishHeight; height-- {
		// Level 0 just looks up the block.
		block, err := s.cfg.Chain.BlockByHeight(height)
		if err != nil {
			logs.Error("Verify is unable to fetch block at "+
				"height %d: %v", height, err)
			return err
		}

		// Level 1 does basic chain sanity checks.
		if level > 0 {
			err := blockchain.CheckBlockSanity(block,
				s.cfg.ChainParams.PowLimit, s.cfg.TimeSource)
			if err != nil {
				logs.Error("Verify is unable to validate "+
					"block at hash %v height %d: %v",
					block.Hash(), height, err)
				return err
			}
		}
	}
	logs.Info("Chain verify completed successfully")

	return nil
}*/ // todo open

// handleVerifyChain implements the verifychain command.
func handleVerifychain(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	/*
		c := cmd.(*btcjson.VerifyChainCmd)

		var checkLevel, checkDepth int32
		if c.CheckLevel != nil {
			checkLevel = *c.CheckLevel
		}
		if c.CheckDepth != nil {
			checkDepth = *c.CheckDepth
		}

		err := verifyChain(s, checkLevel, checkDepth)
		return err == nil, nil
	*/
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

func handlenvalidateblock(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func handleReconsiderblock(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func handleWaitfornewblock(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func handleWaitforblock(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func handleWaitforblockheight(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func registerBlockchainRPCCommands() {
	for name, handler := range blockchainHandlers {
		appendCommand(name, handler)
	}
}
