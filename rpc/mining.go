package rpc

var miningHandlers = map[string]commandHandler{
	"getnetworkhashps":      handleGetnetworkhashps,
	"getmininginfo":         handleGetMiningInfo,
	"prioritisetransaction": handlePrioritisetransaction,
	"getblocktemplate":      handleGetblocktemplate,
	"submitblock":           handleSubmitblock,
	"generate":              handleGenerate,
	"generatetoaddress":     handleGeneratetoaddress,
	"estimatefee":           handleEstimatefee,
	"estimatepriority":      handleEstimatepriority,
	"estimatesmartfee":      handleEstimatesmartfee,
	"estimatesmartpriority": handleEstimatesmartpriority,
}

func handleGetnetworkhashps(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	// handleGetNetworkHashPS implements the getnetworkhashps command.
	/*
		// Note: All valid error return paths should return an int64.
		// Literal zeros are inferred as int, and won't coerce to int64
		// because the return value is an interface{}.

		c := cmd.(*btcjson.GetNetworkHashPSCmd)

		// When the passed height is too high or zero, just return 0 now
		// since we can't reasonably calculate the number of network hashes
		// per second from invalid values.  When it's negative, use the current
		// best block height.
		best := s.cfg.Chain.BestSnapshot()
		endHeight := int32(-1)
		if c.Height != nil {
			endHeight = int32(*c.Height)
		}
		if endHeight > best.Height || endHeight == 0 {
			return int64(0), nil
		}
		if endHeight < 0 {
			endHeight = best.Height
		}

		// Calculate the number of blocks per retarget interval based on the
		// chain parameters.
		blocksPerRetarget := int32(s.cfg.ChainParams.TargetTimespan /
			s.cfg.ChainParams.TargetTimePerBlock)

		// Calculate the starting block height based on the passed number of
		// blocks.  When the passed value is negative, use the last block the
		// difficulty changed as the starting height.  Also make sure the
		// starting height is not before the beginning of the chain.
		numBlocks := int32(120)
		if c.Blocks != nil {
			numBlocks = int32(*c.Blocks)
		}
		var startHeight int32
		if numBlocks <= 0 {
			startHeight = endHeight - ((endHeight % blocksPerRetarget) + 1)
		} else {
			startHeight = endHeight - numBlocks
		}
		if startHeight < 0 {
			startHeight = 0
		}
		logs.Debugf("Calculating network hashes per second from %d to %d",
			startHeight, endHeight)

		// Find the min and max block timestamps as well as calculate the total
		// amount of work that happened between the start and end blocks.
		var minTimestamp, maxTimestamp time.Time
		totalWork := big.NewInt(0)
		for curHeight := startHeight; curHeight <= endHeight; curHeight++ {
			hash, err := s.cfg.Chain.BlockHashByHeight(curHeight)
			if err != nil {
				context := "Failed to fetch block hash"
				return nil, internalRPCError(err.Error(), context)
			}

			// Fetch the header from chain.
			header, err := s.cfg.Chain.FetchHeader(hash)
			if err != nil {
				context := "Failed to fetch block header"
				return nil, internalRPCError(err.Error(), context)
			}

			if curHeight == startHeight {
				minTimestamp = header.Timestamp
				maxTimestamp = minTimestamp
			} else {
				totalWork.Add(totalWork, blockchain.CalcWork(header.Bits))

				if minTimestamp.After(header.Timestamp) {
					minTimestamp = header.Timestamp
				}
				if maxTimestamp.Before(header.Timestamp) {
					maxTimestamp = header.Timestamp
				}
			}
		}

		// Calculate the difference in seconds between the min and max block
		// timestamps and avoid division by zero in the case where there is no
		// time difference.
		timeDiff := int64(maxTimestamp.Sub(minTimestamp) / time.Second)
		if timeDiff == 0 {
			return int64(0), nil
		}

		hashesPerSec := new(big.Int).Div(totalWork, big.NewInt(timeDiff))
		return hashesPerSec.Int64(), nil
	*/
	return nil, nil
}

func handleGetMiningInfo(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	// handleGetMiningInfo implements the getmininginfo command. We only return the
	// fields that are not related to wallet functionality.
	/*
		// Create a default getnetworkhashps command to use defaults and make
		// use of the existing getnetworkhashps handler.
		gnhpsCmd := btcjson.NewGetNetworkHashPSCmd(nil, nil)
		networkHashesPerSecIface, err := handleGetNetworkHashPS(s, gnhpsCmd,
			closeChan)
		if err != nil {
			return nil, err
		}
		networkHashesPerSec, ok := networkHashesPerSecIface.(int64)
		if !ok {
			return nil, &btcjson.RPCError{
				Code:    btcjson.ErrRPCInternal.Code,
				Message: "networkHashesPerSec is not an int64",
			}
		}

		best := s.cfg.Chain.BestSnapshot()
		result := btcjson.GetMiningInfoResult{
			Blocks:             int64(best.Height),
			CurrentBlockSize:   best.BlockSize,
			CurrentBlockWeight: best.BlockWeight,
			CurrentBlockTx:     best.NumTxns,
			Difficulty:         getDifficultyRatio(best.Bits, s.cfg.ChainParams),
			Generate:           s.cfg.CPUMiner.IsMining(),
			GenProcLimit:       s.cfg.CPUMiner.NumWorkers(),
			HashesPerSec:       int64(s.cfg.CPUMiner.HashesPerSecond()),
			NetworkHashPS:      networkHashesPerSec,
			PooledTx:           uint64(s.cfg.TxMemPool.Count()),
			TestNet:            cfg.TestNet3,
		}
		return &result, nil
	*/
	return nil, nil
}

func handlePrioritisetransaction(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

// handleGetBlockTemplateRequest is a helper for handleGetBlockTemplate which
// deals with generating and returning block templates to the caller.  It
// handles both long poll requests as specified by BIP 0022 as well as regular
// requests.  In addition, it detects the capabilities reported by the caller
// in regards to whether or not it supports creating its own coinbase (the
// coinbasetxn and coinbasevalue capabilities) and modifies the returned block
// template accordingly.
/*
func handleGetBlockTemplateRequest(s *Server, request *btcjson.TemplateRequest, closeChan <-chan struct{}) (interface{}, error) {
	// Extract the relevant passed capabilities and restrict the result to
	// either a coinbase value or a coinbase transaction object depending on
	// the request.  Default to only providing a coinbase value.
	useCoinbaseValue := true
	if request != nil {
		var hasCoinbaseValue, hasCoinbaseTxn bool
		for _, capability := range request.Capabilities {
			switch capability {
			case "coinbasetxn":
				hasCoinbaseTxn = true
			case "coinbasevalue":
				hasCoinbaseValue = true
			}
		}

		if hasCoinbaseTxn && !hasCoinbaseValue {
			useCoinbaseValue = false
		}
	}

	// When a coinbase transaction has been requested, respond with an error
	// if there are no addresses to pay the created block template to.
	if !useCoinbaseValue && len(cfg.miningAddrs) == 0 {
		return nil, &btcjson.RPCError{
			Code: btcjson.ErrRPCInternal.Code,
			Message: "A coinbase transaction has been requested, " +
				"but the server has not been configured with " +
				"any payment addresses via --miningaddr",
		}
	}

	// Return an error if there are no peers connected since there is no
	// way to relay a found block or receive transactions to work on.
	// However, allow this state when running in the regression test or
	// simulation test mode.
	if !(cfg.RegressionTest || cfg.SimNet) &&
		s.cfg.ConnMgr.ConnectedCount() == 0 {

		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCClientNotConnected,
			Message: "Bitcoin is not connected",
		}
	}

	// No point in generating or accepting work before the chain is synced.
	currentHeight := s.cfg.Chain.BestSnapshot().Height
	if currentHeight != 0 && !s.cfg.SyncMgr.IsCurrent() {
		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCClientInInitialDownload,
			Message: "Bitcoin is downloading blocks...",
		}
	}

	// When a long poll ID was provided, this is a long poll request by the
	// client to be notified when block template referenced by the ID should
	// be replaced with a new one.
	if request != nil && request.LongPollID != "" {
		return handleGetBlockTemplateLongPoll(s, request.LongPollID,
			useCoinbaseValue, closeChan)
	}

	// Protect concurrent access when updating block templates.
	state := s.gbtWorkState
	state.Lock()
	defer state.Unlock()

	// Get and return a block template.  A new block template will be
	// generated when the current best block has changed or the transactions
	// in the memory pool have been updated and it has been at least five
	// seconds since the last template was generated.  Otherwise, the
	// timestamp for the existing block template is updated (and possibly
	// the difficulty on testnet per the consesus rules).
	if err := state.updateBlockTemplate(s, useCoinbaseValue); err != nil {
		return nil, err
	}
	return state.blockTemplateResult(useCoinbaseValue, nil)
}
*/

// updateBlockTemplate creates or updates a block template for the work state.
// A new block template will be generated when the current best block has
// changed or the transactions in the memory pool have been updated and it has
// been long enough since the last template was generated.  Otherwise, the
// timestamp for the existing block template is updated (and possibly the
// difficulty on testnet per the consesus rules).  Finally, if the
// useCoinbaseValue flag is false and the existing block template does not
// already contain a valid payment address, the block template will be updated
// with a randomly selected payment address from the list of configured
// addresses.
//
// This function MUST be called with the state locked.
/*
func (state *gbtWorkState) updateBlockTemplate(s *Server, useCoinbaseValue bool) error {
	generator := s.cfg.Generator
	lastTxUpdate := generator.TxSource().LastUpdated()
	if lastTxUpdate.IsZero() {
		lastTxUpdate = time.Now()
	}

	// Generate a new block template when the current best block has
	// changed or the transactions in the memory pool have been updated and
	// it has been at least gbtRegenerateSecond since the last template was
	// generated.
	var msgBlock *wire.MsgBlock
	var targetDifficulty string
	latestHash := &s.cfg.Chain.BestSnapshot().Hash
	template := state.template
	if template == nil || state.prevHash == nil ||
		!state.prevHash.IsEqual(latestHash) ||
		(state.lastTxUpdate != lastTxUpdate &&
			time.Now().After(state.lastGenerated.Add(time.Second*
				gbtRegenerateSeconds))) {

		// Reset the previous best hash the block template was generated
		// against so any errors below cause the next invocation to try
		// again.
		state.prevHash = nil

		// Choose a payment address at random if the caller requests a
		// full coinbase as opposed to only the pertinent details needed
		// to create their own coinbase.
		var payAddr btcutil.Address
		if !useCoinbaseValue {
			payAddr = cfg.miningAddrs[rand.Intn(len(cfg.miningAddrs))]
		}

		// Create a new block template that has a coinbase which anyone
		// can redeem.  This is only acceptable because the returned
		// block template doesn't include the coinbase, so the caller
		// will ultimately create their own coinbase which pays to the
		// appropriate address(es).
		blkTemplate, err := generator.NewBlockTemplate(payAddr)
		if err != nil {
			return internalRPCError("Failed to create new block "+
				"template: "+err.Error(), "")
		}
		template = blkTemplate
		msgBlock = template.Block
		targetDifficulty = fmt.Sprintf("%064x",
			blockchain.CompactToBig(msgBlock.Header.Bits))

		// Get the minimum allowed timestamp for the block based on the
		// median timestamp of the last several blocks per the chain
		// consensus rules.
		best := s.cfg.Chain.BestSnapshot()
		minTimestamp := mining.MinimumMedianTime(best)

		// Update work state to ensure another block template isn't
		// generated until needed.
		state.template = template
		state.lastGenerated = time.Now()
		state.lastTxUpdate = lastTxUpdate
		state.prevHash = latestHash
		state.minTimestamp = minTimestamp

		logs.Debugf("Generated block template (timestamp %v, "+
			"target %s, merkle root %s)",
			msgBlock.Header.Timestamp, targetDifficulty,
			msgBlock.Header.MerkleRoot)

		// Notify any clients that are long polling about the new
		// template.
		state.notifyLongPollers(latestHash, lastTxUpdate)
	} else {
		// At this point, there is a saved block template and another
		// request for a template was made, but either the available
		// transactions haven't change or it hasn't been long enough to
		// trigger a new block template to be generated.  So, update the
		// existing block template.

		// When the caller requires a full coinbase as opposed to only
		// the pertinent details needed to create their own coinbase,
		// add a payment address to the output of the coinbase of the
		// template if it doesn't already have one.  Since this requires
		// mining addresses to be specified via the config, an error is
		// returned if none have been specified.
		if !useCoinbaseValue && !template.ValidPayAddress {
			// Choose a payment address at random.
			payToAddr := cfg.miningAddrs[rand.Intn(len(cfg.miningAddrs))]

			// Update the block coinbase output of the template to
			// pay to the randomly selected payment address.
			pkScript, err := txscript.PayToAddrScript(payToAddr)
			if err != nil {
				context := "Failed to create pay-to-addr script"
				return internalRPCError(err.Error(), context)
			}
			template.Block.Transactions[0].TxOut[0].PkScript = pkScript
			template.ValidPayAddress = true

			// Update the merkle root.
			block := btcutil.NewBlock(template.Block)
			merkles := blockchain.BuildMerkleTreeStore(block.Transactions(), false)
			template.Block.Header.MerkleRoot = *merkles[len(merkles)-1]
		}

		// Set locals for convenience.
		msgBlock = template.Block
		targetDifficulty = fmt.Sprintf("%064x",
			blockchain.CompactToBig(msgBlock.Header.Bits))

		// Update the time of the block template to the current time
		// while accounting for the median time of the past several
		// blocks per the chain consensus rules.
		generator.UpdateBlockTime(msgBlock)
		msgBlock.Header.Nonce = 0

		logs.Debugf("Updated block template (timestamp %v, "+
			"target %s)", msgBlock.Header.Timestamp,
			targetDifficulty)
	}

	return nil
}
*/

// blockTemplateResult returns the current block template associated with the
// state as a btcjson.GetBlockTemplateResult that is ready to be encoded to JSON
// and returned to the caller.
//
// This function MUST be called with the state locked.
/*
func (state *gbtWorkState) blockTemplateResult(useCoinbaseValue bool, submitOld *bool) (*btcjson.GetBlockTemplateResult, error) {
	// Ensure the timestamps are still in valid range for the template.
	// This should really only ever happen if the local clock is changed
	// after the template is generated, but it's important to avoid serving
	// invalid block templates.
	template := state.template
	msgBlock := template.Block
	header := &msgBlock.Header
	adjustedTime := state.timeSource.AdjustedTime()
	maxTime := adjustedTime.Add(time.Second * blockchain.MaxTimeOffsetSeconds)
	if header.Timestamp.After(maxTime) {
		return nil, &btcjson.RPCError{
			Code: btcjson.ErrRPCOutOfRange,
			Message: fmt.Sprintf("The template time is after the "+
				"maximum allowed time for a block - template "+
				"time %v, maximum time %v", adjustedTime,
				maxTime),
		}
	}

	// Convert each transaction in the block template to a template result
	// transaction.  The result does not include the coinbase, so notice
	// the adjustments to the various lengths and indices.
	numTx := len(msgBlock.Transactions)
	transactions := make([]btcjson.GetBlockTemplateResultTx, 0, numTx-1)
	txIndex := make(map[chainhash.Hash]int64, numTx)
	for i, tx := range msgBlock.Transactions {
		txHash := tx.TxHash()
		txIndex[txHash] = int64(i)

		// Skip the coinbase transaction.
		if i == 0 {
			continue
		}

		// Create an array of 1-based indices to transactions that come
		// before this one in the transactions list which this one
		// depends on.  This is necessary since the created block must
		// ensure proper ordering of the dependencies.  A map is used
		// before creating the final array to prevent duplicate entries
		// when multiple inputs reference the same transaction.
		dependsMap := make(map[int64]struct{})
		for _, txIn := range tx.TxIn {
			if idx, ok := txIndex[txIn.PreviousOutPoint.Hash]; ok {
				dependsMap[idx] = struct{}{}
			}
		}
		depends := make([]int64, 0, len(dependsMap))
		for idx := range dependsMap {
			depends = append(depends, idx)
		}

		// Serialize the transaction for later conversion to hex.
		txBuf := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))
		if err := tx.Serialize(txBuf); err != nil {
			context := "Failed to serialize transaction"
			return nil, internalRPCError(err.Error(), context)
		}

		bTx := btcutil.NewTx(tx)
		resultTx := btcjson.GetBlockTemplateResultTx{
			Data:    hex.EncodeToString(txBuf.Bytes()),
			Hash:    txHash.String(),
			Depends: depends,
			Fee:     template.Fees[i],
			SigOps:  template.SigOpCosts[i],
			Weight:  blockchain.GetTransactionWeight(bTx),
		}
		transactions = append(transactions, resultTx)
	}

	// Generate the block template reply.  Note that following mutations are
	// implied by the included or omission of fields:
	//  Including MinTime -> time/decrement
	//  Omitting CoinbaseTxn -> coinbase, generation
	targetDifficulty := fmt.Sprintf("%064x", blockchain.CompactToBig(header.Bits))
	templateID := encodeTemplateID(state.prevHash, state.lastGenerated)
	reply := btcjson.GetBlockTemplateResult{
		Bits:         strconv.FormatInt(int64(header.Bits), 16),
		CurTime:      header.Timestamp.Unix(),
		Height:       int64(template.Height),
		PreviousHash: header.PrevBlock.String(),
		WeightLimit:  blockchain.MaxBlockWeight,
		SigOpLimit:   blockchain.MaxBlockSigOpsCost,
		SizeLimit:    wire.MaxBlockPayload,
		Transactions: transactions,
		Version:      header.Version,
		LongPollID:   templateID,
		SubmitOld:    submitOld,
		Target:       targetDifficulty,
		MinTime:      state.minTimestamp.Unix(),
		MaxTime:      maxTime.Unix(),
		Mutable:      gbtMutableFields,
		NonceRange:   gbtNonceRange,
		Capabilities: gbtCapabilities,
	}
	// If the generated block template includes transactions with witness
	// data, then include the witness commitment in the GBT result.
	if template.WitnessCommitment != nil {
		reply.DefaultWitnessCommitment = hex.EncodeToString(template.WitnessCommitment)
	}

	if useCoinbaseValue {
		reply.CoinbaseAux = gbtCoinbaseAux
		reply.CoinbaseValue = &msgBlock.Transactions[0].TxOut[0].Value
	} else {
		// Ensure the template has a valid payment address associated
		// with it when a full coinbase is requested.
		if !template.ValidPayAddress {
			return nil, &btcjson.RPCError{
				Code: btcjson.ErrRPCInternal.Code,
				Message: "A coinbase transaction has been " +
					"requested, but the server has not " +
					"been configured with any payment " +
					"addresses via --miningaddr",
			}
		}

		// Serialize the transaction for conversion to hex.
		tx := msgBlock.Transactions[0]
		txBuf := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))
		if err := tx.Serialize(txBuf); err != nil {
			context := "Failed to serialize transaction"
			return nil, internalRPCError(err.Error(), context)
		}

		resultTx := btcjson.GetBlockTemplateResultTx{
			Data:    hex.EncodeToString(txBuf.Bytes()),
			Hash:    tx.TxHash().String(),
			Depends: []int64{},
			Fee:     template.Fees[0],
			SigOps:  template.SigOpCosts[0],
		}

		reply.CoinbaseTxn = &resultTx
	}

	return &reply, nil
}
*/

// handleGetBlockTemplateLongPoll is a helper for handleGetBlockTemplateRequest
// which deals with handling long polling for block templates.  When a caller
// sends a request with a long poll ID that was previously returned, a response
// is not sent until the caller should stop working on the previous block
// template in favor of the new one.  In particular, this is the case when the
// old block template is no longer valid due to a solution already being found
// and added to the block chain, or new transactions have shown up and some time
// has passed without finding a solution.
//
// See https://en.bitcoin.it/wiki/BIP_0022 for more details.
/*
func handleGetBlockTemplateLongPoll(s *Server, longPollID string, useCoinbaseValue bool, closeChan <-chan struct{}) (interface{}, error) {
	state := s.gbtWorkState
	state.Lock()
	// The state unlock is intentionally not deferred here since it needs to
	// be manually unlocked before waiting for a notification about block
	// template changes.

	if err := state.updateBlockTemplate(s, useCoinbaseValue); err != nil {
		state.Unlock()
		return nil, err
	}

	// Just return the current block template if the long poll ID provided by
	// the caller is invalid.
	prevHash, lastGenerated, err := decodeTemplateID(longPollID)
	if err != nil {
		result, err := state.blockTemplateResult(useCoinbaseValue, nil)
		if err != nil {
			state.Unlock()
			return nil, err
		}

		state.Unlock()
		return result, nil
	}

	// Return the block template now if the specific block template
	// identified by the long poll ID no longer matches the current block
	// template as this means the provided template is stale.
	prevTemplateHash := &state.template.Block.Header.PrevBlock
	if !prevHash.IsEqual(prevTemplateHash) ||
		lastGenerated != state.lastGenerated.Unix() {

		// Include whether or not it is valid to submit work against the
		// old block template depending on whether or not a solution has
		// already been found and added to the block chain.
		submitOld := prevHash.IsEqual(prevTemplateHash)
		result, err := state.blockTemplateResult(useCoinbaseValue,
			&submitOld)
		if err != nil {
			state.Unlock()
			return nil, err
		}

		state.Unlock()
		return result, nil
	}

	// Register the previous hash and last generated time for notifications
	// Get a channel that will be notified when the template associated with
	// the provided ID is stale and a new block template should be returned to
	// the caller.
	longPollChan := state.templateUpdateChan(prevHash, lastGenerated)
	state.Unlock()

	select {
	// When the client closes before it's time to send a reply, just return
	// now so the goroutine doesn't hang around.
	case <-closeChan:
		return nil, ErrClientQuit

	// Wait until signal received to send the reply.
	case <-longPollChan:
		// Fallthrough
	}

	// Get the lastest block template
	state.Lock()
	defer state.Unlock()

	if err := state.updateBlockTemplate(s, useCoinbaseValue); err != nil {
		return nil, err
	}

	// Include whether or not it is valid to submit work against the old
	// block template depending on whether or not a solution has already
	// been found and added to the block chain.
	submitOld := prevHash.IsEqual(&state.template.Block.Header.PrevBlock)
	result, err := state.blockTemplateResult(useCoinbaseValue, &submitOld)
	if err != nil {
		return nil, err
	}

	return result, nil
}
*/


func handleGetblocktemplate(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	// See https://en.bitcoin.it/wiki/BIP_0022 and
	// https://en.bitcoin.it/wiki/BIP_0023 for more details.
	/*
		c := cmd.(*btcjson.GetBlockTemplateCmd)
		request := c.Request

		// Set the default mode and override it if supplied.
		mode := "template"
		if request != nil && request.Mode != "" {
			mode = request.Mode
		}

		switch mode {
		case "template":
			return handleGetBlockTemplateRequest(s, request, closeChan)
		case "proposal":
			return handleGetBlockTemplateProposal(s, request)
		}

		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCInvalidParameter,
			Message: "Invalid mode",
		}
	*/
	return nil, nil
}

// handleSubmitBlock implements the submitblock command.
func handleSubmitblock(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	/*
		c := cmd.(*btcjson.SubmitBlockCmd)

		// Deserialize the submitted block.
		hexStr := c.HexBlock
		if len(hexStr)%2 != 0 {
			hexStr = "0" + c.HexBlock
		}
		serializedBlock, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, rpcDecodeHexError(hexStr)
		}

		block, err := btcutil.NewBlockFromBytes(serializedBlock)
		if err != nil {
			return nil, &btcjson.RPCError{
				Code:    btcjson.ErrRPCDeserialization,
				Message: "Block decode failed: " + err.Error(),
			}
		}

		// Process this block using the same rules as blocks coming from other
		// nodes.  This will in turn relay it to the network like normal.
		_, err = s.cfg.SyncMgr.SubmitBlock(block, blockchain.BFNone)
		if err != nil {
			return fmt.Sprintf("rejected: %s", err.Error()), nil
		}

		logs.Info("Accepted block %s via submitblock", block.Hash())
		return nil, nil
	*/
	return nil, nil
}

func handleGenerate(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	/*
		// Respond with an error if there are no addresses to pay the
		// created blocks to.
		if len(cfg.miningAddrs) == 0 {
			return nil, &btcjson.RPCError{
				Code: btcjson.ErrRPCInternal.Code,
				Message: "No payment addresses specified " +
					"via --miningaddr",
			}
		}

		// Respond with an error if there's virtually 0 chance of mining a block
		// with the CPU.
		if !s.cfg.ChainParams.GenerateSupported {
			return nil, &btcjson.RPCError{
				Code: btcjson.ErrRPCDifficulty,
				Message: fmt.Sprintf("No support for `generate` on "+
					"the current network, %s, as it's unlikely to "+
					"be possible to mine a block with the CPU.",
					s.cfg.ChainParams.Net),
			}
		}

		c := cmd.(*btcjson.GenerateCmd)

		// Respond with an error if the client is requesting 0 blocks to be generated.
		if c.NumBlocks == 0 {
			return nil, &btcjson.RPCError{
				Code:    btcjson.ErrRPCInternal.Code,
				Message: "Please request a nonzero number of blocks to generate.",
			}
		}

		// Create a reply
		reply := make([]string, c.NumBlocks)

		blockHashes, err := s.cfg.CPUMiner.GenerateNBlocks(c.NumBlocks)
		if err != nil {
			return nil, &btcjson.RPCError{
				Code:    btcjson.ErrRPCInternal.Code,
				Message: err.Error(),
			}
		}

		// Mine the correct number of blocks, assigning the hex representation of the
		// hash of each one to its place in the reply.
		for i, hash := range blockHashes {
			reply[i] = hash.String()
		}

		return reply, nil
	*/
	return nil, nil
}

func handleGeneratetoaddress(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func handleEstimatefee(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func handleEstimatepriority(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func handleEstimatesmartfee(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func handleEstimatesmartpriority(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func registerMiningRPCCommands() {
	for name, handler := range abcHandlers {
		appendCommand(name, handler)
	}
}
