package rpc

var rawTransactionHandlers = map[string]commandHandler{
	"getrawtransaction":    handleGetRawTransaction,
	"createrawtransaction": handleCreateRawTransaction,
	"decoderawtransaction": handleDecodeRawTransaction,
	"decodescript":         handleDecodeScript,
	"sendrawtransaction":   handleSendRawTransaction,
}

func handleGetRawTransaction(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	/*
		c := cmd.(*btcjson.GetRawTransactionCmd)

		// Convert the provided transaction hash hex to a Hash.
		txHash, err := chainhash.NewHashFromStr(c.Txid)
		if err != nil {
			return nil, rpcDecodeHexError(c.Txid)
		}

		verbose := false
		if c.Verbose != nil {
			verbose = *c.Verbose != 0
		}

		// Try to fetch the transaction from the memory pool and if that fails,
		// try the block database.
		var mtx *wire.MsgTx
		var blkHash *chainhash.Hash
		var blkHeight int32
		tx, err := s.cfg.TxMemPool.FetchTransaction(txHash)
		if err != nil {
			if s.cfg.TxIndex == nil {
				return nil, &btcjson.RPCError{
					Code: btcjson.ErrRPCNoTxInfo,
					Message: "The transaction index must be " +
						"enabled to query the blockchain " +
						"(specify --txindex)",
				}
			}

			// Look up the location of the transaction.
			blockRegion, err := s.cfg.TxIndex.TxBlockRegion(txHash)
			if err != nil {
				context := "Failed to retrieve transaction location"
				return nil, internalRPCError(err.Error(), context)
			}
			if blockRegion == nil {
				return nil, rpcNoTxInfoError(txHash)
			}

			// Load the raw transaction bytes from the database.
			var txBytes []byte
			err = s.cfg.DB.View(func(dbTx database.Tx) error {
				var err error
				txBytes, err = dbTx.FetchBlockRegion(blockRegion)
				return err
			})
			if err != nil {
				return nil, rpcNoTxInfoError(txHash)
			}

			// When the verbose flag isn't set, simply return the serialized
			// transaction as a hex-encoded string.  This is done here to
			// avoid deserializing it only to reserialize it again later.
			if !verbose {
				return hex.EncodeToString(txBytes), nil
			}

			// Grab the block height.
			blkHash = blockRegion.Hash
			blkHeight, err = s.cfg.Chain.BlockHeightByHash(blkHash)
			if err != nil {
				context := "Failed to retrieve block height"
				return nil, internalRPCError(err.Error(), context)
			}

			// Deserialize the transaction
			var msgTx wire.MsgTx
			err = msgTx.Deserialize(bytes.NewReader(txBytes))
			if err != nil {
				context := "Failed to deserialize transaction"
				return nil, internalRPCError(err.Error(), context)
			}
			mtx = &msgTx
		} else {
			// When the verbose flag isn't set, simply return the
			// network-serialized transaction as a hex-encoded string.
			if !verbose {
				// Note that this is intentionally not directly
				// returning because the first return value is a
				// string and it would result in returning an empty
				// string to the client instead of nothing (nil) in the
				// case of an error.
				mtxHex, err := messageToHex(tx.MsgTx())
				if err != nil {
					return nil, err
				}
				return mtxHex, nil
			}

			mtx = tx.MsgTx()
		}

		// The verbose flag is set, so generate the JSON object and return it.
		var blkHeader *wire.BlockHeader
		var blkHashStr string
		var chainHeight int32
		if blkHash != nil {
			// Fetch the header from chain.
			header, err := s.cfg.Chain.FetchHeader(blkHash)
			if err != nil {
				context := "Failed to fetch block header"
				return nil, internalRPCError(err.Error(), context)
			}

			blkHeader = &header
			blkHashStr = blkHash.String()
			chainHeight = s.cfg.Chain.BestSnapshot().Height
		}

		rawTxn, err := createTxRawResult(s.cfg.ChainParams, mtx, txHash.String(),
			blkHeader, blkHashStr, blkHeight, chainHeight)
		if err != nil {
			return nil, err
		}
		return *rawTxn, nil
	*/
	return nil, nil
}

func handleCreateRawTransaction(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	/*
		c := cmd.(*btcjson.CreateRawTransactionCmd)

		// Validate the locktime, if given.
		if c.LockTime != nil &&
			(*c.LockTime < 0 || *c.LockTime > int64(wire.MaxTxInSequenceNum)) {
			return nil, &btcjson.RPCError{
				Code:    btcjson.ErrRPCInvalidParameter,
				Message: "Locktime out of range",
			}
		}

		// Add all transaction inputs to a new transaction after performing
		// some validity checks.
		mtx := wire.NewMsgTx(wire.TxVersion)
		for _, input := range c.Inputs {
			txHash, err := chainhash.NewHashFromStr(input.Txid)
			if err != nil {
				return nil, rpcDecodeHexError(input.Txid)
			}

			prevOut := wire.NewOutPoint(txHash, input.Vout)
			txIn := wire.NewTxIn(prevOut, []byte{}, nil)
			if c.LockTime != nil && *c.LockTime != 0 {
				txIn.Sequence = wire.MaxTxInSequenceNum - 1
			}
			mtx.AddTxIn(txIn)
		}

		// Add all transaction outputs to the transaction after performing
		// some validity checks.
		params := s.cfg.ChainParams
		for encodedAddr, amount := range c.Amounts {
			// Ensure amount is in the valid range for monetary amounts.
			if amount <= 0 || amount > btcutil.MaxSatoshi {
				return nil, &btcjson.RPCError{
					Code:    btcjson.ErrRPCType,
					Message: "Invalid amount",
				}
			}

			// Decode the provided address.
			addr, err := btcutil.DecodeAddress(encodedAddr, params)
			if err != nil {
				return nil, &btcjson.RPCError{
					Code:    btcjson.ErrRPCInvalidAddressOrKey,
					Message: "Invalid address or key: " + err.Error(),
				}
			}

			// Ensure the address is one of the supported types and that
			// the network encoded with the address matches the network the
			// server is currently on.
			switch addr.(type) {
			case *btcutil.AddressPubKeyHash:
			case *btcutil.AddressScriptHash:
			default:
				return nil, &btcjson.RPCError{
					Code:    btcjson.ErrRPCInvalidAddressOrKey,
					Message: "Invalid address or key",
				}
			}
			if !addr.IsForNet(params) {
				return nil, &btcjson.RPCError{
					Code: btcjson.ErrRPCInvalidAddressOrKey,
					Message: "Invalid address: " + encodedAddr +
						" is for the wrong network",
				}
			}

			// Create a new script which pays to the provided address.
			pkScript, err := txscript.PayToAddrScript(addr)
			if err != nil {
				context := "Failed to generate pay-to-address script"
				return nil, internalRPCError(err.Error(), context)
			}

			// Convert the amount to satoshi.
			satoshi, err := btcutil.NewAmount(amount)
			if err != nil {
				context := "Failed to convert amount"
				return nil, internalRPCError(err.Error(), context)
			}

			txOut := wire.NewTxOut(int64(satoshi), pkScript)
			mtx.AddTxOut(txOut)
		}

		// Set the Locktime, if given.
		if c.LockTime != nil {
			mtx.LockTime = uint32(*c.LockTime)
		}

		// Return the serialized and hex-encoded transaction.  Note that this
		// is intentionally not directly returning because the first return
		// value is a string and it would result in returning an empty string to
		// the client instead of nothing (nil) in the case of an error.
		mtxHex, err := messageToHex(mtx)
		if err != nil {
			return nil, err
		}
		return mtxHex, nil
	*/
	return nil, nil
}

func handleDecodeRawTransaction(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	/*	c := cmd.(*btcjson.DecodeRawTransactionCmd)

		// Deserialize the transaction.
		hexStr := c.HexTx
		if len(hexStr)%2 != 0 {
			hexStr = "0" + hexStr
		}
		serializedTx, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, rpcDecodeHexError(hexStr)
		}
		var mtx wire.MsgTx
		err = mtx.Deserialize(bytes.NewReader(serializedTx))
		if err != nil {
			return nil, &btcjson.RPCError{
				Code:    btcjson.ErrRPCDeserialization,
				Message: "TX decode failed: " + err.Error(),
			}
		}

		// Create and return the result.
		txReply := btcjson.TxRawDecodeResult{
			Txid:     mtx.TxHash().String(),
			Version:  mtx.Version,
			Locktime: mtx.LockTime,
			Vin:      createVinList(&mtx),
			Vout:     createVoutList(&mtx, s.cfg.ChainParams, nil),
		}
		return txReply, nil*/
	return nil, nil
}

func handleDecodeScript(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	/*	c := cmd.(*btcjson.DecodeScriptCmd)

		// Convert the hex script to bytes.
		hexStr := c.HexScript
		if len(hexStr)%2 != 0 {
			hexStr = "0" + hexStr
		}
		script, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, rpcDecodeHexError(hexStr)
		}

		// The disassembled string will contain [error] inline if the script
		// doesn't fully parse, so ignore the error here.
		disbuf, _ := txscript.DisasmString(script)

		// Get information about the script.
		// Ignore the error here since an error means the script couldn't parse
		// and there is no additinal information about it anyways.
		scriptClass, addrs, reqSigs, _ := txscript.ExtractPkScriptAddrs(script,
			s.cfg.ChainParams)
		addresses := make([]string, len(addrs))
		for i, addr := range addrs {
			addresses[i] = addr.EncodeAddress()
		}

		// Convert the script itself to a pay-to-script-hash address.
		p2sh, err := btcutil.NewAddressScriptHash(script, s.cfg.ChainParams)
		if err != nil {
			context := "Failed to convert script to pay-to-script-hash"
			return nil, internalRPCError(err.Error(), context)
		}

		// Generate and return the reply.
		reply := btcjson.DecodeScriptResult{
			Asm:       disbuf,
			ReqSigs:   int32(reqSigs),
			Type:      scriptClass.String(),
			Addresses: addresses,
		}
		if scriptClass != txscript.ScriptHashTy {
			reply.P2sh = p2sh.EncodeAddress()
		}
		return reply, nil*/
	return nil, nil
}

func handleSendRawTransaction(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	/* c := cmd.(*btcjson.SendRawTransactionCmd)
	// Deserialize and send off to tx relay
	hexStr := c.HexTx
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	serializedTx, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, rpcDecodeHexError(hexStr)
	}
	var msgTx msg.TxMessage
	err = msgTx.BitcoinParse(bytes.NewReader(serializedTx),0)
	if err != nil {
		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCDeserialization,
			Message: "TX decode failed: " + err.Error(),
		}
	}

	// Use 0 for the tag to represent local node.
	acceptedTxs, err := s.cfg.TxMemPool.ProcessTransaction(msgTx.Tx, false, false, 0)
	blockchain.
	if err != nil {
		// When the error is a rule error, it means the transaction was
		// simply rejected as opposed to something actually going wrong,
		// so log it as such.  Otherwise, something really did go wrong,
		// so log it as an actual error.  In both cases, a JSON-RPC
		// error is returned to the client with the deserialization
		// error code (to match bitcoind behavior).
		if _, ok := err.(mempool.RuleError); ok {
			logs.Debug("Rejected transaction %v: %v", tx.Hash(),
				err)
		} else {
			logs.Error("Failed to process transaction %v: %v",
				tx.Hash(), err)
		}
		return nil, &btcjson.RPCError{
			Code:    btcjson.ErrRPCDeserialization,
			Message: "TX rejected: " + err.Error(),
		}
	}

	// When the transaction was accepted it should be the first item in the
	// returned array of accepted transactions.  The only way this will not
	// be true is if the API for ProcessTransaction changes and this code is
	// not properly updated, but ensure the condition holds as a safeguard.
	//
	// Also, since an error is being returned to the caller, ensure the
	// transaction is removed from the memory pool.
	if len(acceptedTxs) == 0 || !acceptedTxs[0].Tx.Hash().IsEqual(tx.Hash()) {
		s.cfg.TxMemPool.RemoveTransaction(tx, true)

		errStr := fmt.Sprintf("transaction %v is not in accepted list",
			tx.Hash())
		return nil, internalRPCError(errStr, "")
	}

	// Generate and relay inventory vectors for all newly accepted
	// transactions into the memory pool due to the original being
	// accepted.
	s.cfg.ConnMgr.RelayTransactions(acceptedTxs)

	// Notify both websocket and getblocktemplate long poll clients of all
	// newly accepted transactions.
	s.NotifyNewTransactions(acceptedTxs)

	// Keep track of all the sendrawtransaction request txns so that they
	// can be rebroadcast if they don't make their way into a block.
	txD := acceptedTxs[0]
	iv := wire.NewInvVect(wire.InvTypeTx, txD.Tx.Hash())
	s.cfg.ConnMgr.AddRebroadcastInventory(iv, txD)

	return tx.Hash().String(), nil*/
	return nil, nil
} //Todo

func registeRawTransactionRPCCommands() {
	for name, handler := range rawTransactionHandlers {
		appendCommand(name, handler)
	}
}
