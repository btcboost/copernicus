package rpc

import (
	"bytes"
	"encoding/hex"

	"github.com/btcboost/copernicus/blockchain"
	"github.com/btcboost/copernicus/btcjson"
	"github.com/btcboost/copernicus/core"
	"github.com/btcboost/copernicus/mempool"
	"github.com/btcboost/copernicus/net/msg"
	"github.com/btcboost/copernicus/utils"
	"github.com/btcboost/copernicus/utxo"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

var rawTransactionHandlers = map[string]commandHandler{
	"getrawtransaction":    handleGetRawTransaction,
	"createrawtransaction": handleCreateRawTransaction,
	"decoderawtransaction": handleDecodeRawTransaction,
	"decodescript":         handleDecodeScript,
	"sendrawtransaction":   handleSendRawTransaction,
}

func handleGetRawTransaction(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	c := cmd.(*btcjson.GetRawTransactionCmd)

	// Convert the provided transaction hash hex to a Hash.
	txHash, err := utils.GetHashFromStr(c.Txid)
	if err != nil {
		return nil, rpcDecodeHexError(c.Txid)
	}

	verbose := false
	if c.Verbose != nil {
		verbose = *c.Verbose != 0
	}

	tx, _, ok := GetTransaction(txHash, true)
	if !ok {
		if blockchain.GTxIndex {
			return nil, btcjson.NewRPCError(btcjson.ErrRPCInvalidAddressOrKey,
				"No such mempool or blockchain transaction")
		}
		return nil, btcjson.NewRPCError(btcjson.ErrRPCInvalidAddressOrKey,
			"No such mempool transaction. Use -txindex to enable blockchain transaction queries. Use gettransaction for wallet transactions.")
	}

	buf := bytes.NewBuffer(nil)
	err = tx.Serialize(buf)
	if err != nil {
		return nil, rpcDecodeHexError(c.Txid)
	}
	strHex := hex.EncodeToString(buf.Bytes())
	if !verbose {
		return strHex, nil
	}
	rawTxn, err := createTxRawResult(s.cfg.ChainParams, mtx, txHash.String(),
		blkHeader, blkHashStr, blkHeight, chainHeight)
	if err != nil {
		return nil, err
	}
	return *rawTxn, nil
}

// createTxRawResult converts the passed transaction and associated parameters
// to a raw transaction JSON object.
func createTxRawResult(chainParams *chaincfg.Params, mtx *wire.MsgTx,
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
}

// createVinList returns a slice of JSON objects for the inputs of the passed
// transaction.
func createVinList(mtx *wire.MsgTx) []btcjson.Vin {
	// Coinbase transactions only have a single txin by definition.
	vinList := make([]btcjson.Vin, len(mtx.TxIn))
	if blockchain.IsCoinBaseTx(mtx) {
		txIn := mtx.TxIn[0]
		vinList[0].Coinbase = hex.EncodeToString(txIn.SignatureScript)
		vinList[0].Sequence = txIn.Sequence
		vinList[0].Witness = witnessToHex(txIn.Witness)
		return vinList
	}

	for i, txIn := range mtx.TxIn {
		// The disassembled string will contain [error] inline
		// if the script doesn't fully parse, so ignore the
		// error here.
		disbuf, _ := txscript.DisasmString(txIn.SignatureScript)

		vinEntry := &vinList[i]
		vinEntry.Txid = txIn.PreviousOutPoint.Hash.String()
		vinEntry.Vout = txIn.PreviousOutPoint.Index
		vinEntry.Sequence = txIn.Sequence
		vinEntry.ScriptSig = &btcjson.ScriptSig{
			Asm: disbuf,
			Hex: hex.EncodeToString(txIn.SignatureScript),
		}

		if mtx.HasWitness() {
			vinEntry.Witness = witnessToHex(txIn.Witness)
		}
	}

	return vinList
}

// createVoutList returns a slice of JSON objects for the outputs of the passed
// transaction.
func createVoutList(mtx *wire.MsgTx, chainParams *chaincfg.Params, filterAddrMap map[string]struct{}) []btcjson.Vout {
	voutList := make([]btcjson.Vout, 0, len(mtx.TxOut))
	for i, v := range mtx.TxOut {
		// The disassembled string will contain [error] inline if the
		// script doesn't fully parse, so ignore the error here.
		disbuf, _ := txscript.DisasmString(v.PkScript)

		// Ignore the error here since an error means the script
		// couldn't parse and there is no additional information about
		// it anyways.
		scriptClass, addrs, reqSigs, _ := txscript.ExtractPkScriptAddrs(
			v.PkScript, chainParams)

		// Encode the addresses while checking if the address passes the
		// filter when needed.
		passesFilter := len(filterAddrMap) == 0
		encodedAddrs := make([]string, len(addrs))
		for j, addr := range addrs {
			encodedAddr := addr.EncodeAddress()
			encodedAddrs[j] = encodedAddr

			// No need to check the map again if the filter already
			// passes.
			if passesFilter {
				continue
			}
			if _, exists := filterAddrMap[encodedAddr]; exists {
				passesFilter = true
			}
		}

		if !passesFilter {
			continue
		}

		var vout btcjson.Vout
		vout.N = uint32(i)
		vout.Value = btcutil.Amount(v.Value).ToBTC()
		vout.ScriptPubKey.Addresses = encodedAddrs
		vout.ScriptPubKey.Asm = disbuf
		vout.ScriptPubKey.Hex = hex.EncodeToString(v.PkScript)
		vout.ScriptPubKey.Type = scriptClass.String()
		vout.ScriptPubKey.ReqSigs = int32(reqSigs)

		voutList = append(voutList, vout)
	}

	return voutList
}

func GetTransaction(hash *utils.Hash, allowSlow bool) (*core.Tx, *utils.Hash, bool) {
	tx := mempool.GetTx(hash) // todo realize: in mempool get *core.Tx by hash
	if tx != nil {
		return tx, nil, true
	}

	if blockchain.GTxIndex {
		blockchain.GBlockTree.ReadTxIndex(hash)
		blockchain.OpenBlockFile(, true)
		// todo complete
	}

	// use coin database to locate block that contains transaction, and scan it
	var indexSlow *core.BlockIndex
	if allowSlow {
		coin := utxo.AccessByTxid(blockchain.GCoinsTip, hash)
		if !coin.IsSpent() {
			indexSlow = blockchain.GChainActive.FetchBlockIndexByHeight(coin.GetHeight())   // todo realise : get BlockIndex by height
		}
	}

	if indexSlow != nil {
		var block *core.Block
		if blockchain.ReadBlockFromDisk(block, indexSlow, msg.ActiveNetParams) {
			for _, tx := range block.Txs{
				if *hash == tx.TxHash() {
					return tx, indexSlow.BlockHash, true
				}
			}
		}
	}

	return nil, nil, false
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
