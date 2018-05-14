package rpc

import (
	"github.com/btcboost/copernicus/blockchain"
	"github.com/btcboost/copernicus/btcjson"
	"github.com/btcboost/copernicus/conf"
	"github.com/btcboost/copernicus/net/protocol"
	"github.com/btcboost/copernicus/utils"
)

var miscHandlers = map[string]commandHandler{
	"getinfo":                handleGetInfo,
	"validateaddress":        handleValidateAddress,
	"createmultisig":         handleCreatemultisig,
	"verifymessage":          handleVerifyMessage,
	"signmessagewithprivkey": handleSignMessageWithprivkey,
	"setmocktime":            handleSetMocktime,
	"echo":                   handleEcho,
}

func handleGetInfo(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	best := blockchain.GChainActive.Tip()
	var height int32
	if best == nil {
		height = 0
	}

	ret := &btcjson.InfoChainResult{
		Version:         protocol.Copernicus,
		ProtocolVersion: int32(protocol.BitcoinProtocolVersion),
		Blocks:          height,
		TimeOffset:      utils.GetTimeOffset(),
		//Connections: s.cfg.ConnMgr.ConnectedCount(),
		Proxy:      conf.AppConf.Proxy,
		Difficulty: getDifficulty(blockchain.GChainActive.Tip()),
		TestNet:    conf.AppConf.TestNet3,
		RelayFee:   float64(blockchain.DefaultMinRelayTxFee),
	}

	return ret, nil
}

// handleValidateAddress implements the validateaddress command.
func handleValidateAddress(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	//c := cmd.(*btcjson.ValidateAddressCmd)

	result := btcjson.ValidateAddressChainResult{}
	/*	addr, err := utils.DecodeAddress(c.Address, conf.AppConf.ChainParams)
		if err != nil {
			// Return the default value (false) for IsValid.
			return result, nil
		}

		result.Address = addr.EncodeAddress()   */ // TODO realise
	result.IsValid = true

	return result, nil
}

func handleCreatemultisig(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func handleVerifyMessage(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	/*
		c := cmd.(*btcjson.VerifyMessageCmd)

		// Decode the provided address.
		params := msg.ActiveNetParams
		addr, err := btcutil.DecodeAddress(c.Address, params)
		if err != nil {
			return nil, &btcjson.RPCError{
				Code:    btcjson.ErrRPCInvalidAddressOrKey,
				Message: "Invalid address or key: " + err.Error(),
			}
		}

		// Only P2PKH addresses are valid for signing.
		if _, ok := addr.(*btcutil.AddressPubKeyHash); !ok {
			return nil, &btcjson.RPCError{
				Code:    btcjson.ErrRPCType,
				Message: "Address is not a pay-to-pubkey-hash address",
			}
		}

		// Decode base64 signature.
		sig, err := base64.StdEncoding.DecodeString(c.Signature)
		if err != nil {
			return nil, &btcjson.RPCError{
				Code:    btcjson.ErrRPCParse.Code,
				Message: "Malformed base64 encoding: " + err.Error(),
			}
		}

		// Validate the signature - this just shows that it was valid at all.
		// we will compare it with the key next.
		var buf bytes.Buffer
		wire.WriteVarString(&buf, 0, "Bitcoin Signed Message:\n")
		wire.WriteVarString(&buf, 0, c.Message)
		expectedMessageHash := chainhash.DoubleHashB(buf.Bytes())
		pk, wasCompressed, err := btcec.RecoverCompact(btcec.S256(), sig,
			expectedMessageHash)
		if err != nil {
			// Mirror Bitcoin Core behavior, which treats error in
			// RecoverCompact as invalid signature.
			return false, nil
		}

		// Reconstruct the pubkey hash.
		var serializedPK []byte
		if wasCompressed {
			serializedPK = pk.SerializeCompressed()
		} else {
			serializedPK = pk.SerializeUncompressed()
		}
		address, err := btcutil.NewAddressPubKey(serializedPK, params)
		if err != nil {
			// Again mirror Bitcoin Core behavior, which treats error in public key
			// reconstruction as invalid signature.
			return false, nil
		}

		// Return boolean if addresses match.
		return address.EncodeAddress() == c.Address, nil
	*/
	return nil, nil
}

func handleSignMessageWithprivkey(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	//c := cmd.(*btcjson.SignMessageWithPrivkeyCmd)
	return nil, nil
}

func handleSetMocktime(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func handleEcho(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func registerMiscRPCCommands() {
	for name, handler := range miscHandlers {
		appendCommand(name, handler)
	}
}
