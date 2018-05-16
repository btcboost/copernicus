package rpc

import (
	"fmt"
	"strconv"
	"sync/atomic"

	"github.com/btcboost/copernicus/consensus"
	"github.com/btcboost/copernicus/internal/btcjson"
)

var abcHandlers = map[string]commandHandler{
	"getexcessiveblock": handleGetExcessiveBlock,
	"setexcessiveblock": handleSetExcessiveBlock,
}

func handleGetExcessiveBlock(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return &btcjson.ExcessiveBlockSizeResult{
		ExcessiveBlockSize: consensus.MaxBlockSize,
	}, nil
}

func handleSetExcessiveBlock(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	c := cmd.(*btcjson.SetExcessiveBlockCmd)

	// Do not allow maxBlockSize to be set below historic 1MB limit
	if c.BlockSize <= consensus.LegacyMaxBlockSize {
		return nil, btcjson.RPCError{
			Code:    btcjson.ErrRPCInvalidParameter,
			Message: "Invalid parameter, excessiveblock must be larger than " + strconv.Itoa(consensus.LegacyMaxBlockSize),
		}
	}

	// Set the new max block size.
	ok := atomic.CompareAndSwapUint64(&consensus.MaxBlockSize, consensus.MaxBlockSize, c.BlockSize)
	if !ok {
		return nil, btcjson.RPCError{
			Code:    btcjson.ErrInvalidParameter,
			Message: "Unexpected error",
		}
	}
	// settingsToUserAgentString();
	return "Excessive Block set to " + fmt.Sprintf("%d", c.BlockSize) + " bytes", nil
}

func registerABCRPCCommands() {
	for name, handler := range abcHandlers {
		appendCommand(name, handler)
	}
}
