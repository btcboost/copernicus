package rpc

var abcHandlers = map[string]commandHandler{
	"getexcessiveblock": handleGetexcessiveblock,
	"setexcessiveblock": handleSetexcessiveblock,
}

func handleGetexcessiveblock(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func handleSetexcessiveblock(s *Server, cmd interface{}, closeChan <-chan struct{}) (interface{}, error) {
	return nil, nil
}

func registerABCRPCCommands() {
	for name, handler := range abcHandlers {
		appendCommand(name, handler)
	}
}
