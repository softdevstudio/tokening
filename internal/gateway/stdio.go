package gateway

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/softdevstudio/tokening/internal/stdio"
	"github.com/softdevstudio/tokening/internal/store"
	"github.com/softdevstudio/tokening/internal/version"
)

// stdioCall runs one authorized tool call against an mcp_stdio target: the
// server is started for this call only, with the target's env credential and
// nothing else from the gateway's environment. A result counts as upstream
// status 200; an error answer from the server as 502; a server that can't be
// started, exits or times out as no response (0).
func (g *Gateway) stdioCall(ctx context.Context, info store.TargetInfo, name string, args map[string]json.RawMessage) (json.RawMessage, int, error) {
	var command []string
	if err := json.Unmarshal([]byte(info.Destination), &command); err != nil || len(command) == 0 || command[0] == "" {
		return nil, 0, errors.New("invalid stdio command")
	}
	env := map[string]string{}
	plain, err := g.store.Credential(ctx, info.ID, g.vault)
	switch {
	case errors.Is(err, store.ErrCredentialMissing):
		// A server that needs no secret (a filesystem server) needs no
		// stored credential either.
	case err != nil:
		return nil, 0, err
	default:
		env, err = stdio.ParseCredential(plain)
		clear(plain)
		if err != nil {
			return nil, 0, err
		}
	}
	result, err := stdio.Call(ctx, stdio.Options{Command: command, Env: env, ClientName: "tokening", ClientVersion: version.Version}, name, args)
	if err != nil {
		// The operator's log gets the cause (and the end of the server's
		// stderr); the agent only hears that the call failed.
		g.logger.Printf("stdio target %s: %v", info.ID, err)
		var rpcErr *stdio.RPCError
		if errors.As(err, &rpcErr) {
			return nil, 502, err
		}
		return nil, 0, err
	}
	return result, 200, nil
}
