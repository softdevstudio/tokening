package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/softdevstudio/tokening/internal/stdio"
	"github.com/softdevstudio/tokening/internal/store"
	"github.com/softdevstudio/tokening/internal/version"
)

// MaxStdioServers bounds how many servers one stdio target runs at once. A
// grant with many uses can't start more; further calls wait for a free slot
// and fail after StdioWait, spending their use like any failed forward.
const MaxStdioServers = 4

// StdioWait is how long a call waits for a free server slot.
const StdioWait = 30 * time.Second

type stdioSlots struct {
	mu    sync.Mutex
	slots map[string]chan struct{}
}

func (s *stdioSlots) get(target string) chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.slots == nil {
		s.slots = map[string]chan struct{}{}
	}
	c := s.slots[target]
	if c == nil {
		c = make(chan struct{}, MaxStdioServers)
		s.slots[target] = c
	}
	return c
}

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
	slot := g.stdio.get(info.ID)
	wait := time.NewTimer(StdioWait)
	defer wait.Stop()
	select {
	case slot <- struct{}{}:
		defer func() { <-slot }()
	case <-wait.C:
		g.logger.Printf("stdio target %s: %d servers already running; the call waited %v and gave up", info.ID, MaxStdioServers, StdioWait)
		return nil, 0, errors.New("no free stdio server slot")
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	}
	result, err := stdio.Call(ctx, stdio.Options{Command: command, Env: env, MaxLine: MaxBodyBytes, ClientName: "tokening", ClientVersion: version.Version}, name, args)
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
