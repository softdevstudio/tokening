// Package server owns the two separate listeners and their shared store.
package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/softdevstudio/tokening/internal/admin"
	"github.com/softdevstudio/tokening/internal/gateway"
	"github.com/softdevstudio/tokening/internal/policy"
	"github.com/softdevstudio/tokening/internal/store"
	"github.com/softdevstudio/tokening/internal/vault"
)

type Config struct {
	PolicyFile, Database, KeyFile, AdminToken string
	DemoReplayFile                            string
	AgentAddress, AdminAddress                string
	AllowedOrigins                            []string
	Reload                                    <-chan struct{}
	Logger                                    *log.Logger
}

// Run binds both ports before serving either one, then runs until cancellation
// or a listener failure. ready is called with actual bound addresses.
func Run(ctx context.Context, c Config, ready func(agent, admin string)) error {
	logger := c.Logger
	if logger == nil {
		logger = log.Default()
	}
	v, err := vault.Load(c.KeyFile)
	if err != nil {
		return err
	}
	p, warnings, err := policy.Load(c.PolicyFile)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	s, err := store.Open(ctx, c.Database)
	if err != nil {
		return err
	}
	defer s.Close()
	if err = s.ApplyPolicy(ctx, *p); err != nil {
		return err
	}
	a, err := admin.New(s, v, c.AdminToken, admin.Options{DemoReplayFile: c.DemoReplayFile})
	if err != nil {
		return err
	}
	g, err := gateway.New(s, v, gateway.Options{AllowedOrigins: c.AllowedOrigins, ErrorLog: logger})
	if err != nil {
		return err
	}
	if c.AgentAddress == "" {
		c.AgentAddress = "127.0.0.1:8080"
	}
	if c.AdminAddress == "" {
		c.AdminAddress = "127.0.0.1:8081"
	}
	agent, err := net.Listen("tcp", c.AgentAddress)
	if err != nil {
		return fmt.Errorf("bind agent listener: %w", err)
	}
	defer agent.Close()
	operator, err := net.Listen("tcp", c.AdminAddress)
	if err != nil {
		return fmt.Errorf("bind admin listener: %w", err)
	}
	defer operator.Close()
	for _, warning := range warnings {
		logger.Printf("policy warning: %s", warning)
	}
	makeServer := func(handler http.Handler) *http.Server {
		return &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10, ErrorLog: logger}
	}
	agentServer, adminServer := makeServer(g), makeServer(a)
	results := make(chan error, 2)
	go func() { results <- agentServer.Serve(agent) }()
	go func() { results <- adminServer.Serve(operator) }()
	if ready != nil {
		ready(agent.Addr().String(), operator.Addr().String())
	}
	var runErr error
	running := true
	for running {
		select {
		case <-ctx.Done():
			running = false
		case err := <-results:
			if !errors.Is(err, http.ErrServerClosed) {
				runErr = err
			}
			running = false
		case _, open := <-c.Reload:
			if !open {
				c.Reload = nil
				continue
			}
			next, notices, err := policy.Load(c.PolicyFile)
			if err == nil {
				err = s.ApplyPolicy(ctx, *next)
			}
			if err != nil {
				logger.Print("policy reload failed; prior policy remains active")
				continue
			}
			for _, notice := range notices {
				logger.Printf("policy warning: %s", notice)
			}
			logger.Print("policy reloaded")
		}
	}
	// A bounded drain lets committed calls finish; Close handles stalled clients.
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan struct{}, 2)
	go func() { _ = agentServer.Shutdown(shutdown); _ = agentServer.Close(); done <- struct{}{} }()
	go func() { _ = adminServer.Shutdown(shutdown); _ = adminServer.Close(); done <- struct{}{} }()
	<-done
	<-done
	return runErr
}
