//go:build !windows

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func terminationSignal() os.Signal { return syscall.SIGTERM }
func watchReload(ctx context.Context, reload chan<- struct{}) func() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-signals:
				select {
				case reload <- struct{}{}:
				default:
				}
			}
		}
	}()
	return func() { signal.Stop(signals); close(done) }
}
