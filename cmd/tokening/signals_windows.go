//go:build windows

package main

import (
	"context"
	"os"
)

func terminationSignal() os.Signal                        { return os.Interrupt }
func watchReload(context.Context, chan<- struct{}) func() { return func() {} }
