package main

import (
	"fmt"
	"net"
	"os"

	"github.com/pivotal-golang/lager"
)

type tunnelRunner struct {
	logger  lager.Logger
	server  *tunnelServer
	address string
}

func (runner tunnelRunner) Run(signals <-chan os.Signal, ready chan<- struct{}) error {
	listener, err := net.Listen("tcp", runner.address)
	if err != nil {
		return fmt.Errorf("Failed to listen on %s: %s", runner.address, err)
	}

	runner.logger.Info("Listening")

	close(ready)
	exited := make(chan struct{})

	go func() {
		defer close(exited)
		runner.server.Serve(listener)
	}()

	for {
		select {
		case <-exited:
			return nil
		case <-signals:
			listener.Close()
		}
	}
}
