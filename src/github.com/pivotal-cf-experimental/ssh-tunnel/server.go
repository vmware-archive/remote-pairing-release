package main

// NOTE:
// - Do we want to keep a "heartbeat" concept? Could allow the tunnel to
//   close after a period of inactivity.

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pivotal-golang/lager"
	"github.com/tedsuo/ifrit"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

type tunnelServer struct {
	config        *ssh.ServerConfig
	logger        lager.Logger
	tunnelHost    string
	sessionTokens map[string]string
}

func (s *tunnelServer) Serve(listener net.Listener) {
	for {
		c, err := listener.Accept()
		if err != nil {
			if !strings.Contains(err.Error(), "Use of closed network connection") {
				s.logger.Error("failed-to-accept", err)
			}

			return
		}

		logger := s.logger.Session("connection")

		conn, chans, reqs, err := ssh.NewServerConn(c, s.config)
		if err != nil {
			logger.Info("handshake-failed", lager.Data{"error": err.Error()})
			continue
		}

		go s.handleConn(logger, conn, chans, reqs)
	}
}

type forwardedTCPIP struct {
	bindAddr  string
	process   ifrit.Process
	boundPort uint32
}

func (s *tunnelServer) handleConn(logger lager.Logger, conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	defer conn.Close()

	errorChan := make(chan string, 1)
	// TODO: enforce localhost/loopback forwarding (no external IPs/host)
	go s.handleForwardRequests(conn, reqs, errorChan)

	for newChannel := range chans {
		logger.Info("received-channel", lager.Data{
			"type": newChannel.ChannelType(),
		})

		switch newChannel.ChannelType() {
		case "direct-tcpip":
			s.handleDirectChannel(newChannel)
		case "session":
			s.handleSessionChannel(newChannel, conn.SessionID(), errorChan)
		default:
			logger.Info("rejecting-channel", lager.Data{
				"type": newChannel.ChannelType(),
			})

			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
	}
}

func (s *tunnelServer) handleDirectChannel(newChannel ssh.NewChannel) {
	req := directForwardRequest{}
	ssh.Unmarshal(newChannel.ExtraData(), &req)

	channel, reqs, err := newChannel.Accept()
	if err != nil {
		s.logger.Error("failed-to-accept-channel", err)
		return
	}

	go func() {
		for r := range reqs {
			s.logger.Info("ignoring-request", lager.Data{
				"type": r.Type,
			})

			r.Reply(false, nil)
		}
	}()

	go func(ch ssh.Channel) {
		// TODO: reject if not localhost
		addr := fmt.Sprintf("%s:%d", req.ForwardIP, req.ForwardPort)
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			return
		}
		defer func() {
			ch.Close()
			conn.Close()
		}()

		wg := new(sync.WaitGroup)

		pipe := func(to io.WriteCloser, from io.ReadCloser) {
			// if either end breaks, close both ends to ensure they're both unblocked,
			// otherwise io.Copy can block forever if e.g. reading after write end has
			// gone away
			defer to.Close()
			defer from.Close()
			defer wg.Done()

			io.Copy(to, from)
		}

		wg.Add(1)
		go pipe(ch, conn)

		wg.Add(1)
		go pipe(conn, ch)

		wg.Wait()

	}(channel)
}

func (s *tunnelServer) handleSessionChannel(
	newChannel ssh.NewChannel,
	sessionID []byte,
	errorChan chan string,
) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		s.logger.Error("failed-to-accept-channel", err)
		return
	}
	go func() {
		for {
			errorMsg := <-errorChan
			channel.Write([]byte(errorMsg))
			channel.Close()
		}
	}()

	token, found := s.sessionTokens[string(sessionID)]

	channel.Write([]byte("SSH Tunnel Started\n\r"))
	if found {
		channel.Write([]byte(fmt.Sprintf("Token: %s\n\r", token)))
	}

	// HandleSessionRequests
	go func() {
		for req := range requests {
			ok := true
			switch req.Type {
			case "exec":
				ok = false
			case "shell":
				ok = true
			}

			req.Reply(ok, nil)
		}
	}()

	// HandleTerminalReading
	go func() {
		time.Sleep(40 * time.Millisecond)
		channel.Write([]byte("\n\rType 'exit' to end the session.\n\r"))
		term := terminal.NewTerminal(channel, "> ")
		defer channel.Close()

		for {
			line, err := term.ReadLine()
			if err != nil {
				break
			}

			if strings.Contains(string(line), "exit") {
				channel.Close()
			}
		}
	}()
}

func (s *tunnelServer) handleForwardRequests(
	conn *ssh.ServerConn,
	reqs <-chan *ssh.Request,
	errorChan chan string,
) {

	for r := range reqs {
		switch r.Type {
		case "tcpip-forward":
			logger := s.logger.Session("tcpip-forward")

			var req tcpipForwardRequest
			err := ssh.Unmarshal(r.Payload, &req)
			if err != nil {
				logger.Error("malformed-tcpip-request", err)
				r.Reply(false, nil)
				continue
			}

			if req.BindIP != "localhost" && req.BindIP != "127.0.0.1" {
				errorMsg := "Only localhost forwarding is allowed"
				logger.Error("invalid-forward-address", errors.New(errorMsg))
				errorChan <- errorMsg
				r.Reply(false, nil)
				return
			}

			logger.Info("forward-details-request", lager.Data{"request": req})

			listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", req.BindIP, req.BindPort))
			if err != nil {
				logger.Error("failed-to-listen", err)
				r.Reply(false, nil)
				continue
			}
			logger.Info("local-listener", lager.Data{
				"Addr": listener.Addr().String(),
			})

			defer listener.Close()

			bindAddr := net.JoinHostPort(req.BindIP, fmt.Sprintf("%d", req.BindPort))

			logger.Info("forwarding-tcpip", lager.Data{
				"requested-bind-addr": bindAddr,
			})

			_, port, err := net.SplitHostPort(listener.Addr().String())
			if err != nil {
				r.Reply(false, nil)
				continue
			}

			var res tcpipForwardResponse
			_, err = fmt.Sscanf(port, "%d", &res.BoundPort)
			if err != nil {
				r.Reply(false, nil)
				continue
			}

			logger.Info("forward-details-response", lager.Data{
				"Response": res,
			})

			forPort := req.BindPort
			if forPort == 0 {
				forPort = res.BoundPort
			}

			_ = s.forwardTCPIP(logger, conn, listener, req.BindIP, forPort)

			// forwardedTCPIPs <- forwardedTCPIP{
			// 	bindAddr:  fmt.Sprintf("%s:%d", req.BindIP, req.BindPort),
			// 	boundPort: res.BoundPort,
			// 	process:   process,
			// }

			r.Reply(true, ssh.Marshal(res))
		default:
			if strings.Contains(r.Type, "keepalive") {
				s.logger.Info("keepalive", lager.Data{"type": r.Type})
				r.Reply(true, nil)
			} else {
				s.logger.Info("ignoring-request", lager.Data{"type": r.Type})
				r.Reply(false, nil)
			}
		}
	}
}

func (s *tunnelServer) forwardTCPIP(
	logger lager.Logger,
	conn *ssh.ServerConn,
	listener net.Listener,
	forwardIP string,
	forwardPort uint32,
) ifrit.Process {
	return ifrit.Background(ifrit.RunFunc(func(signals <-chan os.Signal, ready chan<- struct{}) error {
		go func() {
			<-signals
			logger.Info("closing-local-listener")
			listener.Close()
		}()

		close(ready)

		for {
			localConn, err := listener.Accept()
			if err != nil {
				// happens at exit. is that because we're not handling "cancel-tcpip-forward"?
				logger.Error("failed-to-accept", err)
				break
			}
			go forwardLocalConn(logger, localConn, conn, forwardIP, forwardPort)
		}

		return nil
	}))
}

func forwardLocalConn(logger lager.Logger, localConn net.Conn, conn *ssh.ServerConn, forwardIP string, forwardPort uint32) {
	defer localConn.Close()

	var req forwardTCPIPChannelRequest
	req.ForwardIP = forwardIP
	req.ForwardPort = forwardPort

	host, port, err := net.SplitHostPort(localConn.RemoteAddr().String())
	logger.Info("debug", lager.Data{
		"req-forward-ip":   req.ForwardIP,
		"req-forward-port": req.ForwardPort,
		"local-conn-host":  host,
		"local-conn-port":  port,
	})

	if err != nil {
		logger.Error("failed-to-split-host-port", err)
		return
	}

	req.OriginIP = host
	_, err = fmt.Sscanf(port, "%d", &req.OriginPort)
	if err != nil {
		logger.Error("failed-to-parse-port", err)
		return
	}

	channel, reqs, err := conn.OpenChannel("forwarded-tcpip", ssh.Marshal(req))
	if err != nil {
		logger.Error("failed-to-open-channel", err)
		return
	}

	defer channel.Close()

	go func() {
		for r := range reqs {
			logger.Info("ignoring-request", lager.Data{
				"type": r.Type,
			})

			r.Reply(false, nil)
		}
	}()

	wg := new(sync.WaitGroup)

	pipe := func(to io.WriteCloser, from io.ReadCloser) {
		// if either end breaks, close both ends to ensure they're both unblocked,
		// otherwise io.Copy can block forever if e.g. reading after write end has
		// gone away
		defer to.Close()
		defer from.Close()
		defer wg.Done()

		io.Copy(to, from)
	}

	wg.Add(1)
	go pipe(localConn, channel)

	wg.Add(1)
	go pipe(channel, localConn)

	wg.Wait()
}
