package main

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
	config         *ssh.ServerConfig
	logger         lager.Logger
	tunnelSessions map[string]*tunnelSession
	sessionTokens  map[string]string
	sync.Mutex
}

type forwardedTCPIP struct {
	bindAddr  string
	process   ifrit.Process
	boundPort uint32
}

type tunnelSession struct {
	serverChannel ssh.Channel
	remoteChannel ssh.Channel
	boundListener net.Listener
}

func (s *tunnelServer) Serve(listener net.Listener) {
	s.tunnelSessions = map[string]*tunnelSession{}

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

func (s *tunnelServer) handleConn(logger lager.Logger, conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	defer conn.Close()
	errorChan := make(chan string, 1)
	sessionID := conn.SessionID()

	go s.handleForwardRequests(conn, reqs, sessionID, errorChan)

	for newChannel := range chans {
		switch newChannel.ChannelType() {
		case "direct-tcpip":
			logger.Info("direct-tcpip-connection")
			s.handleDirectChannel(newChannel, errorChan)
		case "session":
			logger.Info("session-connection")
			s.handleSessionChannel(conn, newChannel, sessionID, errorChan)
		default:
			logger.Info("rejecting-channel", lager.Data{
				"type": newChannel.ChannelType(),
			})

			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
	}
}

func (s *tunnelServer) handleSessionChannel(
	conn *ssh.ServerConn,
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
			channel.Write([]byte(fmt.Sprintf("\n\r%s\n\r", errorMsg)))
			channel.Close()
		}
	}()

	channel.Write([]byte("SSH Tunnel Started\n\r"))

	s.Lock()

	token, hostFound := s.sessionTokens[string(sessionID)]

	if hostFound {
		tunnel, found := s.tunnelSessions[token]

		if !found {
			tunnel = &tunnelSession{}
		}

		tunnel.serverChannel = channel
		s.tunnelSessions[token] = tunnel
	} else {
		token = conn.User()
		tunnel, found := s.tunnelSessions[token]

		if !found {
			tunnel = &tunnelSession{}
		}

		tunnel.remoteChannel = channel
		s.tunnelSessions[token] = tunnel
	}

	sshdHost, sshdPort, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		s.logger.Error("failed-to-split-local-address", err)
		return
	}
	s.Unlock()

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
		tunnel, found := s.tunnelSessions[token]
		if found && conn.User() == "server" {
			listener := tunnel.boundListener
			if listener != nil {
				_, allocatedPort, err := net.SplitHostPort(listener.Addr().String())
				if err != nil {
					s.logger.Error("failed-to-split-listener-address", err)
					return
				}
				channel.Write([]byte(fmt.Sprintf("Client command:\n\rssh -p %s %s@%s -L 6000:localhost:%s\n\r", sshdPort, token, sshdHost, allocatedPort)))
			}
		}

		channel.Write([]byte("\n\rType 'exit' to end the session.\n\r"))
		term := terminal.NewTerminal(channel, "> ")
		defer channel.Close()

		for {
			line, err := term.ReadLine()
			if err != nil {
				break
			}

			if strings.Contains(string(line), "exit") {
				tunnel, found := s.tunnelSessions[token]
				if found {
					listener := tunnel.boundListener
					if listener != nil {
						listener.Close()
					}

					remoteSession := tunnel.remoteChannel
					if remoteSession != nil {
						remoteSession.Close()
					}

					serverSession := tunnel.serverChannel
					if serverSession != nil {
						serverSession.Close()
					}

					delete(s.tunnelSessions, token)

					var tokenKeyToDelete string
					for key, val := range s.sessionTokens {
						if val == token {
							tokenKeyToDelete = key
							break
						}
					}

					delete(s.sessionTokens, tokenKeyToDelete)
				}

				channel.Close()
			}
		}
	}()
}

func (s *tunnelServer) handleDirectChannel(
	newChannel ssh.NewChannel,
	errorChan chan string,
) {
	logger := s.logger.Session("direct-tcpip")

	req := directForwardRequest{}
	ssh.Unmarshal(newChannel.ExtraData(), &req)

	// NOTE: unfortunately, we don't see this message until traffic is sent.
	if req.ForwardIP != "localhost" && req.ForwardIP != "127.0.0.1" {
		errorMsg := "Only localhost forwarding is allowed"
		logger.Error("invalid-forward-address", errors.New(errorMsg))
		errorChan <- errorMsg
		return
	}

	logger.Info("received-request")

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

func (s *tunnelServer) handleForwardRequests(
	conn *ssh.ServerConn,
	reqs <-chan *ssh.Request,
	sessionID []byte,
	errorChan chan string,
) {

	for r := range reqs {
		switch r.Type {
		case "tcpip-forward":
			logger := s.logger.Session("tcpip-forward")
			logger.Info("received-request")

			token, found := s.sessionTokens[string(sessionID)]
			if !found {
				errorMsg := "Failed to find a valid tunnel session"
				logger.Error("invalid-session-token", errors.New(errorMsg))
				errorChan <- errorMsg
				r.Reply(false, nil)
				return
			}

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

			listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", req.BindIP, req.BindPort))
			if err != nil {
				logger.Error("failed-to-listen", err)
				r.Reply(false, nil)
				continue
			}

			logger.Info(fmt.Sprintf("Port listening to: %s", listener.Addr().String()))

			s.Lock()
			tunnels := s.tunnelSessions
			tunnel, found := tunnels[token]

			if !found {
				tunnel = &tunnelSession{}
			}

			tunnel.boundListener = listener
			s.tunnelSessions[token] = tunnel
			s.Unlock()

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
