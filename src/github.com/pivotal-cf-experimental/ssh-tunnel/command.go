package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/pivotal-golang/lager"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/sigmon"
)

type Command struct {
	BindIP             IPFlag   `long:"bind-ip"         default:"0.0.0.0" description:"IP address on which to listen for SSH."`
	BindPort           uint16   `long:"bind-port"       default:"2222"    description:"Port on which to listen for SSH."`
	AuthorizedKeysPath FileFlag `long:"authorized-keys" required:"true"   description:"Path to file containing keys to authorize, in SSH authorized_keys format."`
	ServerKeyPath      FileFlag `long:"server-key"      required:"true"   description:"Path to the private key to use for the SSH tunnel."`
	ExternalIP         IPFlag   `long:"external-ip"     default:"0.0.0.0" description:"External IP address of the instance the server is running on."`
	logger             lager.Logger
}

func (cmd *Command) Execute(args []string) error {
	runner, err := cmd.Runner(args)
	if err != nil {
		return err
	}

	return <-ifrit.Invoke(sigmon.New(runner)).Wait()
}

func (cmd *Command) Runner(args []string) (ifrit.Runner, error) {
	cmd.logger = lager.NewLogger("ssh-tunnel")
	cmd.logger.RegisterSink(lager.NewWriterSink(os.Stdout, lager.DEBUG))

	authorizedKeys, err := cmd.loadAuthorizedKeys()
	if err != nil {
		return nil, fmt.Errorf("Failed to load authorized keys: %s", err)
	}

	// sessionId -> authorizedToken
	sessionTokens := make(map[string]string)

	config, err := cmd.configureServer(authorizedKeys, sessionTokens)
	if err != nil {
		return nil, fmt.Errorf("Failed to configure SSH server: %s", err)
	}

	address := fmt.Sprintf("%s:%d", cmd.BindIP, cmd.BindPort)

	server := &tunnelServer{
		logger:        cmd.logger,
		config:        config,
		sessionTokens: sessionTokens,
		externalIP:    string(cmd.ExternalIP),
	}

	return tunnelRunner{cmd.logger, server, address}, nil
}

func (cmd *Command) configureServer(authorizedKeys []ssh.PublicKey, sessionTokens map[string]string) (*ssh.ServerConfig, error) {
	certChecker := &ssh.CertChecker{
		IsAuthority: func(key ssh.PublicKey) bool {
			return false
		},

		UserKeyFallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			for _, k := range authorizedKeys {
				if bytes.Equal(k.Marshal(), key.Marshal()) {
					return nil, nil
				}
			}

			return nil, fmt.Errorf("unknown public key")
		},
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			user := conn.User()
			if user == "server" {
				_, err := certChecker.Authenticate(conn, key)
				if err != nil {
					return nil, err
				}

				token := GenerateToken()

				cmd.logger.Info(fmt.Sprintf("Added token: %s", token))
				sessionTokens[string(conn.SessionID())] = token
				return nil, nil
			}

			token := user
			matched := false

			for _, authorizedToken := range sessionTokens {
				if authorizedToken == token {
					matched = true
					break
				}
			}

			if matched {
				cmd.logger.Info(fmt.Sprintf("User logged in: %s", user))
				return nil, nil
			}

			return nil, errors.New("Bad Key or Token")
		},
	}

	privateBytes, err := ioutil.ReadFile(string(cmd.ServerKeyPath))
	if err != nil {
		return nil, err
	}

	privateKey, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return nil, err
	}

	config.AddHostKey(privateKey)

	return config, nil
}

func (cmd *Command) loadAuthorizedKeys() ([]ssh.PublicKey, error) {
	authorizedKeysBytes, err := ioutil.ReadFile(string(cmd.AuthorizedKeysPath))
	if err != nil {
		return nil, err
	}

	var authorizedKeys []ssh.PublicKey

	for {
		key, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			break
		}

		authorizedKeys = append(authorizedKeys, key)
		authorizedKeysBytes = rest
	}

	return authorizedKeys, nil
}
