package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/pivotal-golang/lager"
	"github.com/tedsuo/ifrit"
	"github.com/tedsuo/ifrit/sigmon"
)

type Command struct {
	BindIP   IPFlag `long:"bind-ip"         default:"0.0.0.0" description:"IP address on which to listen for SSH."`
	BindPort uint16 `long:"bind-port"       default:"2222"    description:"Port on which to listen for SSH."`
	PeerIP   string `long:"peer-ip"         required:"true"   description:"IP address for this tunnel host."`

	// AuthorizedKeysPath FileFlag `long:"authorized-keys" required:"true"   description:"Path to file containing keys to authorize, in SSH authorized_keys format."`
	ServerKeyPath FileFlag `long:"server-key"      required:"true"   description:"Path to the private key to use for the SSH tunnel."`
	// SessionKeyPath FileFlag `long:"session-key"     required:"true"   description:"Path to private key to use when signing tokens for registration."`
}

func (cmd *Command) Execute(args []string) error {
	runner, err := cmd.Runner(args)
	if err != nil {
		return err
	}

	return <-ifrit.Invoke(sigmon.New(runner)).Wait()
}

func (cmd *Command) Runner(args []string) (ifrit.Runner, error) {
	logger := lager.NewLogger("ssh-tunnel")
	logger.RegisterSink(lager.NewWriterSink(os.Stdout, lager.DEBUG))

	// authorizedKeys, err := cmd.loadAuthorizedKeys()
	// if err != nil {
	//   return nil, fmt.Errorf("Failed to load authorized keys: %s", err)
	// }

	// sessionKey, err := cmd.loadSessionKey()
	// if err != nil {
	// 	return nil, fmt.Errorf("Failed to load session signing key: %s", err)
	// }

	// config, err : cmd.configureServer(authorizedKeys)
	config, err := cmd.configureServer()
	if err != nil {
		return nil, fmt.Errorf("Failed to configure SSH server: %s", err)
	}

	address := fmt.Sprintf("%s:%d", cmd.BindIP, cmd.BindPort)
	// generator := NewTokenGenerator(sessionKey)

	server := &tunnelServer{
		logger:     logger,
		config:     config,
		tunnelHost: cmd.PeerIP,
	}

	return tunnelRunner{logger, server, address}, nil
}

// func (cmd *Command) configureServer(authorizedKeys []ssh.PublicKey)
func (cmd *Command) configureServer() (*ssh.ServerConfig, error) {
	// certChecker := &ssh.CertChecker{}

	config := &ssh.ServerConfig{
		NoClientAuth: true, // TODO: remove this!!!
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

// func (cmd *Command) loadAuthorizedKeys() ([]ssh.PublicKey, error) {
//   authorizedKeysBytes, err := ioutil.ReadFile(string(cmd.AuthorizedKeysPath))
//   if err != nil {
//     return nil, err
//   }
//
//   var authorizedKeys [].ssh.PublicKey
//
//   for {
//     key, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
//     if err != nil {
//       break
//     }
//
//     authorizedKeys = append(authorizedKeys, key)
//     authorizedKeysBytes = rest
//   }
//
//   return authorizedKeys, nil
// }

// func (cmd *Command) loadSessionKey() (*rsa.PrivateKey, error) {
// 	rsaKeyBlob, err := ioutil.ReadFile(string(cmd.SessionKeyPath))
// 	if err != nil {
// 		return nil, fmt.Errorf("Failed to read session signing key file: %s", err)
// 	}
//
// 	sessionKey, err := jwt.ParseRSAPrivateKeyFromPEM(rsaKeyBlob)
// 	if err != nil {
// 		return nil, fmt.Errorf("Failed to parse session signing key as RSA: %s", err)
// 	}
//
// 	return sessionKey, nil
// }
