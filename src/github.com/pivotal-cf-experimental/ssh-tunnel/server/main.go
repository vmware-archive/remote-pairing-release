package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

var (
	keyParser ssh.Signer
)

func init() {
	keyPath := "./host_key"

	keyData, err := ioutil.ReadFile(keyPath)
	if err != nil {
		panic(err)
	}

	keyParser, err = ssh.ParsePrivateKey(keyData)
	if err != nil {
		panic(err)
	}
}

func main() {
	fmt.Printf("Server...\n")

	config := ssh.ServerConfig{
		PublicKeyCallback: keyAuth,
	}
	config.AddHostKey(keyParser)

	sshPort := "2022"
	socket, err := net.Listen("tcp", ":"+port)
	if err != nil {
		panic(err)
	}

	for {
		fmt.Printf(".")
		tcpConn, err := socket.Accept()
		if err != nil {
			panic(err)
		}

		sshConn, sshChannels, _, err := ssh.NewServerConn(tcpConn, &config)
		if err != nil {
			panic(err)
		}

		fmt.Println("Connection from", sshConn.RemoteAddr())
		go func() {
			for channelReq := range sshChannels {
				go handleChannelReq(channelReq)
			}
			log.Println("End of connection")
			sshConn.Close()
		}()
	}
}

// func authenticateUser(user ssh.Conn.User, key ssh.PublicKey) (ssh.Conn.User, error) {
// 	return ssh.Conn.User{}, nil
// }

func handleChannelReq(channelReq ssh.)

// func handleChannelReq(channelReq ssh.NewChannel) {
// 	if channelReq.ChannelType() != "session" {
// 		channelReq.Reject(ssh.Prohibited, "Channel type is not a session")
// 		return
// 	}
//
// 	ch, requests, err := channelReq.Accept()
// 	if err != nil {
// 		log.Println("Failed to accept channel request", err)
// 		return
// 	}
//
// 	request := <-requests
// 	log.Println("Request type: " + request.Type)
// 	// if request.Type != "exit" {
// 	// 	ch.Write([]byte("Request type '" + request.Type + "' is not acceptable\r\n"))
// 	// 	ch.Close()
// 	// 	return
// 	// }
// 	//
// 	ch.Close()
// }

func keyAuth(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	// user, err := authenticateUser(conn.User(), key)
	// if err != nil {
	// 	log.Println("Failed to authenticate", conn, ":", err)
	// 	return nil, errors.New("Invalid authentication")
	// }
	//
	// return &ssh.Permissions{Extensions: map[string]string{"user_id": user.Id}}, nil

	fmt.Println(conn.RemoteAddr(), "Authenticating with", key.Type())
	return nil, nil
}
