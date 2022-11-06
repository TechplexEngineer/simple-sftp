// An example SFTP server implementation using the golang SSH package.
// Serves the whole filesystem visible to the user, and has a hard-coded username and password,
// so not for real use!
package main

import (
	"flag"
	"fmt"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"net"
)

// Based on example server code from golang.org/x/crypto/ssh and server_standalone
func main() {

	username := flag.String("user", "mfc", "username to accept for sftp connections")
	password := flag.String("pass", "mfc", "password to accept for sftp connections")
	privateKeyFile := flag.String("key", "id_rsa", "path to private key file")
	listen := flag.String("listen", ":2022", "where to attach listener. Supports ip:port, ip is optional or can be 0.0.0.0 or omitted to listen on all interfaces. Use 127.0.0.1 to listen on localhost only")
	flag.Parse()

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Should use constant-time compare (or better, salt+hash) in
			// a production setting.
			log.Printf("%s: Login Request for: %s\n", c.RemoteAddr(), c.User())
			if c.User() == *username && string(pass) == *password {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}

	privateBytes, err := ioutil.ReadFile(*privateKeyFile)
	if err != nil {
		log.Fatal("Failed to load private key", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key", err)
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal("failed to listen for connection", err)
	}
	fmt.Printf("sftp server listening on %v\n", listener.Addr())

	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept incoming connection - %s", err)
			continue
		}

		go handleConnectionRequest(nConn, config)
	}
}

func handleConnectionRequest(nConn net.Conn, config *ssh.ServerConfig) {

	// Before use, a handshake must be performed on the incoming
	// net.Conn.
	_, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Printf("failed to handshake - %s", err)
		return
	}
	log.Printf("%s: SSH login succesfull", nConn.RemoteAddr())

	// The incoming Request channel must be serviced.
	go ssh.DiscardRequests(reqs)

	// Service the incoming Channel channel.
	for newChannel := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of an SFTP session, this is "subsystem"
		// with a payload string of "<length=4>sftp"
		log.Printf("%s: Incoming channel: %s\n", nConn.RemoteAddr(), newChannel.ChannelType())
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			log.Printf("%s: Unknown channel type: %s\n", nConn.RemoteAddr(), newChannel.ChannelType())
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("%s: could not accept channel - %s", nConn.RemoteAddr(), err)
			return
		}
		log.Printf("%s: Channel accepted", nConn.RemoteAddr())

		// Sessions have out-of-band requests such as "shell",
		// "pty-req" and "env".  Here we handle only the
		// "subsystem" request.
		go func(in <-chan *ssh.Request) {
			for req := range in {
				log.Printf("%s: Request: %v\n", nConn.RemoteAddr(), req.Type)
				ok := false
				switch req.Type {
				case "subsystem":
					log.Printf("%s: Subsystem: %s\n", nConn.RemoteAddr(), req.Payload[4:])
					if string(req.Payload[4:]) == "sftp" {
						ok = true
					}
				}
				log.Printf("%s: - accepted: %v\n", nConn.RemoteAddr(), ok)
				_ = req.Reply(ok, nil)
			}
		}(requests)

		serverOptions := []sftp.ServerOption{
			//sftp.WithDebug(debugStream),
		}

		server, err := sftp.NewServer(
			channel,
			serverOptions...,
		)
		if err != nil {
			log.Printf("%: unable to create sftp server - %s", nConn.RemoteAddr(), err)
			return
		}
		if err := server.Serve(); err == io.EOF {
			_ = server.Close()
			log.Printf("%s: sftp client exited session.", nConn.RemoteAddr())
		} else if err != nil {
			log.Printf("%s: sftp server completed with error - %s", nConn.RemoteAddr(), err)
			return
		}
	}
}
