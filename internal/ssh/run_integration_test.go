package ssh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
	"testing"

	gossh "golang.org/x/crypto/ssh"

	"ssm/internal/config"
)

type runTestServerStats struct {
	connections atomic.Int64
	sessions    atomic.Int64
}

func startRunTestSSHServer(t *testing.T) (config.Connection, *config.Vault) {
	t.Helper()
	conn, vault, _ := startTrackedRunTestSSHServer(t)
	return conn, vault
}

func startTrackedRunTestSSHServer(t *testing.T) (config.Connection, *config.Vault, *runTestServerStats) {
	t.Helper()
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := gossh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientSigner, err := gossh.NewSignerFromKey(clientPrivate)
	if err != nil {
		t.Fatal(err)
	}

	serverConfig := &gossh.ServerConfig{
		PublicKeyCallback: func(_ gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			if !bytes.Equal(key.Marshal(), clientSigner.PublicKey().Marshal()) {
				return nil, fmt.Errorf("unexpected public key")
			}
			return nil, nil
		},
	}
	serverConfig.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	stats := &runTestServerStats{}
	go serveRunTestSSH(listener, serverConfig, stats)

	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	block, err := gossh.MarshalPrivateKey(clientPrivate, "ssm-run-integration")
	if err != nil {
		t.Fatal(err)
	}
	vault := &config.Vault{Keys: []config.SSHKey{{Name: "integration", PrivateKey: string(pem.EncodeToMemory(block))}}}
	conn := config.Connection{Name: "integration", Host: "127.0.0.1", Port: port, User: "test", KeyName: "integration"}
	return conn, vault, stats
}

func trustRunTestHost(t *testing.T, connection config.Connection) {
	t.Helper()
	inspection, err := InspectHostKey(connection)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcceptHostKey(connection, inspection.ObservedFingerprint); err != nil {
		t.Fatal(err)
	}
}

func serveRunTestSSH(listener net.Listener, cfg *gossh.ServerConfig, stats *runTestServerStats) {
	for {
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			serverConn, channels, requests, err := gossh.NewServerConn(raw, cfg)
			if err != nil {
				_ = raw.Close()
				return
			}
			stats.connections.Add(1)
			defer func() { _ = serverConn.Close() }()
			go gossh.DiscardRequests(requests)
			for newChannel := range channels {
				if newChannel.ChannelType() != "session" {
					_ = newChannel.Reject(gossh.UnknownChannelType, "session only")
					continue
				}
				channel, channelRequests, err := newChannel.Accept()
				if err != nil {
					continue
				}
				stats.sessions.Add(1)
				go serveRunTestSession(channel, channelRequests)
			}
		}()
	}
}
