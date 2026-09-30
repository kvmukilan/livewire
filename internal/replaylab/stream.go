package replaylab

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

func LabCertificate() (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "livewire software lab"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func SetupStreamFixture(ctx context.Context, dir string, exchanges []Exchange, handler func(net.Conn, *Stats) error, useTLS bool) (_ *Fixture, retErr error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	var server *TCPServer
	var err error
	var cert tls.Certificate
	var ca []byte
	if useTLS {
		cert, ca, err = LabCertificate()
		if err != nil {
			return nil, err
		}
		listener, e := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		if e != nil {
			return nil, e
		}
		server = ServeListener(ctx, listener, func(conn net.Conn, stats *Stats) error {
			peer := conn.(*tls.Conn)
			if err := peer.HandshakeContext(ctx); err != nil {
				return err
			}
			stats.Note("TLS peer negotiated %s; capture baseline TLS 1.2", tls.VersionName(peer.ConnectionState().Version))
			return handler(conn, stats)
		})
	} else {
		server, err = ServeTCP(ctx, handler)
		if err != nil {
			return nil, err
		}
	}
	defer func() {
		if retErr != nil {
			_ = server.Close()
		}
	}()
	capture := filepath.Join(dir, "fixture.pcap")
	args := []string{"-t", server.Address()}
	if useTLS {
		keylog := filepath.Join(dir, "fixture.keys")
		caPath := filepath.Join(dir, "fixture-ca.pem")
		if err = os.WriteFile(caPath, ca, 0600); err != nil {
			return nil, err
		}
		encrypted, keys, encryptErr := EncryptConversation(cert, exchanges)
		if encryptErr != nil {
			return nil, encryptErr
		}
		if err = os.WriteFile(keylog, keys, 0600); err != nil {
			return nil, err
		}
		if err = WriteTCPCapture(capture, server.Port(), encrypted); err != nil {
			return nil, err
		}
		args = append(args, "-keylog", keylog, "-ca", caPath, "-server-name", "localhost")
	} else if err = WriteTCPCapture(capture, server.Port(), exchanges); err != nil {
		return nil, err
	}
	return &Fixture{Capture: capture, Args: args, Snapshot: server.Stats.Snapshot, Events: server.Stats.Events, Close: server.Close}, nil
}

type recordingConn struct {
	net.Conn
	mu     sync.Mutex
	events []Exchange
	at     time.Duration
}

func (c *recordingConn) record(client bool, data []byte) {
	if len(data) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := Exchange{At: c.at}
	c.at += time.Millisecond
	if client {
		e.Client = append([]byte(nil), data...)
	} else {
		e.Server = append([]byte(nil), data...)
	}
	c.events = append(c.events, e)
}
func (c *recordingConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	c.record(false, b[:n])
	return n, e
}
func (c *recordingConn) Write(b []byte) (int, error) {
	n, e := c.Conn.Write(b)
	c.record(true, b[:n])
	return n, e
}

// CaptureTLS records a real certificate-verified TLS session and matching
// ephemeral secrets. Records carry explicitly synthetic fixture timing.
func CaptureTLS(ctx context.Context, capture, keylog, address string, config *tls.Config, exchanges []Exchange) (retErr error) {
	keys, err := os.OpenFile(keylog, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if err := keys.Close(); retErr == nil {
			retErr = err
		}
	}()
	raw, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	recorder := &recordingConn{Conn: raw}
	cfg := config.Clone()
	cfg.KeyLogWriter = keys
	conn := tls.Client(recorder, cfg)
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	if err = conn.HandshakeContext(ctx); err != nil {
		return err
	}
	for _, exchange := range exchanges {
		recorder.mu.Lock()
		if exchange.At > recorder.at {
			recorder.at = exchange.At
		}
		recorder.mu.Unlock()
		if len(exchange.Client) > 0 {
			if _, err = conn.Write(exchange.Client); err != nil {
				return err
			}
		}
		if len(exchange.Server) > 0 {
			got := make([]byte, len(exchange.Server))
			if _, err = io.ReadFull(conn, got); err != nil {
				return err
			}
			if !bytes.Equal(got, exchange.Server) {
				return fmt.Errorf("TLS capture fixture response differs from independent specification")
			}
		}
	}
	if err = conn.Close(); err != nil {
		return err
	}
	port := uint16(raw.RemoteAddr().(*net.TCPAddr).Port)
	return WriteTCPCapture(capture, port, recorder.events)
}

// EncryptConversation builds real TLS records for a supplied fixture exchange,
// without sharing any application decoder with the replay implementation.
func EncryptConversation(cert tls.Certificate, exchanges []Exchange) ([]Exchange, []byte, error) {
	return encryptConversation(cert, exchanges, nil)
}

func encryptConversation(cert tls.Certificate, exchanges []Exchange, alpn []string) ([]Exchange, []byte, error) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	deadline := time.Now().Add(10 * time.Second)
	_ = clientRaw.SetDeadline(deadline)
	_ = serverRaw.SetDeadline(deadline)
	done := make(chan error, 1)
	go func() {
		// #nosec G402 -- Offline synthetic capture deliberately exercises TLS 1.2 decryption; the live peer negotiates current TLS.
		server := tls.Server(serverRaw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, NextProtos: alpn})
		defer serverRaw.Close()
		if err := server.Handshake(); err != nil {
			done <- err
			return
		}
		for _, exchange := range exchanges {
			if len(exchange.Client) > 0 {
				got := make([]byte, len(exchange.Client))
				if _, err := io.ReadFull(server, got); err != nil {
					done <- err
					return
				}
				if !bytes.Equal(got, exchange.Client) {
					done <- fmt.Errorf("fixture encryption client mismatch")
					return
				}
			}
			if len(exchange.Server) > 0 {
				if _, err := server.Write(exchange.Server); err != nil {
					done <- err
					return
				}
			}
		}
		_, err := io.Copy(io.Discard, server)
		done <- err
	}()
	roots := x509.NewCertPool()
	leaf := cert.Leaf
	if leaf == nil {
		var err error
		leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, nil, err
		}
	}
	roots.AddCert(leaf)
	var keys bytes.Buffer
	recorder := &recordingConn{Conn: clientRaw}
	// #nosec G402 -- Offline synthetic capture deliberately exercises TLS 1.2 decryption; no remote connection is made.
	client := tls.Client(recorder, &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, KeyLogWriter: &keys, NextProtos: alpn})
	if err := client.Handshake(); err != nil {
		return nil, nil, err
	}
	for _, exchange := range exchanges {
		recorder.mu.Lock()
		if exchange.At > recorder.at {
			recorder.at = exchange.At
		}
		recorder.mu.Unlock()
		if len(exchange.Client) > 0 {
			if _, err := client.Write(exchange.Client); err != nil {
				return nil, nil, err
			}
		}
		if len(exchange.Server) > 0 {
			got := make([]byte, len(exchange.Server))
			if _, err := io.ReadFull(client, got); err != nil {
				return nil, nil, err
			}
			if !bytes.Equal(got, exchange.Server) {
				return nil, nil, fmt.Errorf("fixture encryption server mismatch")
			}
		}
	}
	if err := client.Close(); err != nil {
		return nil, nil, err
	}
	if err := <-done; err != nil {
		return nil, nil, err
	}
	return recorder.events, keys.Bytes(), nil
}
