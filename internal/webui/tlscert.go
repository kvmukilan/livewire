package webui

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kvmukilan/livewire/internal/securefile"
)

const (
	localCertFile     = "dashboard-cert.pem"
	localKeyFile      = "dashboard-key.pem"
	localCertLifetime = 397 * 24 * time.Hour
	// A certificate this close to expiry is replaced at startup rather than
	// lapsing while the dashboard is open.
	localCertRenewBefore = 30 * 24 * time.Hour
)

// TLSOptions selects the dashboard's server certificate. CertFile and KeyFile
// name an operator-supplied pair. When both are empty a self-signed certificate
// for Hosts is kept in StateDir, so a browser exception granted once keeps
// applying across launches; an empty StateDir keeps it in memory only.
type TLSOptions struct {
	CertFile string
	KeyFile  string
	StateDir string
	Hosts    []string
}

// TLSIdentity is the server configuration plus what an operator needs to
// confirm the browser is talking to this process.
type TLSIdentity struct {
	Config      *tls.Config
	Fingerprint string // SHA-256 of the leaf certificate, colon-separated
	SelfSigned  bool
}

// LoadTLSIdentity returns the dashboard's HTTPS identity. The dashboard has no
// plaintext listener; this is the only way it is served.
func LoadTLSIdentity(o TLSOptions) (TLSIdentity, error) {
	if (o.CertFile == "") != (o.KeyFile == "") {
		return TLSIdentity{}, fmt.Errorf("a dashboard certificate needs both the certificate and its key")
	}
	if o.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
		if err != nil {
			return TLSIdentity{}, fmt.Errorf("load dashboard certificate: %w", err)
		}
		return identityFor(cert, false), nil
	}
	hosts := o.Hosts
	if len(hosts) == 0 {
		hosts = []string{"localhost", "127.0.0.1", "::1"}
	}
	if o.StateDir != "" {
		certPath, keyPath := filepath.Join(o.StateDir, localCertFile), filepath.Join(o.StateDir, localKeyFile)
		if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil && certificateCovers(cert, hosts) {
			return identityFor(cert, true), nil
		}
	}
	certPEM, keyPEM, err := selfSignedPair(hosts)
	if err != nil {
		return TLSIdentity{}, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return TLSIdentity{}, err
	}
	if o.StateDir != "" {
		// Failing to persist only costs a repeated browser prompt next launch.
		_ = persistPair(o.StateDir, certPEM, keyPEM)
	}
	return identityFor(cert, true), nil
}

func identityFor(cert tls.Certificate, selfSigned bool) TLSIdentity {
	sum := sha256.Sum256(cert.Certificate[0])
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = hex.EncodeToString([]byte{b})
	}
	return TLSIdentity{
		Config:      &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}},
		Fingerprint: strings.ToUpper(strings.Join(parts, ":")),
		SelfSigned:  selfSigned,
	}
}

func certificateCovers(cert tls.Certificate, hosts []string) bool {
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter.Add(-localCertRenewBefore)) {
		return false
	}
	for _, host := range hosts {
		if leaf.VerifyHostname(host) != nil {
			return false
		}
	}
	return true
}

func selfSignedPair(hosts []string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Livewire local dashboard"},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(localCertLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else if host != "" {
			template.DNSNames = append(template.DNSNames, host)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func persistPair(dir string, certPEM, keyPEM []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, item := range []struct {
		name string
		data []byte
	}{{localKeyFile, keyPEM}, {localCertFile, certPEM}} {
		target := filepath.Join(dir, item.name)
		if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		f, err := securefile.Create(target)
		if err != nil {
			return err
		}
		if _, err := f.Write(item.data); err != nil {
			return errors.Join(err, f.Abort())
		}
		if err := f.Commit(); err != nil {
			return err
		}
	}
	return nil
}
