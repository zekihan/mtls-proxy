package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

// fuzzPKI is a disposable CA with an upstream server leaf and a client leaf,
// generated once per fuzz worker process. Nothing here touches real keys.
type fuzzPKI struct {
	caCert        *x509.Certificate
	caKey         *ecdsa.PrivateKey
	pool          *x509.CertPool
	server        tls.Certificate
	client        tls.Certificate
	clientCN      string
	clientCertPEM []byte
	clientKeyPEM  []byte
	expiredPEM    []byte
	// secrets are fragments of the client private key that must never show
	// up in errors, logs or responses.
	secrets []string
}

const fuzzUpstreamHost = "upstream.test"

var (
	fuzzPKIOnce  sync.Once
	fuzzPKIValue *fuzzPKI
)

func getFuzzPKI() *fuzzPKI {
	fuzzPKIOnce.Do(func() { fuzzPKIValue = mustFuzzPKI() })
	return fuzzPKIValue
}

func mustFuzzPKI() *fuzzPKI {
	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "disposable fuzz ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	must(err)
	caCert, err := x509.ParseCertificate(caDER)
	must(err)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	issue := func(serial int64, cn string, usage x509.ExtKeyUsage, notBefore, notAfter time.Time) (tls.Certificate, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(err)
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    notBefore,
			NotAfter:     notAfter,
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
			DNSNames:     []string{fuzzUpstreamHost},
			IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		}, caCert, &key.PublicKey, caKey)
		must(err)
		leaf, err := x509.ParseCertificate(der)
		must(err)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, key
	}
	now := time.Now()
	server, _ := issue(2, "disposable fuzz upstream", x509.ExtKeyUsageServerAuth, now.Add(-time.Hour), now.Add(24*time.Hour))
	client, clientKey := issue(3, "disposable fuzz client", x509.ExtKeyUsageClientAuth, now.Add(-time.Hour), now.Add(24*time.Hour))

	keyDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	must(err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: client.Certificate[0]})

	// An expired certificate for the same key, so run stops at the lifetime
	// check and never binds a listener.
	expiredDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "disposable fuzz expired client"},
		NotBefore:    now.Add(-48 * time.Hour),
		NotAfter:     now.Add(-24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, caCert, &clientKey.PublicKey, caKey)
	must(err)

	return &fuzzPKI{
		caCert:        caCert,
		caKey:         caKey,
		pool:          pool,
		server:        server,
		client:        client,
		clientCN:      "disposable fuzz client",
		clientCertPEM: certPEM,
		clientKeyPEM:  keyPEM,
		expiredPEM:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: expiredDER}),
		secrets:       keySecrets(keyPEM, clientKey),
	}
}

// keySecrets returns fragments that identify a private key in text: each
// base64 line of its PEM body and its scalar in decimal and hex.
func keySecrets(keyPEM []byte, key *ecdsa.PrivateKey) []string {
	var secrets []string
	for _, line := range strings.Split(string(keyPEM), "\n") {
		if len(line) >= 16 && !strings.HasPrefix(line, "-----") {
			secrets = append(secrets, line)
		}
	}
	if key != nil {
		d, err := key.Bytes()
		if err == nil {
			secrets = append(secrets, new(big.Int).SetBytes(d).String(), fmt.Sprintf("%x", d))
		}
	}
	return secrets
}

func leakedSecret(text string, secrets []string) string {
	for _, secret := range secrets {
		if strings.Contains(text, secret) {
			return secret
		}
	}
	return ""
}
