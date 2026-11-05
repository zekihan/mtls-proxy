package main

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSelectIdentity(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	leaf := func(before, after time.Duration) *x509.Certificate {
		return &x509.Certificate{Subject: pkix.Name{CommonName: "client"}, NotBefore: now.Add(before), NotAfter: now.Add(after)}
	}
	expired, valid, later := leaf(-48*time.Hour, -time.Hour), leaf(-time.Hour, time.Hour), leaf(-time.Hour, 2*time.Hour)
	for _, tc := range []struct {
		name   string
		leaves []*x509.Certificate
		want   int
	}{
		{"expired first", []*x509.Certificate{expired, valid}, 1},
		{"expired last", []*x509.Certificate{valid, expired}, 0},
		{"later expiry", []*x509.Certificate{valid, later}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectIdentity(tc.leaves, "client", now)
			if err != nil || got != tc.want {
				t.Fatalf("got %d, %v; want %d", got, err, tc.want)
			}
		})
	}
	_, err := selectIdentity([]*x509.Certificate{expired}, "client", now)
	if err == nil || !strings.Contains(err.Error(), expired.NotAfter.Format(time.RFC3339)) {
		t.Fatalf("expiry missing from error: %v", err)
	}
	future := leaf(time.Hour, 2*time.Hour)
	_, err = selectIdentity([]*x509.Certificate{future}, "client", now)
	if err == nil || !strings.Contains(err.Error(), future.NotAfter.Format(time.RFC3339)) {
		t.Fatalf("future validity missing from error: %v", err)
	}
}

func TestStartupCertificateExpiredAndNotYetValid(t *testing.T) {
	leaf := newPKI(t).leaf(t, x509.ExtKeyUsageClientAuth)
	keyDER, err := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert"), filepath.Join(dir, "key")
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"files", "env"} {
		for _, tc := range []struct {
			name string
			now  time.Time
			want string
		}{
			{"Expired", time.Now().Add(2 * time.Hour), "expired"},
			{"NotYetValid", time.Now().Add(-2 * time.Hour), "not yet valid"},
		} {
			t.Run(source+tc.name, func(t *testing.T) {
				config := certificateSource{certFile: certFile, keyFile: keyFile}
				if source == "env" {
					t.Setenv("TEST_CERT", string(certPEM))
					t.Setenv("TEST_KEY", string(keyPEM))
					config = certificateSource{certEnv: "TEST_CERT", keyEnv: "TEST_KEY"}
				}
				cert, err := loadCertificate(config)
				if err != nil {
					t.Fatal(err)
				}
				cert.Leaf = nil
				err = checkClientCertificate(&cert, tc.now, log.New(&bytes.Buffer{}, "", 0))
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("got %v, want %s", err, tc.want)
				}
			})
		}
	}
}

func TestClientCertificateLogging(t *testing.T) {
	leaf := newPKI(t).leaf(t, x509.ExtKeyUsageClientAuth)
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		now  time.Time
		warn bool
	}{
		{"near expiry", parsed.NotAfter.Add(-time.Hour), true},
		{"exactly 30 days", parsed.NotAfter.Add(-30 * 24 * time.Hour), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := leaf
			cert.Leaf = &x509.Certificate{Subject: parsed.Subject, NotBefore: tc.now.Add(-time.Hour), NotAfter: parsed.NotAfter}
			var output bytes.Buffer
			if err := checkClientCertificate(&cert, tc.now, log.New(&output, "", 0)); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), parsed.Subject.String()) || !strings.Contains(output.String(), parsed.NotAfter.Format(time.RFC3339)) {
				t.Fatalf("missing certificate details: %s", output.String())
			}
			if strings.Contains(output.String(), "warning") != tc.warn {
				t.Fatalf("unexpected warning: %s", output.String())
			}
		})
	}
}
