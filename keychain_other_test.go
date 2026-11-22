//go:build !darwin

package main

import (
	"strings"
	"testing"
)

func TestLoadCertificateFromIdentityNeedsKeychain(t *testing.T) {
	_, err := loadCertificate(certificateSource{identity: "clients-laptop"})
	if err == nil || !strings.Contains(err.Error(), "macOS Keychain") {
		t.Fatalf("err = %v", err)
	}
}
