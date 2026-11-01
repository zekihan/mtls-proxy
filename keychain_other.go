//go:build !darwin

package main

import (
	"crypto/tls"
	"errors"
)

func keychainCertificate(string) (tls.Certificate, error) {
	return tls.Certificate{}, errors.New("-identity needs the macOS Keychain; use -cert and -key")
}
