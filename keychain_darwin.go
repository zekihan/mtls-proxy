package main

import (
	"crypto/tls"
	"fmt"

	"github.com/github/smimesign/certstore"
)

// keychainCertificate signs through the Keychain, so the private key never
// has to leave it. The store stays open for the life of the process.
func keychainCertificate(name string) (tls.Certificate, error) {
	store, err := certstore.Open()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("open keychain: %w", err)
	}
	identities, err := store.Identities()
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("list keychain identities: %w", err)
	}
	for _, identity := range identities {
		leaf, err := identity.Certificate()
		if err != nil || leaf.Subject.CommonName != name {
			continue
		}
		signer, err := identity.Signer()
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("open signer for %s: %w", name, err)
		}
		return tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: signer, Leaf: leaf}, nil
	}
	return tls.Certificate{}, fmt.Errorf("keychain identity %q not found", name)
}
