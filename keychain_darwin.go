package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

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
		store.Close()
		return tls.Certificate{}, fmt.Errorf("list keychain identities: %w", err)
	}
	leaves := make([]*x509.Certificate, len(identities))
	for i, identity := range identities {
		leaves[i], _ = identity.Certificate()
	}
	selected, err := selectIdentity(leaves, name, time.Now())
	for i, identity := range identities {
		if i != selected {
			identity.Close()
		}
	}
	if err != nil {
		store.Close()
		return tls.Certificate{}, err
	}
	signer, err := identities[selected].Signer()
	if err != nil {
		identities[selected].Close()
		store.Close()
		return tls.Certificate{}, fmt.Errorf("open signer for %s: %w", name, err)
	}
	leaf := leaves[selected]
	return tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: signer, Leaf: leaf}, nil
}
