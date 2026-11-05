package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"strings"
	"time"
)

func selectIdentity(leaves []*x509.Certificate, name string, now time.Time) (int, error) {
	selected := -1
	var validity []string
	for i, leaf := range leaves {
		if leaf == nil || leaf.Subject.CommonName != name {
			continue
		}
		validity = append(validity, fmt.Sprintf("NotBefore=%s NotAfter=%s", leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339)))
		if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
			continue
		}
		if selected == -1 || leaf.NotAfter.After(leaves[selected].NotAfter) {
			selected = i
		}
	}
	if selected >= 0 {
		return selected, nil
	}
	if len(validity) == 0 {
		return -1, fmt.Errorf("keychain identity %q not found", name)
	}
	return -1, fmt.Errorf("no currently valid keychain identity %q: %s", name, strings.Join(validity, "; "))
}

func checkClientCertificate(cert *tls.Certificate, now time.Time, logger *log.Logger) error {
	if cert.Leaf == nil {
		if len(cert.Certificate) == 0 {
			return fmt.Errorf("client certificate has no leaf")
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return fmt.Errorf("parse client certificate: %w", err)
		}
		cert.Leaf = leaf
	}
	leaf := cert.Leaf
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("client certificate %s is not yet valid until %s (NotAfter %s)", leaf.Subject, leaf.NotBefore.Format(time.RFC3339), leaf.NotAfter.Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("client certificate %s expired at %s", leaf.Subject, leaf.NotAfter.Format(time.RFC3339))
	}
	logger.Printf("client certificate subject=%s NotAfter=%s", leaf.Subject, leaf.NotAfter.Format(time.RFC3339))
	if leaf.NotAfter.Sub(now) < 30*24*time.Hour {
		logger.Printf("warning: client certificate expires in less than 30 days")
	}
	return nil
}
