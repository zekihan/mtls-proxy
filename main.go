// Command mtls_proxy exposes mTLS-protected hosts on loopback for Terraform
// providers that cannot present a client certificate.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

type route struct {
	listen   string
	upstream string
	forward  bool
}

type routeFlag struct {
	routes  *[]route
	forward bool
}

func (f routeFlag) String() string {
	if f.routes == nil {
		return ""
	}
	return fmt.Sprint(*f.routes)
}

func (f routeFlag) Set(value string) error {
	parsed, err := parseRoute(value)
	if err != nil {
		return err
	}
	parsed.forward = f.forward
	*f.routes = append(*f.routes, parsed)
	return nil
}

func parseRoute(value string) (route, error) {
	listen, upstream, ok := strings.Cut(value, "=")
	if !ok || upstream == "" {
		return route{}, fmt.Errorf("route %q must be listen=upstream", value)
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return route{}, fmt.Errorf("route %q: %w", value, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return route{}, fmt.Errorf("route %q must listen on a loopback IP", value)
	}
	return route{listen: listen, upstream: upstream}, nil
}

// newServerCertificate creates a self-signed certificate for the loopback
// listeners. Its key lives only in memory, so each start gets a new one.
func newServerCertificate(routes []route) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "mtls-proxy loopback"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// Clients trust this certificate as a CA, so limit what it can sign to
		// the listener IPs. The .invalid TLD never resolves, so no DNS name passes.
		PermittedDNSDomains: []string{"invalid"},
	}
	seen := map[string]bool{}
	for _, r := range routes {
		if r.forward {
			continue
		}
		host, _, err := net.SplitHostPort(r.listen)
		if err != nil {
			return tls.Certificate{}, err
		}
		if !seen[host] {
			seen[host] = true
			ip := net.ParseIP(host)
			if ip4 := ip.To4(); ip4 != nil {
				ip = ip4
			}
			template.IPAddresses = append(template.IPAddresses, ip)
			bits := len(ip) * 8
			template.PermittedIPRanges = append(template.PermittedIPRanges, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// writeCertificate renames a new file over path, so it never writes through a
// symlink or into a file that another user created there.
func writeCertificate(path string, cert tls.Certificate) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".mtls-proxy-*.pem")
	if err != nil {
		return err
	}
	_, err = file.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
	if err == nil {
		err = file.Chmod(0o644)
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(file.Name(), path)
	}
	if err != nil {
		os.Remove(file.Name())
	}
	return err
}

func newTransport(cert tls.Certificate, roots *x509.CertPool) *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
			// Unlike Certificates, this does not drop the identity when the
			// server's acceptable-CA hints do not match the issuer.
			GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return &cert, nil
			},
		},
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     90 * time.Second,
	}
}

func newProxy(upstream string, transport http.RoundTripper) http.Handler {
	target := &url.URL{Scheme: "https", Host: upstream}
	proxy := &httputil.ReverseProxy{
		Rewrite:   func(r *httputil.ProxyRequest) { r.SetURL(target) },
		Transport: transport,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Browsers set Sec-Fetch-Site and pages cannot change it. Refuse requests
		// made by another site, so a web page cannot use the client identity.
		switch r.Header.Get("Sec-Fetch-Site") {
		case "", "same-origin", "none":
			proxy.ServeHTTP(w, r)
		default:
			http.Error(w, "cross-site request not allowed", http.StatusForbidden)
		}
	})
}

// newForwardProxy serves clients that use HTTP_PROXY, which keeps the real
// hostname in the request. SigV4 signs that hostname, so it cannot go through
// a reverse route. Only the upstream is accepted, so this is not an open proxy.
func newForwardProxy(upstream string, transport http.RoundTripper) http.Handler {
	proxy := newProxy(upstream, transport)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect || !strings.EqualFold(r.Host, upstream) {
			http.Error(w, "target not allowed", http.StatusForbidden)
			return
		}
		proxy.ServeHTTP(w, r)
	})
}

type certificateSource struct {
	identity string
	certFile string
	keyFile  string
	certEnv  string
	keyEnv   string
}

func loadCertificate(source certificateSource) (tls.Certificate, error) {
	switch source {
	case certificateSource{identity: source.identity}:
		if source.identity != "" {
			return keychainCertificate(source.identity)
		}
	case certificateSource{certFile: source.certFile, keyFile: source.keyFile}:
		if source.certFile != "" && source.keyFile != "" {
			return tls.LoadX509KeyPair(source.certFile, source.keyFile)
		}
	case certificateSource{certEnv: source.certEnv, keyEnv: source.keyEnv}:
		if source.certEnv != "" && source.keyEnv != "" {
			return certificateFromEnv(source.certEnv, source.keyEnv)
		}
	}
	return tls.Certificate{}, errors.New("set one of -identity, -cert with -key, or -cert-env with -key-env")
}

// certificateFromEnv removes the variables once read, so child processes and
// later code never see the key.
func certificateFromEnv(certEnv, keyEnv string) (tls.Certificate, error) {
	certPEM, keyPEM := os.Getenv(certEnv), os.Getenv(keyEnv)
	os.Unsetenv(certEnv)
	os.Unsetenv(keyEnv)
	if certPEM == "" {
		return tls.Certificate{}, fmt.Errorf("%s is empty", certEnv)
	}
	if keyPEM == "" {
		return tls.Certificate{}, fmt.Errorf("%s is empty", keyEnv)
	}
	return tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
}

func serve(ctx context.Context, routes []route, transport http.RoundTripper, caOut string) error {
	listeners := make([]net.Listener, 0, len(routes))
	defer func() {
		for _, listener := range listeners {
			listener.Close()
		}
	}()
	for _, r := range routes {
		listener, err := net.Listen("tcp", r.listen)
		if err != nil {
			return err
		}
		listeners = append(listeners, listener)
	}

	var serverCert tls.Certificate
	if slices.ContainsFunc(routes, func(r route) bool { return !r.forward }) {
		var err error
		if serverCert, err = newServerCertificate(routes); err != nil {
			return err
		}
		if err = writeCertificate(caOut, serverCert); err != nil {
			return err
		}
	}
	errs := make(chan error, len(routes))
	servers := make([]*http.Server, 0, len(routes))
	for i, r := range routes {
		server := &http.Server{
			Addr:              r.listen,
			Handler:           newProxy(r.upstream, transport),
			ReadHeaderTimeout: 10 * time.Second,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{serverCert},
				MinVersion:   tls.VersionTLS13,
			},
			// WebSocket upgrades need HTTP/1.1.
			TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		}
		servers = append(servers, server)
		if r.forward {
			server.Handler = newForwardProxy(r.upstream, transport)
			go func() { errs <- server.Serve(listeners[i]) }()
			log.Printf("forward http://%s -> https://%s", r.listen, r.upstream)
			continue
		}
		go func() { errs <- server.ServeTLS(listeners[i], "", "") }()
		log.Printf("https://%s -> https://%s", r.listen, r.upstream)
	}
	var err error
	select {
	case err = <-errs:
	case <-ctx.Done():
	}
	for _, server := range servers {
		server.Close()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func main() {
	var routes []route
	identity := flag.String("identity", "", "macOS Keychain identity common name, e.g. clients-laptop")
	certFile := flag.String("cert", "", "PEM client certificate, used with -key")
	keyFile := flag.String("key", "", "PEM client private key, used with -cert")
	certEnv := flag.String("cert-env", "", "environment variable holding the PEM client certificate, used with -key-env")
	keyEnv := flag.String("key-env", "", "environment variable holding the PEM client private key, used with -cert-env")
	caOut := flag.String("ca-out", "", "path to write the loopback certificate for providers to trust")
	flag.Var(routeFlag{routes: &routes}, "route", "HTTPS reverse route, listen=upstream, e.g. 127.0.0.1:18443=app.example.com (repeatable)")
	flag.Var(routeFlag{routes: &routes, forward: true}, "forward", "HTTP_PROXY route limited to one host, listen=upstream, e.g. 127.0.0.1:18445=s3.example.com (repeatable)")
	flag.Parse()

	if len(routes) == 0 {
		log.Fatal("at least one -route or -forward is required")
	}
	needsTLS := slices.ContainsFunc(routes, func(r route) bool { return !r.forward })
	if needsTLS && *caOut == "" {
		log.Fatal("-ca-out is required with -route")
	}
	cert, err := loadCertificate(certificateSource{
		identity: *identity,
		certFile: *certFile,
		keyFile:  *keyFile,
		certEnv:  *certEnv,
		keyEnv:   *keyEnv,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx, routes, newTransport(cert, nil), *caOut); err != nil {
		log.Fatal(err)
	}
}
