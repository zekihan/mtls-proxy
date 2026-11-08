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
	"io"
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
	"strconv"
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
	if !validUpstream(upstream) {
		return route{}, fmt.Errorf("route %q: upstream must be host or host:port, with IPv6 in brackets", value)
	}
	return route{listen: listen, upstream: upstream}, nil
}

// validUpstream reports whether upstream is a host name or IP literal with an
// optional port. Anything else would be dialed as something other than what
// was configured: "::1" splits into host "::" and port "1".
func validUpstream(upstream string) bool {
	host := upstream
	bracketed := strings.HasPrefix(upstream, "[")
	if h, port, err := net.SplitHostPort(upstream); err == nil {
		if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
			return false
		}
		host = h
	} else if bracketed && strings.HasSuffix(upstream, "]") {
		host = upstream[1 : len(upstream)-1]
	}
	if ip := net.ParseIP(host); ip != nil {
		return bracketed == strings.Contains(host, ":")
	}
	return !bracketed && validHostname(host)
}

func validHostname(name string) bool {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, c := range []byte(label) {
			ok := 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_'
			if !ok {
				return false
			}
		}
	}
	// Resolvers read "127.1" or "0x7f000001" as an IPv4 address.
	last := strings.ToLower(labels[len(labels)-1])
	if strings.Trim(last, "0123456789") == "" {
		return false
	}
	if hex, ok := strings.CutPrefix(last, "0x"); ok && strings.Trim(hex, "0123456789abcdef") == "" {
		return false
	}
	return true
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
		// Cleanup is best-effort; preserve the original write error.
		_ = os.Remove(file.Name())
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
		// The transport accepts any three digits, but WriteHeader panics on
		// a code below 100, so an upstream "000" would abort the handler.
		ModifyResponse: func(r *http.Response) error {
			if r.StatusCode < 100 {
				return fmt.Errorf("upstream returned invalid status %d", r.StatusCode)
			}
			return nil
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A target like "http:evil.example/x" parses as opaque, and the
		// transport would send it verbatim as the upstream request-target.
		if r.URL.Opaque != "" {
			http.Error(w, "request target not allowed", http.StatusBadRequest)
			return
		}
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
	return loadCertificateWithEnv(source, os.Getenv)
}

func loadCertificateWithEnv(source certificateSource, getenv func(string) string) (tls.Certificate, error) {
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
			return certificateFromEnv(source.certEnv, source.keyEnv, getenv)
		}
	}
	return tls.Certificate{}, errors.New("set one of -identity, -cert with -key, or -cert-env with -key-env")
}

// certificateFromEnv removes the variables once read, so child processes and
// later code never see the key.
func certificateFromEnv(certEnv, keyEnv string, getenv func(string) string) (tls.Certificate, error) {
	certPEM, keyPEM := getenv(certEnv), getenv(keyEnv)
	// Removing secrets from the process environment is best-effort.
	_ = os.Unsetenv(certEnv)
	_ = os.Unsetenv(keyEnv)
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
			// Listener cleanup must not replace the serve result.
			_ = listener.Close()
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
		// Closing during cancellation is best-effort; return the serve error.
		_ = server.Close()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func run(ctx context.Context, args []string, getenv func(string) string, stderr io.Writer) error {
	flags := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	var routes []route
	identity := flags.String("identity", "", "macOS Keychain identity common name, e.g. clients-laptop")
	certFile := flags.String("cert", "", "PEM client certificate, used with -key")
	keyFile := flags.String("key", "", "PEM client private key, used with -cert")
	certEnv := flags.String("cert-env", "", "environment variable holding the PEM client certificate, used with -key-env")
	keyEnv := flags.String("key-env", "", "environment variable holding the PEM client private key, used with -cert-env")
	caOut := flags.String("ca-out", "", "path to write the loopback certificate for providers to trust")
	flags.Var(routeFlag{routes: &routes}, "route", "HTTPS reverse route, listen=upstream, e.g. 127.0.0.1:18443=app.example.com (repeatable)")
	flags.Var(routeFlag{routes: &routes, forward: true}, "forward", "HTTP_PROXY route limited to one host, listen=upstream, e.g. 127.0.0.1:18445=s3.example.com (repeatable)")
	if err := flags.Parse(args); err != nil {
		return flagError{err}
	}

	if len(routes) == 0 {
		return errors.New("at least one -route or -forward is required")
	}
	needsTLS := slices.ContainsFunc(routes, func(r route) bool { return !r.forward })
	if needsTLS && *caOut == "" {
		return errors.New("-ca-out is required with -route")
	}
	cert, err := loadCertificateWithEnv(certificateSource{
		identity: *identity,
		certFile: *certFile,
		keyFile:  *keyFile,
		certEnv:  *certEnv,
		keyEnv:   *keyEnv,
	}, getenv)
	if err != nil {
		return err
	}
	if err := checkClientCertificate(&cert, time.Now(), log.Default()); err != nil {
		return err
	}
	return serve(ctx, routes, newTransport(cert, nil), *caOut)
}

type flagError struct{ error }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Getenv, os.Stderr); err != nil {
		var parseErr flagError
		if errors.As(err, &parseErr) {
			if errors.Is(parseErr.error, flag.ErrHelp) {
				return
			}
			os.Exit(2)
		}
		log.Fatal(err)
	}
}
