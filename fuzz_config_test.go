package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// refLoopbackListen is an independent check, built on net/netip rather than
// net.ParseIP, that a listen address names a loopback IP literal.
func refLoopbackListen(listen string) bool {
	i := strings.LastIndexByte(listen, ':')
	if i < 0 {
		return false
	}
	host := listen[:i]
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	} else if strings.Contains(host, ":") {
		return false
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Zone() == "" && addr.Unmap().IsLoopback()
}

// refUpstream is an independent parser for the upstream half of a route: a
// host name, an IPv4 literal or a bracketed IPv6 literal, then an optional
// port from 1 to 65535. It returns the host and port the transport must dial.
func refUpstream(s string) (host, port string, ok bool) {
	rest := ""
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return "", "", false
		}
		host, rest = s[1:end], s[end+1:]
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return "", "", false
		}
	} else {
		host = s
		if i := strings.IndexByte(s, ':'); i >= 0 {
			host, rest = s[:i], s[i:]
		}
		if addr, err := netip.ParseAddr(host); err == nil {
			if !addr.Is4() {
				return "", "", false
			}
		} else if !refHostname(host) {
			return "", "", false
		}
	}
	if rest == "" {
		return host, "", true
	}
	if rest[0] != ':' || len(rest) == 1 {
		return "", "", false
	}
	value := 0
	for _, c := range rest[1:] {
		if c < '0' || c > '9' {
			return "", "", false
		}
		value = value*10 + int(c-'0')
		if value > 65535 {
			return "", "", false
		}
	}
	if value == 0 {
		return "", "", false
	}
	return host, rest[1:], true
}

func refHostname(name string) bool {
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
			if !ok {
				return false
			}
		}
	}
	// Resolvers read an all-digit or 0x-prefixed last label as an IPv4
	// number ("127.1", "0x7f000001"), not as a name.
	last := strings.ToLower(labels[len(labels)-1])
	if strings.Trim(last, "0123456789") == "" {
		return false
	}
	if strings.HasPrefix(last, "0x") && strings.Trim(last[2:], "0123456789abcdef") == "" {
		return false
	}
	return true
}

func FuzzParseRoute(f *testing.F) {
	for _, seed := range []string{
		"127.0.0.1:18443=app.example.com",
		"127.0.0.1:18443=app.example.com:8443",
		"[::1]:18443=app.example.com",
		"[::ffff:127.0.0.1]:1=a",
		"[::1%lo]:1=a",
		"127.0.0.1:0=10.0.0.5:443",
		"127.0.0.1:1=[2001:db8::1]:443",
		"127.0.0.1:1=[2001:db8::1]",
		"127.0.0.1:1=::1",
		"127.0.0.1:1=::8443",
		"127.0.0.1:1=https://x",
		"127.0.0.1:1=a/b",
		"127.0.0.1:1=user@host",
		"127.0.0.1:1=a b",
		"127.0.0.1:1=host:",
		"127.0.0.1:1=host:0",
		"127.0.0.1:1=host:65536",
		"127.0.0.1:1=host:+443",
		"127.0.0.1:1=127.1",
		"127.0.0.1:1=0x7f000001",
		"127.0.0.1:1=[1.2.3.4]:443",
		"127.0.0.1:1=a=b",
		"127.0.0.1:1=app.example.com.",
		"127.0.0.1:abc=a",
		"127.0.0.1:99999=a",
		"127.0.0.1:=a",
		"0.0.0.0:1=a",
		"localhost:1=a",
		"127.000.000.001:1=a",
		"[::]:1=a",
		"=a",
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		r, err := parseRoute(value)
		if err != nil {
			if strings.ContainsAny(err.Error(), "\r\n") && !strings.ContainsAny(value, "\r\n") {
				t.Fatalf("multi-line error %q", err)
			}
			return
		}
		if !refLoopbackListen(r.listen) {
			t.Fatalf("parseRoute(%q) accepted non-loopback listen %q", value, r.listen)
		}
		if addr, err := net.ResolveTCPAddr("tcp", r.listen); err == nil && !addr.IP.IsLoopback() {
			t.Fatalf("parseRoute(%q): listen %q resolves to %v", value, r.listen, addr.IP)
		}
		host, port, ok := refUpstream(r.upstream)
		if !ok {
			t.Fatalf("parseRoute(%q) accepted invalid upstream %q", value, r.upstream)
		}
		target := &url.URL{Scheme: "https", Host: r.upstream}
		if target.Hostname() != host || target.Port() != port {
			t.Fatalf("upstream %q: URL dials host %q port %q, want %q %q", r.upstream, target.Hostname(), target.Port(), host, port)
		}
		again, err := parseRoute(r.listen + "=" + r.upstream)
		if err != nil || again != r {
			t.Fatalf("round trip of %q: %+v, %v", value, again, err)
		}
	})
}

// FuzzParseRouteAcceptsValid checks the other direction: every listen and
// upstream that the reference accepts must be accepted.
func FuzzParseRouteAcceptsValid(f *testing.F) {
	for _, seed := range [][2]string{
		{"127.0.0.1:1", "a"}, {"[::1]:1", "app.example.com:8443"}, {"127.0.0.2:0", "[2001:db8::1]:443"},
		{"[::ffff:127.0.0.1]:1", "10.0.0.5"}, {"127.0.0.1:1", "host_name.internal."},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, listen, upstream string) {
		if !refLoopbackListen(listen) || strings.Contains(listen, "=") {
			return
		}
		port := listen[strings.LastIndexByte(listen, ':')+1:]
		if port == "" || strings.Trim(port, "0123456789") != "" || len(port) > 5 {
			return
		}
		if _, _, ok := refUpstream(upstream); !ok {
			return
		}
		if _, err := parseRoute(listen + "=" + upstream); err != nil {
			t.Fatalf("parseRoute rejected valid %q=%q: %v", listen, upstream, err)
		}
	})
}

var runFlagsWithValue = map[string]bool{
	"identity": true, "cert": true, "key": true, "cert-env": true, "key-env": true,
	"ca-out": true, "route": true, "forward": true,
}

// sanitizeRunArgs drops every flag that could load a real identity, read a
// file or write one, along with its value.
func sanitizeRunArgs(args []string) []string {
	drop := map[string]bool{"identity": true, "cert": true, "key": true, "cert-env": true, "key-env": true, "ca-out": true}
	var out []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" || !strings.HasPrefix(arg, "-") || arg == "-" {
			out = append(out, args[i:]...)
			break
		}
		name, _, hasValue := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-"), "=")
		if drop[name] {
			if !hasValue {
				i++
			}
			continue
		}
		out = append(out, arg)
	}
	return out
}

func FuzzRunArgs(f *testing.F) {
	for _, seed := range []string{
		"-route\x00127.0.0.1:1=a",
		"-forward\x00127.0.0.1:1=s3.example.com",
		"-route=127.0.0.1:1=a\x00-forward=[::1]:2=b:8443",
		"-route\x000.0.0.0:1=a",
		"-route\x00127.0.0.1:1=a\x00extra",
		"route\x00127.0.0.1:1=a",
		"-route\x00127.0.0.1:1=a\x00--\x00-forward\x00127.0.0.1:2=b",
		"-cert\x00/etc/passwd\x00-key\x00/etc/shadow\x00-route\x00127.0.0.1:1=a",
		"-identity\x00me\x00-forward\x00127.0.0.1:1=a",
		"-h",
		"-route",
		"-unknown\x00x",
		"",
	} {
		f.Add([]byte(seed))
	}
	pki := getFuzzPKI()
	caOut := filepath.Join(f.TempDir(), "ca.pem")
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		var fuzzed []string
		if len(data) > 0 {
			fuzzed = strings.Split(string(data), "\x00")
		}
		args := append([]string{"-cert-env", "MTLS_FUZZ_RUN_CERT", "-key-env", "MTLS_FUZZ_RUN_KEY", "-ca-out", caOut}, sanitizeRunArgs(fuzzed)...)
		// The expired certificate stops run before it binds anything.
		getenv := func(name string) string {
			switch name {
			case "MTLS_FUZZ_RUN_CERT":
				return string(pki.expiredPEM)
			case "MTLS_FUZZ_RUN_KEY":
				return string(pki.clientKeyPEM)
			}
			return ""
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var stderr bytes.Buffer
		err := run(ctx, args, getenv, &stderr)
		if err == nil {
			t.Fatalf("run(%q) returned nil with an expired certificate", args)
		}
		if secret := leakedSecret(err.Error()+stderr.String(), pki.secrets); secret != "" {
			t.Fatalf("run(%q) leaked key material %q", args, secret)
		}
		if _, err := os.Stat(caOut); err == nil {
			t.Fatalf("run(%q) wrote %s", args, caOut)
		}
		if !strings.Contains(err.Error(), "expired at") {
			return
		}
		// run accepted the configuration. Parse the same arguments with a
		// plain FlagSet and check every route against the reference.
		ref := flag.NewFlagSet("ref", flag.ContinueOnError)
		ref.SetOutput(io.Discard)
		var values []string
		for name := range runFlagsWithValue {
			if name == "route" || name == "forward" {
				ref.Func(name, "", func(v string) error { values = append(values, v); return nil })
			} else {
				ref.String(name, "", "")
			}
		}
		if err := ref.Parse(args); err != nil {
			t.Fatalf("run accepted %q but a plain FlagSet fails: %v", args, err)
		}
		if ref.NArg() > 0 {
			t.Fatalf("run accepted %q and ignored positional arguments %q", args, ref.Args())
		}
		if len(values) == 0 {
			t.Fatalf("run accepted %q without routes", args)
		}
		for _, v := range values {
			listen, upstream, _ := strings.Cut(v, "=")
			if !refLoopbackListen(listen) {
				t.Fatalf("run accepted non-loopback route %q", v)
			}
			if _, _, ok := refUpstream(upstream); !ok {
				t.Fatalf("run accepted invalid upstream in %q", v)
			}
		}
	})
}

// base64Lines returns lines of input long enough and plain enough to be key
// material rather than a word that also appears in an error message.
func base64Lines(input []byte) []string {
	var out []string
	for _, line := range strings.Split(string(input), "\n") {
		line = strings.TrimSpace(line)
		if len(line) >= 16 && strings.Trim(line, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=") == "" {
			out = append(out, line)
		}
	}
	return out
}

func FuzzLoadCertificate(f *testing.F) {
	pki := getFuzzPKI()
	ecKeyDER, err := x509.MarshalECPrivateKey(pki.client.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		f.Fatal(err)
	}
	ecKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecKeyDER})
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherDER, _ := x509.MarshalPKCS8PrivateKey(otherKey)
	otherPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherDER})
	seeds := [][2][]byte{
		{pki.clientCertPEM, pki.clientKeyPEM},
		{pki.clientCertPEM, ecKeyPEM},
		{pki.expiredPEM, pki.clientKeyPEM},
		{pki.clientCertPEM, otherPEM},
		{pki.clientKeyPEM, pki.clientCertPEM},
		{pki.clientKeyPEM, pki.clientKeyPEM},
		{append(append([]byte{}, pki.clientCertPEM...), pki.clientKeyPEM...), pki.clientKeyPEM},
		{pki.clientCertPEM, append(append([]byte{}, pki.clientCertPEM...), pki.clientKeyPEM...)},
		{pki.clientCertPEM, []byte(strings.Replace(string(pki.clientKeyPEM), "PRIVATE KEY", "RSA PRIVATE KEY", 2))},
		{pki.clientCertPEM, pki.clientKeyPEM[:len(pki.clientKeyPEM)/2]},
		{[]byte("garbage"), []byte("garbage")},
		{nil, nil},
	}
	for _, seed := range seeds {
		f.Add(byte(0), seed[0], seed[1])
		f.Add(byte(1), seed[0], seed[1])
	}
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, mode byte, certPEM, keyPEM []byte) {
		if len(certPEM)+len(keyPEM) > 64<<10 {
			return
		}
		secrets := append(append([]string{}, pki.secrets...), base64Lines(keyPEM)...)
		var source certificateSource
		getenv := os.Getenv
		const certEnv, keyEnv = "MTLS_FUZZ_LOAD_CERT", "MTLS_FUZZ_LOAD_KEY"
		if mode&1 == 0 {
			source = certificateSource{certEnv: certEnv, keyEnv: keyEnv}
			values := map[string]string{certEnv: string(certPEM), keyEnv: string(keyPEM)}
			getenv = func(name string) string { return values[name] }
			// Set the real variables too when the OS allows the bytes, to
			// check that loading clears them.
			_ = os.Setenv(certEnv, string(certPEM))
			_ = os.Setenv(keyEnv, string(keyPEM))
		} else {
			source = certificateSource{certFile: filepath.Join(dir, "client.pem"), keyFile: filepath.Join(dir, "client.key")}
			if err := os.WriteFile(source.certFile, certPEM, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(source.keyFile, keyPEM, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		cert, err := loadCertificateWithEnv(source, getenv)
		if mode&1 == 0 {
			for _, name := range []string{certEnv, keyEnv} {
				if _, found := os.LookupEnv(name); found {
					t.Fatalf("%s was not cleared", name)
				}
			}
		}
		if err != nil {
			if secret := leakedSecret(err.Error(), secrets); secret != "" {
				t.Fatalf("error %q contains key material %q", err, secret)
			}
			return
		}
		if len(cert.Certificate) == 0 {
			t.Fatal("loaded a certificate with no chain")
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("loaded leaf does not parse: %v", err)
		}
		signer, ok := cert.PrivateKey.(crypto.Signer)
		if !ok {
			t.Fatalf("private key %T is not a signer", cert.PrivateKey)
		}
		if pub, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool }); !ok || !pub.Equal(signer.Public()) {
			t.Fatal("loaded private key does not match the leaf")
		}
		var logs logRecords
		logger := log.New(&logs, "", 0)
		_ = checkClientCertificate(&cert, time.Now(), logger)
		for _, v := range logViolations(logs.all(), secrets) {
			if !subjectHasNewline(leaf) || !strings.HasPrefix(v, "log record spans lines") {
				t.Fatal(v)
			}
		}
	})
}

// refSelectIdentity picks the currently valid leaf named name with the
// latest NotAfter, the earliest on a tie. Validity bounds are inclusive.
func refSelectIdentity(leaves []*x509.Certificate, name string, now time.Time) int {
	best := -1
	for i, leaf := range leaves {
		if leaf == nil || leaf.Subject.CommonName != name {
			continue
		}
		if now.Compare(leaf.NotBefore) < 0 || now.Compare(leaf.NotAfter) > 0 {
			continue
		}
		if best < 0 || leaf.NotAfter.Compare(leaves[best].NotAfter) > 0 {
			best = i
		}
	}
	return best
}

func FuzzSelectIdentity(f *testing.F) {
	f.Add("client", []byte{0, 0x80, 0x7f, 0, 0x00, 0x01, 2, 0x00, 0x00})
	f.Add("client", []byte{0, 0xff, 0x01, 0, 0xff, 0x01, 0, 0xfe, 0x01})
	f.Add("cli\nent", []byte{4, 0x00, 0x00, 1, 0, 0})
	f.Add("", []byte{6, 0x00, 0x10})
	names := func(name string) []string { return []string{name, strings.ToUpper(name), name + " ", "other\nline"} }
	f.Fuzz(func(t *testing.T, name string, data []byte) {
		now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		var leaves []*x509.Certificate
		for len(data) >= 3 && len(leaves) < 64 {
			flags, before, after := data[0], int8(data[1]), int8(data[2])
			data = data[3:]
			if flags&1 == 1 {
				leaves = append(leaves, nil)
				continue
			}
			leaves = append(leaves, &x509.Certificate{
				Subject:   pkix.Name{CommonName: names(name)[(flags>>1)&3]},
				NotBefore: now.Add(time.Duration(before) * time.Hour),
				NotAfter:  now.Add(time.Duration(after) * time.Hour),
			})
		}
		got, err := selectIdentity(leaves, name, now)
		want := refSelectIdentity(leaves, name, now)
		if got != want || (err == nil) != (want >= 0) {
			t.Fatalf("selectIdentity = %d, %v; want %d", got, err, want)
		}
		if err != nil && strings.ContainsAny(err.Error(), "\r\n") {
			t.Fatalf("multi-line error %q", err)
		}
	})
}

func FuzzCheckClientCertificate(f *testing.F) {
	f.Add("client", "org", int16(-1), int16(24*365))
	f.Add("client", "", int16(-1), int16(24))
	f.Add("client", "", int16(1), int16(24))
	f.Add("client", "", int16(-48), int16(-1))
	f.Add("cli\nent", "o\r\ng", int16(-1), int16(24))
	pki := getFuzzPKI()
	key := pki.client.PrivateKey.(*ecdsa.PrivateKey)
	f.Fuzz(func(t *testing.T, cn, org string, before, after int16) {
		now := time.Now().Truncate(time.Second)
		notBefore := now.Add(time.Duration(before) * time.Hour)
		notAfter := now.Add(time.Duration(after) * time.Hour)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(9),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    notBefore,
			NotAfter:     notAfter,
		}
		if org != "" {
			template.Subject.Organization = []string{org}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, pki.caCert, &key.PublicKey, pki.caKey)
		if err != nil {
			return
		}
		cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
		var logs logRecords
		err = checkClientCertificate(&cert, now, log.New(&logs, "", 0))
		valid := now.Compare(cert.Leaf.NotBefore) >= 0 && now.Compare(cert.Leaf.NotAfter) <= 0
		if (err == nil) != valid {
			t.Fatalf("NotBefore %v NotAfter %v now %v: err = %v", cert.Leaf.NotBefore, cert.Leaf.NotAfter, now, err)
		}
		if err != nil && strings.ContainsAny(err.Error(), "\r\n") && !subjectHasNewline(cert.Leaf) {
			t.Fatalf("multi-line error %q", err)
		}
		for _, v := range logViolations(logs.all(), pki.secrets) {
			if !subjectHasNewline(cert.Leaf) || !strings.HasPrefix(v, "log record spans lines") {
				t.Fatal(v)
			}
		}
	})
}

var serverCertIPs = []string{"127.0.0.1", "127.0.0.2", "127.255.255.254", "::1", "::ffff:127.0.0.1", "::ffff:127.0.0.9"}

func FuzzServerCertificate(f *testing.F) {
	f.Add([]byte{0, 0})
	f.Add([]byte{0, 0, 3, 0})
	f.Add([]byte{0, 1, 1, 0})
	f.Add([]byte{4, 0, 0, 0, 5, 1})
	probes := []string{"127.0.0.1", "127.0.0.2", "127.0.0.3", "10.0.0.1", "::1", "::2", "127.0.0.9"}
	f.Fuzz(func(t *testing.T, data []byte) {
		var routes []route
		listeners := map[string]bool{}
		for len(data) >= 2 && len(routes) < 8 {
			ip, forward := serverCertIPs[int(data[0])%len(serverCertIPs)], data[1]&1 == 1
			data = data[2:]
			routes = append(routes, route{listen: net.JoinHostPort(ip, "1"), upstream: "a", forward: forward})
			if !forward {
				listeners[net.ParseIP(ip).String()] = true
			}
		}
		if len(listeners) == 0 {
			// serve only makes a certificate when a reverse route exists.
			return
		}
		cert, err := newServerCertificate(routes)
		if err != nil {
			t.Fatal(err)
		}
		ca, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(ca)
		signer := cert.PrivateKey.(crypto.Signer)
		leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		issue := func(ip net.IP, dns string) *x509.Certificate {
			template := &x509.Certificate{
				SerialNumber: big.NewInt(2),
				NotBefore:    time.Now().Add(-time.Minute),
				NotAfter:     time.Now().Add(time.Hour),
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}
			if ip != nil {
				template.IPAddresses = []net.IP{ip}
			} else {
				template.DNSNames = []string{dns}
			}
			der, err := x509.CreateCertificate(rand.Reader, template, ca, &leafKey.PublicKey, signer)
			if err != nil {
				t.Fatal(err)
			}
			leaf, _ := x509.ParseCertificate(der)
			return leaf
		}
		for _, probe := range probes {
			ip := net.ParseIP(probe)
			_, err := issue(ip, "").Verify(x509.VerifyOptions{Roots: roots, DNSName: probe})
			if want := listeners[ip.String()]; (err == nil) != want {
				t.Fatalf("listeners %v: leaf for %s verified = %v (%v)", listeners, probe, err == nil, err)
			}
		}
		for _, name := range []string{"localhost", "example.com"} {
			if _, err := issue(nil, name).Verify(x509.VerifyOptions{Roots: roots, DNSName: name}); err == nil {
				t.Fatalf("CA certified DNS name %s", name)
			}
		}
		if !ca.IsCA || len(ca.PermittedDNSDomains) != 1 || ca.PermittedDNSDomains[0] != "invalid" {
			t.Fatalf("CA %v permits DNS %q", ca.IsCA, ca.PermittedDNSDomains)
		}
	})
}

// subjectHasNewline reports a client certificate whose subject would split a
// log line. The operator supplies that certificate, so docs/fuzzing.md
// records this instead of the code escaping it.
func subjectHasNewline(leaf *x509.Certificate) bool {
	return strings.ContainsAny(leaf.Subject.String(), "\r\n")
}
