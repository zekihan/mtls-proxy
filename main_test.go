package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type pki struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newPKI(t *testing.T) pki {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "disposable test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pki{cert: cert, key: key, pool: pool}
}

func (p pki) leaf(t *testing.T, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "disposable test leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, p.cert, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func mtlsUpstream(t *testing.T, ca pki, handler http.Handler) string {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{ca.leaf(t, x509.ExtKeyUsageServerAuth)},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.pool,
	}
	server.Config.ErrorLog = nil
	server.StartTLS()
	t.Cleanup(server.Close)
	return server.Listener.Addr().String()
}

func TestParseRouteRejectsNonLoopback(t *testing.T) {
	for _, value := range []string{"0.0.0.0:1=a", ":1=a", "10.0.0.1:1=a", "localhost:1=a", "127.0.0.1:1", "127.0.0.1:1="} {
		if _, err := parseRoute(value); err == nil {
			t.Errorf("parseRoute(%q) accepted", value)
		}
	}
	if _, err := parseRoute("[::1]:1=a"); err != nil {
		t.Errorf("IPv6 loopback rejected: %v", err)
	}
}

func TestLoadCertificateFromPEMFiles(t *testing.T) {
	leaf := newPKI(t).leaf(t, x509.ExtKeyUsageClientAuth)
	der, err := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "client.pem")
	keyFile := filepath.Join(dir, "client.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	cert, err := loadCertificate(certificateSource{certFile: certFile, keyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	if string(cert.Certificate[0]) != string(leaf.Certificate[0]) {
		t.Error("loaded a different certificate")
	}
}

func TestLoadCertificateFromEnvClearsTheVariables(t *testing.T) {
	leaf := newPKI(t).leaf(t, x509.ExtKeyUsageClientAuth)
	der, err := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_CERT", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})))
	t.Setenv("TEST_KEY", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))

	cert, err := loadCertificate(certificateSource{certEnv: "TEST_CERT", keyEnv: "TEST_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	if string(cert.Certificate[0]) != string(leaf.Certificate[0]) {
		t.Error("loaded a different certificate")
	}
	for _, name := range []string{"TEST_CERT", "TEST_KEY"} {
		if _, found := os.LookupEnv(name); found {
			t.Errorf("%s was not cleared", name)
		}
	}
}

func TestLoadCertificateFromEmptyEnvNamesTheVariable(t *testing.T) {
	t.Setenv("TEST_CERT", "")
	t.Setenv("TEST_KEY", "x")
	_, err := loadCertificate(certificateSource{certEnv: "TEST_CERT", keyEnv: "TEST_KEY"})
	if err == nil || !strings.Contains(err.Error(), "TEST_CERT") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadCertificateRequiresOneSource(t *testing.T) {
	for _, source := range []certificateSource{
		{},
		{identity: "id", certFile: "c", keyFile: "k"},
		{identity: "id", certFile: "c"},
		{certFile: "c"},
		{keyFile: "k"},
		{certEnv: "C"},
		{keyEnv: "K"},
		{identity: "id", certEnv: "C", keyEnv: "K"},
		{certFile: "c", keyFile: "k", certEnv: "C", keyEnv: "K"},
	} {
		if _, err := loadCertificate(source); err == nil {
			t.Errorf("loadCertificate(%+v) accepted", source)
		}
	}
}

func TestProxyPresentsCertificateAndRewritesHost(t *testing.T) {
	ca := newPKI(t)
	var host, peer string
	upstream := mtlsUpstream(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host = r.Host
		peer = r.TLS.PeerCertificates[0].Subject.CommonName
		_, _ = io.WriteString(w, r.URL.RequestURI())
	}))

	transport := newTransport(ca.leaf(t, x509.ExtKeyUsageClientAuth), ca.pool)
	proxy := httptest.NewServer(newProxy(upstream, transport))
	defer proxy.Close()

	response, err := http.Get(proxy.URL + "/api/settings/get?a=1")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || string(body) != "/api/settings/get?a=1" {
		t.Fatalf("status %d body %q", response.StatusCode, body)
	}
	if host != upstream {
		t.Errorf("upstream saw Host %q, want %q", host, upstream)
	}
	if peer != "disposable test leaf" {
		t.Errorf("upstream saw peer %q", peer)
	}
}

func TestProxyRejectsCrossSiteBrowserRequests(t *testing.T) {
	ca := newPKI(t)
	upstream := mtlsUpstream(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if site := r.Header.Get("Sec-Fetch-Site"); site != "same-origin" && site != "none" {
			t.Errorf("request with Sec-Fetch-Site %q reached upstream", site)
		}
	}))
	transport := newTransport(ca.leaf(t, x509.ExtKeyUsageClientAuth), ca.pool)
	proxy := httptest.NewServer(newProxy(upstream, transport))
	defer proxy.Close()

	for site, want := range map[string]int{
		"cross-site":  http.StatusForbidden,
		"same-site":   http.StatusForbidden,
		"same-origin": http.StatusOK,
		"none":        http.StatusOK,
	} {
		request, err := http.NewRequest(http.MethodGet, proxy.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Sec-Fetch-Site", site)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != want {
			t.Errorf("Sec-Fetch-Site %s got status %d, want %d", site, response.StatusCode, want)
		}
	}
}

func TestProxyFailsWithUntrustedCertificate(t *testing.T) {
	ca := newPKI(t)
	upstream := mtlsUpstream(t, ca, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("request reached upstream")
	}))

	transport := newTransport(newPKI(t).leaf(t, x509.ExtKeyUsageClientAuth), ca.pool)
	proxy := httptest.NewServer(newProxy(upstream, transport))
	defer proxy.Close()

	response, err := http.Get(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d", response.StatusCode)
	}
}

func TestForwardProxyKeepsHostAndRejectsOtherTargets(t *testing.T) {
	ca := newPKI(t)
	var host string
	upstream := mtlsUpstream(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host = r.Host
		_, _ = io.WriteString(w, r.URL.RequestURI())
	}))

	transport := newTransport(ca.leaf(t, x509.ExtKeyUsageClientAuth), ca.pool)
	forward := httptest.NewServer(newForwardProxy(upstream, transport))
	defer forward.Close()
	proxyURL, err := url.Parse(forward.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	response, err := client.Get("http://" + upstream + "/rustfs/admin/v3/is-admin?a=1")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || string(body) != "/rustfs/admin/v3/is-admin?a=1" {
		t.Fatalf("status %d body %q", response.StatusCode, body)
	}
	if host != upstream {
		t.Errorf("upstream saw Host %q, want %q", host, upstream)
	}

	other, err := client.Get("http://example.invalid/")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Body.Close()
	if other.StatusCode != http.StatusForbidden {
		t.Errorf("other target got status %d", other.StatusCode)
	}

	request, err := http.NewRequest(http.MethodConnect, forward.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = upstream
	connect, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer connect.Body.Close()
	if connect.StatusCode != http.StatusForbidden {
		t.Errorf("CONNECT got status %d", connect.StatusCode)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().String()
}

func startServe(t *testing.T, ca pki, upstream string) (string, *x509.CertPool) {
	t.Helper()
	routes := []route{{listen: freeAddr(t), upstream: upstream}}
	caFile := filepath.Join(t.TempDir(), "state", "ca.pem")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	transport := newTransport(ca.leaf(t, x509.ExtKeyUsageClientAuth), ca.pool)
	go func() { done <- serve(ctx, routes, transport, caFile) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})

	for range 100 {
		written, err := os.ReadFile(caFile)
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		conn, err := net.Dial("tcp", routes[0].listen)
		if err == nil {
			conn.Close()
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(written) {
				t.Fatal("written certificate does not parse")
			}
			return routes[0].listen, roots
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("proxy did not start")
	return "", nil
}

func TestServeBindFailurePreservesCaOut(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	first := freeAddr(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	original := []byte("existing certificate")
	if err := os.WriteFile(caFile, original, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(caFile)
	if err != nil {
		t.Fatal(err)
	}
	routes := []route{{listen: first}, {listen: occupied.Addr().String()}}
	if err := serve(context.Background(), routes, http.DefaultTransport, caFile); err == nil {
		t.Fatal("serve succeeded with an occupied address")
	}
	after, err := os.Stat(caFile)
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(contents, original) || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("bind failure changed the CA file")
	}
	listener, err := net.Listen("tcp", first)
	if err != nil {
		t.Fatalf("first listener was not closed: %v", err)
	}
	listener.Close()
}

func TestServerCertificateOnlySignsListenerIPs(t *testing.T) {
	serverCert, err := newServerCertificate([]route{{listen: "127.0.0.1:1"}, {listen: "[::1]:1"}})
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(serverCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := ca.Verify(x509.VerifyOptions{Roots: roots, DNSName: "127.0.0.1"}); err != nil {
		t.Fatalf("loopback certificate does not verify: %v", err)
	}

	verify := func(dnsNames []string, ips []net.IP) error {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: big.NewInt(2),
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(time.Hour),
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     dnsNames,
			IPAddresses:  ips,
		}, ca, &key.PublicKey, serverCert.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		_, err = leaf.Verify(x509.VerifyOptions{Roots: roots})
		return err
	}
	if err := verify(nil, []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback}); err != nil {
		t.Errorf("leaf for the listener IPs rejected: %v", err)
	}
	for _, name := range []string{"example.com", "localhost"} {
		if err := verify([]string{name}, nil); err == nil {
			t.Errorf("leaf for %s accepted", name)
		}
	}
	for _, ip := range []string{"127.0.0.2", "10.0.0.1", "::2"} {
		if err := verify(nil, []net.IP{net.ParseIP(ip)}); err == nil {
			t.Errorf("leaf for %s accepted", ip)
		}
	}
}

func TestWriteCertificateReplacesSymlink(t *testing.T) {
	serverCert, err := newServerCertificate([]route{{listen: "127.0.0.1:1"}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.Symlink(victim, caFile); err != nil {
		t.Fatal(err)
	}

	if err := writeCertificate(caFile, serverCert); err != nil {
		t.Fatal(err)
	}
	if kept, _ := os.ReadFile(victim); string(kept) != "keep" {
		t.Errorf("symlink target was overwritten with %q", kept)
	}
	info, err := os.Lstat(caFile)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Errorf("ca file mode %v, want a regular file", info.Mode())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Errorf("left %d entries in the directory, want 2", len(entries))
	}
}

func TestServeTrustedThroughWrittenCertificate(t *testing.T) {
	ca := newPKI(t)
	upstream := mtlsUpstream(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Host)
	}))
	addr, roots := startServe(t, ca, upstream)

	pinned := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
	}}
	response, err := pinned.Get("https://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if string(body) != upstream {
		t.Fatalf("upstream saw Host %q, want %q", body, upstream)
	}
	if response.TLS.Version != tls.VersionTLS13 {
		t.Errorf("negotiated TLS version %x", response.TLS.Version)
	}

	unpinned := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{}}}
	if _, err := unpinned.Get("https://" + addr + "/"); err == nil {
		t.Error("client without the written certificate connected")
	}
	plain, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Body.Close()
	if plain.StatusCode != http.StatusBadRequest {
		t.Errorf("plain HTTP got status %d", plain.StatusCode)
	}
}

func TestServePassesWebSocketUpgradeOverTLS(t *testing.T) {
	ca := newPKI(t)
	upstream := mtlsUpstream(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buffer, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_ = buffer.Flush()
		line, _ := buffer.ReadString('\n')
		_, _ = buffer.WriteString(strings.ToUpper(line))
		_ = buffer.Flush()
	}))
	addr, roots := startServe(t, ca, upstream)

	// ServerName is the IP literal, as gorilla/websocket sets it for ws endpoints.
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(conn, "GET /api/current HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(status, "101") {
		t.Fatalf("status %q err %v", status, err)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	_, _ = io.WriteString(conn, "ping\n")
	reply, err := reader.ReadString('\n')
	if err != nil || reply != "PING\n" {
		t.Fatalf("reply %q err %v", reply, err)
	}
}

func TestRunValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no routes", nil, "at least one -route or -forward is required"},
		{"route needs CA", []string{"-route", "127.0.0.1:0=example.com"}, "-ca-out is required with -route"},
		{"forward does not need CA", []string{"-forward", "127.0.0.1:0=example.com"}, "set one of -identity"},
		{"invalid address", []string{"-route", "bad=example.com"}, "missing port"},
		{"non loopback", []string{"-forward", "0.0.0.0:0=example.com"}, "loopback IP"},
		{"conflicting sources", []string{"-forward", "127.0.0.1:0=example.com", "-identity", "id", "-cert", "c", "-key", "k"}, "set one of -identity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			err := run(context.Background(), tc.args, os.Getenv, &stderr)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, stderr = %q; want %q", err, stderr.String(), tc.want)
			}
		})
	}
}

func TestRouteFlags(t *testing.T) {
	var routes []route
	reverse := routeFlag{routes: &routes}
	forward := routeFlag{routes: &routes, forward: true}
	if (routeFlag{}).String() != "" {
		t.Fatal("nil route flag should be empty")
	}
	for _, item := range []struct {
		flag  routeFlag
		value string
	}{
		{reverse, "127.0.0.1:1=one"}, {forward, "127.0.0.1:2=two"},
		{reverse, "127.0.0.1:3=three"}, {forward, "127.0.0.1:4=four"},
	} {
		if err := item.flag.Set(item.value); err != nil {
			t.Fatal(err)
		}
	}
	for i, r := range routes {
		if r.forward != (i%2 == 1) {
			t.Errorf("route %d: forward = %v", i, r.forward)
		}
	}
	if !strings.Contains(reverse.String(), "one") {
		t.Fatal("String omitted routes")
	}
}

func TestRunStartsAndStopsMixedListeners(t *testing.T) {
	leaf := newPKI(t).leaf(t, x509.ExtKeyUsageClientAuth)
	key, err := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{
		"CERT": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})),
		"KEY":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})),
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"-cert-env", "CERT", "-key-env", "KEY", "-ca-out", ca,
			"-route", "127.0.0.1:0=one", "-forward", "127.0.0.1:0=two",
			"-route", "127.0.0.1:0=three", "-forward", "127.0.0.1:0=four"},
			func(name string) string { return values[name] }, io.Discard)
	}()
	deadline := time.After(5 * time.Second)
	for {
		if _, err := os.Stat(ca); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("run stopped before startup: %v", err)
		case <-deadline:
			t.Fatal("timed out waiting for CA")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not stop")
	}
}

func TestProxyRejectsOpaqueRequestTargets(t *testing.T) {
	ca := newPKI(t)
	upstream := mtlsUpstream(t, ca, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("request-target %q reached upstream", r.RequestURI)
	}))
	transport := newTransport(ca.leaf(t, x509.ExtKeyUsageClientAuth), ca.pool)
	for _, handler := range []http.Handler{newProxy(upstream, transport), newForwardProxy(upstream, transport)} {
		proxy := httptest.NewServer(handler)
		for _, line := range []string{
			"GET http:evil.example/x HTTP/1.1",
			"GET http:" + upstream + " HTTP/1.1",
			"connect http:evil.example:443 HTTP/1.1",
		} {
			conn, err := net.Dial("tcp", proxy.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.WriteString(conn, line+"\r\nHost: "+upstream+"\r\nConnection: close\r\n\r\n")
			response, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			conn.Close()
			if response.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "request target not allowed") {
				t.Errorf("%q got status %d body %q", line, response.StatusCode, body)
			}
		}
		proxy.Close()
	}
}
