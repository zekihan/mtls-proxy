package main

import (
	"bufio"
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

	cert, err := loadCertificate("", certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(cert.Certificate[0]) != string(leaf.Certificate[0]) {
		t.Error("loaded a different certificate")
	}
}

func TestLoadCertificateRequiresOneSource(t *testing.T) {
	for _, args := range [][3]string{{}, {"id", "c", "k"}, {"id", "c", ""}, {"", "c", ""}, {"", "", "k"}} {
		if _, err := loadCertificate(args[0], args[1], args[2]); err == nil {
			t.Errorf("loadCertificate%v accepted", args)
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
	serverCert, err := newServerCertificate(routes)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "state", "ca.pem")
	if err := writeCertificate(caFile, serverCert); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(written) {
		t.Fatal("written certificate does not parse")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	transport := newTransport(ca.leaf(t, x509.ExtKeyUsageClientAuth), ca.pool)
	go func() { done <- serve(ctx, routes, transport, serverCert) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})

	for range 100 {
		conn, err := net.Dial("tcp", routes[0].listen)
		if err == nil {
			conn.Close()
			return routes[0].listen, roots
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("proxy did not start")
	return "", nil
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
