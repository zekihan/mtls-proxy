package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// proxyMode is one way to configure the handler under test.
type proxyMode struct {
	forward  bool
	upstream string // as configured on the command line
	dial     string // address the transport must dial, lower case
	sni      string // server name the transport must send
}

func (m proxyMode) String() string {
	kind := "route"
	if m.forward {
		kind = "forward"
	}
	return kind + "=" + m.upstream
}

func modeFromByte(b byte) proxyMode {
	m := proxyMode{forward: b&1 == 1}
	switch (b >> 1) & 3 {
	case 0:
		m.upstream, m.dial, m.sni = fuzzUpstreamHost, fuzzUpstreamHost+":443", fuzzUpstreamHost
	case 1:
		m.upstream, m.dial, m.sni = fuzzUpstreamHost+":8443", fuzzUpstreamHost+":8443", fuzzUpstreamHost
	case 2:
		m.upstream, m.dial, m.sni = "UPSTREAM.Test", fuzzUpstreamHost+":443", fuzzUpstreamHost
	case 3:
		m.upstream, m.dial, m.sni = "127.0.0.1:9443", "127.0.0.1:9443", ""
	}
	return m
}

// inboundRequest is what the proxy's own server parsed from the client.
type inboundRequest struct {
	method, host, requestURI, opaque string
	target                           string // what the upstream should see
	header                           http.Header
	forwarded                        bool
	body                             *recordingBody
}

type inboundKey struct{}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type recordingBody struct {
	mu  sync.Mutex
	r   io.ReadCloser
	buf []byte
	eof bool
}

func (b *recordingBody) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.mu.Lock()
	b.buf = append(b.buf, p[:n]...)
	if errors.Is(err, io.EOF) {
		b.eof = true
	}
	b.mu.Unlock()
	return n, err
}

func (b *recordingBody) Close() error { return b.r.Close() }

func (b *recordingBody) bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf...)
}

// upstreamExchange is one request the fake upstream read off the wire.
type upstreamExchange struct {
	req    *wireRequest
	sni    string
	peerCN string
}

// logRecords collects log output one record per Write, which is how
// log.Logger writes, so a record with an embedded newline stands out.
type logRecords struct {
	mu      sync.Mutex
	records []string
}

func (l *logRecords) Write(p []byte) (int, error) {
	l.mu.Lock()
	l.records = append(l.records, string(p))
	l.mu.Unlock()
	return len(p), nil
}

func (l *logRecords) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.records...)
}

// trackedConn tells the harness when the proxy's server has consumed all
// client input and is blocked waiting for more. The server's background
// reads use a one-byte buffer, so only larger reads count.
type trackedConn struct {
	net.Conn
	total    int
	consumed atomic.Int64
	idle     chan struct{}
}

func (c *trackedConn) Read(p []byte) (int, error) {
	if len(p) > 1 && c.consumed.Load() >= int64(c.total) {
		select {
		case c.idle <- struct{}{}:
		default:
		}
	}
	n, err := c.Conn.Read(p)
	c.consumed.Add(int64(n))
	return n, err
}

type oneConnListener struct {
	conn   net.Conn
	once   sync.Once
	closed chan struct{}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	var conn net.Conn
	l.once.Do(func() { conn = l.conn })
	if conn != nil {
		return conn, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}

func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

type proxyRun struct {
	mode       proxyMode
	input      []byte
	inbound    []*inboundRequest
	upstream   []*upstreamExchange
	dials      []string
	handshakes []string // upstream handshake failures
	client     []byte
	logs       []string
	timedOut   string
	panics     []string
}

// respondFunc returns the raw bytes the fake upstream writes for a request
// and whether it closes the connection afterwards.
type respondFunc func(*wireRequest) ([]byte, bool)

func fixedResponse(*wireRequest) ([]byte, bool) {
	return []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), false
}

var globalLogMu sync.Mutex

// runProxy serves input to the real handler for mode over an in-memory
// connection, with the real transport dialing a fake mTLS upstream.
func runProxy(mode proxyMode, input []byte, respond respondFunc, waitHandlers bool) *proxyRun {
	pki := getFuzzPKI()
	run := &proxyRun{mode: mode, input: input}
	logs := &logRecords{}

	globalLogMu.Lock()
	defer globalLogMu.Unlock()
	oldOutput, oldFlags := log.Writer(), log.Flags()
	log.SetOutput(logs)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(oldOutput)
		log.SetFlags(oldFlags)
	}()

	var mu sync.Mutex
	var upstreamWG sync.WaitGroup
	var upstreamConns []net.Conn
	closed := false

	serverConfig := &tls.Config{
		Certificates:           []tls.Certificate{pki.server},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              pki.pool,
		SessionTicketsDisabled: true,
	}
	serveUpstream := func(conn net.Conn) {
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
		tlsConn := tls.Server(conn, serverConfig)
		if err := tlsConn.Handshake(); err != nil {
			mu.Lock()
			run.handshakes = append(run.handshakes, err.Error())
			mu.Unlock()
			return
		}
		state := tlsConn.ConnectionState()
		peerCN := ""
		if len(state.PeerCertificates) > 0 {
			peerCN = state.PeerCertificates[0].Subject.CommonName
		}
		br := bufio.NewReader(tlsConn)
		for {
			req, err := readWireRequest(br)
			if err != nil {
				return
			}
			mu.Lock()
			run.upstream = append(run.upstream, &upstreamExchange{req: req, sni: state.ServerName, peerCN: peerCN})
			mu.Unlock()
			if len(req.violations) > 0 {
				return
			}
			response, closeAfter := respond(req)
			// Close the pipe, not the TLS conn: close_notify on an
			// unbuffered pipe blocks until the peer reads it.
			if _, err := tlsConn.Write(response); err != nil || closeAfter {
				return
			}
		}
	}

	transport := newTransport(pki.client, pki.pool)
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		run.dials = append(run.dials, addr)
		if closed {
			return nil, errors.New("harness closed")
		}
		client, server := net.Pipe()
		upstreamConns = append(upstreamConns, server)
		upstreamWG.Add(1)
		go func() {
			defer upstreamWG.Done()
			serveUpstream(server)
		}()
		return client, nil
	}

	// Mark which inbound requests the handler passed to the transport, so
	// the policy oracle does not have to guess from the wire.
	recording := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if in, ok := req.Context().Value(inboundKey{}).(*inboundRequest); ok {
			mu.Lock()
			in.forwarded = true
			mu.Unlock()
		}
		return transport.RoundTrip(req)
	})
	var handler http.Handler
	if mode.forward {
		handler = newForwardProxy(mode.upstream, recording)
	} else {
		handler = newProxy(mode.upstream, recording)
	}
	var active atomic.Int64
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		active.Add(1)
		defer active.Add(-1)
		defer func() {
			// ReverseProxy aborts with ErrAbortHandler on purpose; any
			// other panic is a bug.
			if p := recover(); p != nil {
				if p != http.ErrAbortHandler {
					mu.Lock()
					run.panics = append(run.panics, fmt.Sprint(p))
					mu.Unlock()
				}
				panic(p)
			}
		}()
		target := r.URL.RequestURI()
		if target == "*" {
			// Rewrite joins "*" onto the empty upstream path. The server
			// answers OPTIONS * itself, so only odd methods such as
			// "PRI * HTTP/2.0" reach here. Recorded in docs/fuzzing.md.
			target = "/%2A"
		}
		in := &inboundRequest{
			method:     r.Method,
			host:       r.Host,
			requestURI: r.RequestURI,
			opaque:     r.URL.Opaque,
			target:     target,
			header:     r.Header.Clone(),
			body:       &recordingBody{r: r.Body},
		}
		r.Body = in.body
		mu.Lock()
		run.inbound = append(run.inbound, in)
		mu.Unlock()
		handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), inboundKey{}, in)))
	})

	clientEnd, serverEnd := net.Pipe()
	tracked := &trackedConn{Conn: serverEnd, total: len(input), idle: make(chan struct{}, 1)}
	server := &http.Server{
		Handler:           wrapped,
		ReadHeaderTimeout: 10 * time.Second,
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ErrorLog:          log.New(logs, "", 0),
	}
	listener := &oneConnListener{conn: tracked, closed: make(chan struct{})}
	serveDone := make(chan struct{})
	go func() {
		_ = server.Serve(listener)
		close(serveDone)
	}()

	go func() { _, _ = clientEnd.Write(input) }()
	var clientOut []byte
	clientDone := make(chan struct{})
	go func() {
		clientOut, _ = io.ReadAll(clientEnd)
		close(clientDone)
	}()

	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
wait:
	for {
		select {
		case <-tracked.idle:
			if !waitHandlers || active.Load() == 0 {
				break wait
			}
		case <-clientDone:
			break wait
		case <-deadline.C:
			run.timedOut = "proxy did not go idle"
			break wait
		}
	}
	_ = clientEnd.Close()
	// Wait for handlers only, not for the connection to close: after an
	// unread body net/http sleeps rstAvoidanceDelay (500ms) before closing.
	if !waitFor(func() bool { return active.Load() == 0 }, 15*time.Second) && run.timedOut == "" {
		run.timedOut = "handlers did not finish after the client closed"
	}
	_ = server.Close()
	<-serveDone

	mu.Lock()
	closed = true
	conns := upstreamConns
	mu.Unlock()
	transport.CloseIdleConnections()
	for _, conn := range conns {
		_ = conn.Close()
	}
	upstreamDone := make(chan struct{})
	go func() {
		upstreamWG.Wait()
		close(upstreamDone)
	}()
	select {
	case <-upstreamDone:
	case <-time.After(15 * time.Second):
		if run.timedOut == "" {
			run.timedOut = "upstream did not finish"
		}
	}
	<-clientDone
	run.client = clientOut
	mu.Lock()
	defer mu.Unlock()
	run.logs = logs.all()
	return run
}

func waitFor(cond func() bool, limit time.Duration) bool {
	deadline := time.Now().Add(limit)
	for !cond() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Microsecond)
	}
	return true
}

// refAllowed is the policy the handler should enforce, written from the
// README: browsers' cross-site requests are refused, and a forward route
// accepts only its upstream (ASCII case-insensitive) and never CONNECT.
func refAllowed(mode proxyMode, in *inboundRequest) bool {
	switch in.header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
	default:
		return false
	}
	if mode.forward {
		return in.method != http.MethodConnect && asciiLower(in.host) == asciiLower(mode.upstream)
	}
	return true
}

var (
	// Never forwarded in either direction.
	hopOnly = []string{"Keep-Alive", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization"}
	// Rewrite drops these, so the upstream cannot be told a different host.
	forwardedHeaders = []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"}
	// The transport or ReverseProxy may regenerate these itself, so a client
	// nominating them in Connection does not mean they must be absent.
	regenerated = map[string]bool{
		"host": true, "content-length": true, "transfer-encoding": true, "te": true, "trailer": true,
		"upgrade": true, "connection": true, "accept-encoding": true, "user-agent": true,
	}
)

// requestViolations checks every property of a run with a well-behaved
// upstream and returns a description of each failure.
func requestViolations(run *proxyRun) []string {
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }
	pki := getFuzzPKI()
	mode := run.mode

	if run.timedOut != "" {
		add("timeout: %s", run.timedOut)
	}
	for _, p := range run.panics {
		add("handler panicked: %s", p)
	}
	for _, addr := range run.dials {
		if asciiLower(addr) != mode.dial {
			add("proxy dialed %q, want only %q", addr, mode.dial)
		}
	}
	next := 0
	for i, ex := range run.upstream {
		req := ex.req
		// SNI host names compare case-insensitively (RFC 6066 section 3).
		if asciiLower(ex.sni) != mode.sni {
			add("upstream request %d: SNI %q, want %q", i, ex.sni, mode.sni)
		}
		if ex.peerCN != pki.clientCN {
			add("upstream request %d: client certificate %q", i, ex.peerCN)
		}
		for _, v := range req.violations {
			add("upstream request %d %q: %s", i, req.startLine, v)
		}
		if len(req.violations) > 0 {
			continue
		}
		if hosts := req.values("Host"); len(hosts) != 1 || asciiLower(hosts[0]) != asciiLower(mode.upstream) {
			add("upstream request %d: Host %q, want %q", i, hosts, mode.upstream)
		}
		switch {
		case strings.HasPrefix(req.target, "/"), req.target == "*":
		case req.method == http.MethodConnect && asciiLower(req.target) == asciiLower(mode.upstream):
		default:
			add("upstream request %d: request-target %q is not origin-form", i, req.target)
		}
		for _, name := range append(append([]string{}, hopOnly...), forwardedHeaders...) {
			if req.has(name) {
				add("upstream request %d: %s %q reached upstream", i, name, req.values(name))
			}
		}
		for _, token := range connectionTokens(req.values("Connection")) {
			if asciiLower(token) != "upgrade" {
				add("upstream request %d: Connection token %q", i, token)
			}
		}
		if req.has("Upgrade") && !strings.EqualFold(strings.Join(req.values("Connection"), ","), "upgrade") {
			add("upstream request %d: Upgrade without Connection: upgrade", i)
		}
		for _, te := range req.values("Te") {
			if asciiLower(te) != "trailers" {
				add("upstream request %d: TE %q", i, te)
			}
		}
		if req.has("Trailer") && !req.chunked {
			add("upstream request %d: Trailer on a body that is not chunked", i)
		}

		// Match the upstream request to the next inbound request with the
		// same method, target and body. Anything unmatched was never accepted
		// by the proxy's server, which would be smuggling.
		matched := -1
		for k := next; k < len(run.inbound); k++ {
			in := run.inbound[k]
			if !in.forwarded {
				continue
			}
			// Compare paths only: ReverseProxy re-encodes or drops a
			// malformed query (cleanQueryParams), which is not smuggling.
			if in.method == req.method && targetPath(in.target) == targetPath(req.target) && string(in.body.bytes()) == string(req.body) {
				matched = k
				break
			}
		}
		if matched < 0 {
			add("upstream request %d %q (body %q) matches no request the proxy accepted", i, req.startLine, req.body)
			continue
		}
		next = matched + 1
		in := run.inbound[matched]
		for _, token := range connectionTokens(in.header.Values("Connection")) {
			if !regenerated[asciiLower(token)] && req.has(token) {
				add("upstream request %d: %s was nominated in Connection but reached upstream", i, token)
			}
		}
		if req.has("Upgrade") && req.values("Upgrade")[0] != in.header.Get("Upgrade") {
			add("upstream request %d: Upgrade %q, client sent %q", i, req.values("Upgrade"), in.header.Values("Upgrade"))
		}
	}
	for k, in := range run.inbound {
		if in.forwarded && !refAllowed(mode, in) {
			add("inbound request %d: policy should refuse method %q host %q Sec-Fetch-Site %q", k, in.method, in.host, in.header.Values("Sec-Fetch-Site"))
		}
	}
	out = append(out, logViolations(run.logs, pki.secrets)...)
	if secret := leakedSecret(string(run.client), pki.secrets); secret != "" {
		add("client response contains key material %q", secret)
	}
	return out
}

func logViolations(records []string, secrets []string) []string {
	var out []string
	for _, record := range records {
		body := strings.TrimSuffix(record, "\n")
		if strings.ContainsAny(body, "\r\n") {
			out = append(out, fmt.Sprintf("log record spans lines: %q", record))
		}
		if strings.Contains(record, "panic serving") {
			out = append(out, fmt.Sprintf("handler panicked: %q", record))
		}
		if secret := leakedSecret(record, secrets); secret != "" {
			out = append(out, fmt.Sprintf("log record contains key material: %q", record))
		}
	}
	return out
}

func targetPath(target string) string {
	path, _, _ := strings.Cut(target, "?")
	return path
}
