package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const maxFuzzInput = 16 << 10

func proxyRequestSeeds() []string {
	h := fuzzUpstreamHost
	return []string{
		"GET / HTTP/1.1\r\nHost: " + h + "\r\n\r\n",
		"GET http://" + h + "/a?b=c HTTP/1.1\r\nHost: " + h + "\r\n\r\n",
		"GET https://" + h + ":8443/ HTTP/1.1\r\nHost: " + h + ":8443\r\n\r\n",
		"GET http://evil.example/ HTTP/1.1\r\nHost: " + h + "\r\n\r\n",
		"GET http://" + h + "/ HTTP/1.1\r\nHost: evil.example\r\n\r\n",
		"GET http://user:pass@" + h + "/ HTTP/1.1\r\nHost: " + h + "\r\n\r\n",
		"GET http://" + h + "@evil.example/ HTTP/1.1\r\nHost: " + h + "\r\n\r\n",
		"GET http:evil.example/x HTTP/1.1\r\nHost: " + h + "\r\n\r\n",
		"connect http:evil.example:443 HTTP/1.1\r\nHost: " + h + "\r\n\r\n",
		"CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n",
		"CONNECT " + h + ":443 HTTP/1.1\r\nHost: " + h + ":443\r\n\r\n",
		"CONNECT /x HTTP/1.1\r\nHost: " + h + "\r\n\r\n",
		"OPTIONS * HTTP/1.1\r\nHost: " + h + "\r\n\r\n",
		"GET //evil.example/x HTTP/1.1\r\nHost: " + h + "\r\n\r\n",
		"GET http://%75pstream.test/ HTTP/1.1\r\nHost: " + h + "\r\n\r\n",
		"GET http://UPSTREAM.TEST/ HTTP/1.1\r\nHost: UPSTREAM.TEST\r\n\r\n",
		"GET http://upstream.tes\u212a/ HTTP/1.1\r\nHost: " + h + "\r\n\r\n",
		"GET http://\u017fpstream.test/ HTTP/1.1\r\nHost: " + h + "\r\n\r\n",
		"GET http://up\u017ftream.te\u017ft/ HTTP/1.1\r\nHost: " + h + "\r\n\r\n",
		"GET http://" + h + "./ HTTP/1.1\r\nHost: " + h + "\r\n\r\n",
		"GET http://[::1]:9443/ HTTP/1.1\r\nHost: [::1]:9443\r\n\r\n",
		"GET http://127.0.0.1:9443/ HTTP/1.1\r\nHost: 127.0.0.1:9443\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: " + h + "\r\nHost: evil.example\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: " + h + "\r\nX-Forwarded-Host: evil.example\r\nForwarded: host=evil.example\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: " + h + "\r\nConnection: X-Secret, Keep-Alive\r\nX-Secret: 1\r\nKeep-Alive: 5\r\nProxy-Authorization: Basic Zm9vOmJhcg==\r\nProxy-Connection: keep-alive\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: " + h + "\r\nTE: trailers, deflate\r\n\r\n",
		"GET /ws HTTP/1.1\r\nHost: " + h + "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
		"GET /ws HTTP/1.1\r\nHost: " + h + "\r\nUpgrade: websocket\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: " + h + "\r\nContent-Length: 5\r\n\r\nhello",
		"POST / HTTP/1.1\r\nHost: " + h + "\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: " + h + "\r\nTransfer-Encoding: chunked\r\nTrailer: X-T\r\n\r\n5\r\nhello\r\n0\r\nX-T: v\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: " + h + "\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: " + h + "\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: " + h + "\r\nContent-Length: 3\r\nContent-Length: 30\r\n\r\nabc",
		"POST / HTTP/1.1\r\nHost: " + h + "\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: " + h + "\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n0\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: " + h + "\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nhi",
		"POST / HTTP/1.1\r\nHost: " + h + "\r\nContent-Length: 100\r\n\r\nshort",
		"GET / HTTP/1.1\nHost: " + h + "\n\n",
		"GET / HTTP/1.1\r\nHost: " + h + "\r\nX-A: a\rb\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: " + h + "\r\nX-A: a\x00b\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: " + h + "\r\nX-A: a\r\n b\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: " + h + "\r\nX-A : a\r\n\r\n",
		"GET / HTTP/1.0\r\n\r\n",
		"GET / HTTP/1.0\r\nHost: " + h + "\r\nConnection: keep-alive\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: " + h + "\r\nSec-Fetch-Site: cross-site\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: " + h + "\r\nSec-Fetch-Site: none\r\nSec-Fetch-Site: cross-site\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: " + h + "\r\nSec-Fetch-Site: Same-Origin\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: " + h + "\r\nConnection: Sec-Fetch-Site\r\nSec-Fetch-Site: cross-site\r\n\r\n",
		"GET /a HTTP/1.1\r\nHost: " + h + "\r\n\r\nGET /b HTTP/1.1\r\nHost: evil.example\r\n\r\nGET /c HTTP/1.1\r\nHost: " + h + "\r\n\r\n",
		"GET /%2e%2e/%0d%0aX:%20y HTTP/1.1\r\nHost: " + h + "\r\n\r\n",
		"GET /\xff\xfe HTTP/1.1\r\nHost: " + h + "\r\n\r\n",
		"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
	}
}

func FuzzProxyRequest(f *testing.F) {
	for _, seed := range proxyRequestSeeds() {
		for mode := byte(0); mode < 8; mode++ {
			f.Add(mode, []byte(seed))
		}
	}
	f.Fuzz(func(t *testing.T, mode byte, input []byte) {
		if len(input) > maxFuzzInput {
			return
		}
		run := runProxy(modeFromByte(mode), input, fixedResponse, false)
		if violations := requestViolations(run); len(violations) > 0 {
			t.Fatalf("%v with input %q:\n%s", run.mode, input, strings.Join(violations, "\n"))
		}
	})
}

// responseRequests are the client requests the response fuzzer pairs with
// upstream bytes. The Host is filled in per mode.
var responseRequests = []struct {
	method, raw string
	upgrade     bool
}{
	{"GET", "GET /r HTTP/1.1\r\nHost: %s\r\n\r\n", false},
	{"HEAD", "HEAD /r HTTP/1.1\r\nHost: %s\r\n\r\n", false},
	{"POST", "POST /r HTTP/1.1\r\nHost: %s\r\nContent-Length: 5\r\n\r\nhello", false},
	{"GET", "GET /ws HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", true},
	{"GET", "GET /r HTTP/1.1\r\nHost: %s\r\nTE: trailers\r\n\r\n", false},
}

func FuzzUpstreamResponse(f *testing.F) {
	seeds := []string{
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-T\r\n\r\n2\r\nok\r\n0\r\nX-T: v\r\n\r\n",
		"HTTP/1.1 200 OK\r\n\r\nclose delimited",
		"HTTP/1.0 200 OK\r\n\r\nold",
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort",
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nok",
		"HTTP/1.1 200 OK\r\nConnection: X-Hop, keep-alive\r\nX-Hop: 1\r\nKeep-Alive: timeout=5\r\nProxy-Authenticate: Basic\r\nUpgrade: h2c\r\nTe: trailers\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nX-A: a\rb\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nX-A: a\x00b\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nX-A: a\r\n b\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\nX-A: a\nContent-Length: 0\n\n",
		"HTTP/1.1 302 Found\r\nLocation: https://evil.example/\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\ntunnel bytes",
		"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n",
		"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 103 Early Hints\r\nLink: </a>; rel=preload\r\nConnection: X-Hop\r\nX-Hop: 1\r\nKeep-Alive: 1\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\nhello",
		"HTTP/1.1 304 Not Modified\r\n\r\n",
		"HTTP/1.1 999 Weird\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nSet-Cookie: a=b\r\nSet-Cookie: c=d\r\nContent-Length: 0\r\n\r\n",
		"garbage",
		"",
	}
	for _, seed := range seeds {
		for variant := range responseRequests {
			f.Add(byte(0), byte(variant), []byte(seed))
			f.Add(byte(1), byte(variant), []byte(seed))
		}
	}
	f.Fuzz(func(t *testing.T, modeByte, variant byte, response []byte) {
		if len(response) > maxFuzzInput {
			return
		}
		mode := modeFromByte(modeByte)
		request := responseRequests[int(variant)%len(responseRequests)]
		input := []byte(fmt.Sprintf(request.raw, mode.upstream))
		run := runProxy(mode, input, func(*wireRequest) ([]byte, bool) { return response, true }, true)
		violations := responseViolations(run, request.method, request.upgrade)
		if len(violations) > 0 {
			t.Fatalf("%v request %q upstream response %q:\nclient got %q\n%s", mode, input, response, run.client, strings.Join(violations, "\n"))
		}
	})
}

// responseViolations checks what the client received for one request.
func responseViolations(run *proxyRun, method string, upgrade bool) []string {
	var out []string
	add := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }
	pki := getFuzzPKI()
	if run.timedOut != "" {
		add("timeout: %s", run.timedOut)
	}
	for _, p := range run.panics {
		add("handler panicked: %s", p)
	}
	for _, addr := range run.dials {
		if asciiLower(addr) != run.mode.dial {
			add("proxy dialed %q", addr)
		}
	}
	out = append(out, logViolations(run.logs, pki.secrets)...)
	if secret := leakedSecret(string(run.client), pki.secrets); secret != "" {
		add("client response contains key material %q", secret)
	}

	br := bufio.NewReader(bytes.NewReader(run.client))
	for n := 0; ; n++ {
		if n > 8 {
			add("too many responses")
			return out
		}
		if upgrade {
			// After a 101 the upstream owns the raw tunnel, so its status
			// line is not the proxy's to check (docs/fuzzing.md).
			if peek, _ := br.Peek(16); isSwitchingProtocols(peek) {
				return out
			}
		}
		resp, err := readWireResponse(br, method)
		if errors.Is(err, errIncomplete) {
			// Truncated: the proxy aborted mid-body, which closes the
			// connection so the client sees the failure.
			return out
		}
		if err != nil {
			add("reading client response: %v", err)
			return out
		}
		for _, v := range resp.violations {
			add("client response %q: %s", resp.startLine, v)
		}
		if len(resp.violations) > 0 {
			return out
		}
		if resp.status == 101 {
			if !upgrade {
				add("client got 101 without asking to upgrade")
			}
			return out
		}
		if resp.status < 200 {
			continue
		}
		for _, name := range hopOnly {
			if resp.has(name) {
				add("client response: %s %q survived", name, resp.values(name))
			}
		}
		for _, name := range []string{"Upgrade", "Te"} {
			if resp.has(name) {
				add("client response: %s %q survived", name, resp.values(name))
			}
		}
		for _, token := range connectionTokens(resp.values("Connection")) {
			if asciiLower(token) != "close" {
				add("client response: Connection token %q", token)
			}
		}
		if bodyAllowed := method != "HEAD" && resp.status != 204 && resp.status != 304; bodyAllowed && resp.has("Trailer") && !resp.chunked {
			add("client response: Trailer without chunked body")
		}
		if rest, _ := br.Peek(1); len(rest) > 0 {
			remaining := make([]byte, br.Buffered())
			_, _ = br.Read(remaining)
			add("client got bytes after the final response: %q", remaining)
		}
		return out
	}
}

func isSwitchingProtocols(statusLine []byte) bool {
	_, rest, ok := bytes.Cut(statusLine, []byte(" "))
	return ok && bytes.HasPrefix(rest, []byte("101"))
}
