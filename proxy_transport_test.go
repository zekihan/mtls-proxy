package main

import (
	"bytes"
	"compress/gzip"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProxyPreservesEncodedResponse(t *testing.T) {
	ca := newPKI(t)
	var encoded bytes.Buffer
	gzipWriter := gzip.NewWriter(&encoded)
	if _, err := io.WriteString(gzipWriter, "stored object data"); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	upstream := mtlsUpstream(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Cache-Control", "no-transform")
		w.Header().Set("X-Received-Accept-Encoding", r.Header.Get("Accept-Encoding"))
		_, _ = w.Write(encoded.Bytes())
	}))

	transport := newTransport(ca.leaf(t, x509.ExtKeyUsageClientAuth), ca.pool)
	t.Cleanup(transport.CloseIdleConnections)
	proxy := httptest.NewTLSServer(newProxy(upstream, transport))
	t.Cleanup(proxy.Close)
	// Inspect the response as sent by the proxy, without client-side decoding.
	client := proxy.Client()
	client.Transport.(*http.Transport).DisableCompression = true
	client.Timeout = 5 * time.Second
	for _, encoding := range []string{"", "gzip"} {
		req, err := http.NewRequest(http.MethodGet, proxy.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		if encoding != "" {
			req.Header.Set("Accept-Encoding", encoding)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if got := resp.Header.Get("X-Received-Accept-Encoding"); got != encoding {
			t.Errorf("upstream received Accept-Encoding %q, want %q", got, encoding)
		}
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Encoding") != "gzip" || !bytes.Equal(body, encoded.Bytes()) {
			t.Errorf("Accept-Encoding %q: status %d, Content-Encoding %q, body %q", encoding, resp.StatusCode, resp.Header.Get("Content-Encoding"), body)
		}
	}
}

func TestProxyTimesOutWaitingForUpstreamHeaders(t *testing.T) {
	ca := newPKI(t)
	started := make(chan struct{})
	release := make(chan struct{})
	upstream := mtlsUpstream(t, ca, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(started)
		<-release
	}))
	defer close(release)

	transport := newTransport(ca.leaf(t, x509.ExtKeyUsageClientAuth), ca.pool)
	// Shorten the configured deadline for the test. A zero value still disables it.
	transport.ResponseHeaderTimeout = min(transport.ResponseHeaderTimeout, 100*time.Millisecond)
	t.Cleanup(transport.CloseIdleConnections)
	proxy := httptest.NewServer(newProxy(upstream, transport))
	t.Cleanup(proxy.Close)
	client := proxy.Client()
	client.Timeout = 3 * time.Second

	response, err := client.Get(proxy.URL)
	if err != nil {
		t.Fatalf("waiting for the proxy to report an upstream timeout: %v", err)
	}
	defer response.Body.Close()
	select {
	case <-started:
	default:
		t.Fatal("upstream never received the request")
	}
	if response.StatusCode != http.StatusBadGateway {
		t.Errorf("status %d, want %d", response.StatusCode, http.StatusBadGateway)
	}
}

func TestProxyOmitsUpstreamErrorDetails(t *testing.T) {
	ca := newPKI(t)
	const token = "synthetic-session-token"
	for _, tc := range []struct {
		name   string
		wire   string
		status int
	}{
		{
			name:   "malformed header",
			wire:   "HTTP/1.1 200 OK\r\nSet-Cookie session=" + token + "\r\n\r\n",
			status: http.StatusBadGateway,
		},
		{
			name:   "malformed trailer",
			wire:   "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Internal-Token " + token + "\r\n\r\n",
			status: http.StatusOK,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs logRecords
			output := log.Writer()
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(output) })

			upstream := mtlsUpstream(t, ca, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				conn, buffered, err := http.NewResponseController(w).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				if _, err := buffered.WriteString(tc.wire); err != nil {
					t.Error(err)
					return
				}
				if err := buffered.Flush(); err != nil {
					t.Error(err)
				}
			}))
			transport := newTransport(ca.leaf(t, x509.ExtKeyUsageClientAuth), ca.pool)
			t.Cleanup(transport.CloseIdleConnections)
			recorder := httptest.NewRecorder()
			newProxy(upstream, transport).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

			if recorder.Code != tc.status || strings.Contains(recorder.Body.String(), token) {
				t.Errorf("proxy returned status %d, body %q", recorder.Code, recorder.Body.String())
			}
			records := strings.Join(logs.all(), "")
			if records == "" || strings.Contains(records, token) {
				t.Errorf("expected a log without the upstream token, got %q", records)
			}
		})
	}
}
