package main

import (
	"bytes"
	"compress/gzip"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
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
