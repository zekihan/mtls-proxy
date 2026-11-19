package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProxyStreamsResponseDuringUpload(t *testing.T) {
	ca := newPKI(t)
	upstream := mtlsUpstream(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		controller := http.NewResponseController(w)
		if err := controller.EnableFullDuplex(); err != nil {
			t.Error(err)
			return
		}
		upload := bufio.NewReader(r.Body)
		if line, err := upload.ReadString('\n'); line != "first\n" || err != nil {
			t.Errorf("first upload line %q, err %v", line, err)
			return
		}
		_, _ = io.WriteString(w, "ready\n")
		if err := controller.Flush(); err != nil {
			t.Error(err)
			return
		}
		if rest, err := io.ReadAll(upload); string(rest) != "second\n" || err != nil {
			t.Errorf("rest of upload %q, err %v", rest, err)
			return
		}
		_, _ = io.WriteString(w, "done\n")
	}))

	transport := newTransport(ca.leaf(t, x509.ExtKeyUsageClientAuth), ca.pool)
	t.Cleanup(transport.CloseIdleConnections)
	proxy := httptest.NewTLSServer(newProxy(upstream, transport))
	t.Cleanup(proxy.Close)
	tlsConfig := proxy.Client().Transport.(*http.Transport).TLSClientConfig
	addr := proxy.Listener.Addr().String()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err = fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nfirst\n\r\n", addr)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("waiting for a response before completing the upload: %v", err)
	}
	defer resp.Body.Close()
	reply := bufio.NewReader(resp.Body)
	if line, err := reply.ReadString('\n'); resp.StatusCode != http.StatusOK || line != "ready\n" || err != nil {
		t.Fatalf("upload acknowledgment: status %d, line %q, err %v", resp.StatusCode, line, err)
	}
	if _, err := io.WriteString(conn, "7\r\nsecond\n\r\n0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if rest, err := io.ReadAll(reply); string(rest) != "done\n" || err != nil {
		t.Fatalf("completed response %q, err %v", rest, err)
	}
}
