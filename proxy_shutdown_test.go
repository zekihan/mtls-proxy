package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

type forwardListenAddresses chan string

func (addresses forwardListenAddresses) Write(p []byte) (int, error) {
	_, destination, _ := strings.Cut(string(p), "forward http://")
	addr, _, ok := strings.Cut(destination, " -> ")
	if ok {
		select {
		case addresses <- addr:
		default:
		}
	}
	return len(p), nil
}

func TestServeDrainsActiveRequestsOnCancellation(t *testing.T) {
	const upstream = "upstream.test"
	routes := []route{
		{listen: "127.0.0.1:0", upstream: upstream, forward: true},
		{listen: "127.0.0.1:0", upstream: upstream, forward: true},
	}
	addresses := make(forwardListenAddresses, len(routes))
	output := log.Writer()
	log.SetOutput(addresses)
	t.Cleanup(func() { log.SetOutput(output) })

	started := make(chan struct{})
	release := make(chan struct{})
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/active" {
			close(started)
			select {
			case <-release:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
		return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
	})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	serveCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- serve(serveCtx, routes, transport, "") }()
	t.Cleanup(func() {
		stop()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(10 * time.Second):
			t.Error("serve did not stop")
		}
	})

	request := func(path string) *bufio.Reader {
		t.Helper()
		var addr string
		select {
		case addr = <-addresses:
		case <-ctx.Done():
			t.Fatal("timed out waiting for a listener to start")
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		deadline, _ := ctx.Deadline()
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(conn, "GET "+path+" HTTP/1.1\r\nHost: "+upstream+"\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		return bufio.NewReader(conn)
	}
	readResponse := func(reader *bufio.Reader, path string) (closeConnection bool) {
		t.Helper()
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatalf("reading %s response: %v", path, err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("%s got %s, want 204 No Content", path, response.Status)
		}
		return response.Close
	}

	active := request("/active")
	idle := request("/idle")
	if readResponse(idle, "/idle") {
		t.Fatal("expected an idle keep-alive connection")
	}
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("active request did not reach the transport")
	}
	stop()
	// The second listener's idle connection makes shutdown observable while
	// the first listener is still waiting for its upstream response.
	if _, err := idle.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("idle connection remained open during shutdown: %v", err)
	}
	close(release)
	readResponse(active, "/active")
}
