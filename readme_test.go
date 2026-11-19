package main

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestREADMEForwardProxyExample(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is required to run the README example")
	}
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl is required to check the README proxy settings")
	}
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	var example string
	for _, block := range strings.Split(string(readme), "```bash\n")[1:] {
		code, _, _ := strings.Cut(block, "\n```")
		if strings.Contains(code, "your-client --endpoint") {
			example = code
			break
		}
	}
	if example == "" {
		t.Fatal("forward client command missing from README")
	}

	// Both paths stay on loopback. An HTTP proxy receives an absolute URL.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.IsAbs() {
			_, _ = io.WriteString(w, "proxy")
			return
		}
		_, _ = io.WriteString(w, "direct")
	}))
	t.Cleanup(server.Close)
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	example = strings.NewReplacer("127.0.0.1:18445", server.Listener.Addr().String(), "s3.example.com", "s3.example.test").Replace(example)
	script := `
mtls-proxy() { :; }
your-client() {
    test "$1" = --endpoint
    test "$2" = http://s3.example.test
    "$CURL" --disable --silent --show-error --fail --max-time 3 \
        --resolve "s3.example.test:$TEST_PORT:127.0.0.1" "$2:$TEST_PORT"
}
` + example
	for _, tc := range []struct {
		name string
		env  []string
	}{
		{"clean environment", nil},
		{"inherited bypass", []string{"http_proxy=" + server.URL, "NO_PROXY=s3.example.test", "no_proxy=s3.example.test"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), bash, "-ec", script)
			cmd.Env = append([]string{"CURL=" + curl, "TEST_PORT=" + port}, tc.env...)
			if output, err := cmd.CombinedOutput(); err != nil || string(output) != "proxy" {
				t.Fatalf("expected proxied request, got %q (error %v)", output, err)
			}
		})
	}
}
