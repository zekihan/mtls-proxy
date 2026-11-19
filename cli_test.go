package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "mtls-proxy" {
		os.Args = os.Args[1:]
		main()
		return
	}
	os.Exit(m.Run())
}

func cliCommand(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	return exec.CommandContext(ctx, executable, append([]string{"mtls-proxy"}, args...)...)
}

func TestCLIRejectsUnusableSystemRoots(t *testing.T) {
	certs := getFuzzPKI()
	dir := t.TempDir()
	certFile := filepath.Join(dir, "client.pem")
	keyFile := filepath.Join(dir, "client.key")
	malformedBundle := filepath.Join(dir, "malformed.pem")
	for path, data := range map[string][]byte{
		certFile:        certs.clientCertPEM,
		keyFile:         certs.clientKeyPEM,
		malformedBundle: []byte("invalid CA bundle"),
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	emptyDir := t.TempDir()
	// An occupied port detects whether the CLI tried to bind before loading roots.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	for _, tc := range []struct {
		name     string
		certFile string
		want     string
	}{
		{"empty pool", malformedBundle, "upstream system trust store contains no certificates"},
		{"load error", emptyDir, "load upstream system CA certificates:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := cliCommand(t, "-cert", certFile, "-key", keyFile, "-forward", listener.Addr().String()+"=upstream.test")
			// System roots are cached process-wide. These paths isolate the child
			// from host trust stores, including the platform verifier on macOS.
			cmd.Env = append(cmd.Environ(), "SSL_CERT_FILE="+tc.certFile, "SSL_CERT_DIR="+emptyDir, "GODEBUG=x509sslcertoverrideplatform=1")
			output, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 || !strings.Contains(string(output), tc.want) {
				t.Fatalf("exit = %v, output = %q, want exit 1 and %q", err, output, tc.want)
			}
		})
	}
}

func TestCLIHelpUsesStdout(t *testing.T) {
	for _, arg := range []string{"-h", "--help"} {
		t.Run(arg, func(t *testing.T) {
			cmd := cliCommand(t, arg)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			stdout, err := cmd.Output()
			if err != nil || stderr.Len() != 0 || !bytes.Contains(stdout, []byte("Usage of mtls-proxy:")) ||
				!bytes.Contains(stdout, []byte("-forward")) {
				t.Fatalf("exit = %v, stdout = %q, stderr = %q", err, stdout, stderr.String())
			}
		})
	}
}

func TestCLIFlagErrorUsesStderr(t *testing.T) {
	stdout, err := cliCommand(t, "-unknown").Output()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Fatalf("exit = %v, stdout = %q, want exit 2", err, stdout)
	}
	if len(stdout) != 0 || !bytes.Contains(exitErr.Stderr, []byte("flag provided but not defined: -unknown")) ||
		!bytes.Contains(exitErr.Stderr, []byte("Usage of mtls-proxy:")) {
		t.Fatalf("stdout = %q, stderr = %q", stdout, exitErr.Stderr)
	}
}
