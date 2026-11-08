package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// This file is a small, strict HTTP/1.1 reader written independently of
// net/http. The fuzz harness uses it on the upstream side to see exactly what
// bytes the proxy put on the wire, so the oracles do not trust the same parser
// that produced the traffic.

type wireHeader struct{ name, value string }

type wireMessage struct {
	startLine  string
	headers    []wireHeader
	trailers   []wireHeader
	body       []byte
	chunked    bool
	violations []string
}

func (m *wireMessage) values(name string) []string {
	var values []string
	for _, h := range m.headers {
		if strings.EqualFold(h.name, name) {
			values = append(values, h.value)
		}
	}
	return values
}

func (m *wireMessage) has(name string) bool { return len(m.values(name)) > 0 }

// errIncomplete means the peer stopped before a whole message arrived. It is
// not a protocol violation by the sender we are checking.
var errIncomplete = errors.New("incomplete message")

const wireHeadLimit = 1 << 20

// readWireLine reads one CRLF-terminated line and reports bare CR or LF.
func readWireLine(br *bufio.Reader, budget *int) (string, []string, error) {
	line, err := br.ReadString('\n')
	*budget -= len(line)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return "", nil, errIncomplete
		}
		return "", nil, err
	}
	if *budget < 0 {
		return "", []string{"head exceeds limit"}, nil
	}
	var violations []string
	if !strings.HasSuffix(line, "\r\n") {
		violations = append(violations, fmt.Sprintf("bare LF ending line %q", line))
		line = strings.TrimSuffix(line, "\n")
	} else {
		line = strings.TrimSuffix(line, "\r\n")
	}
	if strings.ContainsRune(line, '\r') {
		violations = append(violations, fmt.Sprintf("bare CR in line %q", line))
	}
	return line, violations, nil
}

func isTokenByte(c byte) bool {
	if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isTokenByte(s[i]) {
			return false
		}
	}
	return true
}

// checkFieldValue allows VCHAR, obs-text, SP and HTAB, as RFC 9110 5.5 does.
func checkFieldValue(name, value string) []string {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '\t' || c == ' ' || c >= 0x21 && c != 0x7f {
			continue
		}
		return []string{fmt.Sprintf("control byte %#x in %s value %q", c, name, value)}
	}
	return nil
}

func readWireFields(br *bufio.Reader, budget *int) ([]wireHeader, []string, error) {
	var headers []wireHeader
	var violations []string
	for {
		line, bad, err := readWireLine(br, budget)
		if err != nil {
			return nil, nil, err
		}
		violations = append(violations, bad...)
		if len(bad) > 0 && *budget < 0 {
			return headers, violations, nil
		}
		if line == "" {
			return headers, violations, nil
		}
		if line[0] == ' ' || line[0] == '\t' {
			violations = append(violations, fmt.Sprintf("obsolete line folding %q", line))
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || !isToken(name) {
			violations = append(violations, fmt.Sprintf("malformed field line %q", line))
			continue
		}
		value = strings.Trim(value, " \t")
		violations = append(violations, checkFieldValue(name, value)...)
		headers = append(headers, wireHeader{name, value})
	}
}

// readWireBody frames a message body. Ambiguous framing is a violation and
// the body is not read, since a real peer could disagree about its length.
func readWireBody(br *bufio.Reader, m *wireMessage, bodyAllowed bool) error {
	te, cl := m.values("Transfer-Encoding"), m.values("Content-Length")
	switch {
	case len(te) > 0 && len(cl) > 0:
		m.violations = append(m.violations, fmt.Sprintf("both Transfer-Encoding %q and Content-Length %q", te, cl))
		return nil
	case len(te) > 1 || len(te) == 1 && te[0] != "chunked":
		m.violations = append(m.violations, fmt.Sprintf("Transfer-Encoding %q", te))
		return nil
	case len(cl) > 1:
		m.violations = append(m.violations, fmt.Sprintf("several Content-Length %q", cl))
		return nil
	}
	if !bodyAllowed {
		return nil
	}
	if len(te) == 1 {
		m.chunked = true
		return readWireChunked(br, m)
	}
	if len(cl) == 0 {
		return nil
	}
	if cl[0] == "" || strings.Trim(cl[0], "0123456789") != "" || len(cl[0]) > 12 {
		m.violations = append(m.violations, fmt.Sprintf("Content-Length %q", cl[0]))
		return nil
	}
	n, _ := strconv.ParseInt(cl[0], 10, 64)
	if n > 16<<20 {
		// Too large to buffer; a valid length, so stop reading instead.
		return errIncomplete
	}
	m.body = make([]byte, n)
	if _, err := io.ReadFull(br, m.body); err != nil {
		return errIncomplete
	}
	return nil
}

func readWireChunked(br *bufio.Reader, m *wireMessage) error {
	budget := wireHeadLimit
	for {
		line, bad, err := readWireLine(br, &budget)
		if err != nil {
			return err
		}
		if len(bad) > 0 {
			m.violations = append(m.violations, bad...)
			return nil
		}
		size, ext, _ := strings.Cut(line, ";")
		_ = ext
		if size == "" || len(size) > 15 || strings.Trim(strings.ToLower(size), "0123456789abcdef") != "" {
			m.violations = append(m.violations, fmt.Sprintf("chunk size line %q", line))
			return nil
		}
		n, _ := strconv.ParseInt(size, 16, 64)
		if n == 0 {
			trailers, bad, err := readWireFields(br, &budget)
			if err != nil {
				return err
			}
			m.violations = append(m.violations, bad...)
			m.trailers = trailers
			return nil
		}
		if int64(len(m.body))+n > 16<<20 {
			return errIncomplete
		}
		chunk := make([]byte, n+2)
		if _, err := io.ReadFull(br, chunk); err != nil {
			return errIncomplete
		}
		if string(chunk[n:]) != "\r\n" {
			m.violations = append(m.violations, fmt.Sprintf("chunk not followed by CRLF: %q", chunk[n:]))
			return nil
		}
		m.body = append(m.body, chunk[:n]...)
	}
}

type wireRequest struct {
	wireMessage
	method, target, proto string
}

// readWireRequest reads one request as an origin server would.
func readWireRequest(br *bufio.Reader) (*wireRequest, error) {
	budget := wireHeadLimit
	line, bad, err := readWireLine(br, &budget)
	if err != nil {
		return nil, err
	}
	r := &wireRequest{}
	r.startLine = line
	r.violations = append(r.violations, bad...)
	parts := strings.Split(line, " ")
	if len(parts) != 3 {
		r.violations = append(r.violations, fmt.Sprintf("request line %q", line))
		return r, nil
	}
	r.method, r.target, r.proto = parts[0], parts[1], parts[2]
	if !isToken(r.method) {
		r.violations = append(r.violations, fmt.Sprintf("method %q", r.method))
	}
	if r.target == "" {
		r.violations = append(r.violations, "empty request-target")
	}
	query := strings.IndexByte(r.target, '?')
	for i := 0; i < len(r.target); i++ {
		// net/http passes a client's raw non-ASCII query bytes through;
		// docs/fuzzing.md records that. Controls and spaces never pass.
		if c := r.target[i]; c <= 0x20 || c == 0x7f || c > 0x7f && (query < 0 || i < query) {
			r.violations = append(r.violations, fmt.Sprintf("byte %#x in request-target %q", c, r.target))
			break
		}
	}
	if r.proto != "HTTP/1.1" {
		r.violations = append(r.violations, fmt.Sprintf("version %q", r.proto))
	}
	headers, bad, err := readWireFields(br, &budget)
	if err != nil {
		return nil, err
	}
	r.headers = headers
	r.violations = append(r.violations, bad...)
	if len(r.violations) > 0 {
		return r, nil
	}
	if err := readWireBody(br, &r.wireMessage, true); err != nil {
		return nil, err
	}
	return r, nil
}

type wireResponse struct {
	wireMessage
	status int
}

// readWireResponse reads one response to a request with the given method.
func readWireResponse(br *bufio.Reader, method string) (*wireResponse, error) {
	budget := wireHeadLimit
	line, bad, err := readWireLine(br, &budget)
	if err != nil {
		return nil, err
	}
	r := &wireResponse{}
	r.startLine = line
	r.violations = append(r.violations, bad...)
	proto, rest, _ := strings.Cut(line, " ")
	code, _, _ := strings.Cut(rest, " ")
	if proto != "HTTP/1.1" && proto != "HTTP/1.0" || len(code) != 3 || strings.Trim(code, "0123456789") != "" {
		r.violations = append(r.violations, fmt.Sprintf("status line %q", line))
		return r, nil
	}
	r.status, _ = strconv.Atoi(code)
	headers, bad, err := readWireFields(br, &budget)
	if err != nil {
		return nil, err
	}
	r.headers = headers
	r.violations = append(r.violations, bad...)
	if len(r.violations) > 0 {
		return r, nil
	}
	bodyAllowed := method != "HEAD" && r.status >= 200 && r.status != 204 && r.status != 304
	if bodyAllowed && !r.has("Transfer-Encoding") && !r.has("Content-Length") {
		// Delimited by close.
		body, err := io.ReadAll(br)
		r.body = body
		return r, err
	}
	if err := readWireBody(br, &r.wireMessage, bodyAllowed); err != nil {
		return nil, err
	}
	return r, nil
}

// connectionTokens lists the field names a Connection header nominates.
func connectionTokens(values []string) []string {
	var tokens []string
	for _, v := range values {
		for _, t := range strings.Split(v, ",") {
			if t = strings.TrimSpace(t); t != "" {
				tokens = append(tokens, t)
			}
		}
	}
	return tokens
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
