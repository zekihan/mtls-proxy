# Fuzzing

This records a native Go fuzzing campaign run against mtls-proxy in
November 2026 (Go 1.27.3, linux/amd64, `-parallel 4` on a shared machine).

## Threat model

The local client of the proxy and the remote upstream are both partly
untrusted. The client controls the request line, headers, Host,
absolute-form and CONNECT targets and the body. The upstream controls
response headers and body. The bug classes searched for were, worst first:

- the client certificate going to a destination it should not, through
  target, Host, scheme, authority, IPv6, userinfo, percent-encoding,
  redirect or CONNECT confusion
- listening beyond loopback
- request smuggling or header injection: hop-by-hop handling, ambiguous
  Transfer-Encoding/Content-Length, CR/LF in values
- certificate, key or config material in errors and logs
- panics, unbounded allocation or CPU, and invalid config being accepted

## Targets

All targets live in `fuzz_*_test.go`. Committed corpus entries are under
`testdata/fuzz/`.

| Target | Drives | Properties |
| --- | --- | --- |
| `FuzzProxyRequest(mode, raw)` | Raw client bytes into the real `newProxy` / `newForwardProxy` handler over `net.Pipe`. The real `newTransport` dials an in-process mTLS upstream (`RequireAndVerifyClientCert`, disposable CA). Eight modes: route or forward, with upstreams `upstream.test`, `upstream.test:8443`, `UPSTREAM.Test` and `127.0.0.1:9443`. | Dial address and SNI equal the configured upstream (ASCII case-insensitive). The client certificate is presented. Upstream sees exactly one Host, equal to the upstream. The request-target is origin-form. No hop-by-hop, Proxy-Authorization, Forwarded or X-Forwarded-* headers. Connection-nominated headers are removed. Every upstream request is a request the proxy accepted, in order, with the same method, path and body (smuggling check). Each forwarded request satisfies a reference policy (Sec-Fetch-Site, ASCII host match and no CONNECT on forward routes). No handler panics. Log records are single lines with no key material. Wire framing is checked by an HTTP/1.1 reader written independently of net/http (`fuzz_wire_test.go`): bare CR/LF, CTLs, obs-fold, TE+CL, several CL, chunked framing. |
| `FuzzUpstreamResponse(mode, variant, raw)` | Arbitrary upstream response bytes for five client requests (GET, HEAD, POST, WebSocket upgrade, TE: trailers). | The client gets well-framed responses with no bytes after the final one. No 101 unless the client asked to upgrade. Hop-by-hop headers are stripped from final responses. No Trailer without a chunked body. No panics, no key material, single-line logs. |
| `FuzzParseRoute(value)` | `parseRoute`. | An accepted listen is a loopback IP literal per a `net/netip` reference, and `net.ResolveTCPAddr` agrees. An accepted upstream is valid per a reference parser, and `url.URL{Host: upstream}` dials exactly the host and port the reference reads. Routes round-trip as `listen=upstream`. |
| `FuzzParseRouteAcceptsValid(listen, upstream)` | `parseRoute`. | The reverse direction: everything the references accept is accepted. |
| `FuzzRunArgs(args)` | `run` with fuzzed arguments. Identity, file and `-ca-out` flags are stripped; env sources are prepended and return an expired certificate, so `run` never binds. | `run` always fails and never writes `-ca-out`. Errors and stderr hold no key material. When the config is accepted, a plain `flag.FlagSet` parses the same args with no positional arguments, at least one route, and every route valid per the references. |
| `FuzzLoadCertificate(mode, cert, key)` | `loadCertificateWithEnv` from env and from files. | Env variables are always cleared. Errors hold neither the disposable key nor base64 lines of the fuzzed key. A loaded private key matches the leaf. `checkClientCertificate` logs no key material. |
| `FuzzSelectIdentity(name, data)` | `selectIdentity` over generated leaves. | Matches a reference: currently valid with inclusive bounds, latest NotAfter, earliest on a tie. Errors are single-line. |
| `FuzzCheckClientCertificate(cn, org, before, after)` | `checkClientCertificate` on real signed certificates. | Accepts exactly when now is within [NotBefore, NotAfter]. Errors and logs are single-line (except I1 below). |
| `FuzzServerCertificate(data)` | `newServerCertificate` for mixes of reverse and forward routes on several loopback IPs, including IPv4-mapped IPv6. | Leaves signed by the generated CA verify only for reverse-route listener IPs, never for other IPs or any DNS name. |

## Runs

Execs and wall time per target, summed over every run. That includes short
runs on earlier harness versions while the oracles were being fixed.
Coverage-guided except the first 18s `FuzzProxyRequest` run.

| Target | Execs | Time | Longest single run |
| --- | ---: | ---: | --- |
| FuzzProxyRequest | 34,574,876 | 1h52m | 60m, 19.5M execs, clean |
| FuzzUpstreamResponse | 3,429,391 | 49m | 45m, 3.1M execs, clean |
| FuzzParseRoute | 23,430,164 | 16m | 15m, clean |
| FuzzParseRouteAcceptsValid | 17,315,611 | 11m | 10m, clean |
| FuzzRunArgs | 19,320,712 | 16m | 15m, clean |
| FuzzLoadCertificate | 21,572,896 | 16m | 15m, clean |
| FuzzSelectIdentity | 12,893,720 | 11m | 10m, clean |
| FuzzCheckClientCertificate | 6,129,465 | 11m | 10m, clean |
| FuzzServerCertificate | 1,078,959 | 16m | 15m, clean |
| **Total** | **139,745,794** | **about 4h17m** | |

Every target finished its final run with no failures. The final 30m run of
`FuzzProxyRequest`, after all fixes, still found new coverage (91 new
corpus entries on top of 977), so the proxy target has not fully plateaued.
The config and certificate targets were adding inputs only slowly by the
end of their runs.

The progress lines often show `0/sec` for a few seconds at a time. These
are minimization phases of the fuzzing coordinator, not hangs: a watchdog
built during the campaign saw no single input run longer than 8s.

## Findings

Severity is for this tool's threat model. Every fix has a table test that
fails without it.

### F1. Opaque request-targets were forwarded verbatim (Low-Medium)

- Reproducer: `GET http:evil.example/x HTTP/1.1` or
  `connect http:evil.example:443 HTTP/1.1` sent to a route listener (a
  `FuzzProxyRequest` seed).
- Root cause: `net/url` parses `http:evil.example/x` with `Opaque`
  `evil.example/x`. `ProxyRequest.SetURL` keeps `Opaque`, and the transport
  writes it as the request-target, so the upstream received
  `GET evil.example/x HTTP/1.1` and `connect evil.example:443 HTTP/1.1`
  over the client-authenticated connection. A lenient upstream or an
  intermediary could read that as a request for a different target. The
  connection itself always went to the configured upstream.
- Fix: c389574, "Reject opaque request targets" (400). Test:
  `TestProxyRejectsOpaqueRequestTargets`.

### F2. Upstream status codes below 100 panicked the handler (Low)

- Reproducer: `testdata/fuzz/FuzzUpstreamResponse/status-000-panic`
  (upstream answers `HTTP/0.0 000`).
- Root cause: `http.ReadResponse` accepts any three digits, so the status
  was 0. `ReverseProxy` then called `WriteHeader(0)`, which panics. The
  server recovered, but it wrote a multi-line stack trace to the log and
  dropped the client connection with no response.
- Fix: 3e10a38, "Return 502 for upstream status codes below 100", through
  `ModifyResponse`. Test: `TestProxyRejectsInvalidUpstreamStatus`.

### F3. Route upstreams were not validated (Low)

- Reproducer: `-route 127.0.0.1:1=::1` (a `FuzzParseRoute` seed). Also
  `::8443`, `https://x`, `a/b`, `user@host`, `host:0`, `host:65536`,
  `127.1`, `0x7f000001`, `[1.2.3.4]:443` and `a=b`.
- Root cause: `parseRoute` checked only the listen side. For an
  unbracketed IPv6 upstream, `url.URL.Hostname()` and `Port()` split
  `::1` into host `::` and port `1`, so the proxy dialed `[::]:1`, a local
  port, instead of what was configured. Numeric last labels are read as
  IPv4 numbers by some resolvers. TLS verification against the system
  roots would normally reject these destinations; the campaign did not
  exercise that check.
- Fix: 9f47385, "Validate route upstreams". The upstream must be a host
  name (LDH plus `_`, optional trailing dot, last label not numeric or
  `0x` hex) or an IP literal with IPv6 in brackets, with an optional port
  from 1 to 65535. Test: `TestParseRouteValidatesUpstream`.

### F4. Positional arguments were silently ignored (Low)

- Reproducer: `-forward 127.0.0.1:1=a -- -forward 127.0.0.1:2=b`, or
  `-route x=y extra` (`FuzzRunArgs` seeds).
- Root cause: `flag` stops at the first non-flag argument, and `run` never
  checked `NArg()`. Everything after a stray word or `--`, including more
  routes, was dropped while the proxy started.
- Fix: b2958fd, "Reject positional arguments". Test: `TestRunValidation`.

### F5. Forward routes compared hosts with Unicode case folding (Low)

- Reproducer: forward route for `s3.example.com`, request
  `GET http://ſ3.example.com/ HTTP/1.1` (U+017F folds to `s`). Seeded in
  `FuzzProxyRequest` as `upſtream.teſt`.
- Root cause: `strings.EqualFold` folds Unicode, and the URL host of an
  absolute-form request is not limited to ASCII. The request still went
  to the configured upstream with Host rewritten, so this was a policy
  bypass, not a change of destination. The 1h fuzz run did not find it
  without the seed; the input needs one specific two-byte UTF-8 sequence.
- Fix: 44caba4, "Compare forward proxy hosts in ASCII only". Test:
  `TestForwardProxyComparesHostsInASCII`.

### Informational (not changed)

- I1. A CR or LF in the client certificate's subject (CN or O) splits the
  startup log line and the expiry error, because `pkix.Name.String()` does
  not escape control characters. The certificate is the operator's own, so
  the code is unchanged; the oracles allow this case.
- I2. `ReverseProxy` forwards 1xx responses with hop-by-hop headers intact
  (`Connection`, `Keep-Alive`, `Proxy-Authenticate` and headers nominated
  in `Connection`). This is stdlib behaviour, confirmed with a 103 response.
  Clients treat 1xx as interim, and the upstream already controls the
  final response's headers.
- I3. `PRI * HTTP/2.0` reaches the handler and goes upstream as
  `PRI /%2A HTTP/1.1`, because Rewrite joins `*` onto the empty upstream
  path. The server answers `OPTIONS *` itself.
- I4. A malformed client query (`?%`, `;`) is re-encoded or dropped by
  `ReverseProxy` (`cleanQueryParams`). A well-formed query with raw
  non-ASCII bytes (`/?\xc6`) is passed upstream byte for byte. Controls,
  spaces and CR/LF never pass. Corpus entries: `query-reencoded`,
  `raw-non-ascii-query`.
- I5. After a 101 that the client asked for, the upstream's status line is
  copied as is (`HTTP/0.0 101 101`). The upstream controls the tunnel bytes
  from that point anyway. Corpus entry: `upgrade-http00-status`.
- I6. Route mode (not forward) forwards CONNECT to its upstream. The target
  becomes the upstream itself, so no destination confusion was seen.
- I7. Listen ports are not validated by `parseRoute`: `127.0.0.1:abc` and
  `127.0.0.1:99999` fail at `net.Listen`, before the CA is written, and
  service names such as `127.0.0.1:http` bind that port on loopback.
- I8. `newServerCertificate` with only forward routes would produce a CA
  with no IP name constraint. `serve` only calls it when a reverse route
  exists, so this is a hardening note.
- I9. The Sec-Fetch-Site check reads only the first value. Browsers never
  send duplicates.
- I10. SNI keeps the configured case (`UPSTREAM.Test`). RFC 6066 compares
  host names case-insensitively.

## Harness notes

- The upstream side of the in-memory pipe closes the raw connection, not
  the TLS conn. close_notify on an unbuffered `net.Pipe` blocks until the
  peer reads it, and with both sides closing that cost 5s per run.
- The harness waits for handlers to return, not for the connection to
  close. After a request body is left unread, net/http sleeps
  `rstAvoidanceDelay` (500ms) before closing.
- A `RoundTripper` wrapper marks which inbound requests the handler
  forwarded, so the policy oracle does not guess from the wire.
  Wire-to-inbound matching uses method, path and body. Queries are left out
  because of I4.
- Handler panics are caught with `recover` in the wrapper. Panics with
  `http.ErrAbortHandler` are expected.

## Open questions

- Should log and error output escape the certificate subject (I1)?
- Should the proxy reject non-ASCII query bytes (I4) or CONNECT on reverse
  routes (I6)?
- `validUpstream` allows `_` and a trailing dot, and rejects numeric or
  `0x` last labels. Confirm that no real configs use other forms.
- `FuzzProxyRequest` was still finding new coverage at the end. A longer
  run, or a structured request generator, would reach further.

## Rerunning

Seed corpora and committed crashers run as normal tests:

```sh
go test -race ./...
```

Fuzz one target at a time (the `^…$` anchors keep the name from matching
`FuzzParseRouteAcceptsValid` as well):

```sh
go test -run '^$' -fuzz '^FuzzProxyRequest$' -fuzztime 1h -parallel 4 .
go test -run '^$' -fuzz '^FuzzUpstreamResponse$' -fuzztime 45m -parallel 4 .
for t in FuzzParseRoute FuzzParseRouteAcceptsValid FuzzRunArgs FuzzLoadCertificate \
         FuzzSelectIdentity FuzzCheckClientCertificate FuzzServerCertificate; do
  go test -run '^$' -fuzz "^$t\$" -fuzztime 15m -parallel 4 .
done
```

A new failure is written to `testdata/fuzz/<Target>/`. Give it a
descriptive name and commit it with the fix.
