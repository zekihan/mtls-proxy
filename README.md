# mtls-proxy

A small loopback proxy for tools that cannot present a TLS client certificate.
It listens on `127.0.0.1`, adds your client certificate, and forwards to one
upstream host. Terraform providers are the usual case: many have no client
certificate setting and ignore `HTTPS_PROXY`.

The client certificate can come from the macOS Keychain, so the private key never
has to be exported, from PEM files, or from environment variables.

## Install

```bash
go install github.com/zekihan/mtls-proxy@latest
```

With `-identity`, macOS grants Keychain access per binary, so keep the binary at a
fixed path. The Keychain needs cgo, which is the default on macOS. For a static Linux
binary, build with `CGO_ENABLED=0`.

## Usage

```bash
# macOS Keychain identity, selected by certificate common name
mtls-proxy -identity clients-laptop -ca-out ~/.local/state/mtls-proxy/ca.pem \
  -route 127.0.0.1:18443=app.example.com

# PEM files
mtls-proxy -cert client.pem -key client.key -ca-out ca.pem \
  -route 127.0.0.1:18443=app.example.com

# PEM values in environment variables, cleared once read
CERT_PEM="$cert" KEY_PEM="$key" mtls-proxy -cert-env CERT_PEM -key-env KEY_PEM \
  -ca-out ca.pem -route 127.0.0.1:18443=app.example.com
```

Set the variables only on the proxy's command, so other processes do not inherit the
key. Do not do this in a `bash -x` script, because tracing prints the values.

Clearing them does not erase the environment the proxy started with. Processes running
as your user can still read the key there (`/proc/<pid>/environ` on Linux, `ps -E` on
macOS) until the proxy exits. To keep it out of the environment, pass it through process
substitution instead:

```bash
mtls-proxy -cert <(your-secret-command cert) -key <(your-secret-command key) \
  -ca-out ca.pem -route 127.0.0.1:18443=app.example.com
```

The proxy only listens on loopback IPs and refuses anything else.

### `-route`: HTTPS reverse proxy

Point the client at `https://127.0.0.1:18443` (or `wss://` for WebSockets). The proxy
serves HTTPS using a self-signed certificate generated at startup. The key stays in
memory, and the certificate is written to `-ca-out` for the client to pin. It changes
on every start. The proxy rewrites `Host` and SNI to the upstream.

### `-forward`: `HTTP_PROXY` route for signed requests

Clients that sign the hostname, such as S3 SigV4, cannot use `-route` because the
`Host` rewrite invalidates the signature. `-forward` keeps the hostname:

```bash
mtls-proxy -cert client.pem -key client.key -forward 127.0.0.1:18445=s3.example.com
HTTP_PROXY=http://127.0.0.1:18445 your-client --endpoint http://s3.example.com
```

It accepts only that upstream and refuses `CONNECT`, so it cannot be used as an open
proxy. This hop is plain HTTP on loopback, and TLS starts at the proxy. Do not run
such a client without `HTTP_PROXY`, or its requests leave the machine unencrypted.

## Security

- Upstream certificates are verified against the system trust store.
- Any local process can use your client identity through the proxy while it runs.
  Stop it when you finish.
- Requests a browser makes on behalf of another site (`Sec-Fetch-Site: cross-site` or
  `same-site`) are refused, so a web page cannot use your client identity.
