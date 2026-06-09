# nebula-tool

`nebula-tool` is a small CLI that fills operational gaps around Nebula CA key
handling that `nebula-cert` does not cover directly. Its primary uses are:

- **sign Nebula host certificates through `ssh-agent`**, so the CA private key
  can live in an agent (or a hardware token behind it) and never touch disk
- **encrypt and decrypt Nebula CA/signing private keys** at rest

It also handles a few smaller key and certificate chores:

- export an Ed25519 Nebula CA/signing key as an OpenSSH private key (to load
  into `ssh-agent` for the signing workflow above)
- derive a public key from a Nebula private key
- extract a public key from a Nebula certificate

The tool links against `github.com/slackhq/nebula/cert`, so Nebula's own key,
certificate, PEM, and CA key encryption formats are used directly.

## Quick Start

Load an Ed25519 CA key into `ssh-agent`, then sign a host certificate without
the CA key ever being read from disk:

```bash
nebula-tool key export -in ca.key -out ca.ssh.key
ssh-add ca.ssh.key
nebula-tool sign ssh -ca-crt ca.crt -name host1 -networks 10.10.10.1/24 -out-key host1.key -out-crt host1.crt
```

Test that the agent holds the right key before signing:

```bash
nebula-tool sign ssh -test -ca-crt ca.crt
```

Encrypt a plaintext CA key at rest, and decrypt it when needed:

```bash
nebula-tool key encrypt -in ca.key -out ca.enc.key
nebula-tool key decrypt -in ca.enc.key -out ca.key
```

Smaller helpers, derive a public key from a private key, or extract one from a
certificate:

```bash
nebula-tool key public -in host.key -out host.pub
nebula-tool cert public -in host.crt -out host.pub
```

If `-password` is omitted and stdin is a terminal, `nebula-tool` prompts without
echo. Encryption asks for confirmation; decryption asks once.

## Commands

```bash
nebula-tool -help
nebula-tool -version
```

### `sign ssh`

Sign a Nebula host certificate using an Ed25519 CA key available through
`ssh-agent`:

```bash
nebula-tool sign ssh \
  -ca-crt ca.crt \
  -name host1 \
  -networks 10.10.10.1/24 \
  -out-key host1.key \
  -out-crt host1.crt
```

Use an existing host public key:

```bash
nebula-tool sign ssh \
  -ca-crt ca.crt \
  -name host1 \
  -networks 10.10.10.1/24 \
  -in-pub host1.pub \
  -out-crt host1.crt
```

Test agent access without creating a certificate:

```bash
nebula-tool sign ssh -test -ca-crt ca.crt
```

By default the agent socket is read from `SSH_AUTH_SOCK`. Override it with:

```bash
nebula-tool sign ssh -test -ca-crt ca.crt -agent-sock /path/to/agent.sock
```

Supported signing flags mirror the common `nebula-cert sign` flags: `-version`,
`-ca-crt`, `-name`, `-networks`, `-unsafe-networks`, `-duration`, `-groups`,
`-in-pub`, `-out-key`, and `-out-crt`.

Only Ed25519 Nebula CA certificates are currently supported for SSH agent
signing.

### `key encrypt`

Encrypt a plaintext Nebula CA/signing key:

```bash
nebula-tool key encrypt -in ca.key -out ca.enc.key
nebula-tool key encrypt -in ca.key -out ca.enc.key -password env:NEBULA_CA_PASSWORD
nebula-tool key encrypt -in ca.key -out ca.enc.key -password file:/run/secrets/nebula-ca-password
```

### `key decrypt`

Decrypt an encrypted Nebula CA/signing key:

```bash
nebula-tool key decrypt -in ca.enc.key -out ca.key
nebula-tool key decrypt -in ca.enc.key -out ca.key -password env:NEBULA_CA_PASSWORD
nebula-tool key decrypt -in ca.enc.key -out ca.key -password file:/run/secrets/nebula-ca-password
```

### `key export`

Export an Ed25519 Nebula CA/signing key as an OpenSSH private key:

```bash
nebula-tool key export -in ca.key -out ca.ssh.key
nebula-tool key export -in ca.enc.key -out ca.ssh.key -password env:NEBULA_CA_PASSWORD
```

Only Ed25519 CA/signing keys are supported. Host keys and P-256 CA keys are
rejected.

### `key public`

Derive a public key from a private key:

```bash
nebula-tool key public -in host.key -out host.pub
nebula-tool key public -in ca.key -out ca.pub
nebula-tool key public -in ca.enc.key -out ca.pub -password env:NEBULA_CA_PASSWORD
```

### `cert public`

Extract a public key from a Nebula certificate:

```bash
nebula-tool cert public -in host.crt -out host.pub
nebula-tool cert public -in ca.crt -out ca.pub
```

## Common Flags

- `-in PATH` reads input from `PATH`; use `-` for stdin.
- `-out PATH` writes output to `PATH`; use `-` for stdout.
- `nebula-tool` refuses to overwrite an existing output file; remove it first.
- `-password env:NAME` reads a password from an environment variable.
- `-password file:PATH` reads a password from a file, trimming trailing newlines.

## Key Types

Nebula host keys are used as `pki.key` and are not encrypted by Nebula's CA key
encryption format:

- `NEBULA X25519 PRIVATE KEY`
- `NEBULA P256 PRIVATE KEY`

Nebula CA/signing keys are used by `nebula-cert sign` and can be encrypted or
decrypted with this tool:

- `NEBULA ED25519 PRIVATE KEY`
- `NEBULA ECDSA P256 PRIVATE KEY`
- `NEBULA ED25519 ENCRYPTED PRIVATE KEY`
- `NEBULA ECDSA P256 ENCRYPTED PRIVATE KEY`

## Build

```bash
make build
```

or:

```bash
go build -trimpath -ldflags='-s -w' -o nebula-tool .
```

## Build Against a Nebula Tag

To rebuild against a newer Nebula release, pin the dependency to that tag and
build again:

```bash
go get github.com/slackhq/nebula@v1.10.4
go mod tidy
make clean build
```

If Nebula changes the public `cert` package API, the build will fail and
`main.go` must be adjusted to the new API. For testing against a local Nebula
checkout, temporarily add a `replace` directive in `go.mod`, then remove it
before publishing:

```go
replace github.com/slackhq/nebula => ../nebula
```
