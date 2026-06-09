# nebula-tool

`nebula-tool` is a small CLI for day-to-day Nebula key and certificate tasks
that are useful operationally but not exposed directly by `nebula-cert`.

It can:

- derive a public key from a Nebula private key
- extract a public key from a Nebula certificate
- encrypt and decrypt Nebula CA/signing private keys

The tool links against `github.com/slackhq/nebula/cert`, so Nebula's own key,
certificate, PEM, and CA key encryption formats are used directly.

## Quick Start

Derive a host public key from a host private key:

```bash
nebula-tool key public -in host.key -out host.pub
```

Extract a public key from a certificate:

```bash
nebula-tool cert public -in host.crt -out host.pub
```

Encrypt a plaintext CA key:

```bash
nebula-tool key encrypt -in ca.key -out ca.enc.key
```

Decrypt an encrypted CA key:

```bash
nebula-tool key decrypt -in ca.enc.key -out ca.key
```

If `-password` is omitted and stdin is a terminal, `nebula-tool` prompts without
echo. Encryption asks for confirmation; decryption asks once.

## Commands

```bash
nebula-tool -help
nebula-tool -version
```

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

## Common Flags

- `-in PATH` reads input from `PATH`; use `-` for stdin.
- `-out PATH` writes output to `PATH`; use `-` for stdout.
- `-force` overwrites an existing output file.
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
