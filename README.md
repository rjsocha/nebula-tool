# nebula-tool

`nebula-tool` is a small CLI that fills operational gaps around Nebula CA key
handling that `nebula-cert` does not cover directly. Its primary uses are:

- **sign Nebula host certificates through `ssh-agent`**, so the CA private key is
  supplied by the agent at signing time and is not read from disk
- **encrypt and decrypt Nebula CA/signing private keys** at rest

It also handles a few smaller key and certificate chores:

- export a Nebula CA/signing key (Ed25519 or P256) as an OpenSSH private key
  (to load into `ssh-agent` for the signing workflow above)
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

Sign a Nebula host certificate using a CA key available through `ssh-agent`,
on either an Ed25519 (`ssh-ed25519`) or P256 (`ecdsa-sha2-nistp256`) CA:

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

Both Ed25519 and P256 Nebula CA certificates are supported. The host keypair
is generated on the CA's curve, an Ed25519 CA signs through the agent's
`ssh-ed25519` key, and a P256 CA through its `ecdsa-sha2-nistp256` key. Use
`key export` to load either CA key into `ssh-agent`.

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

Export a Nebula CA/signing key as an OpenSSH private key. Ed25519 keys export
as `ssh-ed25519`, P256 keys as `ecdsa-sha2-nistp256`:

```bash
nebula-tool key export -in ca.key -out ca.ssh.key
nebula-tool key export -in ca.enc.key -out ca.ssh.key -password env:NEBULA_CA_PASSWORD
```

Only CA/signing keys are supported; host (`pki.key`) keys are rejected.

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

## Hardware-Backed Keys

`nebula-tool` is agnostic to where the CA key lives. It signs through whatever
identity `ssh-agent` exposes, as long as that identity is a standard
`ssh-ed25519` or `ecdsa-sha2-nistp256` key and the agent returns a standard
signature. A hardware token works today provided it presents such a key, for
example a YubiKey OpenPGP applet via `gpg-agent`. The key must have been
imported onto the token after its `ca.crt` was created in software: the tool
has no command to create a CA certificate, so a key generated on the device and
never extractable cannot bootstrap its own `ca.crt` here. The tool has no
token-specific code of its own, and the supported key types are exactly those
Nebula itself uses.

FIDO2 security-key identities (`sk-ssh-ed25519@openssh.com`,
`sk-ecdsa-sha2-nistp256@openssh.com`) are **not** supported. Their signatures
carry a FIDO envelope (flags and counter) instead of a plain signature over the
certificate, so they never match Nebula's verification, and the agent-key
lookup reports no matching key.

Native FIDO support is a plausible future direction but is out of scope for
this tool: it would require extending Nebula's certificate format and
verification in upstream `slackhq/nebula`, not changes here. A separate,
PKCS#11-backed CA signing path already exists in upstream `nebula-cert`
(P256 only).

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
