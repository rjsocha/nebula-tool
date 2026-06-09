package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"strings"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/term"
)

var version = "dev"

const stdioPath = "-"

func main() {
	err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage(os.Stderr)
		return fmt.Errorf("no command provided")
	}

	switch args[0] {
	case "-version", "--version", "version":
		fmt.Println(version)
		return nil
	case "-h", "-help", "--help", "help":
		usage(os.Stdout)
		return nil
	case "key":
		return runKey(args[1:])
	case "cert":
		return runCert(args[1:])
	default:
		usage(os.Stderr)
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

func usage(out io.Writer) {
	fmt.Fprintln(out, "Usage: nebula-tool [global flags] <command> <subcommand> [flags]")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Global flags:")
	fmt.Fprintln(out, "  -help       show help")
	fmt.Fprintln(out, "  -version    print version")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Commands:")
	fmt.Fprintln(out, "  key public    derive a public key from a private key")
	fmt.Fprintln(out, "  key encrypt   encrypt a plaintext CA/signing private key")
	fmt.Fprintln(out, "  key decrypt   decrypt an encrypted CA/signing private key")
	fmt.Fprintln(out, "  cert public   extract a public key from a certificate")
}

func runKey(args []string) error {
	if len(args) == 0 {
		keyUsage(os.Stderr)
		return fmt.Errorf("no key subcommand provided")
	}
	switch args[0] {
	case "-h", "-help", "--help", "help":
		keyUsage(os.Stdout)
		return nil
	case "public":
		return keyPublic(args[1:])
	case "encrypt":
		return keyEncrypt(args[1:])
	case "decrypt":
		return keyDecrypt(args[1:])
	default:
		keyUsage(os.Stderr)
		return fmt.Errorf("unknown key subcommand: %s", args[0])
	}
}

func keyUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage: nebula-tool key <subcommand> [flags]")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Subcommands:")
	fmt.Fprintln(out, "  public    derive a public key from a private key")
	fmt.Fprintln(out, "  encrypt   encrypt a plaintext CA/signing private key")
	fmt.Fprintln(out, "  decrypt   decrypt an encrypted CA/signing private key")
}

func runCert(args []string) error {
	if len(args) == 0 {
		certUsage(os.Stderr)
		return fmt.Errorf("no cert subcommand provided")
	}
	switch args[0] {
	case "-h", "-help", "--help", "help":
		certUsage(os.Stdout)
		return nil
	case "public":
		return certPublic(args[1:])
	default:
		certUsage(os.Stderr)
		return fmt.Errorf("unknown cert subcommand: %s", args[0])
	}
}

func certUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage: nebula-tool cert <subcommand> [flags]")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Subcommands:")
	fmt.Fprintln(out, "  public    extract a public key from a certificate")
}

func keyPublic(args []string) error {
	fs := flag.NewFlagSet("key public", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	in := fs.String("in", "", "Required: private key path, or - for stdin")
	out := fs.String("out", "", "Required: public key output path, or - for stdout")
	password := fs.String("password", "", "Password source for encrypted CA keys: env:NAME or file:PATH")
	force := fs.Bool("force", false, "Overwrite output file if it exists")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("-in is required")
	}
	if *out == "" {
		return fmt.Errorf("-out is required")
	}
	if *in == stdioPath && *out == stdioPath {
		return fmt.Errorf("-in and -out cannot both be %q", stdioPath)
	}

	raw, err := readPath(*in)
	if err != nil {
		return fmt.Errorf("error while reading -in: %w", err)
	}
	pub, err := publicFromPrivatePEM(raw, *password)
	if err != nil {
		return err
	}
	return writePath(*out, pub, 0600, *force)
}

func keyEncrypt(args []string) error {
	fs := flag.NewFlagSet("key encrypt", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	in := fs.String("in", "", "Required: plaintext CA/signing private key path, or - for stdin")
	out := fs.String("out", "", "Required: encrypted CA/signing private key output path, or - for stdout")
	password := fs.String("password", "", "Password source: env:NAME or file:PATH")
	force := fs.Bool("force", false, "Overwrite output file if it exists")
	argonMemory := fs.Uint("argon-memory", 2*1024*1024, "Argon2 memory parameter in KiB")
	argonParallelism := fs.Uint("argon-parallelism", 4, "Argon2 parallelism parameter")
	argonIterations := fs.Uint("argon-iterations", 1, "Argon2 iterations parameter")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("-in is required")
	}
	if *out == "" {
		return fmt.Errorf("-out is required")
	}
	if *in == stdioPath && *out == stdioPath {
		return fmt.Errorf("-in and -out cannot both be %q", stdioPath)
	}

	raw, err := readPath(*in)
	if err != nil {
		return fmt.Errorf("error while reading -in: %w", err)
	}
	key, rest, curve, err := cert.UnmarshalSigningPrivateKeyFromPEM(raw)
	if err != nil {
		if _, _, _, hostErr := cert.UnmarshalPrivateKeyFromPEM(raw); hostErr == nil {
			return fmt.Errorf("host keys cannot be encrypted for Nebula pki.key; only CA/signing keys are supported")
		}
		return fmt.Errorf("input is not a plaintext Nebula CA/signing private key: %w", err)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return fmt.Errorf("input contains trailing data after the first PEM block")
	}

	params, err := parseArgonParameters(*argonMemory, *argonParallelism, *argonIterations)
	if err != nil {
		return err
	}
	passphrase, err := getPassphrase(*password, true)
	if err != nil {
		return err
	}
	encrypted, err := cert.EncryptAndMarshalSigningPrivateKey(curve, key, passphrase, params)
	if err != nil {
		return fmt.Errorf("error while encrypting key: %w", err)
	}
	return writePath(*out, encrypted, 0600, *force)
}

func keyDecrypt(args []string) error {
	fs := flag.NewFlagSet("key decrypt", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	in := fs.String("in", "", "Required: encrypted CA/signing private key path, or - for stdin")
	out := fs.String("out", "", "Required: plaintext CA/signing private key output path, or - for stdout")
	password := fs.String("password", "", "Password source: env:NAME or file:PATH")
	force := fs.Bool("force", false, "Overwrite output file if it exists")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("-in is required")
	}
	if *out == "" {
		return fmt.Errorf("-out is required")
	}
	if *in == stdioPath && *out == stdioPath {
		return fmt.Errorf("-in and -out cannot both be %q", stdioPath)
	}

	raw, err := readPath(*in)
	if err != nil {
		return fmt.Errorf("error while reading -in: %w", err)
	}
	passphrase, err := getPassphrase(*password, false)
	if err != nil {
		return err
	}
	curve, key, rest, err := cert.DecryptAndUnmarshalSigningPrivateKey(passphrase, raw)
	if err != nil {
		return fmt.Errorf("error while decrypting CA/signing private key: %w", err)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return fmt.Errorf("input contains trailing data after the first PEM block")
	}
	return writePath(*out, cert.MarshalSigningPrivateKeyToPEM(curve, key), 0600, *force)
}

func certPublic(args []string) error {
	fs := flag.NewFlagSet("cert public", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	in := fs.String("in", "", "Required: certificate path, or - for stdin")
	out := fs.String("out", "", "Required: public key output path, or - for stdout")
	force := fs.Bool("force", false, "Overwrite output file if it exists")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("-in is required")
	}
	if *out == "" {
		return fmt.Errorf("-out is required")
	}
	if *in == stdioPath && *out == stdioPath {
		return fmt.Errorf("-in and -out cannot both be %q", stdioPath)
	}

	raw, err := readPath(*in)
	if err != nil {
		return fmt.Errorf("error while reading -in: %w", err)
	}
	crt, rest, err := cert.UnmarshalCertificateFromPEM(raw)
	if err != nil {
		return fmt.Errorf("error while unmarshaling certificate: %w", err)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return fmt.Errorf("input contains trailing data after the first PEM block")
	}
	return writePath(*out, crt.MarshalPublicKeyPEM(), 0600, *force)
}

func publicFromPrivatePEM(raw []byte, passwordSource string) ([]byte, error) {
	if key, rest, curve, err := cert.UnmarshalPrivateKeyFromPEM(raw); err == nil {
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("input contains trailing data after the first PEM block")
		}
		pub, err := deriveHostPublic(curve, key)
		if err != nil {
			return nil, err
		}
		return cert.MarshalPublicKeyToPEM(curve, pub), nil
	}

	key, rest, curve, err := cert.UnmarshalSigningPrivateKeyFromPEM(raw)
	if err == nil {
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("input contains trailing data after the first PEM block")
		}
		pub, err := deriveSigningPublic(curve, key)
		if err != nil {
			return nil, err
		}
		return cert.MarshalSigningPublicKeyToPEM(curve, pub), nil
	}

	if errors.Is(err, cert.ErrPrivateKeyEncrypted) {
		passphrase, passErr := getPassphrase(passwordSource, false)
		if passErr != nil {
			return nil, passErr
		}
		curve, key, rest, err = cert.DecryptAndUnmarshalSigningPrivateKey(passphrase, raw)
		if err != nil {
			return nil, fmt.Errorf("error while decrypting CA/signing private key: %w", err)
		}
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("input contains trailing data after the first PEM block")
		}
		pub, err := deriveSigningPublic(curve, key)
		if err != nil {
			return nil, err
		}
		return cert.MarshalSigningPublicKeyToPEM(curve, pub), nil
	}

	return nil, fmt.Errorf("input is not a supported Nebula private key")
}

func deriveHostPublic(curve cert.Curve, key []byte) ([]byte, error) {
	switch curve {
	case cert.Curve_CURVE25519:
		pub, err := curve25519.X25519(key, curve25519.Basepoint)
		if err != nil {
			return nil, fmt.Errorf("invalid X25519 private key: %w", err)
		}
		return pub, nil
	case cert.Curve_P256:
		priv, err := ecdh.P256().NewPrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("invalid P256 private key: %w", err)
		}
		return priv.PublicKey().Bytes(), nil
	default:
		return nil, fmt.Errorf("invalid curve: %s", curve)
	}
}

func deriveSigningPublic(curve cert.Curve, key []byte) ([]byte, error) {
	switch curve {
	case cert.Curve_CURVE25519:
		if len(key) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid Ed25519 private key")
		}
		return ed25519.PrivateKey(key).Public().(ed25519.PublicKey), nil
	case cert.Curve_P256:
		priv, err := ecdh.P256().NewPrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("invalid ECDSA P256 private key: %w", err)
		}
		return priv.PublicKey().Bytes(), nil
	default:
		return nil, fmt.Errorf("invalid curve: %s", curve)
	}
}

func parseArgonParameters(memory, parallelism, iterations uint) (*cert.Argon2Parameters, error) {
	if memory == 0 || memory > math.MaxUint32 {
		return nil, fmt.Errorf("-argon-memory must be greater than 0 and no more than %d KiB", uint32(math.MaxUint32))
	}
	if parallelism == 0 || parallelism > math.MaxUint8 {
		return nil, fmt.Errorf("-argon-parallelism must be greater than 0 and no more than %d", math.MaxUint8)
	}
	if iterations == 0 || iterations > math.MaxUint32 {
		return nil, fmt.Errorf("-argon-iterations must be greater than 0 and no more than %d", uint32(math.MaxUint32))
	}
	return cert.NewArgon2Parameters(uint32(memory), uint8(parallelism), uint32(iterations)), nil
}

func getPassphrase(source string, confirm bool) ([]byte, error) {
	passphrase, err := readPassphraseSource(source)
	if err != nil {
		return nil, err
	}
	if source != "" {
		if len(passphrase) == 0 {
			return nil, fmt.Errorf("empty password refused")
		}
		return passphrase, nil
	}

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, fmt.Errorf("password required; use -password env:NAME or -password file:PATH")
	}
	first, err := readPassword("Enter password: ")
	if err != nil {
		return nil, err
	}
	if len(first) == 0 {
		return nil, fmt.Errorf("empty password refused")
	}
	if !confirm {
		return first, nil
	}
	second, err := readPassword("Confirm password: ")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(first, second) {
		return nil, fmt.Errorf("passwords did not match")
	}
	return first, nil
}

func readPassphraseSource(source string) ([]byte, error) {
	if source == "" {
		return nil, nil
	}
	if name, ok := strings.CutPrefix(source, "env:"); ok {
		if name == "" {
			return nil, fmt.Errorf("empty env password source")
		}
		return []byte(os.Getenv(name)), nil
	}
	if path, ok := strings.CutPrefix(source, "file:"); ok {
		if path == "" {
			return nil, fmt.Errorf("empty file password source")
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("error while reading password file: %w", err)
		}
		return bytes.TrimRight(b, "\r\n"), nil
	}
	return nil, fmt.Errorf("unsupported password source %q; use env:NAME or file:PATH", source)
}

func readPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("error reading password: %w", err)
	}
	return b, nil
}

func readPath(path string) ([]byte, error) {
	if path == stdioPath {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func writePath(path string, data []byte, perm os.FileMode, force bool) error {
	if path == stdioPath {
		_, err := os.Stdout.Write(data)
		return err
	}
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("empty output path")
	}
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("refusing to overwrite existing file: %s", path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return os.WriteFile(path, data, perm)
}
