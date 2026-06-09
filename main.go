package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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
		usage(os.Stdout)
		return nil
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
	case "sign":
		return runSign(args[1:])
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
	fmt.Fprintln(out, "  key export    export an Ed25519 CA/signing key as an OpenSSH private key")
	fmt.Fprintln(out, "  cert public   extract a public key from a certificate")
	fmt.Fprintln(out, "  sign ssh      sign using an SSH agent")
}

func runKey(args []string) error {
	if len(args) == 0 {
		keyUsage(os.Stdout)
		return nil
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
	case "export":
		return keyExport(args[1:])
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
	fmt.Fprintln(out, "  export    export an Ed25519 CA/signing key as an OpenSSH private key")
}

func runCert(args []string) error {
	if len(args) == 0 {
		certUsage(os.Stdout)
		return nil
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

func runSign(args []string) error {
	if len(args) == 0 {
		signUsage(os.Stdout)
		return nil
	}
	switch args[0] {
	case "-h", "-help", "--help", "help":
		signUsage(os.Stdout)
		return nil
	case "ssh":
		return signSSH(args[1:])
	default:
		signUsage(os.Stderr)
		return fmt.Errorf("unknown sign subcommand: %s", args[0])
	}
}

func signUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage: nebula-tool sign <subcommand> [flags]")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Subcommands:")
	fmt.Fprintln(out, "  ssh    sign using an SSH agent")
}

func signSSHUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage: nebula-tool sign ssh [flags]")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Modes:")
	fmt.Fprintln(out, "  nebula-tool sign ssh -test -ca-crt ca.crt")
	fmt.Fprintln(out, "  nebula-tool sign ssh -ca-crt ca.crt -name host1 -networks 10.10.10.1/24 -out-key host1.key -out-crt host1.crt")
	fmt.Fprintln(out, "  nebula-tool sign ssh -ca-crt ca.crt -name host1 -networks 10.10.10.1/24 -in-pub host1.pub -out-crt host1.crt")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Common flags:")
	fmt.Fprintln(out, "  -agent-sock path")
	fmt.Fprintln(out, "  -ca-crt path")
	fmt.Fprintln(out, "  -duration duration")
	fmt.Fprintln(out, "  -groups group1,group2")
	fmt.Fprintln(out, "  -in-pub path")
	fmt.Fprintln(out, "  -name name")
	fmt.Fprintln(out, "  -networks cidr[,cidr]")
	fmt.Fprintln(out, "  -out-crt path")
	fmt.Fprintln(out, "  -out-key path")
	fmt.Fprintln(out, "  -test")
	fmt.Fprintln(out, "  -unsafe-networks cidr[,cidr]")
	fmt.Fprintln(out, "  -version 1|2")
}

func keyPublic(args []string) error {
	fs := flag.NewFlagSet("key public", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	in := fs.String("in", "", "Required: private key path, or - for stdin")
	out := fs.String("out", "", "Required: public key output path, or - for stdout")
	password := fs.String("password", "", "Password source for encrypted CA keys: env:NAME or file:PATH")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateInOut(*in, *out); err != nil {
		return err
	}

	raw, err := readPath(*in)
	if err != nil {
		return fmt.Errorf("error while reading -in: %w", err)
	}
	pub, err := publicFromPrivatePEM(raw, *password)
	if err != nil {
		return err
	}
	return writePath(*out, pub, 0600)
}

func signSSH(args []string) error {
	if len(args) == 0 {
		signSSHUsage(os.Stdout)
		return nil
	}
	for _, arg := range args {
		if arg == "-h" || arg == "-help" || arg == "--help" || arg == "help" {
			signSSHUsage(os.Stdout)
			return nil
		}
	}
	fs := flag.NewFlagSet("sign ssh", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	test := fs.Bool("test", false, "Run SSH agent connectivity and signing test")
	agentSock := fs.String("agent-sock", "", "Optional: ssh-agent unix socket path. Defaults to SSH_AUTH_SOCK")
	versionFlag := fs.Uint("version", 0, "Optional: version of the certificate format to use. The default is to match the signing CA")
	caCertPath := fs.String("ca-crt", "ca.crt", "Optional: path to the signing CA cert")
	name := fs.String("name", "", "Required: name of the cert, usually a hostname")
	networks := fs.String("networks", "", "Required: comma separated list of ip address and network in CIDR notation to assign to this cert")
	unsafeNetworks := fs.String("unsafe-networks", "", "Optional: comma separated list of ip address and network in CIDR notation. Unsafe networks this cert can route for")
	duration := fs.Duration("duration", 0, "Optional: how long the cert should be valid for. The default is 1 second before the signing cert expires")
	inPubPath := fs.String("in-pub", "", "Optional (if out-key not set): path to read a previously generated public key")
	outKeyPath := fs.String("out-key", "", "Optional (if in-pub not set): path to write the private key to")
	outCertPath := fs.String("out-crt", "", "Optional: path to write the certificate to")
	groupsFlag := fs.String("groups", "", "Optional: comma separated list of groups")
	ip := fs.String("ip", "", "Deprecated, see -networks")
	subnets := fs.String("subnets", "", "Deprecated, see -unsafe-networks")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caCertPath == "" {
		return fmt.Errorf("-ca-crt is required")
	}

	caCert, err := readCACert(*caCertPath)
	if err != nil {
		return err
	}
	if caCert.Curve() != cert.Curve_CURVE25519 {
		return fmt.Errorf("ssh-agent signing currently supports only Ed25519 Nebula CA certificates")
	}

	signer, agentKey, sshPub, closeAgent, err := sshAgentSignerForCA(caCert, *agentSock)
	if err != nil {
		return err
	}
	defer closeAgent()
	if *test {
		return signSSHTest(caCert, signer, agentKey, sshPub)
	}

	if *name == "" {
		return fmt.Errorf("-name is required")
	}
	if *networks == "" && *ip != "" {
		*networks = *ip
	}
	if *networks == "" {
		return fmt.Errorf("-networks is required")
	}
	if *unsafeNetworks == "" && *subnets != "" {
		*unsafeNetworks = *subnets
	}
	if *inPubPath != "" && *outKeyPath != "" {
		return fmt.Errorf("cannot set both -in-pub and -out-key")
	}
	if *outKeyPath == "" {
		*outKeyPath = *name + ".key"
	}
	if *outCertPath == "" {
		*outCertPath = *name + ".crt"
	}
	if *inPubPath == "" && *outKeyPath != stdioPath && *outKeyPath == *outCertPath {
		return fmt.Errorf("-out-key and -out-crt must be different paths")
	}

	version := cert.Version(*versionFlag)
	if version != 0 && version != cert.Version1 && version != cert.Version2 {
		return fmt.Errorf("-version must be either %v or %v", cert.Version1, cert.Version2)
	}
	if version == 0 {
		version = caCert.Version()
	}
	if caCert.Expired(time.Now()) {
		return fmt.Errorf("ca certificate is expired")
	}
	if *duration <= 0 {
		*duration = time.Until(caCert.NotAfter()) - time.Second
	}
	if *duration <= 0 {
		return fmt.Errorf("-duration must be greater than 0")
	}

	v4Networks, v6Networks, err := parseNetworkFlag("-networks", *networks)
	if err != nil {
		return err
	}
	v4UnsafeNetworks, v6UnsafeNetworks, err := parseNetworkFlag("-unsafe-networks", *unsafeNetworks)
	if err != nil {
		return err
	}
	groups := parseGroups(*groupsFlag)

	var pub, rawPriv []byte
	if *inPubPath != "" {
		rawPub, err := readPath(*inPubPath)
		if err != nil {
			return fmt.Errorf("error while reading -in-pub: %w", err)
		}
		var pubCurve cert.Curve
		pub, _, pubCurve, err = cert.UnmarshalPublicKeyFromPEM(rawPub)
		if err != nil {
			return fmt.Errorf("error while parsing -in-pub: %w", err)
		}
		if pubCurve != caCert.Curve() {
			return fmt.Errorf("curve of -in-pub does not match ca")
		}
	} else {
		pub, rawPriv, err = x25519Keypair()
		if err != nil {
			return err
		}
	}

	if err := refuseExisting(*outCertPath, "cert"); err != nil {
		return err
	}
	if *inPubPath == "" {
		if err := refuseExisting(*outKeyPath, "key"); err != nil {
			return err
		}
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(*duration)
	var networksForCert []netip.Prefix
	var unsafeNetworksForCert []netip.Prefix

	switch version {
	case cert.Version1:
		if len(v4Networks) != 1 {
			return fmt.Errorf("invalid -networks definition: v1 certificates can only have a single ipv4 address")
		}
		if len(v6Networks) > 0 {
			return fmt.Errorf("invalid -networks definition: v1 certificates can only contain ipv4 addresses")
		}
		if len(v6UnsafeNetworks) > 0 {
			return fmt.Errorf("invalid -unsafe-networks definition: v1 certificates can only contain ipv4 addresses")
		}
		networksForCert = []netip.Prefix{v4Networks[0]}
		unsafeNetworksForCert = v4UnsafeNetworks
	case cert.Version2:
		networksForCert = append(v4Networks, v6Networks...)
		unsafeNetworksForCert = append(v4UnsafeNetworks, v6UnsafeNetworks...)
	default:
		return fmt.Errorf("invalid version: %d", version)
	}

	t := &cert.TBSCertificate{
		Version:        version,
		Name:           *name,
		Networks:       networksForCert,
		Groups:         groups,
		UnsafeNetworks: unsafeNetworksForCert,
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		PublicKey:      pub,
		IsCA:           false,
		Curve:          caCert.Curve(),
	}

	nc, err := t.SignWith(caCert, caCert.Curve(), signer)
	if err != nil {
		return fmt.Errorf("error while signing with ssh-agent: %w", err)
	}
	if !nc.CheckSignature(caCert.PublicKey()) {
		return fmt.Errorf("produced certificate signature does not verify against CA public key")
	}
	certPEM, err := nc.MarshalPEM()
	if err != nil {
		return fmt.Errorf("error while marshalling certificate: %w", err)
	}
	if *inPubPath == "" {
		if err := writePath(*outKeyPath, cert.MarshalPrivateKeyToPEM(caCert.Curve(), rawPriv), 0600); err != nil {
			return fmt.Errorf("error while writing -out-key: %w", err)
		}
	}
	if err := writePath(*outCertPath, certPEM, 0600); err != nil {
		// The cert failed to write after the private key landed on disk. Remove the
		// freshly written key so a secret is never left behind without its cert.
		if *inPubPath == "" && *outKeyPath != stdioPath {
			_ = os.Remove(*outKeyPath)
		}
		return fmt.Errorf("error while writing -out-crt: %w", err)
	}
	return nil
}

func readCACert(path string) (cert.Certificate, error) {
	raw, err := readPath(path)
	if err != nil {
		return nil, fmt.Errorf("error while reading -ca-crt: %w", err)
	}
	caCert, rest, err := cert.UnmarshalCertificateFromPEM(raw)
	if err != nil {
		return nil, fmt.Errorf("error while unmarshaling CA certificate: %w", err)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("input contains trailing data after the first PEM block")
	}
	if !caCert.IsCA() {
		return nil, fmt.Errorf("-ca-crt is not a CA certificate")
	}
	return caCert, nil
}

func sshAgentSignerForCA(caCert cert.Certificate, agentSock string) (cert.SignerLambda, *agent.Key, ssh.PublicKey, func(), error) {
	sshPub, err := ssh.NewPublicKey(ed25519.PublicKey(caCert.PublicKey()))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("error converting CA public key to SSH format: %w", err)
	}

	agentClient, conn, err := sshAgentClient(agentSock)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	closeAgent := func() { _ = conn.Close() }

	keys, err := agentClient.List()
	if err != nil {
		closeAgent()
		return nil, nil, nil, nil, fmt.Errorf("error listing ssh-agent keys: %w", err)
	}
	var agentKey *agent.Key
	for _, k := range keys {
		if bytes.Equal(k.Marshal(), sshPub.Marshal()) {
			agentKey = k
			break
		}
	}
	if agentKey == nil {
		closeAgent()
		return nil, nil, nil, nil, fmt.Errorf("ssh-agent does not have the key matching CA certificate public key %s", ssh.FingerprintSHA256(sshPub))
	}

	signer := func(certBytes []byte) ([]byte, error) {
		sig, err := agentClient.Sign(agentKey, certBytes)
		if err != nil {
			return nil, fmt.Errorf("ssh-agent signing failed: %w", err)
		}
		if sig.Format != ssh.KeyAlgoED25519 {
			return nil, fmt.Errorf("unexpected ssh signature format: %s", sig.Format)
		}
		return sig.Blob, nil
	}
	return signer, agentKey, sshPub, closeAgent, nil
}

func signSSHTest(caCert cert.Certificate, signer cert.SignerLambda, agentKey *agent.Key, sshPub ssh.PublicKey) error {
	testData := []byte("nebula-tool ssh-agent signing test")
	sig, err := signer(testData)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(caCert.PublicKey()), testData, sig) {
		return fmt.Errorf("ssh-agent signature did not verify against CA certificate public key")
	}

	fmt.Printf("ok ssh-agent key=%s comment=%q signature=%d bytes\n", ssh.FingerprintSHA256(sshPub), agentKey.Comment, len(sig))
	return nil
}

func parseNetworkFlag(flagName, value string) ([]netip.Prefix, []netip.Prefix, error) {
	var v4 []netip.Prefix
	var v6 []netip.Prefix
	if value == "" {
		return v4, v6, nil
	}
	for _, raw := range strings.Split(value, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid %s definition: %s", flagName, raw)
		}
		if prefix.Addr().Is4() {
			v4 = append(v4, prefix)
		} else {
			v6 = append(v6, prefix)
		}
	}
	return v4, v6, nil
}

func parseGroups(value string) []string {
	if value == "" {
		return nil
	}
	var groups []string
	for _, raw := range strings.Split(value, ",") {
		raw = strings.TrimSpace(raw)
		if raw != "" {
			groups = append(groups, raw)
		}
	}
	return groups
}

func validateInOut(in, out string) error {
	if in == "" {
		return fmt.Errorf("-in is required")
	}
	if out == "" {
		return fmt.Errorf("-out is required")
	}
	if in != stdioPath && in == out {
		return fmt.Errorf("-in and -out must be different paths")
	}
	return nil
}

func refuseExisting(path, kind string) error {
	if path == stdioPath {
		return nil
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("refusing to overwrite existing %s: %s", kind, path)
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func x25519Keypair() ([]byte, []byte, error) {
	priv := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, priv); err != nil {
		return nil, nil, fmt.Errorf("error while generating private key: %w", err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("error while generating public key: %w", err)
	}
	return pub, priv, nil
}

func keyEncrypt(args []string) error {
	fs := flag.NewFlagSet("key encrypt", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	in := fs.String("in", "", "Required: plaintext CA/signing private key path, or - for stdin")
	out := fs.String("out", "", "Required: encrypted CA/signing private key output path, or - for stdout")
	password := fs.String("password", "", "Password source: env:NAME or file:PATH")
	argonMemory := fs.Uint("argon-memory", 2*1024*1024, "Argon2 memory parameter in KiB")
	argonParallelism := fs.Uint("argon-parallelism", 4, "Argon2 parallelism parameter")
	argonIterations := fs.Uint("argon-iterations", 1, "Argon2 iterations parameter")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateInOut(*in, *out); err != nil {
		return err
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
	return writePath(*out, encrypted, 0600)
}

func keyDecrypt(args []string) error {
	fs := flag.NewFlagSet("key decrypt", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	in := fs.String("in", "", "Required: encrypted CA/signing private key path, or - for stdin")
	out := fs.String("out", "", "Required: plaintext CA/signing private key output path, or - for stdout")
	password := fs.String("password", "", "Password source: env:NAME or file:PATH")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateInOut(*in, *out); err != nil {
		return err
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
	return writePath(*out, cert.MarshalSigningPrivateKeyToPEM(curve, key), 0600)
}

func keyExport(args []string) error {
	fs := flag.NewFlagSet("key export", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	in := fs.String("in", "", "Required: CA/signing private key path, or - for stdin")
	out := fs.String("out", "", "Required: OpenSSH private key output path, or - for stdout")
	password := fs.String("password", "", "Password source for encrypted CA keys: env:NAME or file:PATH")
	comment := fs.String("comment", "nebula ca", "OpenSSH private key comment")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateInOut(*in, *out); err != nil {
		return err
	}

	raw, err := readPath(*in)
	if err != nil {
		return fmt.Errorf("error while reading -in: %w", err)
	}

	key, curve, err := signingPrivateKeyFromPEM(raw, *password)
	if err != nil {
		return err
	}
	if curve != cert.Curve_CURVE25519 {
		return fmt.Errorf("only Ed25519 CA/signing keys can be exported to OpenSSH private key format")
	}
	if len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid Ed25519 private key")
	}

	block, err := ssh.MarshalPrivateKey(ed25519.PrivateKey(key), *comment)
	if err != nil {
		return fmt.Errorf("error while marshaling OpenSSH private key: %w", err)
	}
	return writePath(*out, pem.EncodeToMemory(block), 0600)
}

func certPublic(args []string) error {
	fs := flag.NewFlagSet("cert public", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	in := fs.String("in", "", "Required: certificate path, or - for stdin")
	out := fs.String("out", "", "Required: public key output path, or - for stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := validateInOut(*in, *out); err != nil {
		return err
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
	return writePath(*out, crt.MarshalPublicKeyPEM(), 0600)
}

func signingPrivateKeyFromPEM(raw []byte, passwordSource string) ([]byte, cert.Curve, error) {
	key, rest, curve, err := cert.UnmarshalSigningPrivateKeyFromPEM(raw)
	if err == nil {
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, 0, fmt.Errorf("input contains trailing data after the first PEM block")
		}
		return key, curve, nil
	}
	if errors.Is(err, cert.ErrPrivateKeyEncrypted) {
		passphrase, passErr := getPassphrase(passwordSource, false)
		if passErr != nil {
			return nil, 0, passErr
		}
		curve, key, rest, err = cert.DecryptAndUnmarshalSigningPrivateKey(passphrase, raw)
		if err != nil {
			return nil, 0, fmt.Errorf("error while decrypting CA/signing private key: %w", err)
		}
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, 0, fmt.Errorf("input contains trailing data after the first PEM block")
		}
		return key, curve, nil
	}
	if _, _, _, hostErr := cert.UnmarshalPrivateKeyFromPEM(raw); hostErr == nil {
		return nil, 0, fmt.Errorf("host keys cannot be exported as OpenSSH CA/signing keys")
	}
	return nil, 0, fmt.Errorf("input is not a Nebula CA/signing private key: %w", err)
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

func sshAgentClient(sock string) (agent.ExtendedAgent, net.Conn, error) {
	if sock == "" {
		sock = os.Getenv("SSH_AUTH_SOCK")
	}
	if sock == "" {
		return nil, nil, fmt.Errorf("ssh-agent socket not provided; set SSH_AUTH_SOCK or use -agent-sock")
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, nil, fmt.Errorf("error connecting to ssh-agent: %w", err)
	}
	return agent.NewClient(conn), conn, nil
}

func readPath(path string) ([]byte, error) {
	if path == stdioPath {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func writePath(path string, data []byte, perm os.FileMode) error {
	if path == stdioPath {
		_, err := os.Stdout.Write(data)
		return err
	}
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("empty output path")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("refusing to overwrite existing file: %s", path)
		}
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
