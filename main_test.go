package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// --- pure helpers -----------------------------------------------------------

func TestValidateInOut(t *testing.T) {
	cases := []struct {
		name    string
		in, out string
		wantErr bool
	}{
		{"both paths", "a", "b", false},
		{"stdin to stdout", "-", "-", false},
		{"file to stdout", "a", "-", false},
		{"stdin to file", "-", "b", false},
		{"empty in", "", "b", true},
		{"empty out", "a", "", true},
		{"same file path", "a", "a", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateInOut(tc.in, tc.out)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateInOut(%q,%q) err=%v wantErr=%v", tc.in, tc.out, err, tc.wantErr)
			}
		})
	}
}

func TestParseNetworkFlag(t *testing.T) {
	v4, v6, err := parseNetworkFlag("-networks", " 10.0.0.1/24 , , fd00::1/64 ,192.168.0.1/16")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(v4) != 2 {
		t.Fatalf("expected 2 v4 prefixes, got %d", len(v4))
	}
	if len(v6) != 1 {
		t.Fatalf("expected 1 v6 prefix, got %d", len(v6))
	}

	if v4, v6, err := parseNetworkFlag("-networks", ""); err != nil || v4 != nil || v6 != nil {
		t.Fatalf("empty input should yield nil slices and no error, got v4=%v v6=%v err=%v", v4, v6, err)
	}

	if _, _, err := parseNetworkFlag("-networks", "not-a-cidr"); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestParseGroups(t *testing.T) {
	if g := parseGroups(""); g != nil {
		t.Fatalf("empty groups should be nil, got %v", g)
	}
	g := parseGroups(" admin , , ops ")
	if len(g) != 2 || g[0] != "admin" || g[1] != "ops" {
		t.Fatalf("unexpected groups: %v", g)
	}
}

func TestParseArgonParameters(t *testing.T) {
	if _, err := parseArgonParameters(1024, 4, 1); err != nil {
		t.Fatalf("valid params rejected: %v", err)
	}
	for _, tc := range []struct{ mem, par, iter uint }{
		{0, 4, 1},
		{1024, 0, 1},
		{1024, 4, 0},
		{1024, 256, 1}, // parallelism > MaxUint8
	} {
		if _, err := parseArgonParameters(tc.mem, tc.par, tc.iter); err == nil {
			t.Fatalf("expected error for params %+v", tc)
		}
	}
}

func TestReadPassphraseSource(t *testing.T) {
	t.Setenv("NT_TEST_PW", "hunter2")
	if b, err := readPassphraseSource("env:NT_TEST_PW"); err != nil || string(b) != "hunter2" {
		t.Fatalf("env source: got %q err=%v", b, err)
	}

	dir := t.TempDir()
	pwFile := filepath.Join(dir, "pw")
	if err := os.WriteFile(pwFile, []byte("filepass\n\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if b, err := readPassphraseSource("file:" + pwFile); err != nil || string(b) != "filepass" {
		t.Fatalf("file source should trim trailing newlines: got %q err=%v", b, err)
	}

	if b, err := readPassphraseSource(""); err != nil || b != nil {
		t.Fatalf("empty source should yield nil: got %q err=%v", b, err)
	}
	for _, src := range []string{"env:", "file:", "bogus:x"} {
		if _, err := readPassphraseSource(src); err == nil {
			t.Fatalf("expected error for source %q", src)
		}
	}
}

// --- public key derivation round-trips --------------------------------------

func TestPublicFromPrivatePEM(t *testing.T) {
	t.Run("host x25519", func(t *testing.T) {
		pub, priv, err := x25519Keypair()
		if err != nil {
			t.Fatal(err)
		}
		raw := cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, priv)
		gotPEM, err := publicFromPrivatePEM(raw, "")
		if err != nil {
			t.Fatal(err)
		}
		want := cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, pub)
		if !bytes.Equal(gotPEM, want) {
			t.Fatalf("derived host public key mismatch")
		}
	})

	t.Run("host p256", func(t *testing.T) {
		k, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		raw := cert.MarshalPrivateKeyToPEM(cert.Curve_P256, k.Bytes())
		gotPEM, err := publicFromPrivatePEM(raw, "")
		if err != nil {
			t.Fatal(err)
		}
		want := cert.MarshalPublicKeyToPEM(cert.Curve_P256, k.PublicKey().Bytes())
		if !bytes.Equal(gotPEM, want) {
			t.Fatalf("derived host p256 public key mismatch")
		}
	})

	t.Run("ca ed25519", func(t *testing.T) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		raw := cert.MarshalSigningPrivateKeyToPEM(cert.Curve_CURVE25519, priv)
		gotPEM, err := publicFromPrivatePEM(raw, "")
		if err != nil {
			t.Fatal(err)
		}
		want := cert.MarshalSigningPublicKeyToPEM(cert.Curve_CURVE25519, pub)
		if !bytes.Equal(gotPEM, want) {
			t.Fatalf("derived ca ed25519 public key mismatch")
		}
	})

	t.Run("encrypted ca ed25519", func(t *testing.T) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		params := cert.NewArgon2Parameters(64*1024, 4, 1)
		enc, err := cert.EncryptAndMarshalSigningPrivateKey(cert.Curve_CURVE25519, priv, []byte("pw"), params)
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("NT_ENC_PW", "pw")
		if _, err := publicFromPrivatePEM(enc, "env:NT_ENC_PW"); err != nil {
			t.Fatalf("encrypted key derivation failed: %v", err)
		}
		if _, err := publicFromPrivatePEM(enc, "env:WRONG_NAME_UNSET"); err == nil {
			t.Fatal("expected error with empty/wrong password")
		}
	})

	t.Run("garbage", func(t *testing.T) {
		if _, err := publicFromPrivatePEM([]byte("not a pem"), ""); err == nil {
			t.Fatal("expected error for non-PEM input")
		}
	})
}

// --- end-to-end command tests -----------------------------------------------

// runCapture runs the CLI with the given stdin, capturing stdout.
func runCapture(t *testing.T, stdin []byte, args ...string) ([]byte, error) {
	t.Helper()
	oldIn, oldOut := os.Stdin, os.Stdout
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin, os.Stdout = inR, outW
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut }()

	go func() {
		_, _ = inW.Write(stdin)
		_ = inW.Close()
	}()
	done := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(outR)
		done <- b
	}()

	runErr := run(args)
	_ = outW.Close()
	out := <-done
	_ = inR.Close()
	_ = outR.Close()
	return out, runErr
}

func TestKeyEncryptDecryptRoundTrip(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plainPath := filepath.Join(dir, "ca.key")
	encPath := filepath.Join(dir, "ca.enc.key")
	outPath := filepath.Join(dir, "ca.out.key")
	plainPEM := cert.MarshalSigningPrivateKeyToPEM(cert.Curve_CURVE25519, priv)
	if err := os.WriteFile(plainPath, plainPEM, 0600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("NT_PW", "correct horse")
	if _, err := runCapture(t, nil, "key", "encrypt", "-in", plainPath, "-out", encPath,
		"-password", "env:NT_PW", "-argon-memory", "65536"); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if _, err := runCapture(t, nil, "key", "decrypt", "-in", encPath, "-out", outPath,
		"-password", "env:NT_PW"); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plainPEM) {
		t.Fatal("decrypted key does not match original plaintext")
	}

	// wrong password must fail
	if _, err := runCapture(t, nil, "key", "decrypt", "-in", encPath,
		"-out", filepath.Join(dir, "nope.key"), "-password", "env:NT_PW_UNSET"); err == nil {
		t.Fatal("decrypt with empty password should fail")
	}
}

func TestKeyEncryptRejectsHostKey(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := x25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(dir, "host.key")
	if err := os.WriteFile(in, cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, priv), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NT_PW", "x")
	_, err = runCapture(t, nil, "key", "encrypt", "-in", in, "-out", filepath.Join(dir, "out"), "-password", "env:NT_PW")
	if err == nil {
		t.Fatal("encrypting a host key should be refused")
	}
}

func TestKeyExport(t *testing.T) {
	dir := t.TempDir()

	t.Run("ed25519 ok", func(t *testing.T) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		in := filepath.Join(dir, "ca.key")
		out := filepath.Join(dir, "ca.ssh.key")
		if err := os.WriteFile(in, cert.MarshalSigningPrivateKeyToPEM(cert.Curve_CURVE25519, priv), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := runCapture(t, nil, "key", "export", "-in", in, "-out", out); err != nil {
			t.Fatalf("export failed: %v", err)
		}
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(b, []byte("-----BEGIN OPENSSH PRIVATE KEY-----")) {
			t.Fatalf("output is not an OpenSSH private key: %s", b[:min(40, len(b))])
		}
	})

	t.Run("host key rejected", func(t *testing.T) {
		_, priv, err := x25519Keypair()
		if err != nil {
			t.Fatal(err)
		}
		in := filepath.Join(dir, "host2.key")
		if err := os.WriteFile(in, cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, priv), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := runCapture(t, nil, "key", "export", "-in", in, "-out", filepath.Join(dir, "x")); err == nil {
			t.Fatal("exporting a host key should be refused")
		}
	})

	t.Run("p256 ok", func(t *testing.T) {
		k, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		scalar := k.Bytes()
		in := filepath.Join(dir, "p256.key")
		out := filepath.Join(dir, "p256.ssh.key")
		if err := os.WriteFile(in, cert.MarshalSigningPrivateKeyToPEM(cert.Curve_P256, scalar), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := runCapture(t, nil, "key", "export", "-in", in, "-out", out); err != nil {
			t.Fatalf("export failed: %v", err)
		}
		parsed, err := ssh.ParseRawPrivateKey(mustRead(t, out))
		if err != nil {
			t.Fatalf("exported key is not a valid OpenSSH private key: %v", err)
		}
		ecPriv, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatalf("exported key is %T, want *ecdsa.PrivateKey", parsed)
		}
		if ecPriv.Curve != elliptic.P256() {
			t.Fatalf("exported key curve = %v, want P256", ecPriv.Curve)
		}
		wantPub, err := deriveSigningPublic(cert.Curve_P256, scalar)
		if err != nil {
			t.Fatal(err)
		}
		gotPub := elliptic.Marshal(elliptic.P256(), ecPriv.X, ecPriv.Y)
		if !bytes.Equal(gotPub, wantPub) {
			t.Fatal("exported OpenSSH key public point does not match the CA key")
		}
	})
}

func TestRefuseOverwrite(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := x25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(dir, "host.key")
	out := filepath.Join(dir, "host.pub")
	if err := os.WriteFile(in, cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, priv), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := runCapture(t, nil, "key", "public", "-in", in, "-out", out); err != nil {
		t.Fatalf("first write failed: %v", err)
	}
	if _, err := runCapture(t, nil, "key", "public", "-in", in, "-out", out); err == nil {
		t.Fatal("second write to existing path should be refused")
	}
}

func TestStdinToStdoutFilter(t *testing.T) {
	_, priv, err := x25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	in := cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, priv)
	out, err := runCapture(t, in, "key", "public", "-in", "-", "-out", "-")
	if err != nil {
		t.Fatalf("stdin->stdout filter failed: %v", err)
	}
	if _, _, _, err := cert.UnmarshalPublicKeyFromPEM(out); err != nil {
		t.Fatalf("stdout is not a valid public key PEM: %v", err)
	}
}

func TestCertPublic(t *testing.T) {
	dir := t.TempDir()
	caPEM, caPriv := newEd25519CA(t, cert.Version2)
	hostKey, hostCrt := signHostCert(t, dir, caPEM, caPriv, cert.Version2)
	_ = hostKey

	out := filepath.Join(dir, "host.pub")
	if _, err := runCapture(t, nil, "cert", "public", "-in", hostCrt, "-out", out); err != nil {
		t.Fatalf("cert public failed: %v", err)
	}
	if _, _, _, err := cert.UnmarshalPublicKeyFromPEM(mustRead(t, out)); err != nil {
		t.Fatalf("extracted public key invalid: %v", err)
	}
}

// --- sign ssh ---------------------------------------------------------------

func TestSignSSH(t *testing.T) {
	for _, version := range []cert.Version{cert.Version1, cert.Version2} {
		version := version
		t.Run(versionName(version), func(t *testing.T) {
			dir := t.TempDir()
			caPEM, caPriv := newEd25519CA(t, version)
			caCrt := filepath.Join(dir, "ca.crt")
			if err := os.WriteFile(caCrt, caPEM, 0600); err != nil {
				t.Fatal(err)
			}
			sock := startAgent(t, caPriv)

			outKey := filepath.Join(dir, "host.key")
			outCrt := filepath.Join(dir, "host.crt")
			if _, err := runCapture(t, nil, "sign", "ssh",
				"-agent-sock", sock, "-ca-crt", caCrt,
				"-name", "host1", "-networks", "10.10.10.1/24",
				"-out-key", outKey, "-out-crt", outCrt); err != nil {
				t.Fatalf("sign ssh failed: %v", err)
			}

			// the produced cert verifies against the CA public key and its
			// public key matches the generated private key
			crt, _, err := cert.UnmarshalCertificateFromPEM(mustRead(t, outCrt))
			if err != nil {
				t.Fatal(err)
			}
			caCert, _, err := cert.UnmarshalCertificateFromPEM(caPEM)
			if err != nil {
				t.Fatal(err)
			}
			if !crt.CheckSignature(caCert.PublicKey()) {
				t.Fatal("produced cert does not verify against CA")
			}
			key, _, curve, err := cert.UnmarshalPrivateKeyFromPEM(mustRead(t, outKey))
			if err != nil {
				t.Fatal(err)
			}
			derivedPub, err := deriveHostPublic(curve, key)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(derivedPub, crt.PublicKey()) {
				t.Fatal("cert public key does not match generated private key")
			}
		})
	}
}

func TestSignSSHTestMode(t *testing.T) {
	dir := t.TempDir()
	caPEM, caPriv := newEd25519CA(t, cert.Version2)
	caCrt := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caCrt, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	sock := startAgent(t, caPriv)

	if _, err := runCapture(t, nil, "sign", "ssh", "-test", "-agent-sock", sock, "-ca-crt", caCrt); err != nil {
		t.Fatalf("sign ssh -test failed: %v", err)
	}

	// agent without the matching key must fail
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherSock := startAgent(t, otherPriv)
	if _, err := runCapture(t, nil, "sign", "ssh", "-test", "-agent-sock", otherSock, "-ca-crt", caCrt); err == nil {
		t.Fatal("test mode should fail when agent lacks the CA key")
	}
}

func TestSignSSHWithInPub(t *testing.T) {
	dir := t.TempDir()
	caPEM, caPriv := newEd25519CA(t, cert.Version2)
	caCrt := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caCrt, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	sock := startAgent(t, caPriv)

	pub, _, err := x25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	inPub := filepath.Join(dir, "host.pub")
	if err := os.WriteFile(inPub, cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, pub), 0600); err != nil {
		t.Fatal(err)
	}
	outCrt := filepath.Join(dir, "host.crt")
	if _, err := runCapture(t, nil, "sign", "ssh", "-agent-sock", sock, "-ca-crt", caCrt,
		"-name", "host1", "-networks", "10.10.10.1/24", "-in-pub", inPub, "-out-crt", outCrt); err != nil {
		t.Fatalf("sign ssh -in-pub failed: %v", err)
	}
	crt, _, err := cert.UnmarshalCertificateFromPEM(mustRead(t, outCrt))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(crt.PublicKey(), pub) {
		t.Fatal("cert public key does not match -in-pub")
	}
	// no private key file should have been written
	if _, err := os.Stat(filepath.Join(dir, "host1.key")); err == nil {
		t.Fatal("unexpected private key written when -in-pub is used")
	}
}

func TestSignSSHP256(t *testing.T) {
	for _, version := range []cert.Version{cert.Version1, cert.Version2} {
		version := version
		t.Run(versionName(version), func(t *testing.T) {
			dir := t.TempDir()
			caPEM, caPriv := newP256CA(t, version)
			caCrt := filepath.Join(dir, "ca.crt")
			if err := os.WriteFile(caCrt, caPEM, 0600); err != nil {
				t.Fatal(err)
			}
			sock := startAgent(t, caPriv)

			outKey := filepath.Join(dir, "host.key")
			outCrt := filepath.Join(dir, "host.crt")
			if _, err := runCapture(t, nil, "sign", "ssh",
				"-agent-sock", sock, "-ca-crt", caCrt,
				"-name", "host1", "-networks", "10.10.10.1/24",
				"-out-key", outKey, "-out-crt", outCrt); err != nil {
				t.Fatalf("sign ssh failed: %v", err)
			}

			crt, _, err := cert.UnmarshalCertificateFromPEM(mustRead(t, outCrt))
			if err != nil {
				t.Fatal(err)
			}
			caCert, _, err := cert.UnmarshalCertificateFromPEM(caPEM)
			if err != nil {
				t.Fatal(err)
			}
			if !crt.CheckSignature(caCert.PublicKey()) {
				t.Fatal("produced cert does not verify against P256 CA")
			}
			if crt.Curve() != cert.Curve_P256 {
				t.Fatalf("host cert curve = %v, want P256", crt.Curve())
			}
			key, _, curve, err := cert.UnmarshalPrivateKeyFromPEM(mustRead(t, outKey))
			if err != nil {
				t.Fatal(err)
			}
			derivedPub, err := deriveHostPublic(curve, key)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(derivedPub, crt.PublicKey()) {
				t.Fatal("cert public key does not match generated private key")
			}
		})
	}
}

func TestSignSSHP256TestMode(t *testing.T) {
	dir := t.TempDir()
	caPEM, caPriv := newP256CA(t, cert.Version2)
	caCrt := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caCrt, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	sock := startAgent(t, caPriv)

	if _, err := runCapture(t, nil, "sign", "ssh", "-test", "-agent-sock", sock, "-ca-crt", caCrt); err != nil {
		t.Fatalf("sign ssh -test failed: %v", err)
	}

	// an agent without the matching P256 key must fail
	otherPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherSock := startAgent(t, otherPriv)
	if _, err := runCapture(t, nil, "sign", "ssh", "-test", "-agent-sock", otherSock, "-ca-crt", caCrt); err == nil {
		t.Fatal("test mode should fail when agent lacks the CA key")
	}
}

// --- test helpers -----------------------------------------------------------

func newEd25519CA(t *testing.T, version cert.Version) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tbs := &cert.TBSCertificate{
		Curve:     cert.Curve_CURVE25519,
		Version:   version,
		Name:      "test ca",
		NotBefore: time.Now().Add(-time.Hour).Round(time.Second),
		NotAfter:  time.Now().Add(time.Hour).Round(time.Second),
		PublicKey: pub,
		IsCA:      true,
	}
	c, err := tbs.Sign(nil, cert.Curve_CURVE25519, priv)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := c.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	return pem, priv
}

func newP256CA(t *testing.T, version cert.Version) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	privk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := elliptic.Marshal(elliptic.P256(), privk.PublicKey.X, privk.PublicKey.Y)
	priv := privk.D.FillBytes(make([]byte, 32))
	tbs := &cert.TBSCertificate{
		Curve:     cert.Curve_P256,
		Version:   version,
		Name:      "test ca p256",
		NotBefore: time.Now().Add(-time.Hour).Round(time.Second),
		NotAfter:  time.Now().Add(time.Hour).Round(time.Second),
		PublicKey: pub,
		IsCA:      true,
	}
	c, err := tbs.Sign(nil, cert.Curve_P256, priv)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := c.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	return pem, privk
}

// signHostCert produces a host key + cert via the CLI and returns their paths.
func signHostCert(t *testing.T, dir string, caPEM []byte, caPriv ed25519.PrivateKey, version cert.Version) (string, string) {
	t.Helper()
	caCrt := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caCrt, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	sock := startAgent(t, caPriv)
	outKey := filepath.Join(dir, "h.key")
	outCrt := filepath.Join(dir, "h.crt")
	if _, err := runCapture(t, nil, "sign", "ssh", "-agent-sock", sock, "-ca-crt", caCrt,
		"-name", "h", "-networks", "10.10.10.1/24", "-out-key", outKey, "-out-crt", outCrt); err != nil {
		t.Fatalf("signHostCert: %v", err)
	}
	return outKey, outCrt
}

// startAgent serves an in-process ssh-agent holding the given keys over a unix
// socket and returns the socket path. Keys may be any type ssh-agent accepts
// (e.g. ed25519.PrivateKey, *ecdsa.PrivateKey).
func startAgent(t *testing.T, keys ...any) string {
	t.Helper()
	dir := t.TempDir()
	sock := filepath.Join(dir, "a.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	kr := agent.NewKeyring()
	for _, k := range keys {
		if err := kr.Add(agent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatal(err)
		}
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(kr, conn) }()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return sock
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func versionName(v cert.Version) string {
	if v == cert.Version1 {
		return "v1"
	}
	return "v2"
}
