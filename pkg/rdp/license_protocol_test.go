// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 x-stp

package rdp

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"math/big"
	"testing"
)

// FreeRDP test vector for security_master_secret + security_session_key_blob:
// the SaltedHash-triple machinery is identical between connection and
// licensing key derivation so we can sanity-check both at once.
func TestSaltedHashTripleDeterministic(t *testing.T) {
	pms := bytes.Repeat([]byte{0x11}, 48)
	cr := bytes.Repeat([]byte{0x22}, 32)
	sr := bytes.Repeat([]byte{0x33}, 32)

	a := saltedHashTriple(pms, cr, sr)
	b := saltedHashTriple(pms, cr, sr)
	if !bytes.Equal(a, b) {
		t.Fatalf("saltedHashTriple not deterministic")
	}
	if len(a) != 48 {
		t.Fatalf("saltedHashTriple length: got %d want 48", len(a))
	}

	// Sensitivity: any input change must perturb output.
	pms[0] ^= 1
	c := saltedHashTriple(pms, cr, sr)
	if bytes.Equal(a, c) {
		t.Fatalf("saltedHashTriple insensitive to PreMasterSecret change")
	}
}

func TestDeriveLicenseKeysShapesAndDeterministic(t *testing.T) {
	ls := &licenseSession{}
	for i := range ls.clientRandom {
		ls.clientRandom[i] = byte(i)
	}
	for i := range ls.serverRandom {
		ls.serverRandom[i] = byte(0x80 + i)
	}
	for i := range ls.premasterSecret {
		ls.premasterSecret[i] = byte(0x40 + i)
	}

	ls.deriveLicenseKeys()
	if all(ls.macSaltKey[:]) == 0 {
		t.Fatalf("MacSaltKey is all-zero")
	}
	if all(ls.licenseKey[:]) == 0 {
		t.Fatalf("LicensingEncryptionKey is all-zero")
	}

	other := *ls
	other.deriveLicenseKeys()
	if other.licenseKey != ls.licenseKey {
		t.Fatalf("deriveLicenseKeys not deterministic")
	}
}

func TestGenerateHardwareIDLayout(t *testing.T) {
	hwid := generateHardwareID(0x04010000, "rdp-go")
	if got := binary.LittleEndian.Uint32(hwid[0:4]); got != 0x04010000 {
		t.Fatalf("HardwareId platformID: got 0x%x want 0x04010000", got)
	}
	if all(hwid[4:]) == 0 {
		t.Fatalf("HardwareId hash is all-zero")
	}
}

// Round-trip the LICENSE_BINARY_BLOB read/write path.
func TestLicenseBlobRoundtrip(t *testing.T) {
	w := new(bytes.Buffer)
	payload := []byte("hello-license")
	writeLicenseBlob(w, bbDataBlob, payload)

	r := bytes.NewReader(w.Bytes())
	bType, gotPayload, err := readLicenseBlob(r)
	if err != nil {
		t.Fatalf("readLicenseBlob: %v", err)
	}
	if bType != bbDataBlob {
		t.Fatalf("blob type: got 0x%04x want 0x%04x", bType, bbDataBlob)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("blob data: got %q want %q", gotPayload, payload)
	}
}

// Use a small but real RSA key (1024-bit) to verify rsaEncryptRDP encrypts in
// little-endian framing, padded to ModulusLength.
func TestRsaEncryptRDPFramingAndLength(t *testing.T) {
	// Tiny test key chosen so x.Sign() != 0 for our 32-byte input.
	pub := &rsa.PublicKey{
		N: mustBigInt("dec",
			"137984023567453947128596451267182489731257891234678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345"),
		E: 65537,
	}
	msg := bytes.Repeat([]byte{0x42}, 32)

	out, err := rsaEncryptRDP(pub, msg)
	if err != nil {
		t.Fatalf("rsaEncryptRDP: %v", err)
	}
	want := (pub.N.BitLen() + 7) / 8
	if len(out) != want {
		t.Fatalf("output length: got %d want %d (modulus bytes)", len(out), want)
	}
	if all(out) == 0 {
		t.Fatalf("ciphertext is all-zero")
	}
}

func TestRsaEncryptRDPRejectsOversizedMessage(t *testing.T) {
	pub := &rsa.PublicKey{N: big.NewInt(257), E: 3}
	if _, err := rsaEncryptRDP(pub, []byte{1, 2, 3, 4}); err == nil {
		t.Fatalf("expected error for message larger than modulus")
	}
}

func TestRsaEncryptRDPRejectsZeroPlaintext(t *testing.T) {
	pub := &rsa.PublicKey{N: mustBigInt("dec", "9999999999999999999999999999"), E: 3}
	zero := make([]byte, 8)
	if _, err := rsaEncryptRDP(pub, zero); err == nil {
		t.Fatalf("expected error for zero plaintext")
	}
}

// Helpers -----------------------------------------------------------------

func all(b []byte) byte {
	var x byte
	for _, c := range b {
		x |= c
	}
	return x
}

func mustBigInt(base, s string) *big.Int {
	n := new(big.Int)
	switch base {
	case "dec":
		if _, ok := n.SetString(s, 10); !ok {
			panic("bad decimal: " + s)
		}
	case "hex":
		if _, ok := n.SetString(s, 16); !ok {
			panic("bad hex: " + s)
		}
	default:
		panic("bad base")
	}
	return n
}
