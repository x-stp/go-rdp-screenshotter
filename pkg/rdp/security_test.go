package rdp

import (
	"bytes"
	"testing"
)

func TestDeriveSessionKeys128BitShape(t *testing.T) {
	cr := bytes.Repeat([]byte{0xAA}, 32)
	sr := bytes.Repeat([]byte{0x55}, 32)

	keys, err := deriveSessionKeys(cr, sr, ENCRYPTION_METHOD_128BIT)
	if err != nil {
		t.Fatalf("deriveSessionKeys: %v", err)
	}
	if len(keys.MACKey) != 16 {
		t.Fatalf("MACKey length: got %d want 16", len(keys.MACKey))
	}
	if len(keys.EncryptKey) != 16 || len(keys.DecryptKey) != 16 {
		t.Fatalf("encrypt/decrypt key length: got %d/%d want 16/16", len(keys.EncryptKey), len(keys.DecryptKey))
	}
	if bytes.Equal(keys.EncryptKey, keys.DecryptKey) {
		t.Fatalf("encrypt and decrypt keys are identical")
	}
}

func TestDeriveSessionKeysDeterministic(t *testing.T) {
	cr := bytes.Repeat([]byte{0x01}, 32)
	sr := bytes.Repeat([]byte{0x02}, 32)
	a, _ := deriveSessionKeys(cr, sr, ENCRYPTION_METHOD_128BIT)
	b, _ := deriveSessionKeys(cr, sr, ENCRYPTION_METHOD_128BIT)
	if !bytes.Equal(a.EncryptKey, b.EncryptKey) ||
		!bytes.Equal(a.DecryptKey, b.DecryptKey) ||
		!bytes.Equal(a.MACKey, b.MACKey) {
		t.Fatalf("session key derivation non-deterministic")
	}
}

func TestDeriveSessionKeysShortRandomRejected(t *testing.T) {
	if _, err := deriveSessionKeys(make([]byte, 10), make([]byte, 32), ENCRYPTION_METHOD_128BIT); err == nil {
		t.Fatalf("expected error for short client random")
	}
}

func TestMake40BitSalt(t *testing.T) {
	k := make([]byte, 16)
	for i := range k {
		k[i] = 0xff
	}
	make40Bit(k)
	if k[0] != 0xD1 || k[1] != 0x26 || k[2] != 0x9E {
		t.Fatalf("make40Bit salt mismatch: got %02x %02x %02x want D1 26 9E", k[0], k[1], k[2])
	}
}

func TestRdpMacSignatureDeterministic(t *testing.T) {
	key := bytes.Repeat([]byte{0x10}, 16)
	data := []byte("payload-bytes")
	a := rdpMacSignature(key, data)
	b := rdpMacSignature(key, data)
	if a != b {
		t.Fatalf("rdpMacSignature non-deterministic")
	}
	if a == ([16]byte{}) {
		t.Fatalf("rdpMacSignature returned all-zero")
	}
}
