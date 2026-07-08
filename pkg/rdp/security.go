// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 x-stp

package rdp

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math/big"
	"slices"
)

type SecurityData struct {
	ServerRandom     []byte
	ServerPublicKey  *rsa.PublicKey
	EncryptionMethod uint32
	EncryptionLevel  uint32
}

type SessionKeys struct {
	EncryptKey []byte
	DecryptKey []byte
	MACKey     []byte
}

func buildSecurityExchangePDU(serverSecurityData *SecurityData) ([]byte, []byte, error) {
	clientRandom := make([]byte, 32)
	if _, err := rand.Read(clientRandom); err != nil {
		return nil, nil, fmt.Errorf("failed to generate client random: %w", err)
	}

	if serverSecurityData.ServerPublicKey == nil {
		return nil, nil, fmt.Errorf("cannot perform security exchange without server public key")
	}

	encryptedRandom, err := rsaEncryptRDP(serverSecurityData.ServerPublicKey, clientRandom)
	if err != nil {
		return nil, nil, fmt.Errorf("RSA encrypt client random failed: %w", err)
	}

	// [MS-RDPBCGR] §3.2.5.3.10: encrypted random + 8 trailing zero pad bytes.
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(len(encryptedRandom)+8))
	buf.Write(encryptedRandom)
	buf.Write(make([]byte, 8))
	return buf.Bytes(), clientRandom, nil
}

// deriveSessionKeys derives MAC, encrypt and decrypt keys per [MS-RDPBCGR]
// §5.3.5.1. PreMasterSecret = CR[0:24]||SR[0:24]; FinalHash(K) = MD5(K||CR||SR)
// wraps the encrypt and decrypt halves in client mode. 40-bit and 56-bit
// methods overwrite the leading 3 / 1 bytes with the {0xD1,0x26,0x9E} salt.
func deriveSessionKeys(clientRandom, serverRandom []byte, encryptionMethod uint32) (*SessionKeys, error) {
	if len(clientRandom) < 24 || len(serverRandom) < 24 {
		return nil, fmt.Errorf("client/server random too short: %d/%d", len(clientRandom), len(serverRandom))
	}
	preMasterSecret := make([]byte, 0, 48)
	preMasterSecret = append(preMasterSecret, clientRandom[:24]...)
	preMasterSecret = append(preMasterSecret, serverRandom[:24]...)

	masterSecret := make([]byte, 0, 48)
	masterSecret = append(masterSecret, saltedHash(preMasterSecret, []byte("A"), clientRandom, serverRandom)...)
	masterSecret = append(masterSecret, saltedHash(preMasterSecret, []byte("BB"), clientRandom, serverRandom)...)
	masterSecret = append(masterSecret, saltedHash(preMasterSecret, []byte("CCC"), clientRandom, serverRandom)...)

	sessionKeyBlob := make([]byte, 0, 48)
	sessionKeyBlob = append(sessionKeyBlob, saltedHash(masterSecret, []byte("X"), clientRandom, serverRandom)...)
	sessionKeyBlob = append(sessionKeyBlob, saltedHash(masterSecret, []byte("YY"), clientRandom, serverRandom)...)
	sessionKeyBlob = append(sessionKeyBlob, saltedHash(masterSecret, []byte("ZZZ"), clientRandom, serverRandom)...)

	keys := &SessionKeys{}
	keys.MACKey = append([]byte(nil), sessionKeyBlob[0:16]...)
	keys.DecryptKey = finalHash(sessionKeyBlob[16:32], clientRandom, serverRandom)
	keys.EncryptKey = finalHash(sessionKeyBlob[32:48], clientRandom, serverRandom)

	switch encryptionMethod {
	case ENCRYPTION_METHOD_40BIT:
		make40Bit(keys.MACKey)
		make40Bit(keys.DecryptKey)
		make40Bit(keys.EncryptKey)
	case ENCRYPTION_METHOD_56BIT:
		make56Bit(keys.MACKey)
		make56Bit(keys.DecryptKey)
		make56Bit(keys.EncryptKey)
	case ENCRYPTION_METHOD_128BIT:
	case ENCRYPTION_METHOD_FIPS:
		return nil, fmt.Errorf("ENCRYPTION_METHOD_FIPS not supported")
	default:
		return nil, fmt.Errorf("unsupported encryption method: 0x%08X", encryptionMethod)
	}
	return keys, nil
}

// finalHash = MD5(K || ClientRandom || ServerRandom) per [MS-RDPBCGR] §5.3.5.1.
func finalHash(k, clientRandom, serverRandom []byte) []byte {
	h := md5.New()
	h.Write(k)
	h.Write(clientRandom)
	h.Write(serverRandom)
	return h.Sum(nil)
}

func saltedHash(secret, salt, input1, input2 []byte) []byte {
	sha1Hash := sha1.New()
	sha1Hash.Write(salt)
	sha1Hash.Write(secret)
	sha1Hash.Write(input1)
	sha1Hash.Write(input2)
	md5Hash := md5.New()
	md5Hash.Write(secret)
	md5Hash.Write(sha1Hash.Sum(nil))
	return md5Hash.Sum(nil)
}

var rdpKeySalt = [3]byte{0xD1, 0x26, 0x9E}

func make40Bit(key []byte) {
	if len(key) >= 3 {
		copy(key[0:3], rdpKeySalt[:])
	}
}

func make56Bit(key []byte) {
	if len(key) >= 1 {
		key[0] = rdpKeySalt[0]
	}
}

// rsaEncryptRDP performs RDP's raw RSA per [MS-RDPBCGR] §5.3.4.1: msg is a
// little-endian integer, ciphertext is y = msg^e mod n returned zero-padded
// to the modulus length in little-endian. No PKCS#1 padding. Required because
// RDP exchange keys are 512-bit, which Go's crypto/rsa rejects.
func rsaEncryptRDP(pub *rsa.PublicKey, msg []byte) ([]byte, error) {
	keyLen := (pub.N.BitLen() + 7) / 8
	if len(msg) > keyLen {
		return nil, fmt.Errorf("rsa: message too long: %d > %d", len(msg), keyLen)
	}
	be := slices.Clone(msg)
	slices.Reverse(be)
	x := new(big.Int).SetBytes(be)
	if x.Sign() == 0 {
		return nil, fmt.Errorf("rsa: zero plaintext")
	}
	y := new(big.Int).Exp(x, big.NewInt(int64(pub.E)), pub.N)
	out := make([]byte, keyLen)
	yBytes := y.Bytes()
	copy(out[keyLen-len(yBytes):], yBytes)
	slices.Reverse(out)
	return out, nil
}

// Basic security header flags per [MS-RDPBCGR] §2.2.8.1.1.2.1.
const (
	SEC_EXCHANGE_PKT       uint16 = 0x0001
	SEC_TRANSPORT_REQ      uint16 = 0x0002
	SEC_TRANSPORT_RSP      uint16 = 0x0004
	SEC_ENCRYPT            uint16 = 0x0008
	SEC_RESET_SEQNO        uint16 = 0x0010
	SEC_IGNORE_SEQNO       uint16 = 0x0020
	SEC_INFO_PKT           uint16 = 0x0040
	SEC_LICENSE_PKT        uint16 = 0x0080
	SEC_LICENSE_ENCRYPT_CS uint16 = 0x0200
	SEC_LICENSE_ENCRYPT_SC uint16 = 0x0200
	SEC_REDIRECTION_PKT    uint16 = 0x0400
	SEC_SECURE_CHECKSUM    uint16 = 0x0800
	SEC_AUTODETECT_REQ     uint16 = 0x1000
	SEC_AUTODETECT_RSP     uint16 = 0x2000
	SEC_HEARTBEAT          uint16 = 0x4000
	SEC_FLAGSHI_VALID      uint16 = 0x8000
)

// rdpMacSignature is the Standard RDP Security MAC per [MS-RDPBCGR] §5.3.6.1
// (the unsalted form; §5.3.6.1.1 is the salted variant gated by
// SEC_SECURE_CHECKSUM): MAC = First64Bits(MD5(macSaltKey || pad2 ||
// SHA1(macSaltKey || pad1 || u32_le(len) || data))).
func rdpMacSignature(macSaltKey, data []byte) [16]byte {
	var pad1 [40]byte
	for i := range pad1 {
		pad1[i] = 0x36
	}
	var pad2 [48]byte
	for i := range pad2 {
		pad2[i] = 0x5C
	}

	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(data)))

	sha := sha1.New()
	sha.Write(macSaltKey)
	sha.Write(pad1[:])
	sha.Write(lenBuf[:])
	sha.Write(data)
	sum := sha.Sum(nil)

	md5h := md5.New()
	md5h.Write(macSaltKey)
	md5h.Write(pad2[:])
	md5h.Write(sum)

	var out [16]byte
	copy(out[:], md5h.Sum(nil))
	return out
}
