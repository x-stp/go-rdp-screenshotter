// RDP Screenshotter Go - Capture screenshots from RDP servers
// Copyright (C) 2025 - Pepijn van der Stap, pepijn@neosecurity.nl
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package rdp

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
)

// Security Exchange PDU (MS-RDPBCGR 2.2.1.10)
type SecurityExchangePDU struct {
	Flags           uint32
	ClientRandom    []byte // 32 bytes for standard RDP security
	EncryptedRandom []byte // Encrypted with server's public key
}

// SecurityData holds security-related information
type SecurityData struct {
	ServerRandom      []byte
	ServerCertificate []byte
	EncryptionMethod  uint32
	EncryptionLevel   uint32
	ServerPublicKey   []byte
}

// SessionKeys holds the derived session keys
type SessionKeys struct {
	SigningKey []byte
	EncryptKey []byte
	DecryptKey []byte
	UpdateKey  []byte
	MACKey     []byte
	MACKey64   []byte
}

// buildSecurityExchangePDU creates a Client Security Exchange PDU
func buildSecurityExchangePDU(serverSecurityData *SecurityData) ([]byte, []byte, error) {
	buf := new(bytes.Buffer)

	// Basic TS_SECURITY_HEADER (MS-RDPBCGR 2.2.8.1.1.2.1)
	binary.Write(buf, binary.LittleEndian, uint16(SEC_EXCHANGE_PKT)) // flags
	binary.Write(buf, binary.LittleEndian, uint16(0))                // flagsHi

	// Generate client random (32 bytes)
	clientRandom := make([]byte, 32)
	if _, err := rand.Read(clientRandom); err != nil {
		return nil, nil, fmt.Errorf("failed to generate client random: %w", err)
	}

	if serverSecurityData.EncryptionMethod == ENCRYPTION_METHOD_NONE {
		// TS_SECURITY_PACKET (MS-RDPBCGR 2.2.1.10.1)
		binary.Write(buf, binary.LittleEndian, uint32(32)) // Length
		buf.Write(clientRandom)
	} else { /*  @TODO [!] parse x.509, serverSecurityData.ServerCertificate
		this'll be RSA -- PKCS1v15/OAEP [BER]..
		-  enc clientRandom w/ RSA public key */
		binary.Write(buf, binary.LittleEndian, uint32(32))
		buf.Write(clientRandom)
	}

	return buf.Bytes(), clientRandom, nil
}

// deriveSessionKeys derives session keys from client and server randoms
// MS-RDPBCGR section 5.3.5
func deriveSessionKeys(clientRandom, serverRandom []byte, encryptionMethod uint32) (*SessionKeys, error) {
	// Concatenate client and server randoms
	preMasterSecret := append(clientRandom, serverRandom...)

	// Derive master secret
	masterSecret := saltedHash(preMasterSecret, []byte("A"), clientRandom, serverRandom)
	masterSecret = append(masterSecret, saltedHash(preMasterSecret, []byte("BB"), clientRandom, serverRandom)...)
	masterSecret = append(masterSecret, saltedHash(preMasterSecret, []byte("CCC"), clientRandom, serverRandom)...)

	// Derive session key
	sessionKeyBlob := saltedHash(masterSecret, []byte("X"), clientRandom, serverRandom)
	sessionKeyBlob = append(sessionKeyBlob, saltedHash(masterSecret, []byte("YY"), clientRandom, serverRandom)...)
	sessionKeyBlob = append(sessionKeyBlob, saltedHash(masterSecret, []byte("ZZZ"), clientRandom, serverRandom)...)

	keys := &SessionKeys{}

	// Determine key lengths based on encryption method
	var macKeyLen, keyLen int
	switch encryptionMethod {
	case ENCRYPTION_METHOD_40BIT:
		macKeyLen = 8
		keyLen = 8
	case ENCRYPTION_METHOD_56BIT:
		macKeyLen = 8
		keyLen = 8
	case ENCRYPTION_METHOD_128BIT:
		macKeyLen = 16
		keyLen = 16
	case ENCRYPTION_METHOD_FIPS:
		macKeyLen = 16
		keyLen = 16
	default:
		return nil, fmt.Errorf("unsupported encryption method: 0x%08X", encryptionMethod)
	}

	// Extract keys from session key blob
	offset := 0
	keys.MACKey = sessionKeyBlob[offset : offset+macKeyLen]
	offset += macKeyLen

	if encryptionMethod == ENCRYPTION_METHOD_FIPS {
		// FIPS uses different key derivation
		keys.EncryptKey = sessionKeyBlob[offset : offset+keyLen]
		offset += keyLen
		keys.DecryptKey = sessionKeyBlob[offset : offset+keyLen]
	} else {
		// Non-FIPS methods use the same key for encrypt/decrypt
		keys.EncryptKey = sessionKeyBlob[offset : offset+keyLen]
		keys.DecryptKey = keys.EncryptKey
	}

	// For 40-bit and 56-bit encryption, reduce key strength
	if encryptionMethod == ENCRYPTION_METHOD_40BIT {
		// Set first 3 bytes to 0xD1269E for 40-bit
		keys.EncryptKey[0] = 0xD1
		keys.EncryptKey[1] = 0x26
		keys.EncryptKey[2] = 0x9E
		keys.DecryptKey[0] = 0xD1
		keys.DecryptKey[1] = 0x26
		keys.DecryptKey[2] = 0x9E
	} else if encryptionMethod == ENCRYPTION_METHOD_56BIT {
		// Set first byte to 0xD1 for 56-bit
		keys.EncryptKey[0] = 0xD1
		keys.DecryptKey[0] = 0xD1
	}

	// Generate update key
	keys.UpdateKey = make([]byte, keyLen)
	copy(keys.UpdateKey, keys.EncryptKey)

	// Generate MAC key for 64-bit if needed
	if macKeyLen == 8 {
		keys.MACKey64 = make([]byte, 8)
		copy(keys.MACKey64, keys.MACKey)
	}

	return keys, nil
}

// saltedHash implements the SaltedHash function from MS-RDPBCGR 5.3.5.1
func saltedHash(secret, salt, input1, input2 []byte) []byte {
	// SHA1(salt + SHA1(input1 + secret + input2))
	sha1Hash := sha1.New()

	// Inner hash: SHA1(input1 + secret + input2)
	sha1Hash.Write(input1)
	sha1Hash.Write(secret)
	sha1Hash.Write(input2)
	innerHash := sha1Hash.Sum(nil)

	// Outer hash: SHA1(salt + innerHash)
	sha1Hash.Reset()
	sha1Hash.Write(salt)
	sha1Hash.Write(innerHash)

	// Return first 16 bytes
	result := sha1Hash.Sum(nil)
	if len(result) > 16 {
		return result[:16]
	}
	return result
}

// RC4Encryptor handles RC4 encryption for RDP
type RC4Encryptor struct {
	cipher *rc4.Cipher
}

// NewRC4Encryptor creates a new RC4 encryptor with the given key
func NewRC4Encryptor(key []byte) (*RC4Encryptor, error) {
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &RC4Encryptor{cipher: cipher}, nil
}

// Encrypt encrypts data in place
func (e *RC4Encryptor) Encrypt(data []byte) {
	e.cipher.XORKeyStream(data, data)
}

// Decrypt decrypts data in place (RC4 is symmetric)
func (e *RC4Encryptor) Decrypt(data []byte) {
	e.cipher.XORKeyStream(data, data)
}

// UpdateSessionKey updates the session key (MS-RDPBCGR 5.3.5.2)
func UpdateSessionKey(currentKey, updateKey []byte) []byte {
	sha1Hash := sha1.New()
	md5Hash := md5.New()

	// SHA1(updateKey + pad1 + currentKey)
	sha1Hash.Write(updateKey)
	sha1Hash.Write(pad1[:len(updateKey)])
	sha1Hash.Write(currentKey)
	sha1Result := sha1Hash.Sum(nil)

	// MD5(updateKey + pad2 + SHA1Result)
	md5Hash.Write(updateKey)
	md5Hash.Write(pad2[:len(updateKey)])
	md5Hash.Write(sha1Result)
	md5Result := md5Hash.Sum(nil)

	// RC4(key = md5Result)
	rc4Cipher, _ := rc4.NewCipher(md5Result)
	// @TODO proper rework.
	// even tho RC4 already broken.. this still deserves love.
	newKey := make([]byte, len(currentKey))
	rc4Cipher.XORKeyStream(newKey, currentKey)

	return newKey
}

// Padding constants for key updates
var (
	pad1 = []byte{
		0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
		0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
		0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
		0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
		0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	}
	pad2 = []byte{
		0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
		0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
		0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
		0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
		0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C, 0x5C,
	}
)

// Security constants from MS-RDPBCGR
const (
	// Security header flags
	SEC_EXCHANGE_PKT    = 0x0001
	SEC_ENCRYPT         = 0x0008
	SEC_RESET_SEQNO     = 0x0010
	SEC_IGNORE_SEQNO    = 0x0020
	SEC_INFO_PKT        = 0x0040
	SEC_LICENSE_PKT     = 0x0080
	SEC_LICENSE_ENCRYPT = 0x0200
	SEC_REDIRECTION_PKT = 0x0400
	SEC_SECURE_CHECKSUM = 0x0800
	SEC_AUTODETECT_REQ  = 0x1000
	SEC_AUTODETECT_RSP  = 0x2000
	SEC_HEARTBEAT       = 0x4000
	SEC_FLAGSHI_VALID   = 0x8000
)
