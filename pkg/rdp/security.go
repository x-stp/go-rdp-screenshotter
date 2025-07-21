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
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package rdp

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
)

// SecurityData holds security-related information
type SecurityData struct {
	ServerRandom     []byte
	ServerPublicKey  *rsa.PublicKey
	EncryptionMethod uint32
	EncryptionLevel  uint32
}

// SessionKeys holds the derived session keys
type SessionKeys struct {
	EncryptKey []byte
	DecryptKey []byte
	MACKey     []byte
}

// buildSecurityExchangePDU creates a Client Security Exchange PDU.
func buildSecurityExchangePDU(serverSecurityData *SecurityData) ([]byte, []byte, error) {
	clientRandom := make([]byte, 32)
	if _, err := rand.Read(clientRandom); err != nil {
		return nil, nil, fmt.Errorf("failed to generate client random: %w", err)
	}

	if serverSecurityData.ServerPublicKey == nil {
		return nil, nil, fmt.Errorf("cannot perform security exchange without server public key")
	}

	encryptedRandom, err := rsa.EncryptPKCS1v15(rand.Reader, serverSecurityData.ServerPublicKey, clientRandom)
	if err != nil {
		return nil, nil, fmt.Errorf("RSA encrypt client random failed: %w", err)
	}

	// Per MS-RDPBCGR section 5.3.3.1, the encrypted random must be byte-reversed for transport.
	for i, j := 0, len(encryptedRandom)-1; i < j; i, j = i+1, j-1 {
		encryptedRandom[i], encryptedRandom[j] = encryptedRandom[j], encryptedRandom[i]
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(len(encryptedRandom)))
	buf.Write(encryptedRandom)

	return buf.Bytes(), clientRandom, nil
}

// deriveSessionKeys derives session keys from client and server randoms
func deriveSessionKeys(clientRandom, serverRandom []byte, encryptionMethod uint32) (*SessionKeys, error) {
	preMasterSecret := append(clientRandom, serverRandom...)
	masterSecret := saltedHash(preMasterSecret, []byte("A"), clientRandom, serverRandom)
	masterSecret = append(masterSecret, saltedHash(preMasterSecret, []byte("BB"), clientRandom, serverRandom)...)
	masterSecret = append(masterSecret, saltedHash(preMasterSecret, []byte("CCC"), clientRandom, serverRandom)...)

	sessionKeyBlob := saltedHash(masterSecret, []byte("X"), clientRandom, serverRandom)
	sessionKeyBlob = append(sessionKeyBlob, saltedHash(masterSecret, []byte("YY"), clientRandom, serverRandom)...)
	sessionKeyBlob = append(sessionKeyBlob, saltedHash(masterSecret, []byte("ZZZ"), clientRandom, serverRandom)...)

	keys := &SessionKeys{}
	var macKeyLen, keyLen int
	switch encryptionMethod {
	case ENCRYPTION_METHOD_40BIT, ENCRYPTION_METHOD_56BIT:
		macKeyLen, keyLen = 8, 8
	case ENCRYPTION_METHOD_128BIT, ENCRYPTION_METHOD_FIPS:
		macKeyLen, keyLen = 16, 16
	default:
		return nil, fmt.Errorf("unsupported encryption method: 0x%08X", encryptionMethod)
	}

	keys.MACKey = sessionKeyBlob[:macKeyLen]
	keys.EncryptKey = sessionKeyBlob[macKeyLen : macKeyLen+keyLen]
	keys.DecryptKey = sessionKeyBlob[macKeyLen+keyLen : macKeyLen+keyLen*2]

	if encryptionMethod == ENCRYPTION_METHOD_40BIT {
		make40Bit(keys.EncryptKey)
		make40Bit(keys.DecryptKey)
	}
	return keys, nil
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

func make40Bit(key []byte) {
	key[0] = 0xd1
	key[1] = 0x26
	key[2] = 0x9e
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

func (e *RC4Encryptor) Encrypt(data []byte) {
	e.cipher.XORKeyStream(data, data)
}

func (e *RC4Encryptor) Decrypt(data []byte) {
	e.cipher.XORKeyStream(data, data)
}

// Security constants
const (
	SEC_EXCHANGE_PKT = 0x0001
	SEC_ENCRYPT      = 0x0008
	SEC_LICENSE_PKT  = 0x0080
)
