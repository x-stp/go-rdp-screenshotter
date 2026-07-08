// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 x-stp

package rdp

// This file implements the RDP licensing protocol per [MS-RDPELE]. The
// package doc comment lives in doc.go.

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
)

type licenseSession struct {
	clientRandom    [32]byte
	serverRandom    [32]byte
	premasterSecret [48]byte
	masterSecret    [48]byte
	sessionKeyBlob  [48]byte
	macSaltKey      [16]byte
	licenseKey      [16]byte
	hardwareID      [20]byte
	serverPubKey    *rsa.PublicKey
}

// LICENSE_BINARY_BLOB types per [MS-RDPBCGR] §2.2.1.12.1.2.
const (
	bbDataBlob              uint16 = 0x0001
	bbRandomBlob            uint16 = 0x0002
	bbCertificateBlob       uint16 = 0x0003
	bbErrorBlob             uint16 = 0x0004
	bbEncryptedDataBlob     uint16 = 0x0009
	bbKeyExchgAlgBlob       uint16 = 0x000D
	bbScopeBlob             uint16 = 0x000E
	bbClientUserNameBlob    uint16 = 0x000F
	bbClientMachineNameBlob uint16 = 0x0010
)

// MS-RDPELE constants.
const (
	keyExchangeAlgRSA  uint32 = 0x00000001
	platformIDWinPost  uint32 = 0x04010000 // CLIENT_OS_ID_WINNT_POST_52|CLIENT_IMAGE_ID_MICROSOFT
	pcrVersion         uint16 = 0x0100     // PLATFORM_CHALLENGE_RESPONSE_VERSION
	otherPlatformCType uint16 = 0xFF00     // OTHER_PLATFORM_CHALLENGE_TYPE
	licenseDetailLevel uint16 = 0x0003     // LICENSE_DETAIL_DETAIL
)

// parseServerLicenseRequest decodes SERVER_LICENSE_REQUEST per [MS-RDPELE]
// §2.2.2.1 (LICENSE_PREAMBLE already stripped) and returns ServerRandom and
// the embedded ServerCertificate.
func parseServerLicenseRequest(body []byte) (serverRandom []byte, serverCert []byte, err error) {
	if len(body) < 32 {
		return nil, nil, fmt.Errorf("license request too short for ServerRandom: %d", len(body))
	}
	serverRandom = body[0:32]
	r := bytes.NewReader(body[32:])

	// PRODUCT_INFO { dwVersion(4) cbCompanyName(4) pbCompanyName cbProductId(4) pbProductId }
	if r.Len() < 12 {
		return nil, nil, fmt.Errorf("license request truncated in ProductInfo")
	}
	r.Seek(4, 1)
	var cbCompanyName uint32
	binary.Read(r, binary.LittleEndian, &cbCompanyName)
	if uint32(r.Len()) < cbCompanyName+8 {
		return nil, nil, fmt.Errorf("license request: ProductInfo cbCompanyName=%d overflow", cbCompanyName)
	}
	r.Seek(int64(cbCompanyName), 1)
	var cbProductId uint32
	binary.Read(r, binary.LittleEndian, &cbProductId)
	if uint32(r.Len()) < cbProductId {
		return nil, nil, fmt.Errorf("license request: ProductInfo cbProductId=%d overflow", cbProductId)
	}
	r.Seek(int64(cbProductId), 1)

	if _, _, err := readLicenseBlob(r); err != nil {
		return nil, nil, fmt.Errorf("license request: KeyExchangeList: %w", err)
	}

	_, certData, err := readLicenseBlob(r)
	if err != nil {
		return nil, nil, fmt.Errorf("license request: ServerCertificate: %w", err)
	}
	serverCert = certData
	return serverRandom, serverCert, nil
}

func readLicenseBlob(r *bytes.Reader) (uint16, []byte, error) {
	if r.Len() < 4 {
		return 0, nil, fmt.Errorf("blob header truncated")
	}
	var bType, bLen uint16
	binary.Read(r, binary.LittleEndian, &bType)
	binary.Read(r, binary.LittleEndian, &bLen)
	if r.Len() < int(bLen) {
		return 0, nil, fmt.Errorf("blob data truncated: need %d have %d", bLen, r.Len())
	}
	data := make([]byte, bLen)
	r.Read(data)
	return bType, data, nil
}

func writeLicenseBlob(w *bytes.Buffer, bType uint16, data []byte) {
	binary.Write(w, binary.LittleEndian, bType)
	binary.Write(w, binary.LittleEndian, uint16(len(data)))
	w.Write(data)
}

func extractLicenseServerCertKey(certData []byte) (*rsa.PublicKey, error) {
	return parseServerCertificate(certData)
}

// deriveLicenseKeys derives MasterSecret, SessionKeyBlob, MacSaltKey and
// LicensingEncryptionKey per MS-RDPELE 5.1.4.
func (ls *licenseSession) deriveLicenseKeys() {
	master := saltedHashTriple(ls.premasterSecret[:], ls.clientRandom[:], ls.serverRandom[:])
	copy(ls.masterSecret[:], master)

	// MS-RDPELE 5.1.4: SessionKeyBlob uses (MS, ServerRandom, ClientRandom),
	// the reverse argument order of the connection key derivation.
	skb := saltedHashTriple(ls.masterSecret[:], ls.serverRandom[:], ls.clientRandom[:])
	copy(ls.sessionKeyBlob[:], skb)

	copy(ls.macSaltKey[:], ls.sessionKeyBlob[0:16])

	// LicensingEncryptionKey = MD5(SessionKeyBlob[16:32] || ClientRandom || ServerRandom)
	h := md5.New()
	h.Write(ls.sessionKeyBlob[16:32])
	h.Write(ls.clientRandom[:])
	h.Write(ls.serverRandom[:])
	copy(ls.licenseKey[:], h.Sum(nil))
}

// saltedHashTriple = SaltedHash("A") || SaltedHash("BB") || SaltedHash("CCC").
func saltedHashTriple(secret, r1, r2 []byte) []byte {
	out := make([]byte, 0, 48)
	out = append(out, saltedHash(secret, []byte("A"), r1, r2)...)
	out = append(out, saltedHash(secret, []byte("BB"), r1, r2)...)
	out = append(out, saltedHash(secret, []byte("CCC"), r1, r2)...)
	return out
}

// generateHardwareID = PlatformId (LE u32) || MD5(hostname).
// CLIENT_HARDWARE_ID per [MS-RDPELE] §2.2.2.3.1.
func generateHardwareID(platformID uint32, hostname string) [20]byte {
	var hwid [20]byte
	binary.LittleEndian.PutUint32(hwid[0:4], platformID)
	h := md5.New()
	h.Write([]byte(hostname))
	copy(hwid[4:], h.Sum(nil))
	return hwid
}

// buildNewLicenseRequest serialises CLIENT_NEW_LICENSE_REQUEST per
// [MS-RDPELE] §2.2.2.2 (LICENSE_PREAMBLE not included).
func buildNewLicenseRequest(ls *licenseSession, encryptedPMS []byte, modulusLen int, username, hostname string) []byte {
	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, keyExchangeAlgRSA)
	binary.Write(body, binary.LittleEndian, platformIDWinPost)
	body.Write(ls.clientRandom[:])

	// EncryptedPremasterSecret: BB_RANDOM_BLOB, wBlobLen = ModulusLength + 8,
	// data = encrypted PMS right-padded to ModulusLength then 8 zero bytes
	// per [MS-RDPELE] §2.2.2.2.
	binary.Write(body, binary.LittleEndian, bbRandomBlob)
	binary.Write(body, binary.LittleEndian, uint16(modulusLen+8))
	body.Write(encryptedPMS)
	body.Write(make([]byte, modulusLen+8-len(encryptedPMS)))

	user := append([]byte(username), 0)
	writeLicenseBlob(body, bbClientUserNameBlob, user)
	host := append([]byte(hostname), 0)
	writeLicenseBlob(body, bbClientMachineNameBlob, host)
	return body.Bytes()
}

func rc4Crypt(key, data []byte) []byte {
	c, _ := rc4.NewCipher(key)
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out
}

// buildPlatformChallengeResponse serialises CLIENT_PLATFORM_CHALLENGE_RESPONSE
// per [MS-RDPELE] §2.2.2.5 + §2.2.2.5.1, given the decrypted server challenge.
func buildPlatformChallengeResponse(ls *licenseSession, decryptedChallenge []byte) []byte {
	pcrd := new(bytes.Buffer)
	binary.Write(pcrd, binary.LittleEndian, pcrVersion)
	binary.Write(pcrd, binary.LittleEndian, otherPlatformCType)
	binary.Write(pcrd, binary.LittleEndian, licenseDetailLevel)
	binary.Write(pcrd, binary.LittleEndian, uint16(len(decryptedChallenge)))
	pcrd.Write(decryptedChallenge)
	pcrdBytes := pcrd.Bytes()

	macInput := make([]byte, 0, len(pcrdBytes)+20)
	macInput = append(macInput, pcrdBytes...)
	macInput = append(macInput, ls.hardwareID[:]...)
	mac := rdpMacSignature(ls.macSaltKey[:], macInput)

	body := new(bytes.Buffer)
	writeLicenseBlob(body, bbDataBlob, rc4Crypt(ls.licenseKey[:], pcrdBytes))
	writeLicenseBlob(body, bbEncryptedDataBlob, rc4Crypt(ls.licenseKey[:], ls.hardwareID[:]))
	body.Write(mac[:16])
	return body.Bytes()
}

// parsePlatformChallenge decrypts the EncryptedPlatformChallenge blob in
// SERVER_PLATFORM_CHALLENGE ([MS-RDPELE] §2.2.2.4). The MAC is not verified;
// the server only inspects the response, never our parse step.
func parsePlatformChallenge(ls *licenseSession, body []byte) ([]byte, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("platform challenge truncated in ConnectFlags")
	}
	r := bytes.NewReader(body[4:])
	_, encChallenge, err := readLicenseBlob(r)
	if err != nil {
		return nil, fmt.Errorf("EncryptedPlatformChallenge: %w", err)
	}
	if r.Len() < 16 {
		return nil, fmt.Errorf("MACData truncated")
	}
	return rc4Crypt(ls.licenseKey[:], encChallenge), nil
}

func generateLicenseRandoms(ls *licenseSession) error {
	if _, err := rand.Read(ls.clientRandom[:]); err != nil {
		return fmt.Errorf("client random: %w", err)
	}
	if _, err := rand.Read(ls.premasterSecret[:]); err != nil {
		return fmt.Errorf("premaster: %w", err)
	}
	return nil
}
