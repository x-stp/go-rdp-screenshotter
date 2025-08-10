package rdp

// NTLMv2 mandates MD4(unicode(password)) for NTOWFv2 per [MS-NLMP] §3.3.2 and
// RC4 + MD5 for message sealing per §3.4. These are protocol-compatibility
// requirements, not security choices, so silence the deprecation warnings the
// weak-crypto imports would otherwise raise.
//
//lint:file-ignore SA1019 MD4/RC4/MD5 are mandated by NTLMv2 (MS-NLMP §3.3.2, §3.4)

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4" //nolint:staticcheck // MD4 required by NTLMv2 (MS-NLMP §3.3.2)
)

// NTLM message signature, message types and NEGOTIATE_* flag bits per
// [MS-NLMP] §2.2.2.5.
const (
	ntlmSignature             = "NTLMSSP\x00"
	ntlmTypeNegotiate         = 1
	ntlmTypeChallenge         = 2
	ntlmTypeAuthenticate      = 3
	negotiateUnicode          = 0x00000001
	negotiateOEM              = 0x00000002
	requestTarget             = 0x00000004
	negotiateSign             = 0x00000010
	negotiateSeal             = 0x00000020
	negotiateNTLM             = 0x00000200
	negotiateAnonymous        = 0x00000800
	negotiateAlwaysSign       = 0x00008000
	negotiateExtSessSecNTLMv2 = 0x00080000
	negotiate128              = 0x20000000
	negotiateKeyExch          = 0x40000000
	negotiate56               = 0x80000000
)

type ntlmChallenge struct {
	ServerChallenge []byte
	TargetInfo      []byte
	NegotiateFlags  uint32
}

type ntlmSession struct {
	SessionKey      []byte
	ClientChallenge []byte
	ServerChallenge []byte
	NTProofStr      []byte
}

// buildNtlmNegotiate emits an NTLM NEGOTIATE_MESSAGE per [MS-NLMP] §2.2.1.1.
// NEGOTIATE_ANONYMOUS MUST NOT be set in Type 1 ([MS-NLMP] §3.1.5.1.1); the
// `anonymous` argument is therefore intentionally unused here and only flows
// into Type 3.
func buildNtlmNegotiate(_ string, _ bool) ([]byte, error) {
	flags := uint32(negotiateUnicode | negotiateOEM | requestTarget |
		negotiateNTLM | negotiateAlwaysSign | negotiateExtSessSecNTLMv2 |
		negotiateSign | negotiateSeal | negotiate128 | negotiateKeyExch | negotiate56)

	msg := make([]byte, 32)
	copy(msg[0:], ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:], ntlmTypeNegotiate)
	binary.LittleEndian.PutUint32(msg[12:], flags)
	return msg, nil
}

func parseNtlmChallenge(data []byte) (*ntlmChallenge, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("NTLM challenge too short: %d bytes", len(data))
	}
	if string(data[:8]) != ntlmSignature {
		return nil, fmt.Errorf("invalid NTLM signature")
	}
	if msgType := binary.LittleEndian.Uint32(data[8:12]); msgType != ntlmTypeChallenge {
		return nil, fmt.Errorf("expected NTLM Type 2, got %d", msgType)
	}

	c := &ntlmChallenge{
		NegotiateFlags:  binary.LittleEndian.Uint32(data[20:24]),
		ServerChallenge: append([]byte(nil), data[24:32]...),
	}
	if len(data) >= 48 {
		tiLen := binary.LittleEndian.Uint16(data[40:42])
		tiOff := binary.LittleEndian.Uint32(data[44:48])
		if tiLen > 0 && tiOff > 0 && tiOff+uint32(tiLen) <= uint32(len(data)) {
			c.TargetInfo = append([]byte(nil), data[tiOff:tiOff+uint32(tiLen)]...)
		}
	}
	return c, nil
}

// ntlmAuthMaterial bundles every byte string that goes into
// AUTHENTICATE_MESSAGE plus the matching ntlmSession state. Splitting it out
// lets buildNtlmAuthenticate stay a thin marshaller while the anon vs real
// branches live in dedicated helpers.
type ntlmAuthMaterial struct {
	lmResp                    []byte
	ntResp                    []byte
	encryptedRandomSessionKey []byte
	session                   *ntlmSession
}

// anonymousAuthMaterial constructs the [MS-NLMP] §3.1.5.1.2 null-session
// form: NtChallengeResponse is empty, LmChallengeResponse is one 0x00 byte,
// the SessionBaseKey is the 16-byte zero vector.
func anonymousAuthMaterial(challenge *ntlmChallenge) ntlmAuthMaterial {
	zero := make([]byte, 16)
	return ntlmAuthMaterial{
		lmResp:                    []byte{0x00},
		encryptedRandomSessionKey: zero,
		session: &ntlmSession{
			SessionKey:      zero,
			ServerChallenge: challenge.ServerChallenge,
			NTProofStr:      make([]byte, 16),
		},
	}
}

// realAuthMaterial computes NTLMv2 response, derives the session base key
// and exports a fresh random session key encrypted under it per
// [MS-NLMP] §3.3.2 + §3.4.5.
func realAuthMaterial(domain, user, pass string, challenge *ntlmChallenge) (ntlmAuthMaterial, error) {
	ntlmV2Hash := ntlmNTOWFv2(pass, user, domain)
	clientChallenge := make([]byte, 8)
	if _, err := rand.Read(clientChallenge); err != nil {
		return ntlmAuthMaterial{}, fmt.Errorf("rand for NTLM client challenge: %w", err)
	}
	// Convert Unix epoch to Windows FILETIME (100ns intervals since 1601).
	timestamp := (time.Now().Unix() + 11644473600) * 10000000
	ntResp, ntProofStr := computeNtlmV2Response(ntlmV2Hash, challenge.ServerChallenge, clientChallenge, challenge.TargetInfo, timestamp)
	sessionBaseKey := deriveNtlmSessionKey(ntlmV2Hash, ntProofStr)

	exportedKey := make([]byte, 16)
	if _, err := rand.Read(exportedKey); err != nil {
		return ntlmAuthMaterial{}, fmt.Errorf("rand for NTLM session key: %w", err)
	}
	c, err := rc4.NewCipher(sessionBaseKey)
	if err != nil {
		return ntlmAuthMaterial{}, fmt.Errorf("rc4 cipher for key exchange: %w", err)
	}
	encryptedKey := make([]byte, 16)
	c.XORKeyStream(encryptedKey, exportedKey)

	return ntlmAuthMaterial{
		ntResp:                    ntResp,
		encryptedRandomSessionKey: encryptedKey,
		session: &ntlmSession{
			SessionKey:      exportedKey,
			ClientChallenge: clientChallenge,
			ServerChallenge: challenge.ServerChallenge,
			NTProofStr:      ntProofStr,
		},
	}, nil
}

// buildNtlmAuthenticate marshals AUTHENTICATE_MESSAGE per [MS-NLMP]
// §2.2.1.3: 72-byte fixed header (no MIC) followed by Domain, User,
// Workstation, LmChallengeResponse, NtChallengeResponse and
// EncryptedRandomSessionKey payload areas. Branches into anon vs real
// material via the helpers above.
func buildNtlmAuthenticate(domain, user, pass, workstation string, challenge *ntlmChallenge, anonymous bool) ([]byte, *ntlmSession, error) {
	var (
		mat ntlmAuthMaterial
		err error
	)
	if anonymous {
		mat = anonymousAuthMaterial(challenge)
	} else {
		mat, err = realAuthMaterial(domain, user, pass, challenge)
		if err != nil {
			return nil, nil, err
		}
	}

	flags := challenge.NegotiateFlags | negotiateSign | negotiateSeal | negotiate128 | negotiateKeyExch | negotiate56
	if anonymous {
		flags |= negotiateAnonymous
	}

	domainBytes := toUnicode(domain)
	userBytes := toUnicode(user)
	wsBytes := toUnicode(workstation)

	const headerLen = 72
	totalPayload := len(mat.lmResp) + len(mat.ntResp) + len(domainBytes) + len(userBytes) + len(wsBytes) + len(mat.encryptedRandomSessionKey)
	msg := make([]byte, headerLen+totalPayload)
	copy(msg[0:], ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:], ntlmTypeAuthenticate)

	off := headerLen
	writeField := func(hdrOff int, payload []byte) {
		binary.LittleEndian.PutUint16(msg[hdrOff:], uint16(len(payload)))
		binary.LittleEndian.PutUint16(msg[hdrOff+2:], uint16(len(payload)))
		binary.LittleEndian.PutUint32(msg[hdrOff+4:], uint32(off))
		copy(msg[off:], payload)
		off += len(payload)
	}
	writeField(12, mat.lmResp)
	writeField(20, mat.ntResp)
	writeField(28, domainBytes)
	writeField(36, userBytes)
	writeField(44, wsBytes)
	writeField(52, mat.encryptedRandomSessionKey)

	binary.LittleEndian.PutUint32(msg[60:], flags)
	return msg, mat.session, nil
}

// ntlmNTOWFv2 = HMAC-MD5(MD4(unicode(password)), unicode(UPPER(user)+domain))
// per [MS-NLMP] §3.3.2.
func ntlmNTOWFv2(password, username, domain string) []byte {
	h := hmac.New(md5.New, md4Hash(toUnicode(password)))
	h.Write(toUnicode(strings.ToUpper(username) + domain))
	return h.Sum(nil)
}

func deriveNtlmSessionKey(ntlmV2Hash, ntProofStr []byte) []byte {
	h := hmac.New(md5.New, ntlmV2Hash)
	h.Write(ntProofStr)
	return h.Sum(nil)
}

// computeNtlmV2Response builds the NTLMv2 response blob and NTProofStr per
// [MS-NLMP] §3.3.2.
func computeNtlmV2Response(ntlmV2Hash, serverChallenge, clientChallenge, targetInfo []byte, timestamp int64) ([]byte, []byte) {
	blob := make([]byte, 28+len(targetInfo))
	binary.LittleEndian.PutUint16(blob[0:], 1)
	binary.LittleEndian.PutUint16(blob[2:], 1)
	binary.LittleEndian.PutUint64(blob[8:], uint64(timestamp))
	copy(blob[16:], clientChallenge)
	copy(blob[28:], targetInfo)

	h := hmac.New(md5.New, ntlmV2Hash)
	h.Write(serverChallenge)
	h.Write(blob)
	ntProofStr := h.Sum(nil)
	return append(ntProofStr, blob...), ntProofStr
}

// ntlmSealKey derives the NTLM seal key from the session key per [MS-NLMP] §3.4.5.3.
func ntlmSealKey(sessionKey []byte) []byte {
	h := md5.New()
	h.Write(sessionKey)
	h.Write([]byte("session key to client-to-server sealing key magic constant\x00"))
	return h.Sum(nil)
}

// ntlmSignKey derives the NTLM sign key from the session key per [MS-NLMP] §3.4.5.2.
func ntlmSignKey(sessionKey []byte) []byte {
	h := md5.New()
	h.Write(sessionKey)
	h.Write([]byte("session key to client-to-server signing key magic constant\x00"))
	return h.Sum(nil)
}

// ntlmSeal encrypts data and produces the 16-byte NTLMSSP_MESSAGE_SIGNATURE
// per [MS-NLMP] §3.4.4 (NEGOTIATE_KEY_EXCH + NEGOTIATE_SEAL + NTLMv2 session
// security).
func ntlmSeal(sessionKey []byte, seqNum uint32, data []byte) ([]byte, error) {
	sealKey := ntlmSealKey(sessionKey)
	signKey := ntlmSignKey(sessionKey)

	cipher, err := rc4.NewCipher(sealKey)
	if err != nil {
		return nil, fmt.Errorf("rc4 cipher: %w", err)
	}
	encrypted := make([]byte, len(data))
	cipher.XORKeyStream(encrypted, data)

	seqBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(seqBytes, seqNum)

	mac := hmac.New(md5.New, signKey)
	mac.Write(seqBytes)
	mac.Write(data)
	macSum := mac.Sum(nil)[:8]

	encMac := make([]byte, 8)
	cipher2, _ := rc4.NewCipher(sealKey)
	cipher2.XORKeyStream(encMac, macSum)

	sig := make([]byte, 16)
	binary.LittleEndian.PutUint32(sig[0:4], 0x00000001)
	copy(sig[4:12], encMac)
	binary.LittleEndian.PutUint32(sig[12:16], seqNum)

	return append(sig, encrypted...), nil
}

// toUnicode returns the UTF-16LE encoding of s with no terminator. Used
// throughout the NTLM and Client Info paths.
func toUnicode(s string) []byte {
	uints := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(uints))
	for i, r := range uints {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}

// md4Hash wraps the canonical x/crypto MD4 implementation used by NTLMv2
// password hashing per [MS-NLMP] §3.3.2 (NTOWFv2).
func md4Hash(data []byte) []byte {
	h := md4.New()
	h.Write(data)
	return h.Sum(nil)
}
