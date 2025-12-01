package rdp

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

const (
	CREDSSP_VERSION = 3
)

type NegoData []NegoToken

type NegoToken struct {
	Token []byte `asn1:"explicit,tag:0"`
}

type TSRequest struct {
	Version     int      `asn1:"explicit,tag:0"`
	NegoTokens  NegoData `asn1:"explicit,optional,tag:1"`
	AuthInfo    []byte   `asn1:"explicit,optional,tag:2"`
	PubKeyAuth  []byte   `asn1:"explicit,optional,tag:3"`
	ErrorCode   int      `asn1:"explicit,optional,tag:4"`
	ClientNonce []byte   `asn1:"explicit,optional,tag:5"`
}

// [MS-CSSP] Section 2.2.1.2: TSCredentials
type TSCredentials struct {
	CredType    int    `asn1:"explicit,tag:0"`
	Credentials []byte `asn1:"explicit,tag:1"`
}

// [MS-CSSP] Section 2.2.1.2.1: TSPasswordCreds
type TSPasswordCreds struct {
	DomainName []byte `asn1:"explicit,tag:0"`
	UserName   []byte `asn1:"explicit,tag:1"`
	Password   []byte `asn1:"explicit,tag:2"`
}

func (c *Client) PerformCredSSPAuth() error {
	fmt.Printf("\n========================================\n")
	fmt.Printf("=== STARTING CREDSSP AUTHENTICATION ===\n")
	fmt.Printf("========================================\n\n")

	domain := ""
	username := ""
	password := ""

	if c.opts != nil {
		if c.opts.Domain != "" {
			domain = c.opts.Domain
		}
		if c.opts.Username != "" {
			username = c.opts.Username
		}
		if c.opts.Password != "" {
			password = c.opts.Password
		}
	}

	fmt.Printf("CredSSP Parameters:\n")
	fmt.Printf("  Username: %q\n", username)
	fmt.Printf("  Domain: %q\n", domain)
	fmt.Printf("  Has Password: %v\n", password != "")
	fmt.Printf("  CredSSP Version: %d\n", CREDSSP_VERSION)
	fmt.Printf("  Target: %s\n", c.target)
	fmt.Printf("  TLS Enabled: %v\n", c.tlsEnabled)
	fmt.Printf("  Has Certificate: %v\n\n", c.tlsCertificate != nil)

	// --- Step 1: TLS Handshake (Already done by caller) ---
	if c.tlsCertificate == nil {
		return fmt.Errorf("TLS certificate not available, cannot proceed with CredSSP")
	}

	// Extract SubjectPublicKey
	// Extract SubjectPublicKey
	cert, err := x509.ParseCertificate(c.tlsCertificate)
	if err != nil {
		return fmt.Errorf("failed to parse TLS certificate: %w", err)
	}
	pubKeyInfo := cert.RawSubjectPublicKeyInfo
	subjectPublicKey, err := extractSubjectPublicKey(pubKeyInfo)
	if err != nil {
		return fmt.Errorf("failed to extract SubjectPublicKey: %w", err)
	}
	fmt.Printf("DEBUG: Extracted SubjectPublicKey length: %d bytes\n", len(subjectPublicKey))

	// --- Step 2: NTLM Type 1 (Negotiate) ---
	fmt.Printf("--- Step 2: Sending NTLM Type 1 ---\n")

	ntlmType1, err := buildNtlmType1(domain)
	if err != nil {
		return fmt.Errorf("failed to build NTLM Type 1: %w", err)
	}

	spnegoToken1, err := wrapNTLMInSPNEGO(ntlmType1, true)
	if err != nil {
		return fmt.Errorf("failed to wrap NTLM Type 1 in SPNEGO: %w", err)
	}

	tsReq1 := TSRequest{
		Version: CREDSSP_VERSION,
		NegoTokens: NegoData{
			{Token: spnegoToken1},
		},
	}

	if err := c.sendTSRequest(tsReq1); err != nil {
		return fmt.Errorf("failed to send TSRequest (Type 1): %w", err)
	}

	// --- Step 3: Receive NTLM Type 2 (Challenge) ---
	fmt.Printf("--- Step 3: Receiving NTLM Type 2 ---\n")

	tsResp1, err := c.receiveTSRequest()
	if err != nil {
		return fmt.Errorf("failed to receive TSRequest (Type 2): %w", err)
	}

	if len(tsResp1.NegoTokens) == 0 {
		return fmt.Errorf("server sent empty NegoTokens in Type 2 response")
	}

	lastToken := tsResp1.NegoTokens[len(tsResp1.NegoTokens)-1].Token
	ntlmType2Bytes, err := unwrapSPNEGOManual(lastToken)
	if err != nil {
		return fmt.Errorf("failed to unwrap SPNEGO token (Type 2): %w", err)
	}

	challenge, err := parseNtlmChallenge(ntlmType2Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse NTLM Type 2: %w", err)
	}

	// --- Step 4: Send NTLM Type 3 (Authenticate) + PubKeyAuth ---
	fmt.Printf("--- Step 4: Sending NTLM Type 3 + PubKeyAuth ---\n")

	// Build NTLM Type 3 and get Session Key
	ntlmType3, sessionKey, err := buildNtlmType3AndKey(domain, username, password, challenge)
	if err != nil {
		return fmt.Errorf("failed to build NTLM Type 3: %w", err)
	}
	fmt.Printf("DEBUG: NTLM Session Key: %x\n", sessionKey)

	spnegoToken3, err := wrapNTLMInSPNEGO(ntlmType3, false)
	if err != nil {
		return fmt.Errorf("failed to wrap NTLM Type 3 in SPNEGO: %w", err)
	}

	// Calculate PubKeyAuth: Encrypt(SessionKey, SubjectPublicKey)
	pubKeyAuth, err := encryptRC4(sessionKey, subjectPublicKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt PubKeyAuth: %w", err)
	}

	tsReq2 := TSRequest{
		Version: CREDSSP_VERSION,
		NegoTokens: NegoData{
			{Token: spnegoToken3},
		},
		PubKeyAuth: pubKeyAuth,
	}

	if err := c.sendTSRequest(tsReq2); err != nil {
		return fmt.Errorf("failed to send TSRequest (Type 3): %w", err)
	}

	// --- Step 5: Receive Server PubKeyAuth Verification ---
	fmt.Printf("--- Step 5: Receiving Server PubKeyAuth Verification ---\n")

	tsResp2, err := c.receiveTSRequest()
	if err != nil {
		return fmt.Errorf("failed to receive TSRequest (Step 5): %w", err)
	}

	if len(tsResp2.PubKeyAuth) == 0 {
		fmt.Printf("DEBUG: TSRequest ErrorCode: %d\n", tsResp2.ErrorCode)
		return fmt.Errorf("server did not send PubKeyAuth verification")
	}

	decryptedPubKeyAuth, err := decryptRC4(sessionKey, tsResp2.PubKeyAuth)
	if err != nil {
		return fmt.Errorf("failed to decrypt server PubKeyAuth: %w", err)
	}

	if len(decryptedPubKeyAuth) != len(subjectPublicKey) {
		return fmt.Errorf("server PubKeyAuth length mismatch")
	}

	expectedFirstByte := byte(subjectPublicKey[0] + 1)
	if decryptedPubKeyAuth[0] != expectedFirstByte {
		return fmt.Errorf("server PubKeyAuth verification failed: first byte mismatch")
	}

	if !bytes.Equal(decryptedPubKeyAuth[1:], subjectPublicKey[1:]) {
		return fmt.Errorf("server PubKeyAuth verification failed: remaining bytes mismatch")
	}

	fmt.Printf("SUCCESS: Server PubKeyAuth verified!\n")

	// --- Step 6: Send AuthInfo (Encrypted Credentials) ---
	fmt.Printf("--- Step 6: Sending AuthInfo (Encrypted Credentials) ---\n")

	passwordCreds := TSPasswordCreds{
		DomainName: encodeUTF16(domain),
		UserName:   encodeUTF16(username),
		Password:   encodeUTF16(password),
	}

	passCredsBytes, err := asn1.Marshal(passwordCreds)
	if err != nil {
		return fmt.Errorf("failed to marshal TSPasswordCreds: %w", err)
	}

	tsCreds := TSCredentials{
		CredType:    1, // TSPasswordCreds
		Credentials: passCredsBytes,
	}

	tsCredsBytes, err := asn1.Marshal(tsCreds)
	if err != nil {
		return fmt.Errorf("failed to marshal TSCredentials: %w", err)
	}

	authInfo, err := encryptRC4(sessionKey, tsCredsBytes)
	if err != nil {
		return fmt.Errorf("failed to encrypt AuthInfo: %w", err)
	}

	tsReq3 := TSRequest{
		Version:  CREDSSP_VERSION,
		AuthInfo: authInfo,
	}

	if err := c.sendTSRequest(tsReq3); err != nil {
		return fmt.Errorf("failed to send TSRequest (AuthInfo): %w", err)
	}

	fmt.Printf("SUCCESS: AuthInfo sent. CredSSP Handshake Complete.\n")
	return nil
}

func (c *Client) sendTSRequest(req TSRequest) error {
	data, err := asn1.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal TSRequest: %w", err)
	}
	_, err = c.conn.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write TSRequest to TLS: %w", err)
	}
	return nil
}

func (c *Client) receiveTSRequest() (*TSRequest, error) {
	buf := make([]byte, 16384)
	n, err := c.conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read from TLS: %w", err)
	}
	data := buf[:n]
	fmt.Printf("DEBUG: Received %d bytes from TLS\n", n)
	hexDump(data)

	var req TSRequest
	rest, err := asn1.Unmarshal(data, &req)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal TSRequest: %w", err)
	}
	if len(rest) > 0 {
		fmt.Printf("DEBUG: %d bytes of trailing data after TSRequest\n", len(rest))
	}
	return &req, nil
}

func extractSubjectPublicKey(pubKeyInfo []byte) ([]byte, error) {
	type SubjectPublicKeyInfo struct {
		Algorithm        asn1.RawValue
		SubjectPublicKey asn1.BitString
	}
	var spki SubjectPublicKeyInfo
	_, err := asn1.Unmarshal(pubKeyInfo, &spki)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SubjectPublicKeyInfo: %w", err)
	}
	return spki.SubjectPublicKey.Bytes, nil
}

func encodeUTF16(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	b := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return b
}

func encryptRC4(key, data []byte) ([]byte, error) {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, len(data))
	c.XORKeyStream(dst, data)
	return dst, nil
}

func decryptRC4(key, data []byte) ([]byte, error) {
	return encryptRC4(key, data)
}

// --- NTLM Helpers ---

func buildNtlmType1(domain string) ([]byte, error) {
	flags := uint32(0xe208b207) // Negotiate Unicode, NT LM, Request Target, Negotiate 56, Negotiate 128, Negotiate Version, Negotiate Extended Session Security, Negotiate Always Sign, Negotiate NTLM, Negotiate Key Exch

	buf := new(bytes.Buffer)
	buf.WriteString("NTLMSSP\x00")
	binary.Write(buf, binary.LittleEndian, uint32(1))
	binary.Write(buf, binary.LittleEndian, flags)

	binary.Write(buf, binary.LittleEndian, uint16(0)) // Domain Len
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))

	binary.Write(buf, binary.LittleEndian, uint16(0)) // Workstation Len
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))

	buf.Write([]byte{0x06, 0x01, 0xb1, 0x1d, 0x00, 0x00, 0x00, 0x0f}) // Version

	return buf.Bytes(), nil
}

type ntlmChallenge struct {
	ServerChallenge []byte
	TargetInfo      []byte
	NegotiateFlags  uint32
}

func parseNtlmChallenge(data []byte) (*ntlmChallenge, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("NTLM challenge too short")
	}
	if string(data[:8]) != "NTLMSSP\x00" {
		return nil, fmt.Errorf("invalid NTLM signature")
	}
	msgType := binary.LittleEndian.Uint32(data[8:12])
	if msgType != 2 {
		return nil, fmt.Errorf("invalid NTLM message type: %d", msgType)
	}

	challenge := &ntlmChallenge{}
	challenge.NegotiateFlags = binary.LittleEndian.Uint32(data[20:24])

	challenge.ServerChallenge = make([]byte, 8)
	copy(challenge.ServerChallenge, data[24:32])

	targetInfoLen := binary.LittleEndian.Uint16(data[40:42])
	targetInfoOffset := binary.LittleEndian.Uint32(data[44:48])

	if targetInfoLen > 0 && int(targetInfoOffset)+int(targetInfoLen) <= len(data) {
		challenge.TargetInfo = make([]byte, targetInfoLen)
		copy(challenge.TargetInfo, data[targetInfoOffset:targetInfoOffset+uint32(targetInfoLen)])
	}
	return challenge, nil
}

func buildNtlmType3AndKey(domain, username, password string, challenge *ntlmChallenge) ([]byte, []byte, error) {
	// NTLMv2 Implementation

	// 1. NTLMv2 Hash
	h := md4.New()
	h.Write(encodeUTF16(password))
	ntlmHash := h.Sum(nil)

	hm := hmac.New(md5.New, ntlmHash)
	hm.Write(encodeUTF16(strings.ToUpper(username) + domain))
	ntlmv2Hash := hm.Sum(nil)

	// 2. Client Challenge (CNonce)
	clientChallenge := make([]byte, 8)
	rand.Read(clientChallenge)

	// 3. Blob (Timestamp + CNonce + TargetInfo)
	// Timestamp (Current time in Windows FileTime format - 100ns intervals since Jan 1 1601)
	now := time.Now()
	nanos := now.UnixNano()
	// Unix epoch (1970) to Windows epoch (1601) is 11644473600 seconds
	fileTime := (nanos / 100) + 116444736000000000

	blob := new(bytes.Buffer)
	binary.Write(blob, binary.LittleEndian, uint32(0x01010000)) // Signature
	binary.Write(blob, binary.LittleEndian, uint32(0))          // Reserved
	binary.Write(blob, binary.LittleEndian, uint64(fileTime))   // Timestamp
	blob.Write(clientChallenge)                                 // Client Challenge
	binary.Write(blob, binary.LittleEndian, uint32(0))          // Reserved
	blob.Write(challenge.TargetInfo)                            // Target Info (Echoed)
	binary.Write(blob, binary.LittleEndian, uint32(0))          // Reserved

	blobBytes := blob.Bytes()

	// 4. NTProofStr = HMAC-MD5(ntlmv2Hash, ServerChallenge + Blob)
	hm = hmac.New(md5.New, ntlmv2Hash)
	hm.Write(challenge.ServerChallenge)
	hm.Write(blobBytes)
	ntProofStr := hm.Sum(nil)

	// 5. NT Response = NTProofStr + Blob
	ntResponse := append(ntProofStr, blobBytes...)

	// 6. Session Base Key = HMAC-MD5(ntlmv2Hash, NTProofStr)
	hm = hmac.New(md5.New, ntlmv2Hash)
	hm.Write(ntProofStr)
	sessionBaseKey := hm.Sum(nil)

	// 7. Session Key (Key Exchange)
	// Generate Random Session Key
	randomSessionKey := make([]byte, 16)
	rand.Read(randomSessionKey)

	// Encrypt Random Session Key with Session Base Key (RC4)
	encryptedRandomSessionKey, err := encryptRC4(sessionBaseKey, randomSessionKey)
	if err != nil {
		return nil, nil, err
	}

	// 8. Build Type 3 Message
	buf := new(bytes.Buffer)
	buf.WriteString("NTLMSSP\x00")
	binary.Write(buf, binary.LittleEndian, uint32(3)) // Type 3

	// LM Response (Empty)
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// NT Response
	ntRespLen := len(ntResponse)
	// We need to calculate offsets.
	// Fixed header size is 64 bytes? No, variable.
	// Let's calculate lengths first.

	domBytes := encodeUTF16(domain)
	userBytes := encodeUTF16(username)
	hostBytes := encodeUTF16("WORKSTATION")
	sessKeyBytes := encryptedRandomSessionKey

	// Offsets
	// Signature(8) + Type(4) + LM(8) + NT(8) + Dom(8) + User(8) + Host(8) + SessKey(8) + Flags(4) = 64 bytes.
	// Wait, 8+4+8+8+8+8+8+8+4 = 64. Correct.
	// But we might have Version field (8 bytes) if negotiated?
	// Let's assume 72 bytes to be safe or 64.
	// Standard Type 3 header is 64 bytes.

	offset := 64

	// NT Response Header
	binary.Write(buf, binary.LittleEndian, uint16(ntRespLen))
	binary.Write(buf, binary.LittleEndian, uint16(ntRespLen))
	binary.Write(buf, binary.LittleEndian, uint32(offset+len(domBytes)+len(userBytes)+len(hostBytes))) // Put NT response at end?
	// Usually: Domain, User, Host, SessionKey, NTResp

	// Let's order payload: Domain, User, Host, SessionKey, NTResp
	offsetDomain := 72 // Header (64) + Version (8)
	offsetUser := offsetDomain + len(domBytes)
	offsetHost := offsetUser + len(userBytes)
	offsetSessKey := offsetHost + len(hostBytes)
	offsetNTResp := offsetSessKey + len(sessKeyBytes)

	// Rewrite buffer with correct offsets
	buf.Reset()
	buf.WriteString("NTLMSSP\x00")
	binary.Write(buf, binary.LittleEndian, uint32(3))

	// LM Response (Empty)
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// NT Response
	binary.Write(buf, binary.LittleEndian, uint16(ntRespLen))
	binary.Write(buf, binary.LittleEndian, uint16(ntRespLen))
	binary.Write(buf, binary.LittleEndian, uint32(offsetNTResp))

	// Domain
	binary.Write(buf, binary.LittleEndian, uint16(len(domBytes)))
	binary.Write(buf, binary.LittleEndian, uint16(len(domBytes)))
	binary.Write(buf, binary.LittleEndian, uint32(offsetDomain))

	// User
	binary.Write(buf, binary.LittleEndian, uint16(len(userBytes)))
	binary.Write(buf, binary.LittleEndian, uint16(len(userBytes)))
	binary.Write(buf, binary.LittleEndian, uint32(offsetUser))

	// Workstation
	binary.Write(buf, binary.LittleEndian, uint16(len(hostBytes)))
	binary.Write(buf, binary.LittleEndian, uint16(len(hostBytes)))
	binary.Write(buf, binary.LittleEndian, uint32(offsetHost))

	// Session Key
	binary.Write(buf, binary.LittleEndian, uint16(len(sessKeyBytes)))
	binary.Write(buf, binary.LittleEndian, uint16(len(sessKeyBytes)))
	binary.Write(buf, binary.LittleEndian, uint32(offsetSessKey))

	// Flags
	flags := uint32(0xe208b205) // Matches Type 1 (with Key Exch)
	binary.Write(buf, binary.LittleEndian, flags)

	// Version (8 bytes) - Windows 10 / Server 2016 (10.0.14393)
	// Major=6, Minor=1, Build=7601 (Win7 SP1) - Common compatibility
	// Or use 10.0.19041 (Win10)
	// Let's use 6.1.7601 for broad compatibility
	buf.Write([]byte{0x06, 0x01, 0xb1, 0x1d, 0x00, 0x00, 0x00, 0x0f})

	// Payload
	buf.Write(domBytes)
	buf.Write(userBytes)
	buf.Write(hostBytes)
	buf.Write(sessKeyBytes)
	buf.Write(ntResponse)

	return buf.Bytes(), randomSessionKey, nil
}

func hexDump(data []byte) {
	for i := 0; i < len(data); i += 16 {

		fmt.Printf("%04x  ", i)

		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				fmt.Printf("%02x ", data[i+j])
			} else {
				fmt.Print("   ")
			}
			if j == 7 {
				fmt.Print(" ")
			}
		}

		fmt.Print(" |")
		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 0x20 && b <= 0x7e {
				fmt.Printf("%c", b)
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println("|")
	}
	fmt.Println()
}
