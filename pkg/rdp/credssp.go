















package rdp

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	CREDSSP_VERSION = 3 
)



type NegoData []NegoToken



type NegoToken struct {
	Token asn1.RawValue `asn1:"explicit,tag:0"`
}




type TSRequest struct {
	Version    int      `asn1:"explicit,tag:0"`
	NegoTokens NegoData `asn1:"explicit,optional,tag:1"`
	AuthInfo   []byte   `asn1:"explicit,optional,tag:2"`
	PubKeyAuth []byte   `asn1:"explicit,optional,tag:3"`
	ErrorCode  int      `asn1:"explicit,optional,tag:4"`
	ClientNonce []byte  `asn1:"explicit,optional,tag:5"`
}


type TSRequestInitial struct {
	Version    int    `asn1:"explicit,tag:0"`
	NegoTokens []byte `asn1:"explicit,optional,tag:1"` 
	AuthInfo   []byte `asn1:"explicit,optional,tag:2"`
	PubKeyAuth []byte `asn1:"explicit,optional,tag:3"`
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

	
	negotiateMsg, err := buildNtlmNegotiate(domain)
	if err != nil {
		return fmt.Errorf("failed to build NTLM negotiate message: %w", err)
	}

	if err := c.sendCredSSPRequest(negotiateMsg, nil, nil); err != nil {
		return fmt.Errorf("failed to send NTLM Type 1 (Negotiate): %w", err)
	}
	fmt.Println("CredSSP: Sent NTLM Type 1 (Negotiate)")

	
	challengeReq, err := c.receiveCredSSPRequest()
	if err != nil {
		return fmt.Errorf("failed to receive NTLM Type 2 (Challenge): %w", err)
	}

	if len(challengeReq.NegoTokens) == 0 {
		return fmt.Errorf("no NTLM token in server's challenge response")
	}
	
	
	ntlmToken := challengeReq.NegoTokens[0].Token.Bytes
	
	/*
	
	ntlmToken, err := unwrapSPNEGO(spnegoToken)
	if err != nil {
		return fmt.Errorf("failed to unwrap SPNEGO: %w", err)
	}
	*/
	
	challengeMsg, err := parseNtlmChallenge(ntlmToken)
	if err != nil {
		return err
	}
	fmt.Println("CredSSP: Received NTLM Type 2 (Challenge)")

	
	authenticateMsg, ntlmSession, err := buildNtlmAuthenticate(domain, username, password, "WORKSTATION", challengeMsg)
	if err != nil {
		return fmt.Errorf("failed to build NTLM Type 3 (Authenticate): %w", err)
	}
	
	
	c.ntlmSession = ntlmSession
	fmt.Printf("NTLM session key derived: %x\n", ntlmSession.SessionKey[:16])

	
	
	
	
	if c.tlsCertificate == nil {
		return fmt.Errorf("no TLS certificate available for public key verification")
	}
	
	cert, err := x509.ParseCertificate(c.tlsCertificate)
	if err != nil {
		return fmt.Errorf("failed to parse TLS certificate: %w", err)
	}
	
	
	_, err = x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	
	
	var pubKeyHash []byte
	var clientNonce []byte
	
	if challengeReq.Version >= 5 {
		
		magicString := "CredSSP Client-To-Server Binding Hash\x00"
		
		
		clientNonce = make([]byte, 32)
		rand.Read(clientNonce)
		
		
		subjectPublicKeyInfo, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to marshal SubjectPublicKeyInfo: %w", err)
		}
		
		
		h := sha256.New()
		h.Write(subjectPublicKeyInfo)
		h.Write([]byte(magicString))
		h.Write(clientNonce)
		pubKeyHash = h.Sum(nil)
		
		fmt.Printf("CredSSP: Computing public key auth (version %d)\n", challengeReq.Version)
		fmt.Printf("  SubjectPublicKeyInfo size: %d bytes\n", len(subjectPublicKeyInfo))
		fmt.Printf("  Magic string: %q\n", magicString)
		fmt.Printf("  Client nonce: %x\n", clientNonce[:8])
		fmt.Printf("  Hash (first 16 bytes): %x\n", pubKeyHash[:16])
	} else {
		
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			return fmt.Errorf("failed to marshal public key: %w", err)
		}
		pubKeyHash = pubKeyBytes
		fmt.Printf("CredSSP: Using public key directly (version %d)\n", challengeReq.Version)
	}
	
	
	encryptedHash, err := encryptWithRC4(c.ntlmSession.SessionKey, pubKeyHash[:])
	if err != nil {
		return fmt.Errorf("failed to encrypt public key hash: %w", err)
	}
	fmt.Printf("Encrypted public key hash (first 16 bytes): %x\n", encryptedHash[:16])
	
	
	if challengeReq.Version >= 5 && clientNonce != nil {
		
		if err := c.sendCredSSPRequestWithNonce(authenticateMsg, nil, encryptedHash, clientNonce); err != nil {
			return fmt.Errorf("failed to send NTLM Type 3 (Authenticate) with pubKeyAuth: %w", err)
		}
	} else {
		if err := c.sendCredSSPRequest(authenticateMsg, nil, encryptedHash); err != nil {
			return fmt.Errorf("failed to send NTLM Type 3 (Authenticate) with pubKeyAuth: %w", err)
		}
	}
	fmt.Println("CredSSP: Sent NTLM Type 3 (Authenticate) with pubKeyAuth")

	
	pubKeyResp, err := c.receiveCredSSPRequest()
	if err != nil {
		return fmt.Errorf("failed to read server public key response: %w", err)
	}

	if pubKeyResp.PubKeyAuth == nil {
		return fmt.Errorf("NLA authentication failed: server did not return public key hash")
	}
	
	fmt.Println("CredSSP: Received server's public key hash")
	
	
	
	
	
	
	tsCredentials := []byte{0x01, 0x00, 0x00, 0x00} 
	
	
	if challengeReq.Version >= 5 {
		
		magicString := "CredSSP Server-To-Client Binding Hash\x00"
		
		
		subjectPublicKeyInfo, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
		
		
		h := sha256.New()
		h.Write(subjectPublicKeyInfo)
		h.Write([]byte(magicString))
		h.Write(clientNonce) 
		serverHash := h.Sum(nil)
		
		
		encryptedHash2, _ := encryptWithRC4(c.ntlmSession.SessionKey, serverHash)
		if err := c.sendCredSSPRequest(nil, tsCredentials, encryptedHash2); err != nil {
			return fmt.Errorf("failed to send final CredSSP message: %w", err)
		}
	} else {
		
		encryptedHash2, _ := encryptWithRC4(c.ntlmSession.SessionKey, pubKeyHash)
		if err := c.sendCredSSPRequest(nil, tsCredentials, encryptedHash2); err != nil {
			return fmt.Errorf("failed to send final CredSSP message: %w", err)
		}
	}
	
	fmt.Println("CredSSP authentication handshake completed successfully.")
	return nil
}


func (c *Client) sendCredSSPRequestWithNonce(ntlmMsg, authInfo, pubKeyAuth, clientNonce []byte) error {
	return c.sendCredSSPRequestInternal(ntlmMsg, authInfo, pubKeyAuth, clientNonce)
}


func (c *Client) sendCredSSPRequest(ntlmMsg, authInfo, pubKeyAuth []byte) error {
	return c.sendCredSSPRequestInternal(ntlmMsg, authInfo, pubKeyAuth, nil)
}


func (c *Client) sendCredSSPRequestInternal(ntlmMsg, authInfo, pubKeyAuth, clientNonce []byte) error {
	
	
	var tokenToSend []byte
	if ntlmMsg != nil {
		
		
		fmt.Printf("\nTEST: Sending raw NTLM without SPNEGO wrapper\n")
		fmt.Printf("NTLM message size: %d bytes\n", len(ntlmMsg))
		tokenToSend = ntlmMsg
		
		/*
		
		isInitial := len(authInfo) == 0 && len(pubKeyAuth) == 0 && ntlmMsg != nil
		var err error
		tokenToSend, err = wrapNTLMInSPNEGO(ntlmMsg, isInitial)
		if err != nil {
			return fmt.Errorf("failed to wrap NTLM in SPNEGO: %w", err)
		}
		*/
	}
	
	
	var data []byte
	
	
	var content []byte
	
	
	versionField := []byte{0xa0, 0x03, 0x02, 0x01, byte(CREDSSP_VERSION)}
	content = append(content, versionField...)
	
	
	if tokenToSend != nil {
		
		tokenLen := len(tokenToSend)
		octetStringLen := tokenLen + 2 
		contextTagLen := octetStringLen + 2 
		innerSeqLen := contextTagLen
		outerSeqLen := innerSeqLen + 2 
		negoTokensLen := outerSeqLen + 2 
		
		
		var negoTokensField []byte
		negoTokensField = append(negoTokensField, 0xa1) 
		if negoTokensLen < 128 {
			negoTokensField = append(negoTokensField, byte(negoTokensLen))
		} else {
			negoTokensField = append(negoTokensField, 0x81, byte(negoTokensLen))
		}
		
		
		negoTokensField = append(negoTokensField, 0x30)
		if outerSeqLen < 128 {
			negoTokensField = append(negoTokensField, byte(outerSeqLen))
		} else {
			negoTokensField = append(negoTokensField, 0x81, byte(outerSeqLen))
		}
		
		
		negoTokensField = append(negoTokensField, 0x30)
		if innerSeqLen < 128 {
			negoTokensField = append(negoTokensField, byte(innerSeqLen))
		} else {
			negoTokensField = append(negoTokensField, 0x81, byte(innerSeqLen))
		}
		
		
		negoTokensField = append(negoTokensField, 0xa0)
		if contextTagLen-2 < 128 {
			negoTokensField = append(negoTokensField, byte(contextTagLen-2))
		} else {
			negoTokensField = append(negoTokensField, 0x81, byte(contextTagLen-2))
		}
		
		
		negoTokensField = append(negoTokensField, 0x04)
		if tokenLen < 128 {
			negoTokensField = append(negoTokensField, byte(tokenLen))
		} else {
			negoTokensField = append(negoTokensField, 0x81, byte(tokenLen))
		}
		negoTokensField = append(negoTokensField, tokenToSend...)
		
		content = append(content, negoTokensField...)
	}
	
	
	if authInfo != nil {
		content = append(content, 0xa2)
		if len(authInfo) < 128 {
			content = append(content, byte(len(authInfo)))
		} else {
			content = append(content, 0x81, byte(len(authInfo)))
		}
		content = append(content, authInfo...)
	}
	
	
	if pubKeyAuth != nil {
		content = append(content, 0xa3)
		if len(pubKeyAuth) < 128 {
			content = append(content, byte(len(pubKeyAuth)))
		} else {
			content = append(content, 0x81, byte(len(pubKeyAuth)))
		}
		content = append(content, pubKeyAuth...)
	}
	
	
	if clientNonce != nil {
		content = append(content, 0xa5)
		if len(clientNonce) < 128 {
			content = append(content, byte(len(clientNonce)))
		} else {
			content = append(content, 0x81, byte(len(clientNonce)))
		}
		content = append(content, clientNonce...)
	}
	
	
	data = append(data, 0x30) 
	if len(content) < 128 {
		data = append(data, byte(len(content)))
	} else if len(content) < 256 {
		data = append(data, 0x81, byte(len(content)))
	} else {
		data = append(data, 0x82, byte(len(content)>>8), byte(len(content)))
	}
	data = append(data, content...)

	
	fmt.Printf("\n=== SENDING TSRequest (%d bytes) ===\n", len(data))
	fmt.Printf("Version: %d\n", CREDSSP_VERSION)
	fmt.Printf("NegoTokens: %v\n", tokenToSend != nil)
	fmt.Printf("AuthInfo: %v\n", authInfo != nil)
	fmt.Printf("PubKeyAuth: %v\n", pubKeyAuth != nil)
	fmt.Printf("ClientNonce: %v\n", clientNonce != nil)
	fmt.Printf("Raw ASN.1 hex:\n")
	hexDump(data)
	
	_, err := c.conn.Write(data)
	return err
}


func (c *Client) receiveCredSSPRequest() (*TSRequest, error) {
	buf := make([]byte, 8192) 
	n, err := c.conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read from TLS connection: %w", err)
	}
	
	fmt.Printf("\n=== RECEIVED TSRequest (%d bytes) ===\n", n)
	fmt.Printf("Raw ASN.1 hex:\n")
	hexDump(buf[:n])
	
	
	if n > 0 {
		fmt.Printf("\nASN.1 structure analysis:\n")
		fmt.Printf("First byte: 0x%02x (Class: %d, Constructed: %v, Tag: %d)\n", 
			buf[0], (buf[0]>>6)&3, (buf[0]&0x20) != 0, buf[0]&0x1f)
		
		
		if n == 15 {
			fmt.Printf("\nWARNING: Received only 15 bytes - this might be an error response\n")
			
			if buf[0] == 0x30 { 
				fmt.Printf("Detected SEQUENCE tag\n")
				
				if buf[2] == 0xa0 && buf[3] == 0x03 && buf[4] == 0x02 && buf[5] == 0x01 {
					version := int(buf[6])
					fmt.Printf("Found version field: %d\n", version)
				}
				if n >= 13 && buf[7] == 0xa4 {
					fmt.Printf("Found error code field at offset 7\n")
					if buf[8] == 0x06 && buf[9] == 0x02 && buf[10] == 0x04 {
						
						errorCode := binary.BigEndian.Uint32([]byte{buf[11], buf[12], buf[13], buf[14]})
						fmt.Printf("Error code value: 0x%08x (%d)\n", errorCode, errorCode)
						switch errorCode {
						case 0x80090302:
							fmt.Printf("ERROR: SEC_E_INCOMPLETE_MESSAGE - The message is incomplete, more data required\n")
						case 0x80090308:
							fmt.Printf("ERROR: SEC_E_INVALID_TOKEN - The NTLM token is invalid or malformed\n")
						case 0x8009030C:
							fmt.Printf("ERROR: SEC_E_LOGON_DENIED - The logon attempt failed\n")
						case 0x8009030E:
							fmt.Printf("ERROR: SEC_E_NO_CREDENTIALS - No credentials available\n")
						case 0x80090311:
							fmt.Printf("ERROR: SEC_E_NO_AUTHENTICATING_AUTHORITY - No authority to authenticate\n")
						case 0x00090312:
							fmt.Printf("INFO: SEC_I_CONTINUE_NEEDED - Continue with next token\n")
						default:
							fmt.Printf("ERROR: Unknown error code\n")
						}
					}
				}
			}
		}
	}

	var req TSRequest
	_, err = asn1.Unmarshal(buf[:n], &req)
	if err != nil {
		fmt.Printf("ERROR: Failed to unmarshal TSRequest: %v\n", err)
		
		fmt.Printf("Trying to parse as raw ASN.1...\n")
		var raw asn1.RawValue
		if _, err2 := asn1.Unmarshal(buf[:n], &raw); err2 == nil {
			fmt.Printf("Raw ASN.1: Class=%d, Tag=%d, IsCompound=%v, Bytes=%d\n", 
				raw.Class, raw.Tag, raw.IsCompound, len(raw.Bytes))
		}
		return nil, fmt.Errorf("failed to unmarshal TSRequest: %w", err)
	}
	
	fmt.Printf("Successfully parsed TSRequest:\n")
	fmt.Printf("  Version: %d\n", req.Version)
	fmt.Printf("  NegoTokens: %d\n", len(req.NegoTokens))
	fmt.Printf("  AuthInfo: %v\n", req.AuthInfo != nil)
	fmt.Printf("  PubKeyAuth: %v\n", req.PubKeyAuth != nil)
	if req.ErrorCode != 0 {
		fmt.Printf("  ErrorCode: 0x%08x (%d)\n", uint32(req.ErrorCode), req.ErrorCode)
		interpretErrorCode(uint32(req.ErrorCode))
	}

	return &req, nil
}


func interpretErrorCode(errorCode uint32) {
	switch errorCode {
	case 0x80090302:
		fmt.Printf("    SEC_E_INCOMPLETE_MESSAGE - The message is incomplete\n")
	case 0x80090308:
		fmt.Printf("    SEC_E_INVALID_TOKEN - The security token is invalid\n")
		fmt.Printf("    This usually means the SPNEGO wrapper or NTLM message format is incorrect\n")
	case 0x8009030C:
		fmt.Printf("    SEC_E_LOGON_DENIED - The logon was denied\n")
	case 0x8009030E:
		fmt.Printf("    SEC_E_NO_CREDENTIALS - No credentials available\n")
	case 0x80090311:
		fmt.Printf("    SEC_E_NO_AUTHENTICATING_AUTHORITY - No authority to authenticate\n")
	}
}




const (
	NTLM_SIGNATURE         = "NTLMSSP\x00"
	NTLM_TYPE_NEGOTIATE    = 1
	NTLM_TYPE_CHALLENGE    = 2
	NTLM_TYPE_AUTHENTICATE = 3
	NEGOTIATE_UNICODE      = 0x00000001
	NEGOTIATE_OEM          = 0x00000002
	REQUEST_TARGET         = 0x00000004
	NEGOTIATE_SIGN         = 0x00000010
	NEGOTIATE_SEAL         = 0x00000020
	NEGOTIATE_NTLM         = 0x00000200
	NEGOTIATE_ALWAYS_SIGN  = 0x00008000
	NEGOTIATE_NTLM2_KEY    = 0x00080000
	NEGOTIATE_128          = 0x20000000
	NEGOTIATE_KEY_EXCH     = 0x40000000
	NEGOTIATE_56           = 0x80000000
)

func buildNtlmNegotiate(domain string) ([]byte, error) {
	
	flags := NEGOTIATE_UNICODE | NEGOTIATE_OEM | REQUEST_TARGET | 
		NEGOTIATE_NTLM | NEGOTIATE_ALWAYS_SIGN | NEGOTIATE_NTLM2_KEY
	
	
	msg := make([]byte, 32)
	copy(msg[0:], []byte(NTLM_SIGNATURE))
	binary.LittleEndian.PutUint32(msg[8:], NTLM_TYPE_NEGOTIATE)
	binary.LittleEndian.PutUint32(msg[12:], uint32(flags))

	
	
	binary.LittleEndian.PutUint16(msg[16:], 0) 
	binary.LittleEndian.PutUint16(msg[18:], 0) 
	binary.LittleEndian.PutUint32(msg[20:], 0) 

	
	binary.LittleEndian.PutUint16(msg[24:], 0) 
	binary.LittleEndian.PutUint16(msg[26:], 0) 
	binary.LittleEndian.PutUint32(msg[28:], 0) 
	
	fmt.Printf("\n=== NTLM Type 1 (Negotiate) ===\n")
	fmt.Printf("Flags: 0x%08x\n", flags)
	fmt.Printf("Message size: %d bytes\n", len(msg))
	fmt.Printf("Message hex:\n")
	hexDump(msg)

	return msg, nil
}

type ntlmChallenge struct {
	ServerChallenge []byte
	TargetInfo      []byte
	NegotiateFlags  uint32
}


type ntlmSession struct {
	SessionKey     []byte
	ClientChallenge []byte
	ServerChallenge []byte
	NTProofStr     []byte
}

func parseNtlmChallenge(data []byte) (*ntlmChallenge, error) {
	fmt.Printf("\n=== PARSING NTLM TYPE 2 CHALLENGE ===\n")
	fmt.Printf("Data length: %d bytes\n", len(data))
	fmt.Printf("First 16 bytes: %x\n", data[:min(16, len(data))])
	
	
	if len(data) < 32 {
		return nil, fmt.Errorf("NTLM challenge too short: %d bytes (need at least 32)", len(data))
	}
	
	
	if string(data[:8]) != NTLM_SIGNATURE {
		return nil, fmt.Errorf("invalid NTLM signature: got %x, want %x", data[:8], []byte(NTLM_SIGNATURE))
	}
	
	
	msgType := binary.LittleEndian.Uint32(data[8:12])
	if msgType != NTLM_TYPE_CHALLENGE {
		return nil, fmt.Errorf("invalid NTLM message type: got %d, want %d (Type 2)", msgType, NTLM_TYPE_CHALLENGE)
	}

	challenge := &ntlmChallenge{}
	
	
	targetNameLen := binary.LittleEndian.Uint16(data[12:14])
	targetNameMaxLen := binary.LittleEndian.Uint16(data[14:16])
	targetNameOffset := binary.LittleEndian.Uint32(data[16:20])
	fmt.Printf("Target name: len=%d, maxlen=%d, offset=%d\n", targetNameLen, targetNameMaxLen, targetNameOffset)
	
	
	challenge.NegotiateFlags = binary.LittleEndian.Uint32(data[20:24])
	fmt.Printf("Negotiate flags: 0x%08x\n", challenge.NegotiateFlags)
	
	
	challenge.ServerChallenge = make([]byte, 8)
	copy(challenge.ServerChallenge, data[24:32])
	fmt.Printf("Server challenge: %x\n", challenge.ServerChallenge)
	
	
	
	
	if len(data) >= 48 {
		targetInfoLen := binary.LittleEndian.Uint16(data[40:42])
		targetInfoMaxLen := binary.LittleEndian.Uint16(data[42:44])
		targetInfoOffset := binary.LittleEndian.Uint32(data[44:48])
		fmt.Printf("Target info: len=%d, maxlen=%d, offset=%d\n", targetInfoLen, targetInfoMaxLen, targetInfoOffset)
		
		if targetInfoLen > 0 && targetInfoOffset > 0 && targetInfoOffset+uint32(targetInfoLen) <= uint32(len(data)) {
			challenge.TargetInfo = make([]byte, targetInfoLen)
			copy(challenge.TargetInfo, data[targetInfoOffset:targetInfoOffset+uint32(targetInfoLen)])
			fmt.Printf("Target info captured: %d bytes\n", len(challenge.TargetInfo))
		}
	}
	
	fmt.Printf("NTLM Type 2 challenge parsed successfully\n\n")
	return challenge, nil
}

func buildNtlmAuthenticate(domain, user, pass, workstation string, challenge *ntlmChallenge) ([]byte, *ntlmSession, error) {
	domainBytes := toUnicode(domain)
	userBytes := toUnicode(user)
	workstationBytes := toUnicode(workstation)

	
	ntlmV2Hash := ntlm_NTOWFv2(pass, user, domain)

	
	clientChallenge := make([]byte, 8)
	rand.Read(clientChallenge)
	timestamp := (time.Now().Unix() + 11644473600) * 10000000

	
	ntlmV2Resp, ntProofStr := computeNtlmV2Response(ntlmV2Hash, challenge.ServerChallenge, clientChallenge, challenge.TargetInfo, timestamp)
	
	
	sessionKey := deriveNtlmSessionKey(ntlmV2Hash, ntProofStr)
	
	
	session := &ntlmSession{
		SessionKey:      sessionKey,
		ClientChallenge: clientChallenge,
		ServerChallenge: challenge.ServerChallenge,
		NTProofStr:     ntProofStr,
	}

	
	payloadOffset := 64
	msg := make([]byte, payloadOffset+len(domainBytes)+len(userBytes)+len(workstationBytes)+len(ntlmV2Resp))

	copy(msg[0:], []byte(NTLM_SIGNATURE))
	binary.LittleEndian.PutUint32(msg[8:], NTLM_TYPE_AUTHENTICATE)

	
	binary.LittleEndian.PutUint16(msg[28:], uint16(len(domainBytes)))
	binary.LittleEndian.PutUint16(msg[30:], uint16(len(domainBytes)))
	binary.LittleEndian.PutUint32(msg[32:], uint32(payloadOffset))
	copy(msg[payloadOffset:], domainBytes)
	payloadOffset += len(domainBytes)

	
	binary.LittleEndian.PutUint16(msg[36:], uint16(len(userBytes)))
	binary.LittleEndian.PutUint16(msg[38:], uint16(len(userBytes)))
	binary.LittleEndian.PutUint32(msg[40:], uint32(payloadOffset))
	copy(msg[payloadOffset:], userBytes)
	payloadOffset += len(userBytes)

	
	binary.LittleEndian.PutUint16(msg[44:], uint16(len(workstationBytes)))
	binary.LittleEndian.PutUint16(msg[46:], uint16(len(workstationBytes)))
	binary.LittleEndian.PutUint32(msg[48:], uint32(payloadOffset))
	copy(msg[payloadOffset:], workstationBytes)
	payloadOffset += len(workstationBytes)

	
	binary.LittleEndian.PutUint16(msg[20:], uint16(len(ntlmV2Resp)))
	binary.LittleEndian.PutUint16(msg[22:], uint16(len(ntlmV2Resp)))
	binary.LittleEndian.PutUint32(msg[24:], uint32(payloadOffset))
	copy(msg[payloadOffset:], ntlmV2Resp)

	
	binary.LittleEndian.PutUint32(msg[60:], challenge.NegotiateFlags)

	return msg, session, nil
}



func ntlm_NTOWFv2(password, username, domain string) []byte {
	hash := md4Hash(toUnicode(password))
	h := hmac.New(md5.New, hash)
	h.Write(toUnicode(strings.ToUpper(username) + domain))
	return h.Sum(nil)
}


func deriveNtlmSessionKey(ntlmV2Hash, ntProofStr []byte) []byte {
	h := hmac.New(md5.New, ntlmV2Hash)
	h.Write(ntProofStr)
	return h.Sum(nil)
}


func encryptWithRC4(key, data []byte) ([]byte, error) {
	encryptor, err := NewRC4Encryptor(key)
	if err != nil {
		return nil, err
	}
	encrypted := make([]byte, len(data))
	copy(encrypted, data)
	encryptor.Encrypt(encrypted)
	return encrypted, nil
}

func computeNtlmV2Response(ntlmV2Hash, serverChallenge, clientChallenge, targetInfo []byte, timestamp int64) ([]byte, []byte) {
	
	temp := make([]byte, 8+len(targetInfo))
	binary.LittleEndian.PutUint64(temp[0:], uint64(timestamp))
	copy(temp[8:], clientChallenge)

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

func toUnicode(s string) []byte {
	uints := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(uints))
	for i, r := range uints {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}




type md4digest struct {
	s   [4]uint32
	x   [64]byte
	nx  int
	len uint64
}

func (d *md4digest) Reset() {
	d.s[0] = 0x67452301
	d.s[1] = 0xefcdab89
	d.s[2] = 0x98badcfe
	d.s[3] = 0x10325476
	d.nx = 0
	d.len = 0
}

func (d *md4digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == 64 {
			md4Block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= 64 {
		n := len(p) &^ 63
		md4Block(d, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d0 *md4digest) Sum(in []byte) []byte {
	d := *d0
	if in != nil {
		d.Write(in)
	}
	len := d.len
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		d.Write(tmp[0 : 56-len%64])
	} else {
		d.Write(tmp[0 : 64+56-len%64])
	}
	binary.LittleEndian.PutUint64(tmp[0:], len<<3)
	d.Write(tmp[0:8])

	out := make([]byte, 16)
	binary.LittleEndian.PutUint32(out[0:], d.s[0])
	binary.LittleEndian.PutUint32(out[4:], d.s[1])
	binary.LittleEndian.PutUint32(out[8:], d.s[2])
	binary.LittleEndian.PutUint32(out[12:], d.s[3])
	return out
}

func md4Hash(data []byte) []byte {
	d := new(md4digest)
	d.Reset()
	d.Write(data)
	return d.Sum(nil)
}

func md4Block(d *md4digest, p []byte) {
	a, b, c, s := d.s[0], d.s[1], d.s[2], d.s[3]
	x := make([]uint32, 16)
	for len(p) >= 64 {
		for i := 0; i < 16; i++ {
			x[i] = binary.LittleEndian.Uint32(p[i*4:])
		}

		aa, bb, cc, ss := a, b, c, s

		
		for _, i := range []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} {
			sft := []uint{3, 7, 11, 19}[i%4]
			a = a + ((b & c) | (^b & s)) + x[i]
			a = (a << sft) | (a >> (32 - sft))
			a, b, c, s = s, a, b, c
		}

		
		for _, i := range []uint{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15} {
			sft := []uint{3, 5, 9, 13}[i%4]
			a = a + ((b & c) | (b & s) | (c & s)) + x[i] + 0x5a827999
			a = (a << sft) | (a >> (32 - sft))
			a, b, c, s = s, a, b, c
		}

		
		for _, i := range []uint{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15} {
			sft := []uint{3, 9, 11, 15}[i%4]
			a = a + (b ^ c ^ s) + x[i] + 0x6ed9eba1
			a = (a << sft) | (a >> (32 - sft))
			a, b, c, s = s, a, b, c
		}

		a += aa
		b += bb
		c += cc
		s += ss

		p = p[64:]
	}
	d.s[0], d.s[1], d.s[2], d.s[3] = a, b, c, s
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
