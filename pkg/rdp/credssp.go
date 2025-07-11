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
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	CREDSSP_VERSION = 2
)

// TSRequest is the top-level structure for CredSSP messages.
// Ref: [MS-CSSP] section 2.2.1
type TSRequest struct {
	Version    int         `asn1:"tag:0,explicit"`
	NegoTokens []NegoToken `asn1:"optional,tag:1,explicit"`
	AuthInfo   []byte      `asn1:"optional,tag:2,explicit"`
	PubKeyAuth []byte      `asn1:"optional,tag:3,explicit"`
	ErrorCode  uint32      `asn1:"optional,tag:4,explicit"`
}

// NegoToken wraps the NTLM message payload.
type NegoToken struct {
	Token []byte `asn1:"tag:0,explicit"`
}

// PerformCredSSPAuth performs the NLA/CredSSP handshake over an established TLS connection.
// It retrieves credentials from the Client's options.
func (c *Client) PerformCredSSPAuth() error {
	// Use blank credentials if none provided
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

	fmt.Printf("Starting CredSSP authentication (user: %q, domain: %q, has_password: %v)...\n",
		username, domain, password != "")

	// === Step 1: Send NTLM NEGOTIATE_MESSAGE ===
	negotiateMsg, err := buildNtlmNegotiate(domain)
	if err != nil {
		return fmt.Errorf("failed to build NTLM negotiate message: %w", err)
	}

	if err := c.sendCredSSPRequest(negotiateMsg, nil, nil); err != nil {
		return fmt.Errorf("failed to send NTLM Type 1 (Negotiate): %w", err)
	}
	fmt.Println("CredSSP: Sent NTLM Type 1 (Negotiate)")

	// === Step 2: Receive NTLM CHALLENGE_MESSAGE ===
	challengeReq, err := c.receiveCredSSPRequest()
	if err != nil {
		return fmt.Errorf("failed to receive NTLM Type 2 (Challenge): %w", err)
	}

	if len(challengeReq.NegoTokens) == 0 {
		return fmt.Errorf("no NTLM token in server's challenge response")
	}
	challengeMsg, err := parseNtlmChallenge(challengeReq.NegoTokens[0].Token)
	if err != nil {
		return err
	}
	fmt.Println("CredSSP: Received NTLM Type 2 (Challenge)")

	// === Step 3: Send NTLM AUTHENTICATE_MESSAGE ===
	authenticateMsg, err := buildNtlmAuthenticate(domain, username, password, "WORKSTATION", challengeMsg)
	if err != nil {
		return fmt.Errorf("failed to build NTLM Type 3 (Authenticate): %w", err)
	}

	if err := c.sendCredSSPRequest(authenticateMsg, nil, nil); err != nil {
		return fmt.Errorf("failed to send NTLM Type 3 (Authenticate): %w", err)
	}
	fmt.Println("CredSSP: Sent NTLM Type 3 (Authenticate)")

	// === Step 4: Receive final server response with public key hash ===
	finalResp, err := c.receiveCredSSPRequest()
	if err != nil {
		return fmt.Errorf("failed to read final CredSSP response: %w", err)
	}

	// A successful handshake includes a non-nil PubKeyAuth from the server
	if finalResp.PubKeyAuth == nil {
		return fmt.Errorf("NLA authentication failed: server did not return public key hash")
	}

	fmt.Println("CredSSP authentication handshake completed successfully.")
	return nil
}

// sendCredSSPRequest wraps an NTLM message in SPNEGO and TSRequest and sends it.
func (c *Client) sendCredSSPRequest(ntlmMsg, authInfo, pubKeyAuth []byte) error {
	negoToken := NegoToken{Token: ntlmMsg}
	tsReq := TSRequest{
		Version:    CREDSSP_VERSION,
		NegoTokens: []NegoToken{negoToken},
		AuthInfo:   authInfo,
		PubKeyAuth: pubKeyAuth,
	}

	data, err := asn1.Marshal(tsReq)
	if err != nil {
		return fmt.Errorf("failed to marshal TSRequest: %w", err)
	}

	// CredSSP sends raw ASN.1 data over the TLS stream, it does not use TPKT/X.224
	_, err = c.conn.Write(data)
	return err
}

// receiveCredSSPRequest reads the next TSRequest from the server.
func (c *Client) receiveCredSSPRequest() (*TSRequest, error) {
	buf := make([]byte, 8192) // A large buffer to receive the response
	n, err := c.conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read from TLS connection: %w", err)
	}

	var req TSRequest
	_, err = asn1.Unmarshal(buf[:n], &req)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal TSRequest: %w", err)
	}

	return &req, nil
}

// --- NTLM Message Building and Parsing ---

const (
	NTLM_SIGNATURE         = "NTLMSSP\x00"
	NTLM_TYPE_NEGOTIATE    = 1
	NTLM_TYPE_CHALLENGE    = 2
	NTLM_TYPE_AUTHENTICATE = 3
	NEGOTIATE_UNICODE      = 0x0001
	NEGOTIATE_OEM          = 0x0002
	REQUEST_TARGET         = 0x0004
	NEGOTIATE_NTLM_KEY     = 0x0200
	NEGOTIATE_ALWAYS_SIGN  = 0x8000
	NEGOTIATE_NTLM2_KEY    = 0x80000
)

func buildNtlmNegotiate(domain string) ([]byte, error) {
	flags := NEGOTIATE_UNICODE | REQUEST_TARGET | NEGOTIATE_NTLM_KEY | NEGOTIATE_ALWAYS_SIGN | NEGOTIATE_NTLM2_KEY
	domainBytes := toUnicode(domain)

	msg := make([]byte, 32+len(domainBytes))
	copy(msg[0:], []byte(NTLM_SIGNATURE))
	binary.LittleEndian.PutUint32(msg[8:], NTLM_TYPE_NEGOTIATE)
	binary.LittleEndian.PutUint32(msg[12:], uint32(flags))

	// Domain Name
	binary.LittleEndian.PutUint16(msg[16:], uint16(len(domainBytes)))
	binary.LittleEndian.PutUint16(msg[18:], uint16(len(domainBytes)))
	binary.LittleEndian.PutUint32(msg[20:], 32)

	copy(msg[32:], domainBytes)

	return msg, nil
}

type ntlmChallenge struct {
	ServerChallenge []byte
	TargetInfo      []byte
	NegotiateFlags  uint32
}

func parseNtlmChallenge(data []byte) (*ntlmChallenge, error) {
	if string(data[:8]) != NTLM_SIGNATURE || binary.LittleEndian.Uint32(data[8:12]) != NTLM_TYPE_CHALLENGE {
		return nil, fmt.Errorf("invalid NTLM challenge signature")
	}

	challenge := &ntlmChallenge{}
	challenge.ServerChallenge = data[24:32]
	challenge.NegotiateFlags = binary.LittleEndian.Uint32(data[20:24])

	targetInfoLen := binary.LittleEndian.Uint16(data[40:42])
	targetInfoOffset := binary.LittleEndian.Uint32(data[44:48])
	if targetInfoOffset+uint32(targetInfoLen) > uint32(len(data)) {
		return nil, fmt.Errorf("invalid target info offset/length in NTLM challenge")
	}
	challenge.TargetInfo = data[targetInfoOffset : targetInfoOffset+uint32(targetInfoLen)]

	return challenge, nil
}

func buildNtlmAuthenticate(domain, user, pass, workstation string, challenge *ntlmChallenge) ([]byte, error) {
	domainBytes := toUnicode(domain)
	userBytes := toUnicode(user)
	workstationBytes := toUnicode(workstation)

	// NTLMv2 hash of the password
	ntlmV2Hash := ntlm_NTOWFv2(pass, user, domain)

	// Create timestamp and client challenge
	clientChallenge := make([]byte, 8)
	rand.Read(clientChallenge)
	timestamp := (time.Now().Unix() + 11644473600) * 10000000

	// Compute NTLMv2 Response
	ntlmV2Resp, _ := computeNtlmV2Response(ntlmV2Hash, challenge.ServerChallenge, clientChallenge, challenge.TargetInfo, timestamp)

	// Layout of the AUTHENTICATE_MESSAGE
	payloadOffset := 64
	msg := make([]byte, payloadOffset+len(domainBytes)+len(userBytes)+len(workstationBytes)+len(ntlmV2Resp))

	copy(msg[0:], []byte(NTLM_SIGNATURE))
	binary.LittleEndian.PutUint32(msg[8:], NTLM_TYPE_AUTHENTICATE)

	// Domain
	binary.LittleEndian.PutUint16(msg[28:], uint16(len(domainBytes)))
	binary.LittleEndian.PutUint16(msg[30:], uint16(len(domainBytes)))
	binary.LittleEndian.PutUint32(msg[32:], uint32(payloadOffset))
	copy(msg[payloadOffset:], domainBytes)
	payloadOffset += len(domainBytes)

	// User
	binary.LittleEndian.PutUint16(msg[36:], uint16(len(userBytes)))
	binary.LittleEndian.PutUint16(msg[38:], uint16(len(userBytes)))
	binary.LittleEndian.PutUint32(msg[40:], uint32(payloadOffset))
	copy(msg[payloadOffset:], userBytes)
	payloadOffset += len(userBytes)

	// Workstation
	binary.LittleEndian.PutUint16(msg[44:], uint16(len(workstationBytes)))
	binary.LittleEndian.PutUint16(msg[46:], uint16(len(workstationBytes)))
	binary.LittleEndian.PutUint32(msg[48:], uint32(payloadOffset))
	copy(msg[payloadOffset:], workstationBytes)
	payloadOffset += len(workstationBytes)

	// NTLMv2 Response
	binary.LittleEndian.PutUint16(msg[20:], uint16(len(ntlmV2Resp)))
	binary.LittleEndian.PutUint16(msg[22:], uint16(len(ntlmV2Resp)))
	binary.LittleEndian.PutUint32(msg[24:], uint32(payloadOffset))
	copy(msg[payloadOffset:], ntlmV2Resp)

	// Flags
	binary.LittleEndian.PutUint32(msg[60:], challenge.NegotiateFlags)

	return msg, nil
}

// --- Cryptography Implementation ---

func ntlm_NTOWFv2(password, username, domain string) []byte {
	hash := md4Hash(toUnicode(password))
	h := hmac.New(md5.New, hash)
	h.Write(toUnicode(strings.ToUpper(username) + domain))
	return h.Sum(nil)
}

func computeNtlmV2Response(ntlmV2Hash, serverChallenge, clientChallenge, targetInfo []byte, timestamp int64) ([]byte, error) {
	// Create the v2 Client Challenge structure
	temp := make([]byte, 8+len(targetInfo))
	binary.LittleEndian.PutUint64(temp[0:], uint64(timestamp))
	copy(temp[8:], clientChallenge)

	blob := make([]byte, 28+len(targetInfo))
	binary.LittleEndian.PutUint16(blob[0:], 1) // Response version
	binary.LittleEndian.PutUint16(blob[2:], 1) // Hi-response version
	// 4 bytes of Z(4) padding
	binary.LittleEndian.PutUint64(blob[8:], uint64(timestamp))
	copy(blob[16:], clientChallenge)
	// 4 bytes of Z(4) padding
	copy(blob[28:], targetInfo)

	h := hmac.New(md5.New, ntlmV2Hash)
	h.Write(serverChallenge)
	h.Write(blob)
	ntProofStr := h.Sum(nil)

	return append(ntProofStr, blob...), nil
}

func toUnicode(s string) []byte {
	uints := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(uints))
	for i, r := range uints {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}

// --- MD4 Hash Implementation ---

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

		// Round 1
		for _, i := range []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} {
			sft := []uint{3, 7, 11, 19}[i%4]
			a = a + ((b & c) | (^b & s)) + x[i]
			a = (a << sft) | (a >> (32 - sft))
			a, b, c, s = s, a, b, c
		}

		// Round 2
		for _, i := range []uint{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15} {
			sft := []uint{3, 5, 9, 13}[i%4]
			a = a + ((b & c) | (b & s) | (c & s)) + x[i] + 0x5a827999
			a = (a << sft) | (a >> (32 - sft))
			a, b, c, s = s, a, b, c
		}

		// Round 3
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
