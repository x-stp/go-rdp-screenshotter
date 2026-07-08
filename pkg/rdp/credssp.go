// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 x-stp

package rdp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"strings"
)

const credSSPVersion = 3

// TSRequest is the outermost CredSSP message ([MS-CSSP] §2.2.1) carrying the
// SPNEGO/NTLMSSP NegoTokens, the encrypted public-key auth blob, the
// encrypted credentials envelope, and the protocol version.
type TSRequest struct {
	Version     int      `asn1:"explicit,tag:0"`
	NegoTokens  NegoData `asn1:"explicit,optional,tag:1"`
	AuthInfo    []byte   `asn1:"explicit,optional,tag:2"`
	PubKeyAuth  []byte   `asn1:"explicit,optional,tag:3"`
	ErrorCode   int      `asn1:"explicit,optional,tag:4"`
	ClientNonce []byte   `asn1:"explicit,optional,tag:5"`
}

type NegoData []NegoToken

type NegoToken struct {
	Token []byte `asn1:"explicit,tag:0"`
}

// TSCredentials per [MS-CSSP] §2.2.1.2 -- credType=1 means TSPasswordCreds.
type TSCredentials struct {
	CredType    int    `asn1:"explicit,tag:0"`
	Credentials []byte `asn1:"explicit,tag:1"`
}

type TSPasswordCreds struct {
	DomainName []byte `asn1:"explicit,tag:0"`
	UserName   []byte `asn1:"explicit,tag:1"`
	Password   []byte `asn1:"explicit,tag:2"`
}

// credSSPAuth describes the user inputs that drive PerformCredSSPAuth. It's a
// thin convenience over ClientOptions so the helpers below don't have to keep
// re-deriving anonymous/workstation from opts.
type credSSPAuth struct {
	domain, username, password string
	anonymous                  bool // [MS-NLMP] §3.1.5.1.2 null session
	workstation                string
}

func (c *Client) credSSPInputs() credSSPAuth {
	a := credSSPAuth{workstation: "WORKSTATION"}
	if c.opts == nil {
		return a
	}
	a.domain = c.opts.Domain
	a.username = c.opts.Username
	a.password = c.opts.Password
	a.anonymous = c.opts.AnonymousNLA && a.password == ""
	if a.anonymous {
		a.workstation = ""
	}
	return a
}

// PerformCredSSPAuth runs the full CredSSP/NLA exchange over the (already
// TLS-upgraded) connection. Phases per [MS-CSSP] §3.2.5:
//
//  1. Send NTLM Type 1 wrapped in a SPNEGO NegTokenInit.
//  2. Receive NTLM Type 2 wrapped in a SPNEGO NegTokenResp.
//  3. Send NTLM Type 3 + sealed pubKeyAuth (and ClientNonce for v5+).
//  4. Receive server's pubKeyAuth response (or error).
//  5. Send the sealed TSCredentials envelope (skipped in anonymous mode).
//
// When opts.Kerberos is set we attempt RFC 4121 GSS-Kerberos in step 1
// instead of NTLM (mech-list contains only OIDKerberos5). Failure at any
// stage of the Kerberos branch logs and falls through to the NTLM path
// below, so the same flag works for AD-joined and standalone hosts.
func (c *Client) PerformCredSSPAuth() error {
	Logger.Debug().Msg("credssp: starting authentication")

	if c.opts != nil && c.opts.Kerberos {
		if err := c.performKerberosCredSSP(); err == nil {
			return nil
		} else {
			Logger.Warn().Err(err).Msg("credssp: kerberos branch failed; falling back to NTLM")
		}
	}

	in := c.credSSPInputs()
	Logger.Debug().Str("user", in.username).Str("domain", in.domain).Bool("anonymous", in.anonymous).Int("version", credSSPVersion).Msg("credssp: negotiating (NTLM)")

	challenge, serverVersion, err := c.ntlmExchangeChallenge(in)
	if err != nil {
		return err
	}

	pubKeyInfo, err := c.serverSubjectPublicKey()
	if err != nil {
		return err
	}

	seqNum, accepted, err := c.ntlmAuthenticateAndBindPubKey(in, challenge, pubKeyInfo, serverVersion)
	if err != nil || !accepted {
		return err
	}
	return c.sendNTLMCredentials(in, seqNum)
}

// ntlmExchangeChallenge runs the NTLM Type-1 / Type-2 round trip wrapped in
// SPNEGO. Returns the parsed challenge and the negotiated CredSSP version
// the server wants us to use for the pubKeyAuth binding ([MS-CSSP] §3.1.5).
func (c *Client) ntlmExchangeChallenge(in credSSPAuth) (*ntlmChallenge, int, error) {
	negotiateMsg, err := buildNtlmNegotiate(in.domain, in.anonymous)
	if err != nil {
		return nil, 0, fmt.Errorf("build NTLM negotiate: %w", err)
	}
	spnegoInit, err := wrapNTLMInSPNEGO(negotiateMsg, true)
	if err != nil {
		return nil, 0, fmt.Errorf("wrap negotiate in SPNEGO: %w", err)
	}
	if err := c.sendTSRequest(&TSRequest{
		Version:    credSSPVersion,
		NegoTokens: NegoData{{Token: spnegoInit}},
	}); err != nil {
		return nil, 0, fmt.Errorf("send negotiate TSRequest: %w", err)
	}
	Logger.Debug().Msg("credssp: sent NTLM Type 1 (Negotiate) in SPNEGO")

	resp, err := c.receiveTSRequest()
	if err != nil {
		return nil, 0, fmt.Errorf("receive challenge: %w", err)
	}
	if resp.ErrorCode != 0 {
		return nil, 0, fmt.Errorf("server error code: 0x%08x", uint32(resp.ErrorCode))
	}
	if len(resp.NegoTokens) == 0 {
		return nil, 0, fmt.Errorf("no NTLM token in server challenge")
	}
	ntlmToken, err := unwrapSPNEGO(resp.NegoTokens[0].Token)
	if err != nil {
		return nil, 0, fmt.Errorf("unwrap SPNEGO challenge: %w", err)
	}
	challenge, err := parseNtlmChallenge(ntlmToken)
	if err != nil {
		return nil, 0, err
	}
	Logger.Debug().Msg("credssp: received NTLM Type 2 (Challenge)")

	serverVersion := resp.Version
	if serverVersion < 2 {
		serverVersion = credSSPVersion
	}
	return challenge, serverVersion, nil
}

// ntlmAuthenticateAndBindPubKey sends the NTLM Type-3 message with the
// public-key-binding pubKeyAuth piggy-backed on the same TSRequest, then
// validates the server's response. Returns the next free sequence number for
// the credentials envelope, plus a bool telling the caller whether to send
// credentials at all (false in anonymous mode where the server rejected).
func (c *Client) ntlmAuthenticateAndBindPubKey(in credSSPAuth, challenge *ntlmChallenge, pubKeyInfo []byte, serverVersion int) (uint32, bool, error) {
	authenticateMsg, sess, err := buildNtlmAuthenticate(in.domain, in.username, in.password, in.workstation, challenge, in.anonymous)
	if err != nil {
		return 0, false, fmt.Errorf("build NTLM authenticate: %w", err)
	}
	c.ntlmSession = sess

	pubKeyAuth, clientNonce, nextSeq, err := c.sealPubKeyAuth(serverVersion, pubKeyInfo)
	if err != nil {
		return 0, false, err
	}
	spnegoResp, err := wrapNTLMInSPNEGO(authenticateMsg, false)
	if err != nil {
		return 0, false, fmt.Errorf("wrap authenticate in SPNEGO: %w", err)
	}
	req := &TSRequest{
		Version:     credSSPVersion,
		NegoTokens:  NegoData{{Token: spnegoResp}},
		PubKeyAuth:  pubKeyAuth,
		ClientNonce: clientNonce,
	}
	if err := c.sendTSRequest(req); err != nil {
		return 0, false, fmt.Errorf("send authenticate TSRequest: %w", err)
	}
	Logger.Debug().Msg("credssp: sent NTLM Type 3 (Authenticate) with pubKeyAuth")

	resp, err := c.receiveTSRequest()
	if err != nil {
		return 0, false, fmt.Errorf("receive pubKeyAuth response: %w", err)
	}
	if resp.ErrorCode != 0 {
		if in.anonymous {
			Logger.Debug().Uint32("errorCode", uint32(resp.ErrorCode)).Msg("credssp: anonymous auth rejected as expected")
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("server rejected auth, error code: 0x%08x", uint32(resp.ErrorCode))
	}
	if resp.PubKeyAuth == nil && !in.anonymous {
		return 0, false, fmt.Errorf("NLA auth failed: no pubKeyAuth in server response")
	}
	Logger.Debug().Msg("credssp: server pubKeyAuth received, validation accepted")

	if in.anonymous {
		Logger.Info().Msg("credssp: anonymous session accepted")
		return 0, false, nil
	}
	return nextSeq, true, nil
}

// sendNTLMCredentials seals and ships the TSCredentials envelope (step 5).
func (c *Client) sendNTLMCredentials(in credSSPAuth, seqNum uint32) error {
	tsCredsBytes, err := marshalTSPasswordCreds(in.domain, in.username, in.password)
	if err != nil {
		return err
	}
	encrypted, err := ntlmSeal(c.ntlmSession.SessionKey, seqNum, tsCredsBytes)
	if err != nil {
		return fmt.Errorf("seal credentials: %w", err)
	}
	if err := c.sendTSRequest(&TSRequest{
		Version:  credSSPVersion,
		AuthInfo: encrypted,
	}); err != nil {
		return fmt.Errorf("send credentials TSRequest: %w", err)
	}
	Logger.Info().Msg("credssp: authentication completed")
	return nil
}

// performKerberosCredSSP runs steps 1-5 of [MS-CSSP] §3.2.5 with Kerberos as
// the underlying GSS mechanism. On any error the caller falls back to NTLM.
func (c *Client) performKerberosCredSSP() error {
	if !kerberosNegotiateBytesAvailable() && (c.opts == nil || c.opts.Password == "") {
		return fmt.Errorf("no Kerberos credential cache and no password supplied")
	}
	cl, err := loadKerberosClient(kerberosCreds{
		CCachePath: c.opts.KerberosCCache,
		ConfigPath: c.opts.KerberosConfig,
		Username:   c.opts.Username,
		Password:   c.opts.Password,
		Realm:      strings.ToUpper(c.opts.Domain),
	})
	if err != nil {
		return err
	}
	defer cl.Destroy()

	if err := c.kerberosAPExchange(cl); err != nil {
		return err
	}

	pubKeyInfo, err := c.serverSubjectPublicKey()
	if err != nil {
		return err
	}
	if err := c.kerberosBindPubKey(pubKeyInfo); err != nil {
		return err
	}
	return c.sendKerberosCredentials()
}

// kerberosAPExchange does the AP-REQ / AP-REP round trip and stashes the
// resulting session subkey on c.kerberosSess for the GSS_Wrap calls below.
func (c *Client) kerberosAPExchange(cl *gokrb5Client) error {
	spn := servicePrincipalForHost(c.target)
	apReqToken, sess, err := kerberosNegotiate(cl, spn)
	if err != nil {
		return err
	}
	c.kerberosSess = sess

	if err := c.sendTSRequest(&TSRequest{
		Version:    credSSPVersion,
		NegoTokens: NegoData{{Token: apReqToken}},
	}); err != nil {
		return fmt.Errorf("send AP-REQ TSRequest: %w", err)
	}
	Logger.Debug().Str("spn", spn).Msg("credssp: sent Kerberos AP-REQ in SPNEGO")

	resp, err := c.receiveTSRequest()
	if err != nil {
		return fmt.Errorf("receive AP-REP: %w", err)
	}
	if resp.ErrorCode != 0 {
		return fmt.Errorf("server error during Kerberos: 0x%08x", uint32(resp.ErrorCode))
	}
	if len(resp.NegoTokens) == 0 {
		return fmt.Errorf("no AP-REP token in server response")
	}
	if err := c.kerberosSess.processKerberosResponse(resp.NegoTokens[0].Token); err != nil {
		return err
	}
	Logger.Debug().Msg("credssp: AP-REP verified")
	return nil
}

// kerberosBindPubKey GSS_Wraps the SubjectPublicKeyInfo and sends it in a
// fresh TSRequest, awaiting the server's ack.
func (c *Client) kerberosBindPubKey(pubKeyInfo []byte) error {
	pubKeyAuth, err := c.kerberosSess.wrapPubKeyAuth(pubKeyInfo)
	if err != nil {
		return err
	}
	if err := c.sendTSRequest(&TSRequest{
		Version:    credSSPVersion,
		PubKeyAuth: pubKeyAuth,
	}); err != nil {
		return fmt.Errorf("send pubKeyAuth: %w", err)
	}
	Logger.Debug().Msg("credssp: sent GSS-wrapped pubKeyAuth")

	resp, err := c.receiveTSRequest()
	if err != nil {
		return fmt.Errorf("receive pubKeyAuth response: %w", err)
	}
	if resp.ErrorCode != 0 {
		return fmt.Errorf("server rejected pubKeyAuth: 0x%08x", uint32(resp.ErrorCode))
	}
	return nil
}

func (c *Client) sendKerberosCredentials() error {
	tsCredsBytes, err := marshalTSPasswordCreds(c.opts.Domain, c.opts.Username, c.opts.Password)
	if err != nil {
		return err
	}
	wrapped, err := c.kerberosSess.wrapCredentials(tsCredsBytes)
	if err != nil {
		return err
	}
	if err := c.sendTSRequest(&TSRequest{
		Version:  credSSPVersion,
		AuthInfo: wrapped,
	}); err != nil {
		return fmt.Errorf("send credentials: %w", err)
	}
	Logger.Info().Msg("credssp: Kerberos authentication completed")
	return nil
}

// serverSubjectPublicKey extracts the TLS server's PKIX-marshalled public
// key for use as the channel-binding payload in pubKeyAuth.
func (c *Client) serverSubjectPublicKey() ([]byte, error) {
	if c.tlsCertificate == nil {
		return nil, fmt.Errorf("no TLS certificate for public key verification")
	}
	cert, err := x509.ParseCertificate(c.tlsCertificate)
	if err != nil {
		return nil, fmt.Errorf("parse TLS certificate: %w", err)
	}
	pubKeyInfo, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	return pubKeyInfo, nil
}

// marshalTSPasswordCreds builds the inner CredSSP credentials envelope used
// by both NTLM and Kerberos paths so the call sites stay symmetric.
func marshalTSPasswordCreds(domain, username, password string) ([]byte, error) {
	pwd, err := asn1.Marshal(TSPasswordCreds{
		DomainName: toUnicode(domain),
		UserName:   toUnicode(username),
		Password:   toUnicode(password),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal TSPasswordCreds: %w", err)
	}
	return asn1.Marshal(TSCredentials{CredType: 1, Credentials: pwd})
}

// sealPubKeyAuth produces the pubKeyAuth blob per [MS-CSSP] §3.1.5.
//   - v5+: NTLM-seal SHA256("CredSSP Client-To-Server Binding Hash\x00" ||
//     ClientNonce || SubjectPublicKey).
//   - v2-4: NTLM-seal raw SubjectPublicKey.
//
// The next free sequence number for the credentials envelope is returned.
func (c *Client) sealPubKeyAuth(serverVersion int, subjectPubKeyInfo []byte) (pubKeyAuth, clientNonce []byte, nextSeq uint32, err error) {
	const seqNum uint32 = 0
	if serverVersion >= 5 {
		clientNonce = make([]byte, 32)
		if _, err = rand.Read(clientNonce); err != nil {
			return nil, nil, 0, fmt.Errorf("rand for ClientNonce: %w", err)
		}
		h := sha256.New()
		h.Write([]byte("CredSSP Client-To-Server Binding Hash\x00"))
		h.Write(clientNonce)
		h.Write(subjectPubKeyInfo)
		pubKeyAuth, err = ntlmSeal(c.ntlmSession.SessionKey, seqNum, h.Sum(nil))
	} else {
		pubKeyAuth, err = ntlmSeal(c.ntlmSession.SessionKey, seqNum, subjectPubKeyInfo)
	}
	if err != nil {
		return nil, nil, 0, fmt.Errorf("seal pubKeyAuth: %w", err)
	}
	return pubKeyAuth, clientNonce, seqNum + 1, nil
}

// sendTSRequest marshals a TSRequest and writes it to the TLS connection.
func (c *Client) sendTSRequest(req *TSRequest) error {
	data, err := asn1.Marshal(*req)
	if err != nil {
		return fmt.Errorf("marshal TSRequest: %w", err)
	}
	_, err = c.conn.Write(data)
	return err
}

// receiveTSRequest reads exactly one BER-framed TSRequest from the TLS
// connection. The frame size is taken from the outer SEQUENCE length field,
// so this works under arbitrary TCP fragmentation.
func (c *Client) receiveTSRequest() (*TSRequest, error) {
	frame, err := readBERFrame(c.conn)
	if err != nil {
		return nil, fmt.Errorf("read TSRequest: %w", err)
	}
	var req TSRequest
	if _, err := asn1.Unmarshal(frame, &req); err != nil {
		return nil, fmt.Errorf("unmarshal TSRequest: %w", err)
	}
	return &req, nil
}

// readBERFrame reads a single BER-encoded SEQUENCE (tag 0x30) from r and
// returns the full TLV. Long-form lengths up to 4 bytes are accepted, which
// is comfortably more than any TSRequest the spec permits (16 KiB).
func readBERFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 0x30 {
		return nil, fmt.Errorf("ber: expected SEQUENCE tag, got 0x%02x", hdr[0])
	}

	var contentLen, nLen int
	var lenBytes [4]byte
	if hdr[1]&0x80 == 0 {
		contentLen = int(hdr[1])
	} else {
		nLen = int(hdr[1] & 0x7F)
		if nLen == 0 || nLen > 4 {
			return nil, fmt.Errorf("ber: bad long-form length nLen=%d", nLen)
		}
		if _, err := io.ReadFull(r, lenBytes[:nLen]); err != nil {
			return nil, err
		}
		for i := 0; i < nLen; i++ {
			contentLen = (contentLen << 8) | int(lenBytes[i])
		}
	}

	out := make([]byte, 2+nLen+contentLen)
	out[0], out[1] = hdr[0], hdr[1]
	copy(out[2:], lenBytes[:nLen])
	if _, err := io.ReadFull(r, out[2+nLen:]); err != nil {
		return nil, err
	}
	return out, nil
}
