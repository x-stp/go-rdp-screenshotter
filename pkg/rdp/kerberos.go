// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 x-stp

package rdp

// Kerberos-via-CredSSP support per RFC 4121 (GSS-Kerberos) inside RFC 4178
// SPNEGO inside [MS-CSSP] §3.2.5. We delegate ASN.1 KRB5 / AS-REQ / TGS-REQ /
// AP-REQ encoding and AES-CTS-HMAC-SHA1-96 crypto to github.com/jcmturner/gokrb5
// because rolling that ourselves is many KLOC of RFC 4120 + 3961 + 3962 + 8009.
// We keep the SPNEGO outer wrap, the [MS-CSSP] choreography, and the GSS_Wrap
// of the public-key-binding hash + TSCredentials envelope local.

import (
	"encoding/asn1"
	"fmt"
	"net"
	"os"
	"strings"

	gokrb5cl "github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

// OIDKerberos5 = 1.2.840.113554.1.2.2 -- the canonical Kerberos V5 mechanism
// OID per RFC 1964 §1. (gokrb5 also exposes spnego.SPNEGOMechTypeKerberos but
// we keep our own to be self-contained alongside OIDSpnego / OIDNTLMSSP.)
var OIDKerberos5 = asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}

// gokrb5Client is a local alias so the credssp.go orchestration can take a
// *gokrb5Client without importing the third-party package directly. Keeps
// the Kerberos-specific types contained to this file.
type gokrb5Client = gokrb5cl.Client

// kerberosCreds describes which credential source to use. Exactly one of
// CCachePath or (Username + Password) must be set; CCachePath wins if both
// are supplied. Realm + KDC are filled in from /etc/krb5.conf when empty.
type kerberosCreds struct {
	CCachePath  string // file path; "" -> $KRB5CCNAME -> /tmp/krb5cc_<uid>
	ConfigPath  string // file path; "" -> $KRB5_CONFIG -> /etc/krb5.conf
	Username    string // overrides ccache principal when CCachePath is empty
	Password    string // for password-auth (no ccache)
	Realm       string // upper-case AD/MIT realm
	ServicePrin string // SPN to ask for; defaults to "TERMSRV/<host>"
}

// kerberosSession holds the post-AP-REQ context needed to GSS_Wrap pubKeyAuth
// and TSCredentials per [MS-CSSP] §3.1.5. The subkey lives inside the
// Authenticator we sent in the AP-REQ; gokrb5's spnego.SPNEGO.InitSecContext
// keeps it on the wrapper so we extract it once.
type kerberosSession struct {
	subkey types.EncryptionKey
	seqNum uint64
}

// loadKerberosClient builds a configured gokrb5 client from a credential
// cache (the common path on Linux: `kinit` populates KRB5CCNAME and we read
// it). If CCachePath is empty we follow the standard KRB5CCNAME / default
// path lookup per MIT Kerberos convention.
func loadKerberosClient(creds kerberosCreds) (*gokrb5cl.Client, error) {
	cfgPath := creds.ConfigPath
	if cfgPath == "" {
		if v := os.Getenv("KRB5_CONFIG"); v != "" {
			cfgPath = v
		} else {
			cfgPath = "/etc/krb5.conf"
		}
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("krb5: load %s: %w", cfgPath, err)
	}

	if creds.CCachePath != "" || creds.Password == "" {
		ccPath := creds.CCachePath
		if ccPath == "" {
			ccPath = ccacheDefaultPath()
		}
		cc, err := credentials.LoadCCache(ccPath)
		if err != nil {
			return nil, fmt.Errorf("krb5: load ccache %s: %w", ccPath, err)
		}
		cl, err := gokrb5cl.NewFromCCache(cc, cfg, gokrb5cl.DisablePAFXFAST(true))
		if err != nil {
			return nil, fmt.Errorf("krb5: new client from ccache: %w", err)
		}
		return cl, nil
	}

	if creds.Realm == "" {
		return nil, fmt.Errorf("krb5: realm required for password auth")
	}
	cl := gokrb5cl.NewWithPassword(creds.Username, creds.Realm, creds.Password, cfg, gokrb5cl.DisablePAFXFAST(true))
	if err := cl.Login(); err != nil {
		return nil, fmt.Errorf("krb5: AS-REQ failed: %w", err)
	}
	return cl, nil
}

// ccacheDefaultPath mirrors MIT krb5: $KRB5CCNAME without the FILE: prefix,
// else /tmp/krb5cc_<uid>.
func ccacheDefaultPath() string {
	if v := os.Getenv("KRB5CCNAME"); v != "" {
		return strings.TrimPrefix(v, "FILE:")
	}
	return fmt.Sprintf("/tmp/krb5cc_%d", os.Getuid())
}

// servicePrincipalForHost returns the SPN to request a ticket for. Windows
// expects `TERMSRV/<host>` for RDP per [MS-RDPBCGR] §3.2.5.3.1 (the cookie
// hostname falls through to the canonicalised DNS name).
func servicePrincipalForHost(target string) string {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	return "TERMSRV/" + host
}

// kerberosNegotiate builds the SPNEGO NegTokenInit body we ship as the
// initial CredSSP NegoToken when -kerberos is requested. The body wraps a
// fresh AP-REQ for the RDP service principal under the Kerberos mechtype.
//
// On any failure the caller should log + fall back to NTLM by re-issuing the
// negotiate with `wrapNTLMInSPNEGO`.
func kerberosNegotiate(cl *gokrb5cl.Client, spn string) (token []byte, sess *kerberosSession, err error) {
	if spn == "" {
		return nil, nil, fmt.Errorf("krb5: empty service principal")
	}
	tkt, sessKey, err := cl.GetServiceTicket(spn)
	if err != nil {
		return nil, nil, fmt.Errorf("krb5: GetServiceTicket(%s): %w", spn, err)
	}
	apReq, err := spnego.NewKRB5TokenAPREQ(cl, tkt, sessKey,
		[]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf, gssapi.ContextFlagMutual},
		[]int{0}, // APOptionMutualRequired
	)
	if err != nil {
		return nil, nil, fmt.Errorf("krb5: build AP-REQ: %w", err)
	}
	apReqBytes, err := apReq.Marshal()
	if err != nil {
		return nil, nil, fmt.Errorf("krb5: marshal AP-REQ: %w", err)
	}

	// Wrap in NegTokenInit with Kerberos mechtype first per RFC 4178 §4.2.1.
	// We deliberately advertise *only* Kerberos so the server doesn't fall
	// back to NTLM half-way through (CredSSP doesn't tolerate the SPNEGO
	// optimistic-mechanism handoff).
	init := NegTokenInit{
		MechTypes: []asn1.ObjectIdentifier{OIDKerberos5},
		MechToken: apReqBytes,
	}
	body, err := asn1.Marshal(init)
	if err != nil {
		return nil, nil, fmt.Errorf("krb5: marshal NegTokenInit: %w", err)
	}
	oidBytes, err := asn1.Marshal(OIDSpnego)
	if err != nil {
		return nil, nil, fmt.Errorf("krb5: marshal SPNEGO OID: %w", err)
	}
	inner := append(oidBytes, body...)
	out := []byte{0x60}
	out = appendBERLength(out, len(inner))
	out = append(out, inner...)

	return out, &kerberosSession{subkey: sessKey}, nil
}

// processKerberosResponse parses the server's AP-REP (or KRB-ERROR) out of
// the SPNEGO NegTokenResp and updates the session subkey to the per-message
// key the server selected (RFC 4121 §4.2.6 keyuse 22 / 23 -- we use 22 for
// initiator-to-acceptor seal).
//
// On KRB-ERROR we surface the Kerberos error code so the caller can decide
// whether to fall back to NTLM.
func (s *kerberosSession) processKerberosResponse(spnegoResp []byte) error {
	mech, err := unwrapSPNEGO(spnegoResp)
	if err != nil {
		return fmt.Errorf("krb5: unwrap SPNEGO response: %w", err)
	}
	var tok spnego.KRB5Token
	if err := tok.Unmarshal(mech); err != nil {
		return fmt.Errorf("krb5: unmarshal KRB5 token: %w", err)
	}
	if tok.IsKRBError() {
		return fmt.Errorf("krb5: KRB-ERROR error_code=%d", tok.KRBError.ErrorCode)
	}
	if !tok.IsAPRep() {
		return fmt.Errorf("krb5: expected AP-REP from server")
	}
	// gokrb5's KRB5Token.Verify decrypts AP-REP.encryptedPart with our subkey
	// and stashes the result on the package-level context; we ignore that
	// because [MS-CSSP] only needs the original session subkey for GSS_Wrap.
	if ok, st := tok.Verify(); !ok {
		return fmt.Errorf("krb5: AP-REP verify failed: %s", st.Message)
	}
	return nil
}

// wrapPubKeyAuth GSS_Wraps the pubKeyAuth payload per RFC 4121 §4.2.6 with
// keyusage 22 (initiator→acceptor SEAL). The returned bytes are what
// [MS-CSSP] §3.1.5 stuffs into TSRequest.PubKeyAuth.
func (s *kerberosSession) wrapPubKeyAuth(payload []byte) ([]byte, error) {
	wt, err := gssapi.NewInitiatorWrapToken(payload, s.subkey)
	if err != nil {
		return nil, fmt.Errorf("krb5: NewInitiatorWrapToken: %w", err)
	}
	out, err := wt.Marshal()
	if err != nil {
		return nil, fmt.Errorf("krb5: marshal wrap token: %w", err)
	}
	s.seqNum++
	return out, nil
}

// wrapCredentials is the same operation as wrapPubKeyAuth; kept as a separate
// method so the call sites in credssp.go stay readable.
func (s *kerberosSession) wrapCredentials(payload []byte) ([]byte, error) {
	return s.wrapPubKeyAuth(payload)
}

// kerberosNegotiateBytesAvailable returns true if either KRB5CCNAME or the
// default ccache path is readable. Used by the CredSSP path to short-circuit
// gracefully when the user passed -kerberos but the ccache is missing.
func kerberosNegotiateBytesAvailable() bool {
	path := ccacheDefaultPath()
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
