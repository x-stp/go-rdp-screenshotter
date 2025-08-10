package rdp

import (
	"encoding/asn1"
	"fmt"
)

// SPNEGO and NTLMSSP mechanism OIDs per RFC 4178 §4.1 and [MS-NLMP].
var (
	OIDSpnego  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}
	OIDNTLMSSP = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}
)

type NegTokenInit struct {
	MechTypes   []asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
	ReqFlags    asn1.BitString          `asn1:"explicit,optional,tag:1"`
	MechToken   []byte                  `asn1:"explicit,optional,tag:2"`
	MechListMIC []byte                  `asn1:"explicit,optional,tag:3"`
}

type NegTokenResp struct {
	NegState      asn1.Enumerated       `asn1:"explicit,optional,tag:0"`
	SupportedMech asn1.ObjectIdentifier `asn1:"explicit,optional,tag:1"`
	ResponseToken []byte                `asn1:"explicit,optional,tag:2"`
	MechListMIC   []byte                `asn1:"explicit,optional,tag:3"`
}

const (
	AcceptCompleted  = 0
	AcceptIncomplete = 1
	Reject           = 2
	RequestMIC       = 3
)

// wrapNTLMInSPNEGO wraps an NTLM message per RFC 4178 §4.2: NegTokenInit for
// the initial Type 1 Negotiate, NegTokenResp for subsequent Type 3 messages.
func wrapNTLMInSPNEGO(ntlmMsg []byte, isInitial bool) ([]byte, error) {
	if isInitial {
		negTokenInit := NegTokenInit{
			MechTypes: []asn1.ObjectIdentifier{OIDNTLMSSP},
			MechToken: ntlmMsg,
		}

		tokenBytes, err := asn1.Marshal(negTokenInit)
		if err != nil {
			return nil, fmt.Errorf("marshal NegTokenInit: %w", err)
		}

		// GSS-API InitialContextToken per RFC 2743 §3.1: APPLICATION[0]
		// { mechanism OID, innerContextToken }.
		oidBytes, err := asn1.Marshal(OIDSpnego)
		if err != nil {
			return nil, fmt.Errorf("marshal SPNEGO OID: %w", err)
		}

		innerPayload := append(oidBytes, tokenBytes...)

		out := []byte{0x60}
		out = appendBERLength(out, len(innerPayload))
		out = append(out, innerPayload...)
		return out, nil
	}

	tokenBytes, err := asn1.Marshal(NegTokenResp{
		NegState:      AcceptIncomplete,
		ResponseToken: ntlmMsg,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal NegTokenResp: %w", err)
	}

	// CONTEXT[1] CONSTRUCTED wrap.
	out := []byte{0xa1}
	out = appendBERLength(out, len(tokenBytes))
	return append(out, tokenBytes...), nil
}

// unwrapSPNEGO extracts the NTLM mechanism token from either a NegTokenInit
// (with the GSS-API InitialContextToken outer wrap) or a NegTokenResp.
func unwrapSPNEGO(spnegoData []byte) ([]byte, error) {
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(spnegoData, &raw); err != nil {
		return nil, fmt.Errorf("unmarshal SPNEGO wrapper: %w", err)
	}

	switch {
	case raw.Class == asn1.ClassApplication && raw.Tag == 0:
		var oid asn1.ObjectIdentifier
		rest, err := asn1.Unmarshal(raw.Bytes, &oid)
		if err != nil {
			return nil, fmt.Errorf("unmarshal SPNEGO OID: %w", err)
		}
		var init NegTokenInit
		if _, err := asn1.Unmarshal(rest, &init); err != nil {
			return nil, fmt.Errorf("unmarshal NegTokenInit: %w", err)
		}
		return init.MechToken, nil
	case raw.Class == asn1.ClassContextSpecific && raw.Tag == 1:
		var resp NegTokenResp
		if _, err := asn1.Unmarshal(raw.Bytes, &resp); err != nil {
			return nil, fmt.Errorf("unmarshal NegTokenResp: %w", err)
		}
		return resp.ResponseToken, nil
	}
	return nil, fmt.Errorf("unknown SPNEGO token type: class=%d tag=%d", raw.Class, raw.Tag)
}

func appendBERLength(buf []byte, length int) []byte {
	if length < 128 {
		return append(buf, byte(length))
	} else if length < 256 {
		return append(buf, 0x81, byte(length))
	}
	return append(buf, 0x82, byte(length>>8), byte(length))
}
