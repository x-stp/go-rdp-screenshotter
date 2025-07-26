















package rdp

import (
	"encoding/asn1"
	"fmt"
)


var (
	OIDSpnego    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}
	OIDNTLMSSP   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}
	OIDKerberos5 = asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}
)


type NegTokenInit struct {
	MechTypes    []asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
	ReqFlags     asn1.BitString          `asn1:"explicit,optional,tag:1"`
	MechToken    []byte                  `asn1:"explicit,optional,tag:2"`
	MechListMIC  []byte                  `asn1:"explicit,optional,tag:3"`
}


type NegTokenResp struct {
	NegState      asn1.Enumerated         `asn1:"explicit,optional,tag:0"`
	SupportedMech asn1.ObjectIdentifier   `asn1:"explicit,optional,tag:1"`
	ResponseToken []byte                  `asn1:"explicit,optional,tag:2"`
	MechListMIC   []byte                  `asn1:"explicit,optional,tag:3"`
}


const (
	AcceptCompleted   = 0
	AcceptIncomplete  = 1
	Reject           = 2
	RequestMIC       = 3
)


func wrapNTLMInSPNEGO(ntlmMsg []byte, isInitial bool) ([]byte, error) {
	fmt.Printf("\nDEBUG: wrapNTLMInSPNEGO called with isInitial=%v, ntlmMsg len=%d\n", isInitial, len(ntlmMsg))
	
	if isInitial {
		
		negTokenInit := NegTokenInit{
			MechTypes: []asn1.ObjectIdentifier{OIDNTLMSSP},
			MechToken: ntlmMsg,
		}
		
		
		tokenBytes, err := asn1.Marshal(negTokenInit)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal NegTokenInit: %w", err)
		}
		
		
		
		
		var result []byte
		result = append(result, 0x60) 
		
		
		if len(tokenBytes) < 128 {
			result = append(result, byte(len(tokenBytes)))
		} else if len(tokenBytes) < 256 {
			result = append(result, 0x81, byte(len(tokenBytes)))
		} else {
			result = append(result, 0x82, byte(len(tokenBytes)>>8), byte(len(tokenBytes)))
		}
		
		result = append(result, tokenBytes...)
		
		fmt.Printf("DEBUG: Built SPNEGO NegTokenInit wrapper, total size=%d\n", len(result))
		return result, nil
	} else {
		
		negTokenResp := NegTokenResp{
			NegState:      AcceptIncomplete,
			ResponseToken: ntlmMsg,
		}
		
		
		tokenBytes, err := asn1.Marshal(negTokenResp)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal NegTokenResp: %w", err)
		}
		
		
		
		var result []byte
		result = append(result, 0xa1) 
		
		
		if len(tokenBytes) < 128 {
			result = append(result, byte(len(tokenBytes)))
		} else if len(tokenBytes) < 256 {
			result = append(result, 0x81, byte(len(tokenBytes)))
		} else {
			result = append(result, 0x82, byte(len(tokenBytes)>>8), byte(len(tokenBytes)))
		}
		
		result = append(result, tokenBytes...)
		
		fmt.Printf("DEBUG: Built SPNEGO NegTokenResp wrapper, total size=%d\n", len(result))
		return result, nil
	}
}


func unwrapSPNEGO(spnegoData []byte) ([]byte, error) {
	var raw asn1.RawValue
	_, err := asn1.Unmarshal(spnegoData, &raw)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal SPNEGO wrapper: %w", err)
	}
	
	
	if raw.Class == asn1.ClassApplication && raw.Tag == 0 {
		
		var negTokenInit NegTokenInit
		_, err = asn1.Unmarshal(raw.Bytes, &negTokenInit)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal NegTokenInit: %w", err)
		}
		return negTokenInit.MechToken, nil
	} else if raw.Class == 2 && raw.Tag == 1 { 
		
		var negTokenResp NegTokenResp
		_, err = asn1.Unmarshal(raw.Bytes, &negTokenResp)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal NegTokenResp: %w", err)
		}
		return negTokenResp.ResponseToken, nil
	}
	
	return nil, fmt.Errorf("unknown SPNEGO token type")
}