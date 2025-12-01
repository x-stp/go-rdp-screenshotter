package rdp

import (
	"encoding/asn1"
	"fmt"
)

// OIDs for SPNEGO and NTLM
var (
	OIDSpnego    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}
	OIDNTLMSSP   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}
	OIDKerberos5 = asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}
)

// NegTokenInit represents the initial negotiation token (client -> server)
// Defined in RFC 4178 / MS-SPNG
type NegTokenInit struct {
	MechTypes []asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
	ReqFlags  asn1.BitString          `asn1:"explicit,optional,tag:1"`
	MechToken []byte                  `asn1:"explicit,optional,tag:2"`
	// MS-SPNG Extension: NegHints at tag 3
	NegHints asn1.RawValue `asn1:"explicit,optional,tag:3"`
	// RFC 4178 defines MechListMIC at tag 3, but MS moves it to tag 4 if hints are present.
	// We handle this by checking the tag of the raw value at tag 3 or looking for tag 4 manually if needed.
	// For simplicity in this struct, we map tag 4 to MechListMIC.
	MechListMIC []byte `asn1:"explicit,optional,tag:4"`
}

// NegTokenResp represents the response negotiation token (server <-> client)
// Defined in RFC 4178 / MS-SPNG
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

// wrapNTLMInSPNEGO wraps an NTLM message in a SPNEGO token.
// isInitial should be true for NTLM Type 1 (Negotiate), false for Type 3 (Authenticate).
func wrapNTLMInSPNEGO(ntlmMsg []byte, isInitial bool) ([]byte, error) {
	fmt.Printf("\nDEBUG: wrapNTLMInSPNEGO called with isInitial=%v, ntlmMsg len=%d\n", isInitial, len(ntlmMsg))

	if isInitial {
		// For NTLM Type 1, we send NegTokenInit
		// [MS-SPNG] Section 2: The NegTokenInit is wrapped in the GSS-API InitialContextToken
		// RFC 4178 Section 4.2.1: NegTokenInit ::= SEQUENCE { ... }

		negTokenInit := NegTokenInit{
			MechTypes: []asn1.ObjectIdentifier{OIDNTLMSSP},
			MechToken: ntlmMsg,
		}

		negTokenInitBytes, err := asn1.Marshal(negTokenInit)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal NegTokenInit: %w", err)
		}

		// NegotiationToken ::= CHOICE {
		//    negTokenInit    [0] NegTokenInit,
		//    negTokenTarg    [1] NegTokenTarg
		// }
		// We need to wrap NegTokenInit in [0] EXPLICIT context-specific tag (0xA0)

		// Manual wrapping for [0] EXPLICIT
		negotiationToken := append([]byte{0xa0}, encodeLength(len(negTokenInitBytes))...)
		negotiationToken = append(negotiationToken, negTokenInitBytes...)

		// GSS-API InitialContextToken ::= [APPLICATION 0] IMPLICIT SEQUENCE {
		//    thisMech MechType,
		//    innerContextToken ANY DEFINED BY thisMech
		// }
		// For SPNEGO, thisMech is 1.3.6.1.5.5.2

		oidBytes, err := asn1.Marshal(OIDSpnego)
		if err != nil {
			return nil, err
		}
		// asn1.Marshal wraps OID in 0x06 tag.

		// GSS-API token format: [Application 0] [Length] [OID] [NegotiationToken]

		totalLen := len(oidBytes) + len(negotiationToken)

		gssHeader := append([]byte{0x60}, encodeLength(totalLen)...)
		gssHeader = append(gssHeader, oidBytes...)
		gssHeader = append(gssHeader, negotiationToken...)

		fmt.Printf("DEBUG: Built SPNEGO NegTokenInit wrapper, total size=%d\n", len(gssHeader))
		return gssHeader, nil

	} else {
		// For NTLM Type 3, we send NegTokenResp
		// [MS-SPNG] Section 2: Subsequent tokens are NOT wrapped in GSS-API header, just NegotiationToken
		// RFC 4178 Section 4.2.2: NegTokenResp ::= SEQUENCE { ... }

		negTokenResp := NegTokenResp{
			// NegState is optional, but usually omitted in the client's final response or set to AcceptCompleted if done
			// However, for NTLM Type 3, we are just sending the token.
			ResponseToken: ntlmMsg,
		}

		negTokenRespBytes, err := asn1.Marshal(negTokenResp)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal NegTokenResp: %w", err)
		}

		// NegotiationToken ::= CHOICE {
		//    negTokenInit    [0] NegTokenInit,
		//    negTokenTarg    [1] NegTokenTarg
		// }
		// We need to wrap NegTokenResp in [1] EXPLICIT context-specific tag (0xA1)

		negotiationToken := append([]byte{0xa1}, encodeLength(len(negTokenRespBytes))...)
		negotiationToken = append(negotiationToken, negTokenRespBytes...)

		fmt.Printf("DEBUG: Built SPNEGO NegTokenResp wrapper, total size=%d\n", len(negotiationToken))
		return negotiationToken, nil
	}
}

// encodeLength encodes the length of an ASN.1 value
func encodeLength(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}
	if length < 256 {
		return []byte{0x81, byte(length)}
	}
	return []byte{0x82, byte(length >> 8), byte(length)}
}

// unwrapSPNEGO extracts the NTLM message from a SPNEGO token
func unwrapSPNEGO(spnegoData []byte) ([]byte, error) {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(spnegoData, &raw)
	if err != nil {
		return nil, fmt.Errorf("SPNEGO wrapper decode failed: %w", err)
	}
	if len(rest) > 0 {
		fmt.Printf("DEBUG: SPNEGO wrapper has %d bytes of trailing data\n", len(rest))
	}

	// Critical Fix: Check for ContextSpecific, not Application
	if raw.Class != asn1.ClassContextSpecific {
		// It might be a GSS-API header [Application 0]
		if raw.Class == asn1.ClassApplication && raw.Tag == 0 {
			// This is likely a GSS-API wrapped NegTokenInit
			// We need to parse inside to find the NegotiationToken
			// The structure is [OID] [NegotiationToken]

			// Skip OID. OID is encoded as [Tag] [Length] [Value...]
			// Tag for OID is 0x06
			if len(raw.Bytes) < 2 {
				return nil, fmt.Errorf("GSS-API token too short")
			}

			if raw.Bytes[0] != 0x06 {
				return nil, fmt.Errorf("expected OID at start of GSS-API token")
			}

			// Parse OID length
			offset := 1
			oidLen := int(raw.Bytes[offset])
			offset++
			if oidLen&0x80 != 0 {
				lenBytes := oidLen & 0x7F
				if len(raw.Bytes) < offset+lenBytes {
					return nil, fmt.Errorf("invalid OID length")
				}
				// Simplified length parsing for now
				oidLen = 0
				for i := 0; i < lenBytes; i++ {
					oidLen = (oidLen << 8) | int(raw.Bytes[offset])
					offset++
				}
			}

			offset += oidLen
			if offset >= len(raw.Bytes) {
				return nil, fmt.Errorf("GSS-API token truncated after OID")
			}

			// Remaining bytes should be the NegotiationToken
			negotiationTokenBytes := raw.Bytes[offset:]

			return unwrapSPNEGO(negotiationTokenBytes)
		}

		// If it's a SEQUENCE (0x30), it might be a NegTokenResp that wasn't wrapped in a CHOICE tag (rare but possible)
		if raw.Tag == 16 { // SEQUENCE
			var respToken NegTokenResp
			_, err := asn1.Unmarshal(spnegoData, &respToken)
			if err == nil {
				return respToken.ResponseToken, nil
			}
		}

		return nil, fmt.Errorf("invalid ASN.1 class: %d, tag: %d", raw.Class, raw.Tag)
	}

	switch raw.Tag {
	case 0: // NegTokenInit
		var initToken NegTokenInit
		_, err := asn1.Unmarshal(raw.Bytes, &initToken)
		if err != nil {
			return nil, fmt.Errorf("NegTokenInit decode failed: %w", err)
		}
		return initToken.MechToken, nil

	case 1: // NegTokenResp
		// The raw.Bytes here is the content of the [1] tag, which is the SEQUENCE of NegTokenResp
		// NegTokenResp ::= SEQUENCE {
		//    negState       [0] Enumerated OPTIONAL,
		//    supportedMech  [1] MechType OPTIONAL,
		//    responseToken  [2] OCTET STRING OPTIONAL,
		//    mechListMIC    [3] OCTET STRING OPTIONAL
		// }

		// We need to unmarshal this SEQUENCE manually or define a struct that matches exactly.
		// The struct NegTokenResp defined above uses `asn1:"explicit,optional,tag:X"` which expects
		// the fields to be wrapped in context-specific tags.

		var respToken NegTokenResp
		_, err := asn1.Unmarshal(raw.Bytes, &respToken)
		if err != nil {
			return nil, fmt.Errorf("NegTokenResp decode failed: %w", err)
		}

		// Check for NegState. If rejected, error out.
		if respToken.NegState == Reject {
			return nil, fmt.Errorf("SPNEGO negotiation rejected by peer")
		}

		return respToken.ResponseToken, nil

	default:
		return nil, fmt.Errorf("unknown NegotiationToken tag: %d", raw.Tag)
	}
}

// Helper function: Unwrap SPNEGO NegTokenResp structure
// Input: Raw SPNEGO message (may include outer OCTET STRING wrapper)
// Output: Raw NTLM message (NTLMSSP...)
func unwrapSPNEGOManual(data []byte) ([]byte, error) {
	pos := 0

	// Step 1: Skip outer OCTET STRING wrapper if present (tag 0x04)
	// This is the TSRequest.negoTokens[N].Token field
	if pos < len(data) && data[pos] == 0x04 {
		fmt.Printf("DEBUG: Stripping outer OCTET STRING wrapper\n")
		pos++

		// Parse length bytes
		if pos >= len(data) {
			return nil, fmt.Errorf("truncated OCTET STRING length")
		}

		lenByte := data[pos]
		pos++

		if lenByte > 0x80 {
			numLenBytes := int(lenByte & 0x7f)
			if pos+numLenBytes > len(data) {
				return nil, fmt.Errorf("truncated long-form length")
			}
			// Skip the length bytes (we don't use the value, just position)
			pos += numLenBytes
		}
	}

	// Step 2: Parse SPNEGO NegTokenResp [1] tag (0xa1)
	if pos >= len(data) {
		return nil, fmt.Errorf("data too short for SPNEGO tag")
	}

	if data[pos] != 0xa1 {
		return nil, fmt.Errorf("expected SPNEGO NegTokenResp [1] tag (0xa1), got 0x%02x at offset 0x%02x", data[pos], pos)
	}
	pos++
	fmt.Printf("DEBUG: Found SPNEGO NegTokenResp [1] tag at offset 0x%02x\n", pos-1)

	// Parse length bytes
	if pos >= len(data) {
		return nil, fmt.Errorf("truncated SPNEGO NegTokenResp length")
	}

	lenByte := data[pos]
	pos++

	if lenByte > 0x80 {
		numLenBytes := int(lenByte & 0x7f)
		if pos+numLenBytes > len(data) {
			return nil, fmt.Errorf("truncated long-form SPNEGO length")
		}
		pos += numLenBytes
	}

	// Step 3: Parse SEQUENCE tag (0x30)
	if pos >= len(data) {
		return nil, fmt.Errorf("data too short for SEQUENCE tag")
	}

	if data[pos] != 0x30 {
		return nil, fmt.Errorf("expected SEQUENCE tag (0x30) inside NegTokenResp, got 0x%02x", data[pos])
	}
	pos++
	fmt.Printf("DEBUG: Found SEQUENCE at offset 0x%02x\n", pos-1)

	// Parse length bytes
	if pos >= len(data) {
		return nil, fmt.Errorf("truncated SEQUENCE length")
	}

	lenByte = data[pos]
	pos++

	if lenByte > 0x80 {
		numLenBytes := int(lenByte & 0x7f)
		if pos+numLenBytes > len(data) {
			return nil, fmt.Errorf("truncated SEQUENCE long-form length")
		}
		pos += numLenBytes
	}

	// Step 4: Iterate through SPNEGO fields to find [2] responseToken
	for pos < len(data) {
		if pos+2 > len(data) {
			return nil, fmt.Errorf("truncated field header")
		}

		fieldTag := data[pos]
		pos++

		lenByte := data[pos]
		pos++
		var fieldLen int

		if lenByte > 0x80 {
			numLenBytes := int(lenByte & 0x7f)
			if pos+numLenBytes > len(data) {
				return nil, fmt.Errorf("truncated long-form field length")
			}

			fieldLen = 0
			for i := 0; i < numLenBytes; i++ {
				fieldLen = (fieldLen << 8) | int(data[pos])
				pos++
			}
		} else {
			fieldLen = int(lenByte)
		}

		fmt.Printf("DEBUG: Found field tag 0x%02x, length %d at offset 0x%02x\n", fieldTag, fieldLen, pos-2)

		if fieldTag == 0xa0 {
			// [0] negState - skip it
			fmt.Printf("DEBUG: Skipping [0] negState\n")
			pos += fieldLen
		} else if fieldTag == 0xa1 {
			// [1] supportedMech - skip it
			fmt.Printf("DEBUG: Skipping [1] supportedMech\n")
			pos += fieldLen
		} else if fieldTag == 0xa2 {
			// [2] responseToken - THIS IS WHAT WE WANT
			fmt.Printf("DEBUG: Found [2] responseToken at offset 0x%02x\n", pos-2)

			// The responseToken is an EXPLICIT [2] tag containing an OCTET STRING
			// We need to extract the OCTET STRING inside it

			if pos >= len(data) {
				return nil, fmt.Errorf("truncated responseToken content")
			}

			if data[pos] != 0x04 {
				return nil, fmt.Errorf("expected OCTET STRING (0x04) inside responseToken, got 0x%02x", data[pos])
			}
			pos++

			// Parse OCTET STRING length
			if pos >= len(data) {
				return nil, fmt.Errorf("truncated OCTET STRING length in responseToken")
			}

			octetLenByte := data[pos]
			pos++
			var octetLen int

			if octetLenByte > 0x80 {
				numLenBytes := int(octetLenByte & 0x7f)
				if pos+numLenBytes > len(data) {
					return nil, fmt.Errorf("truncated OCTET STRING long-form length")
				}

				octetLen = 0
				for i := 0; i < numLenBytes; i++ {
					octetLen = (octetLen << 8) | int(data[pos])
					pos++
				}
			} else {
				octetLen = int(octetLenByte)
			}

			fmt.Printf("DEBUG: OCTET STRING length: %d, starting at offset 0x%02x\n", octetLen, pos)

			// Now pos points to the start of NTLM payload
			if pos+octetLen > len(data) {
				return nil, fmt.Errorf("truncated NTLM payload in responseToken")
			}

			ntlmPayload := data[pos : pos+octetLen]
			fmt.Printf("DEBUG: Extracted NTLM payload: %d bytes, starts with %x\n", len(ntlmPayload), ntlmPayload[:min(8, len(ntlmPayload))])

			return ntlmPayload, nil
		} else if fieldTag == 0xa3 {
			// [3] mechListMIC - skip it (optional)
			fmt.Printf("DEBUG: Skipping [3] mechListMIC\n")
			pos += fieldLen
		} else {
			// Unknown field
			fmt.Printf("DEBUG: Skipping unknown field 0x%02x\n", fieldTag)
			pos += fieldLen
		}
	}

	return nil, fmt.Errorf("responseToken [2] not found in SPNEGO NegTokenResp")
}

// Helper: min function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
