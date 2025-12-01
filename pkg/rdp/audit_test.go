package rdp

import (
	"encoding/asn1"
	"fmt"
	"testing"
)

func TestAuditASN1Tags(t *testing.T) {
	// 1. Test NegTokenInit
	// We want to see if MechTypes produces [0] EXPLICIT SEQUENCE OF OID
	initToken := NegTokenInit{
		MechTypes: []asn1.ObjectIdentifier{OIDNTLMSSP},
		MechToken: []byte{0x01, 0x02, 0x03},
	}
	data, err := asn1.Marshal(initToken)
	if err != nil {
		t.Fatalf("Failed to marshal NegTokenInit: %v", err)
	}
	fmt.Printf("NegTokenInit: %x\n", data)
	// Expected:
	// Sequence (30)
	//   [0] (A0) -> MechTypes
	//     Sequence (30) (SEQUENCE OF)
	//       OID (06) ...
	//   [2] (A2) -> MechToken
	//     OctetString (04) ...

	// Check MechTypes tag
	if data[0] != 0x30 {
		t.Errorf("Expected SEQUENCE (0x30), got 0x%02x", data[0])
	}
	// Skip length
	pos := 2 // assuming short length
	if data[1] > 0x80 {
		pos = 1 + int(data[1]&0x7f) + 1
	}
	
	if pos >= len(data) {
		t.Fatal("Truncated data")
	}

	// First field should be MechTypes [0]
	if data[pos] != 0xA0 {
		t.Errorf("Expected [0] EXPLICIT (0xA0), got 0x%02x", data[pos])
	} else {
		fmt.Println("NegTokenInit.MechTypes has correct tag [0] EXPLICIT")
	}

	// 2. Test TSRequest
	// We want to see if NegoTokens produces [1] EXPLICIT SEQUENCE OF NegoToken
	tsReq := TSRequest{
		Version: 3,
		NegoTokens: NegoData{
			{Token: []byte{0xAA, 0xBB}},
		},
	}
	data, err = asn1.Marshal(tsReq)
	if err != nil {
		t.Fatalf("Failed to marshal TSRequest: %v", err)
	}
	fmt.Printf("TSRequest: %x\n", data)

	// Expected:
	// Sequence (30)
	//   [0] (A0) -> Version
	//     Integer (02) ...
	//   [1] (A1) -> NegoTokens
	//     Sequence (30) (SEQUENCE OF)
	//       Sequence (30) (NegoToken)
	//         [0] (A0) -> Token
	//           OctetString (04) ...

	// Check Version tag
	pos = 2 // assuming short length
	if data[1] > 0x80 {
		pos = 1 + int(data[1]&0x7f) + 1
	}

	if data[pos] != 0xA0 {
		t.Errorf("Expected Version [0] EXPLICIT (0xA0), got 0x%02x", data[pos])
	} else {
		fmt.Println("TSRequest.Version has correct tag [0] EXPLICIT")
	}
	
	// Skip Version
	// A0 len 02 len val
	// Let's just search for A1
	foundA1 := false
	for i := pos; i < len(data); i++ {
		if data[i] == 0xA1 {
			foundA1 = true
			// Check content of A1
			// Should contain SEQUENCE (30)
			if i+2 < len(data) && data[i+2] == 0x30 {
				fmt.Println("TSRequest.NegoTokens has correct tag [1] EXPLICIT wrapping SEQUENCE")
			} else {
				// Length might be > 127
				if i+3 < len(data) && data[i+3] == 0x30 {
					fmt.Println("TSRequest.NegoTokens has correct tag [1] EXPLICIT wrapping SEQUENCE (long len)")
				} else {
					// It might be short len
					fmt.Printf("TSRequest.NegoTokens content starts with 0x%02x\n", data[i+2])
				}
			}
			break
		}
	}
	if !foundA1 {
		t.Errorf("Did not find NegoTokens [1] EXPLICIT (0xA1)")
	}

	// 3. Test TSCredentials
	tsCreds := TSCredentials{
		CredType: 1,
		Credentials: []byte{0xCC, 0xDD},
	}
	data, err = asn1.Marshal(tsCreds)
	if err != nil {
		t.Fatalf("Failed to marshal TSCredentials: %v", err)
	}
	fmt.Printf("TSCredentials: %x\n", data)
	// Expected:
	// Sequence (30)
	//   [0] (A0) -> CredType
	//     Integer (02)
	//   [1] (A1) -> Credentials
	//     OctetString (04)

	if data[2] != 0xA0 { // Assuming short len for Sequence
		t.Errorf("Expected CredType [0] EXPLICIT (0xA0), got 0x%02x", data[2])
	}
}
