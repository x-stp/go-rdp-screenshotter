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
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package rdp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// MCS Connect Initial PDU structure (T.125)
// This is a simplified version focusing on RDP requirements

// BER encoding helpers (ITU-T X.690)
func berEncodeLength(w io.Writer, length int) error {
	if length < 128 {
		// Short form
		return binary.Write(w, binary.BigEndian, uint8(length))
	}

	// Long form (up to 2 bytes for our use case)
	if length < 256 {
		binary.Write(w, binary.BigEndian, uint8(0x81)) // 1 length octet follows
		return binary.Write(w, binary.BigEndian, uint8(length))
	}

	// 2 bytes
	binary.Write(w, binary.BigEndian, uint8(0x82)) // 2 length octets follow
	return binary.Write(w, binary.BigEndian, uint16(length))
}

// MCSConnectInitial represents the MCS Connect Initial PDU
type MCSConnectInitial struct {
	// We'll build this as raw bytes for simplicity
	// In a production system, you'd want proper ASN.1 encoding
}

// buildMCSConnectInitial creates a minimal MCS Connect Initial PDU for RDP
func buildMCSConnectInitial() ([]byte, error) {
	buf := new(bytes.Buffer)

	// MCS Connect Initial structure (T.125 section 11.1)
	// This is a BER-encoded structure

	// Application tag 101 (0x65) with CONSTRUCTED bit set = 0x7F65
	buf.WriteByte(0x7F)
	buf.WriteByte(0x65)

	// We'll calculate and write the length later
	lengthPos := buf.Len()
	buf.WriteByte(0x00) // Placeholder for length
	buf.WriteByte(0x00)

	// callingDomainSelector (OCTET STRING) - "1"
	buf.WriteByte(0x04) // OCTET STRING tag
	buf.WriteByte(0x01) // Length
	buf.WriteByte(0x01) // Value "1"

	// calledDomainSelector (OCTET STRING) - "1"
	buf.WriteByte(0x04) // OCTET STRING tag
	buf.WriteByte(0x01) // Length
	buf.WriteByte(0x01) // Value "1"

	// upwardFlag (BOOLEAN) - TRUE
	buf.WriteByte(0x01) // BOOLEAN tag
	buf.WriteByte(0x01) // Length
	buf.WriteByte(0xFF) // TRUE

	// targetParameters - DomainParameters
	buf.WriteByte(0x30) // SEQUENCE tag
	buf.WriteByte(0x19) // Length (25 bytes)

	// maxChannelIds
	buf.WriteByte(0x02) // INTEGER tag
	buf.WriteByte(0x01) // Length
	buf.WriteByte(0x22) // 34

	// maxUserIds
	buf.WriteByte(0x02) // INTEGER tag
	buf.WriteByte(0x01) // Length
	buf.WriteByte(0x02) // 2

	// maxTokenIds
	buf.WriteByte(0x02) // INTEGER tag
	buf.WriteByte(0x01) // Length
	buf.WriteByte(0x00) // 0

	// numPriorities
	buf.WriteByte(0x02) // INTEGER tag
	buf.WriteByte(0x01) // Length
	buf.WriteByte(0x01) // 1

	// minThroughput
	buf.WriteByte(0x02) // INTEGER tag
	buf.WriteByte(0x01) // Length
	buf.WriteByte(0x00) // 0

	// maxHeight
	buf.WriteByte(0x02) // INTEGER tag
	buf.WriteByte(0x01) // Length
	buf.WriteByte(0x01) // 1

	// maxMCSPDUsize
	buf.WriteByte(0x02) // INTEGER tag
	buf.WriteByte(0x02) // Length
	buf.WriteByte(0xFF) // 65535
	buf.WriteByte(0xFF)

	// protocolVersion
	buf.WriteByte(0x02) // INTEGER tag
	buf.WriteByte(0x01) // Length
	buf.WriteByte(0x00) // 0

	// minimumParameters - DomainParameters (same structure, minimal values)
	buf.WriteByte(0x30) // SEQUENCE tag
	buf.WriteByte(0x19) // Length
	// ... (similar to targetParameters but with minimal values)
	// For brevity, using same values as target
	buf.Write([]byte{
		0x02, 0x01, 0x01, // maxChannelIds = 1
		0x02, 0x01, 0x01, // maxUserIds = 1
		0x02, 0x01, 0x01, // maxTokenIds = 1
		0x02, 0x01, 0x01, // numPriorities = 1
		0x02, 0x01, 0x00, // minThroughput = 0
		0x02, 0x01, 0x01, // maxHeight = 1
		0x02, 0x02, 0x04, 0x00, // maxMCSPDUsize = 1024
		0x02, 0x01, 0x00, // protocolVersion = 0
	})

	// maximumParameters - DomainParameters
	buf.WriteByte(0x30) // SEQUENCE tag
	buf.WriteByte(0x1C) // Length
	buf.Write([]byte{
		0x02, 0x02, 0xFF, 0xFF, // maxChannelIds = 65535
		0x02, 0x02, 0xFC, 0x17, // maxUserIds = 64535
		0x02, 0x02, 0xFF, 0xFF, // maxTokenIds = 65535
		0x02, 0x01, 0x01, // numPriorities = 1
		0x02, 0x01, 0x00, // minThroughput = 0
		0x02, 0x01, 0x01, // maxHeight = 1
		0x02, 0x02, 0xFF, 0xFF, // maxMCSPDUsize = 65535
		0x02, 0x01, 0x00, // protocolVersion = 0
	})

	// userData (OCTET STRING) - This will contain the RDP-specific data
	userData := buildRDPUserData()
	buf.WriteByte(0x04) // OCTET STRING tag
	berEncodeLength(buf, len(userData))
	buf.Write(userData)

	// Now go back and write the total length
	data := buf.Bytes()
	totalLength := len(data) - 4 // Exclude tag and length fields
	binary.BigEndian.PutUint16(data[lengthPos:], uint16(totalLength))

	return data, nil
}

// buildRDPUserData creates the RDP-specific user data for MCS Connect Initial
func buildRDPUserData() []byte {
	buf := new(bytes.Buffer)

	// CS_CORE (MS-RDPBCGR section 2.2.1.3.2)
	csCore := buildCSCore()
	buf.Write(csCore)

	// CS_SECURITY (MS-RDPBCGR section 2.2.1.3.3)
	csSecurity := buildCSSecurity()
	buf.Write(csSecurity)

	// CS_NET (MS-RDPBCGR section 2.2.1.3.4)
	// Skipping for minimal implementation

	return buf.Bytes()
}

// buildCSCore creates the Client Core Data structure
// @TODO this is a mess.
// i am no fan either
// consts are great. 0x00080001, 0xCA00.. not so much.
func buildCSCore() []byte {
	buf := new(bytes.Buffer)

	// Header
	binary.Write(buf, binary.LittleEndian, uint16(0x01C0)) // type: CS_CORE
	binary.Write(buf, binary.LittleEndian, uint16(216))    // length

	// Version - RDP 5.0
	binary.Write(buf, binary.LittleEndian, uint32(0x00080001)) // RDP 5.0

	// Desktop size
	binary.Write(buf, binary.LittleEndian, uint16(1024)) // width
	binary.Write(buf, binary.LittleEndian, uint16(768))  // height

	// Color depth - Request high color (15-bit)
	binary.Write(buf, binary.LittleEndian, uint16(0xCA00)) // 15 bpp

	// SAS Sequence
	binary.Write(buf, binary.LittleEndian, uint16(0xAA03)) // RNS_UD_SAS_DEL

	// Keyboard layout
	binary.Write(buf, binary.LittleEndian, uint32(0x409)) // US English

	// Client build
	binary.Write(buf, binary.LittleEndian, uint32(2600)) // NT.5 first XP; 7601=Windows 7(sp1)

	// Client name (32 Unicode characters, null-padded)
	clientName := "x-stp\\MCS_W00T"
	for i := 0; i < 32; i++ {
		if i < len(clientName) {
			buf.WriteByte(clientName[i])
			buf.WriteByte(0) // Unicode null byte
		} else {
			binary.Write(buf, binary.LittleEndian, uint16(0))
		}
	}

	// Keyboard type, subtype, function keys
	binary.Write(buf, binary.LittleEndian, uint32(0x04)) // IBM enhanced (101/102 keys)
	binary.Write(buf, binary.LittleEndian, uint32(0))    // Subtype
	binary.Write(buf, binary.LittleEndian, uint32(12))   // Function keys

	// IME file name (64 bytes, zeros)
	buf.Write(make([]byte, 64))

	// Post Beta2 color depth - high color
	binary.Write(buf, binary.LittleEndian, uint16(0x0010)) // 16 bpp

	// Client product ID
	binary.Write(buf, binary.LittleEndian, uint16(1))

	// Serial number
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// High color depth - 16 bpp
	binary.Write(buf, binary.LittleEndian, uint16(0x0010)) // 16 bpp

	// Supported color depths - 15 and 16 bpp
	binary.Write(buf, binary.LittleEndian, uint16(0x0001)) // 15 bpp supported

	// Early capability flags
	binary.Write(buf, binary.LittleEndian, uint16(0x0001)) // RNS_UD_CS_SUPPORT_ERRINFO_PDU

	// Client dig product ID (64 bytes, zeros)
	buf.Write(make([]byte, 64))

	// Connection type
	buf.WriteByte(0) // Unknown connection

	// Pad
	buf.WriteByte(0)

	// Server selected protocol
	binary.Write(buf, binary.LittleEndian, uint32(0)) // Standard RDP

	return buf.Bytes()
}

// buildCSSecurity creates the Client Security Data structure
func buildCSSecurity() []byte {
	buf := new(bytes.Buffer)

	// Header
	binary.Write(buf, binary.LittleEndian, uint16(0x02C0)) // type: CS_SECURITY
	binary.Write(buf, binary.LittleEndian, uint16(12))     // length

	// Encryption methods
	binary.Write(buf, binary.LittleEndian, uint32(0)) // No encryption for simplicity

	// Ext encryption methods
	binary.Write(buf, binary.LittleEndian, uint32(0))

	return buf.Bytes()
}

// MCS Domain PDU builders

// buildMCSErectDomainRequest creates an MCS Erect Domain Request PDU
func buildMCSErectDomainRequest() []byte {
	// ErectDomainRequest ::= [APPLICATION 4] IMPLICIT SEQUENCE {
	//     subHeight   INTEGER (0..MAX),
	//     subInterval INTEGER (0..MAX)
	// }
	buf := new(bytes.Buffer)

	// Application tag 4
	buf.WriteByte(0x04)

	// Length (4 bytes for two integers)
	buf.WriteByte(0x04)

	// subHeight (0)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)

	// subInterval (0)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)

	return buf.Bytes()
}

// buildMCSAttachUserRequest creates an MCS Attach User Request PDU
func buildMCSAttachUserRequest() []byte {
	// AttachUserRequest ::= [APPLICATION 10] IMPLICIT SEQUENCE {}
	// Empty sequence
	return []byte{0x10, 0x00} // Tag 10, length 0
}

// buildMCSChannelJoinRequest creates an MCS Channel Join Request PDU
func buildMCSChannelJoinRequest(userID, channelID uint16) []byte {
	// ChannelJoinRequest ::= [APPLICATION 14] IMPLICIT SEQUENCE {
	//     initiator   UserId,
	//     channelId   ChannelId
	// }
	buf := new(bytes.Buffer)

	// Application tag 14
	buf.WriteByte(0x14)

	// Length (4 bytes for two 16-bit integers)
	buf.WriteByte(0x04)

	// initiator (user ID)
	binary.Write(buf, binary.BigEndian, userID)

	// channelId
	binary.Write(buf, binary.BigEndian, channelID)

	return buf.Bytes()
}

// MCS Disconnect reasons
const (
	MCS_REASON_DOMAIN_DISCONNECTED = 0x00
	MCS_REASON_PROVIDER_INITIATED  = 0x01
	MCS_REASON_TOKEN_PURGED        = 0x02
	MCS_REASON_USER_REQUESTED      = 0x03
	MCS_REASON_CHANNEL_PURGED      = 0x04
)

// mcsDisconnectReason returns a human-readable disconnect reason
func mcsDisconnectReason(reason uint8) string {
	// Standard MCS reasons
	switch reason {
	case MCS_REASON_DOMAIN_DISCONNECTED:
		return "Domain disconnected"
	case MCS_REASON_PROVIDER_INITIATED:
		return "Provider initiated disconnect"
	case MCS_REASON_TOKEN_PURGED:
		return "Token purged"
	case MCS_REASON_USER_REQUESTED:
		return "User requested"
	case MCS_REASON_CHANNEL_PURGED:
		return "Channel purged"
	}

	// RDP-specific reasons (non-standard)
	switch reason {
	case 0x80:
		return "RDP protocol error - likely security negotiation failure"
	case 0x81:
		return "Server refused connection - check security settings"
	case 0x82:
		return "Server configuration error"
	default:
		return fmt.Sprintf("Unknown reason (0x%02X)", reason)
	}
}

// parseMCSConnectResponse parses an MCS Connect Response PDU
func parseMCSConnectResponse(data []byte) (*SecurityData, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("MCS PDU too short: %d bytes", len(data))
	}

	// Debug output
	fmt.Printf("MCS PDU data: %x\n", data)

	// Check for various MCS PDU types
	tag := data[0]

	switch tag {
	case 0x7F:
		// BER tag 0x7F66 (Connect-Response)
		if len(data) < 3 || data[1] != 0x66 {
			return nil, fmt.Errorf("invalid MCS Connect Response tag: %02X%02X", data[0], data[1])
		}

		// Parse the MCS Connect Response to extract server security data
		securityData, err := parseMCSConnectResponseData(data)
		if err != nil {
			return nil, err
		}
		return securityData, nil

	case 0x21:
		// Disconnect Provider Ultimatum (0x21)
		if len(data) < 2 {
			return nil, fmt.Errorf("Disconnect Provider Ultimatum too short")
		}
		reason := data[1]

		fmt.Printf("\n[:(] - MSC let you down. \n")
		fmt.Printf("Disconnect reason: %s\n", mcsDisconnectReason(reason))

		if reason == 0x80 {
			fmt.Println("\nThis typically means:")
			fmt.Println("- The server requires TLS/SSL or NLA but we sent standard RDP")
			fmt.Println("- The server does not agree with initialized MCS conn params")
			fmt.Println("- The server thinks we're alien droids")
			fmt.Println("\nTo connect to this server, you would need to:")
			fmt.Println("1. Implement TLS support if the server requires SSL")
			fmt.Println("2. Implement CredSSP/NLA if the server requires it")
			fmt.Println("3. Ensure the RDP security settings match the server's requirements")
		}

		return nil, fmt.Errorf("MCS Disconnect: %s", mcsDisconnectReason(reason))

	default:
		return nil, fmt.Errorf("unexpected MCS PDU type: 0x%02X", tag)
	}
}

// parseMCSConnectResponseData extracts server security data from MCS Connect Response
func parseMCSConnectResponseData(data []byte) (*SecurityData, error) {
	// Skip BER header and length encoding
	offset := 2

	// Read length
	if data[offset] == 0x82 {
		// 2-byte length
		offset += 3
	} else if data[offset] == 0x81 {
		// 1-byte length
		offset += 2
	} else {
		// Short form
		offset += 1
	}

	// Skipping result, calledConnectId, and domainParameters for mvp.

	// For full ASN.1 (ITU-T X.680) and BER encoding (X.690) as used in the Microsoft RDP stack;
	// read the following:
	//  - CredSSP (MS-CSSP), RDP core (MS-RDPBCGR), licensing (MS-RDPELE), smart card (MS-RDPEFS).
	// TSRequest type: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/6aac4dea-08ef-47a6-8747-22ea7f6d8685
	//  zmap/zcrypto's ASN.1 is best afaik in go atm.
	// For anyone maintaining this after me: yes, it's BER, yes, it's ASN.1, yes, it's weird.

	// Look for the user data (OCTET STRING)
	for offset < len(data)-2 {
		if data[offset] == 0x04 { // OCTET STRING tag
			offset++

			// Read length
			var userDataLen int
			if data[offset] == 0x82 {
				userDataLen = int(binary.BigEndian.Uint16(data[offset+1:]))
				offset += 3
			} else if data[offset] == 0x81 {
				userDataLen = int(data[offset+1])
				offset += 2
			} else {
				userDataLen = int(data[offset])
				offset += 1
			}

			// Parse GCC Conference Create Response
			if offset+userDataLen <= len(data) {
				return parseGCCConferenceCreateResponse(data[offset : offset+userDataLen])
			}
		}
		offset++
	}

	return nil, fmt.Errorf("user data not found in MCS Connect Response")
}

// parseGCCConferenceCreateResponse parses the GCC Conference Create Response
func parseGCCConferenceCreateResponse(data []byte) (*SecurityData, error) {
	securityData := &SecurityData{}

	// Skip GCC header (simplified)
	offset := 21 // Typical offset to server data

	// Parse server data blocks
	for offset < len(data)-4 {
		// Read header type and length
		headerType := binary.LittleEndian.Uint16(data[offset:])
		length := binary.LittleEndian.Uint16(data[offset+2:])

		if offset+int(length) > len(data) {
			break
		}

		switch headerType {
		case 0x0C02: // SC_SECURITY
			// Parse security data
			if length >= 12 {
				securityData.EncryptionMethod = binary.LittleEndian.Uint32(data[offset+4:])
				securityData.EncryptionLevel = binary.LittleEndian.Uint32(data[offset+8:])

				if length > 12 {
					// Server random follows
					randomLen := binary.LittleEndian.Uint32(data[offset+12:])
					if randomLen == 32 && int(length) >= 16+int(randomLen) {
						securityData.ServerRandom = make([]byte, 32)
						copy(securityData.ServerRandom, data[offset+16:offset+16+32])
					}

					// Certificate may follow
					if int(length) > 16+int(randomLen) {
						certOffset := offset + 16 + int(randomLen)
						certLen := binary.LittleEndian.Uint32(data[certOffset:])
						if certLen > 0 && int(certLen) <= len(data)-certOffset-4 {
							securityData.ServerCertificate = make([]byte, certLen)
							copy(securityData.ServerCertificate, data[certOffset+4:])
						}
					}
				}

				fmt.Printf("Server Security: Method=0x%08X, Level=0x%08X\n",
					securityData.EncryptionMethod, securityData.EncryptionLevel)
			}
		}

		offset += int(length)
	}

	return securityData, nil
}

// parseMCSAttachUserConfirm parses an MCS Attach User Confirm PDU
func parseMCSAttachUserConfirm(data []byte) (uint16, error) {
	if len(data) < 5 {
		return 0, fmt.Errorf("MCS Attach User Confirm too short: %d bytes", len(data))
	}

	// Debug output
	fmt.Printf("MCS Attach User Confirm data: %x\n", data[:min(16, len(data))])

	// Check for tag 0x11 (Attach-User-Confirm)
	if data[0] != 0x11 {
		return 0, fmt.Errorf("invalid MCS Attach User Confirm tag: %02X", data[0])
	}

	// Skip length byte
	// Result should be 0 (rt-successful)
	if data[2] != 0 {
		return 0, fmt.Errorf("MCS Attach User failed with result: %02X", data[2])
	}

	// Extract user ID (big-endian)
	userID := binary.BigEndian.Uint16(data[3:5])
	return userID, nil
}

// parseMCSChannelJoinConfirm parses an MCS Channel Join Confirm PDU
func parseMCSChannelJoinConfirm(data []byte) error {
	if len(data) < 5 {
		return fmt.Errorf("MCS Channel Join Confirm too short: %d bytes", len(data))
	}

	// Debug output
	fmt.Printf("MCS Channel Join Confirm data: %x\n", data[:min(16, len(data))])

	// Check for tag 0x15 (Channel-Join-Confirm)
	if data[0] != 0x15 {
		return fmt.Errorf("invalid MCS Channel Join Confirm tag: %02X", data[0])
	}

	// Result should be 0 (rt-successful)
	if data[2] != 0 {
		return fmt.Errorf("MCS Channel Join failed with result: %02X", data[2])
	}

	return nil
}
