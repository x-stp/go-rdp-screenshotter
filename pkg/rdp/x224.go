// RDP Screenshotte Go - Capture screenshots from RDP servers
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

// X224ConnectionRequest represents an X.224 Connection Request PDU (CR TPDU)
// as defined in ITU-T X.224 (ISO 8073).
//
// Structure:
//   - Length Indicator (1 byte): Length of header excluding LI field
//   - TPDU Code (1 byte): 0xE0 for Connection Request
//   - DST-REF (2 bytes): Destination reference (0 for CR)
//   - SRC-REF (2 bytes): Source reference (arbitrary)
//   - Class/Options (1 byte): Protocol class and options
//   - Variable Part: Optional parameters (e.g., RDP cookie)
type X224ConnectionRequest struct {
	LengthIndicator uint8
	TPDUCode        uint8
	DstRef          uint16
	SrcRef          uint16
	ClassOptions    uint8
	Cookie          []byte // Optional RDP negotiation cookie
}

// NewX224ConnectionRequest creates a new X.224 Connection Request PDU.
// The cookie parameter is optional and can be empty for basic connections.
func NewX224ConnectionRequest(cookie string) *X224ConnectionRequest {
	cr := &X224ConnectionRequest{
		TPDUCode:     X224_TPDU_CONNECTION_REQUEST,
		DstRef:       0,      // Always 0 for CR
		SrcRef:       0x1234, // Arbitrary source reference
		ClassOptions: 0,      // Class 0, no options
	}

	// Add RDP negotiation request to probe server capabilities
	negReq := RDPNegReq{
		Type:      TYPE_RDP_NEG_REQ,
		Flags:     0,
		Length:    8,
		Protocols: PROTOCOL_SSL | PROTOCOL_HYBRID, // Request both SSL and NLA
	}

	// Build cookie with negotiation
	var cookieData bytes.Buffer

	// Add cookie if provided
	if cookie != "" {
		cookieData.WriteString(fmt.Sprintf("Cookie: mstshash=%s\r\n", cookie))
	}

	// Add negotiation request
	binary.Write(&cookieData, binary.LittleEndian, negReq)

	cr.Cookie = cookieData.Bytes()

	// Calculate length indicator (header size minus LI field itself)
	cr.LengthIndicator = uint8(6 + len(cr.Cookie))

	return cr
}

// WriteTo implements io.WriterTo interface for X224ConnectionRequest.
func (cr *X224ConnectionRequest) WriteTo(w io.Writer) (int64, error) {
	// Use a buffer to track bytes written
	buf := new(bytes.Buffer)

	// Write fixed header fields
	fields := []interface{}{
		cr.LengthIndicator,
		cr.TPDUCode,
		cr.DstRef,
		cr.SrcRef,
		cr.ClassOptions,
	}

	for _, field := range fields {
		if err := binary.Write(buf, binary.BigEndian, field); err != nil {
			return 0, fmt.Errorf("failed to write X.224 CR field: %w", err)
		}
	}

	// Write variable part (cookie)
	if len(cr.Cookie) > 0 {
		if _, err := buf.Write(cr.Cookie); err != nil {
			return 0, fmt.Errorf("failed to write RDP cookie: %w", err)
		}
	}

	// Write to the actual writer
	n, err := w.Write(buf.Bytes())
	return int64(n), err
}

// X224ConnectionConfirm represents an X.224 Connection Confirm PDU (CC TPDU).
type X224ConnectionConfirm struct {
	LengthIndicator uint8
	TPDUCode        uint8
	DstRef          uint16
	SrcRef          uint16
	ClassOptions    uint8
	// Additional fields may be present in the variable part
	NegotiatedProtocol uint32 // The protocol selected by the server (0 if no negotiation)
}

// RDP Negotiation structures (MS-RDPBCGR section 2.2.1.1)
const (
	TYPE_RDP_NEG_REQ     = 0x01
	TYPE_RDP_NEG_RSP     = 0x02
	TYPE_RDP_NEG_FAILURE = 0x03

	// Protocol flags
	PROTOCOL_RDP       = 0x00000000
	PROTOCOL_SSL       = 0x00000001
	PROTOCOL_HYBRID    = 0x00000002
	PROTOCOL_RDSTLS    = 0x00000004
	PROTOCOL_HYBRID_EX = 0x00000008

	// Failure codes
	SSL_REQUIRED_BY_SERVER      = 0x00000001
	SSL_NOT_ALLOWED_BY_SERVER   = 0x00000002
	SSL_CERT_NOT_ON_SERVER      = 0x00000003
	INCONSISTENT_FLAGS          = 0x00000004
	HYBRID_REQUIRED_BY_SERVER   = 0x00000005
	SSL_WITH_USER_AUTH_REQUIRED = 0x00000006
)

// RDPNegReq represents an RDP Negotiation Request
type RDPNegReq struct {
	Type      uint8
	Flags     uint8
	Length    uint16
	Protocols uint32
}

// RDPNegRsp represents an RDP Negotiation Response
type RDPNegRsp struct {
	Type      uint8
	Flags     uint8
	Length    uint16
	Protocols uint32
}

// RDPNegFailure represents an RDP Negotiation Failure
type RDPNegFailure struct {
	Type        uint8
	Flags       uint8
	Length      uint16
	FailureCode uint32
}

// protocolName returns a human-readable name for the protocol
func protocolName(protocol uint32) string {
	switch protocol {
	case PROTOCOL_RDP:
		return "Standard RDP (no security)"
	case PROTOCOL_SSL:
		return "TLS/SSL Security"
	case PROTOCOL_HYBRID:
		return "CredSSP (NLA)"
	case PROTOCOL_RDSTLS:
		return "RDSTLS"
	case PROTOCOL_HYBRID_EX:
		return "CredSSP with Early User Auth"
	default:
		return fmt.Sprintf("Unknown (0x%08X)", protocol)
	}
}

// failureReason returns a human-readable failure reason
func failureReason(code uint32) string {
	switch code {
	case SSL_REQUIRED_BY_SERVER:
		return "SSL/TLS required by server"
	case SSL_NOT_ALLOWED_BY_SERVER:
		return "SSL/TLS not allowed by server"
	case SSL_CERT_NOT_ON_SERVER:
		return "SSL certificate not configured on server"
	case INCONSISTENT_FLAGS:
		return "Inconsistent negotiation flags"
	case HYBRID_REQUIRED_BY_SERVER:
		return "CredSSP/NLA required by server"
	case SSL_WITH_USER_AUTH_REQUIRED:
		return "SSL with user authentication required"
	default:
		return fmt.Sprintf("Unknown failure code (0x%08X)", code)
	}
}

// parseRDPNegotiationResponse parses RDP negotiation data from X.224 CC
// Returns the negotiated protocol (0 if no negotiation or failure)
func parseRDPNegotiationResponse(data []byte) uint32 {
	if len(data) < 1 {
		return 0
	}

	negType := data[0]

	switch negType {
	case TYPE_RDP_NEG_RSP:
		if len(data) >= 8 {
			var rsp RDPNegRsp
			rsp.Type = data[0]
			rsp.Flags = data[1]
			rsp.Length = binary.LittleEndian.Uint16(data[2:4])
			rsp.Protocols = binary.LittleEndian.Uint32(data[4:8])

			fmt.Printf("\n=== RDP Negotiation Response ===\n")
			fmt.Printf("Server selected protocol: %s\n", protocolName(rsp.Protocols))
			fmt.Printf("This means the server requires: ")

			switch rsp.Protocols {
			case PROTOCOL_RDP:
				fmt.Println("No special security (legacy RDP)")
			case PROTOCOL_SSL:
				fmt.Println("TLS/SSL encryption")
			case PROTOCOL_HYBRID:
				fmt.Println("Network Level Authentication (NLA) with CredSSP")
			case PROTOCOL_HYBRID_EX:
				fmt.Println("Enhanced NLA with early user authentication")
			}
			fmt.Println("================================")

			return rsp.Protocols
		}

	case TYPE_RDP_NEG_FAILURE:
		if len(data) >= 8 {
			var fail RDPNegFailure
			fail.Type = data[0]
			fail.Flags = data[1]
			fail.Length = binary.LittleEndian.Uint16(data[2:4])
			fail.FailureCode = binary.LittleEndian.Uint32(data[4:8])

			fmt.Printf("\n=== RDP Negotiation Failure ===\n")
			fmt.Printf("Server rejected connection: %s\n", failureReason(fail.FailureCode))
			fmt.Printf("===============================\n\n")
		}
	}

	return 0
}

// ReadX224ConnectionConfirm reads an X.224 Connection Confirm PDU from the reader.
func ReadX224ConnectionConfirm(r io.Reader) (*X224ConnectionConfirm, error) {
	var cc X224ConnectionConfirm

	// Read length indicator
	if err := binary.Read(r, binary.BigEndian, &cc.LengthIndicator); err != nil {
		return nil, fmt.Errorf("failed to read CC length indicator: %w", err)
	}

	// Read fixed header fields
	fields := []interface{}{
		&cc.TPDUCode,
		&cc.DstRef,
		&cc.SrcRef,
		&cc.ClassOptions,
	}

	for _, field := range fields {
		if err := binary.Read(r, binary.BigEndian, field); err != nil {
			return nil, fmt.Errorf("failed to read CC field: %w", err)
		}
	}

	// Validate TPDU code
	if cc.TPDUCode != X224_TPDU_CONNECTION_CONFIRM {
		return nil, fmt.Errorf("invalid TPDU code for CC: expected 0x%02X, got 0x%02X",
			X224_TPDU_CONNECTION_CONFIRM, cc.TPDUCode)
	}

	// Check if there's RDP negotiation data in the variable part
	if cc.LengthIndicator > 6 {
		remaining := int(cc.LengthIndicator) - 6
		negData := make([]byte, remaining)
		if _, err := io.ReadFull(r, negData); err != nil {
			return nil, fmt.Errorf("failed to read CC variable part: %w", err)
		}

		// Parse RDP negotiation response and store the result
		cc.NegotiatedProtocol = parseRDPNegotiationResponse(negData)
	}

	return &cc, nil
}

// X224DataTPDU represents an X.224 Data TPDU (DT TPDU)
// Used to transport user data after connection establishment
type X224DataTPDU struct {
	LengthIndicator uint8
	TPDUCode        uint8
	EOT             uint8 // End of TSDU mark (bit 7: 1=end, 0=not end)
}

// WriteTo implements io.WriterTo interface for X224DataTPDU
func (dt *X224DataTPDU) WriteTo(w io.Writer) (int64, error) {
	data := []byte{
		dt.LengthIndicator,
		dt.TPDUCode,
		dt.EOT,
	}
	n, err := w.Write(data)
	return int64(n), err
}

// sendX224ConnectionRequest sends an X.224 Connection Request wrapped in a TPKT packet.
func (c *Client) sendX224ConnectionRequest(cookie string) error {
	// Create the X.224 CR PDU
	cr := NewX224ConnectionRequest(cookie)

	// Calculate total size for TPKT header
	crSize := int(cr.LengthIndicator) + 1 // +1 for LI field itself
	tpkt := NewTPKTHeader(crSize)

	// Write TPKT header and X.224 CR to buffer
	buf := new(bytes.Buffer)
	if _, err := tpkt.WriteTo(buf); err != nil {
		return err
	}
	if _, err := cr.WriteTo(buf); err != nil {
		return err
	}

	// Debug logging
	fmt.Printf("Sending X.224 CR: TPKT length=%d, X.224 LI=%d, cookie=%q\n",
		tpkt.Length, cr.LengthIndicator, string(cr.Cookie))

	// Send to server
	if _, err := c.conn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to send X.224 Connection Request: %w", err)
	}

	return nil
}

// receiveX224ConnectionConfirm receives and parses an X.224 Connection Confirm PDU
func (c *Client) receiveX224ConnectionConfirm() (uint32, error) {
	// Read TPKT header
	tpkt, err := ReadTPKTHeader(c.conn)
	if err != nil {
		return 0, fmt.Errorf("failed to read TPKT header: %w", err)
	}

	// Read X.224 Connection Confirm
	cc, err := ReadX224ConnectionConfirm(c.conn)
	if err != nil {
		return 0, err
	}

	// Store the source reference
	c.x224SrcRef = cc.SrcRef

	fmt.Printf("X.224 Connection Confirm received (TPKT length: %d, DST-REF: 0x%04X, SRC-REF: 0x%04X)\n",
		tpkt.Length, cc.DstRef, cc.SrcRef)

	return cc.NegotiatedProtocol, nil
}
