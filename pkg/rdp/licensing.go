// RDP Screenshotter - Capture screenshots from RDP servers
// Copyright (C) 2025 - Pepijn van der Stap, pepijn@neosecurity.nl
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package rdp

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Licensing PDU types (MS-RDPELE)
const (
	LICENSE_REQUEST             = 0x01
	PLATFORM_CHALLENGE          = 0x02
	NEW_LICENSE                 = 0x03
	UPGRADE_LICENSE             = 0x04
	LICENSE_INFO                = 0x12
	NEW_LICENSE_REQUEST         = 0x13
	PLATFORM_CHALLENGE_RESPONSE = 0x15
	ERROR_ALERT                 = 0xFF
)

// License error codes and states
const (
	ERR_INVALID_SERVER_CERTIFICATE = 0x00000001
	ERR_NO_LICENSE                 = 0x00000002
	ERR_INVALID_SCOPE              = 0x00000004
	ERR_NO_LICENSE_SERVER          = 0x00000006
	ST_NO_TRANSITION               = 0x00000001
	ERR_INVALID_CLIENT             = 0x00000008
	ERR_INVALID_PRODUCTID          = 0x0000000B
	ERR_INVALID_MESSAGE_LEN        = 0x0000000C
	ERR_INVALID_MAC                = 0x00000003
	STATUS_VALID_CLIENT            = 0x00000007
	ST_TOTAL_ABORT                 = 0x00000002
)

// LicensingPDU represents a licensing PDU header
type LicensingPDU struct {
	SecurityHeader uint32
	PDUType        uint8
	Flags          uint8
	Size           uint16
}

// handleLicensingPDU processes licensing PDUs. Note: This is currently dead code as
// the main workflow uses the simplified handleLicensingPhase in client.go.
func (c *Client) handleLicensingPDU(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("licensing PDU too short")
	}

	// Parse licensing PDU header
	r := bytes.NewReader(data)
	var hdr LicensingPDU
	binary.Read(r, binary.LittleEndian, &hdr.SecurityHeader)
	binary.Read(r, binary.LittleEndian, &hdr.PDUType)
	binary.Read(r, binary.LittleEndian, &hdr.Flags)
	binary.Read(r, binary.LittleEndian, &hdr.Size)

	fmt.Printf("Licensing PDU: Type=0x%02X, Flags=0x%02X, Size=%d\n",
		hdr.PDUType, hdr.Flags, hdr.Size)

	switch hdr.PDUType {
	case LICENSE_REQUEST:
		return c.handleLicenseRequest(data[8:])
	case ERROR_ALERT:
		return c.handleLicenseError(data[8:])
	default:
		fmt.Printf("Unhandled licensing PDU type: 0x%02X\n", hdr.PDUType)
	}

	return nil
}

// handleLicenseRequest handles a license request from the server.
func (c *Client) handleLicenseRequest(data []byte) error {
	fmt.Println("Received License Request")
	return c.sendLicenseErrorAlert(STATUS_VALID_CLIENT)
}

// handleLicenseError handles a license error from the server.
func (c *Client) handleLicenseError(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("license error PDU too short")
	}

	errorCode := binary.LittleEndian.Uint32(data[0:4])
	stateTransition := binary.LittleEndian.Uint32(data[4:8])

	fmt.Printf("License Error: Code=0x%08X, StateTransition=0x%08X\n",
		errorCode, stateTransition)

	// STATUS_VALID_CLIENT means licensing is complete
	if errorCode == STATUS_VALID_CLIENT {
		fmt.Println("Licensing completed successfully (valid client)")
		return nil
	}

	return fmt.Errorf("licensing error: 0x%08X", errorCode)
}

// sendLicenseErrorAlert sends a license error alert PDU.
func (c *Client) sendLicenseErrorAlert(errorCode uint32) error {
	// This function builds the core license PDU.
	pduBuf := new(bytes.Buffer)
	binary.Write(pduBuf, binary.LittleEndian, uint8(ERROR_ALERT))
	binary.Write(pduBuf, binary.LittleEndian, uint8(0x03)) // flags (PREAMBLE_VERSION_3_0)
	binary.Write(pduBuf, binary.LittleEndian, uint16(12))  // size = 4 (header) + 8 (data)
	binary.Write(pduBuf, binary.LittleEndian, errorCode)
	binary.Write(pduBuf, binary.LittleEndian, uint32(ST_NO_TRANSITION))

	// Wrap the core PDU with security headers and encryption.
	wrappedPDU := c.secureWrap(SEC_ENCRYPT|SEC_LICENSE_PKT, pduBuf.Bytes())

	// Send the final wrapped PDU.
	return c.sendPDU(wrappedPDU)
}
