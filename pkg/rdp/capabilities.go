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
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package rdp

import (
	"bytes"
	"encoding/binary"
)

// buildConfirmActivePDU creates a Client Confirm Active PDU with a minimal set of capabilities.
func buildConfirmActivePDU(shareID uint32) ([]byte, error) {
	capsBuf := new(bytes.Buffer)

	// A minimal set of capabilities for compatibility
	addGeneralCapabilitySet(capsBuf)
	addBitmapCapabilitySet(capsBuf)
	addOrderCapabilitySet(capsBuf)
	addPointerCapabilitySet(capsBuf)

	capsData := capsBuf.Bytes()

	// TS_CONFIRM_ACTIVE_PDU structure
	pdu := new(bytes.Buffer)
	binary.Write(pdu, binary.LittleEndian, shareID)
	binary.Write(pdu, binary.LittleEndian, uint16(1002)) // OriginatorID
	binary.Write(pdu, binary.LittleEndian, uint16(4))    // Length of "RDP\x00"
	binary.Write(pdu, binary.LittleEndian, uint16(len(capsData)))
	pdu.WriteString("RDP\x00")
	binary.Write(pdu, binary.LittleEndian, uint16(4)) // numCapabilities
	binary.Write(pdu, binary.LittleEndian, uint16(0)) // pad2Octets
	pdu.Write(capsData)

	// Wrap in Share Control Header
	finalPDU := new(bytes.Buffer)
	pduBytes := pdu.Bytes()
	totalLength := uint16(len(pduBytes) + 6)
	binary.Write(finalPDU, binary.LittleEndian, totalLength)
	binary.Write(finalPDU, binary.LittleEndian, uint16(PDUTYPE_CONFIRMACTIVEPDU|0x10))
	binary.Write(finalPDU, binary.LittleEndian, uint16(1002)) // pduSource
	finalPDU.Write(pduBytes)

	return finalPDU.Bytes(), nil
}

// addGeneralCapabilitySet adds a General Capability Set
func addGeneralCapabilitySet(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint16(CAPSTYPE_GENERAL))
	binary.Write(buf, binary.LittleEndian, uint16(24))     // length
	binary.Write(buf, binary.LittleEndian, uint16(1))      // osMajorType
	binary.Write(buf, binary.LittleEndian, uint16(3))      // osMinorType
	binary.Write(buf, binary.LittleEndian, uint16(0x0200)) // protocolVersion
	buf.Write(make([]byte, 14))                            // Padding and unused fields
}

// addBitmapCapabilitySet adds a Bitmap Capability Set
func addBitmapCapabilitySet(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint16(CAPSTYPE_BITMAP))
	binary.Write(buf, binary.LittleEndian, uint16(28))   // length
	binary.Write(buf, binary.LittleEndian, uint16(24))   // preferredBitsPerPixel
	binary.Write(buf, binary.LittleEndian, uint16(1))    // receive1BitPerPixel
	binary.Write(buf, binary.LittleEndian, uint16(1))    // receive4BitsPerPixel
	binary.Write(buf, binary.LittleEndian, uint16(1))    // receive8BitsPerPixel
	binary.Write(buf, binary.LittleEndian, uint16(1024)) // desktopWidth
	binary.Write(buf, binary.LittleEndian, uint16(768))  // desktopHeight
	buf.Write(make([]byte, 2))                           // pad2octets
	binary.Write(buf, binary.LittleEndian, uint16(1))    // desktopResizeFlag
	binary.Write(buf, binary.LittleEndian, uint16(1))    // bitmapCompressionFlag
	buf.Write(make([]byte, 8))                           // Unused fields
}

// addOrderCapabilitySet adds an Order Capability Set
func addOrderCapabilitySet(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint16(CAPSTYPE_ORDER))
	binary.Write(buf, binary.LittleEndian, uint16(88)) // length
	buf.Write(make([]byte, 84))                        // All fields set to zero for simplicity
}

// addPointerCapabilitySet adds a Pointer Capability Set
func addPointerCapabilitySet(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint16(CAPSTYPE_POINTER))
	binary.Write(buf, binary.LittleEndian, uint16(10)) // length
	binary.Write(buf, binary.LittleEndian, uint16(1))  // colorPointerFlag
	binary.Write(buf, binary.LittleEndian, uint16(20)) // colorPointerCacheSize
	binary.Write(buf, binary.LittleEndian, uint16(20)) // pointerCacheSize
}
