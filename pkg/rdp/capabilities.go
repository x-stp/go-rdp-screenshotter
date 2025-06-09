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
)

// General Capability Set flags
const (
	TS_CAPS_PROTOCOLVERSION    = 0x0200
	FASTPATH_OUTPUT_SUPPORTED  = 0x0001
	NO_BITMAP_COMPRESSION_HDR  = 0x0400
	LONG_CREDENTIALS_SUPPORTED = 0x0004
	AUTORECONNECT_SUPPORTED    = 0x0008
	ENC_SALTED_CHECKSUM        = 0x0010
)

// Bitmap Capability flags
const (
	DRAW_ALLOW_DYNAMIC_COLOR_FIDELITY = 0x02
	DRAW_ALLOW_COLOR_SUBSAMPLING      = 0x04
	DRAW_ALLOW_SKIP_ALPHA             = 0x08
)

// Order Capability flags
const (
	NEGOTIATEORDERSUPPORT   = 0x0002
	ZEROBOUNDSDELTASSUPPORT = 0x0008
	COLORINDEXSUPPORT       = 0x0020
	SOLIDPATTERNBRUSHONLY   = 0x0040
	ORDERFLAGS_EXTRA_FLAGS  = 0x0080
)

// Input Capability flags
const (
	INPUT_FLAG_SCANCODES         = 0x0001
	INPUT_FLAG_MOUSEX            = 0x0004
	INPUT_FLAG_FASTPATH_INPUT    = 0x0008
	INPUT_FLAG_UNICODE           = 0x0010
	INPUT_FLAG_FASTPATH_INPUT2   = 0x0020
	INPUT_FLAG_UNUSED1           = 0x0040
	INPUT_FLAG_UNUSED2           = 0x0080
	TS_INPUT_FLAG_MOUSE_HWHEEL   = 0x0100
	TS_INPUT_FLAG_QOE_TIMESTAMPS = 0x0200
)

// DemandActivePDU represents the Server Demand Active PDU (MS-RDPBCGR 2.2.1.13.1)
type DemandActivePDU struct {
	ShareID                    uint32
	LengthSourceDescriptor     uint16
	LengthCombinedCapabilities uint16
	SourceDescriptor           string
	NumberCapabilities         uint16
	Pad2Octets                 uint16
	CapabilitySets             []CapabilitySet
	SessionID                  uint32
}

// ConfirmActivePDU represents the Client Confirm Active PDU (MS-RDPBCGR 2.2.1.13.2)
type ConfirmActivePDU struct {
	ShareID                    uint32
	OriginatorID               uint16
	LengthSourceDescriptor     uint16
	LengthCombinedCapabilities uint16
	SourceDescriptor           string
	NumberCapabilities         uint16
	Pad2Octets                 uint16
	CapabilitySets             []CapabilitySet
}

// CapabilitySet represents a generic capability set
type CapabilitySet struct {
	Type   uint16
	Length uint16
	Data   []byte
}

// buildConfirmActivePDU creates a Client Confirm Active PDU
func buildConfirmActivePDU(shareID uint32) ([]byte, error) {
	buf := new(bytes.Buffer)

	// TS_SHARECONTROLHEADER (MS-RDPBCGR 2.2.8.1.1.1.1)
	binary.Write(buf, binary.LittleEndian, uint16(0))                             // totalLength - will be filled later
	binary.Write(buf, binary.LittleEndian, uint16(PDUTYPE_CONFIRMACTIVEPDU|0x10)) // pduType with protocol version
	binary.Write(buf, binary.LittleEndian, uint16(MCS_CHANNEL_GLOBAL))            // PDUSource (user channel ID)

	// TS_CONFIRM_ACTIVE_PDU
	binary.Write(buf, binary.LittleEndian, shareID)        // shareId
	binary.Write(buf, binary.LittleEndian, uint16(0x03EA)) // originatorId (1002)
	binary.Write(buf, binary.LittleEndian, uint16(6))      // lengthSourceDescriptor
	binary.Write(buf, binary.LittleEndian, uint16(0))      // lengthCombinedCapabilities - will be filled later

	// Source descriptor
	buf.WriteString("RDP-GO")

	// Capability sets
	capsBuf := new(bytes.Buffer)

	// Add capability sets
	addGeneralCapabilitySet(capsBuf)
	addBitmapCapabilitySet(capsBuf)
	addOrderCapabilitySet(capsBuf)
	addBitmapCacheCapabilitySet(capsBuf)
	addPointerCapabilitySet(capsBuf)
	addInputCapabilitySet(capsBuf)
	addBrushCapabilitySet(capsBuf)
	addGlyphCacheCapabilitySet(capsBuf)
	addOffscreenCacheCapabilitySet(capsBuf)
	addVirtualChannelCapabilitySet(capsBuf)
	addSoundCapabilitySet(capsBuf)

	// Write number of capability sets
	binary.Write(buf, binary.LittleEndian, uint16(11)) // numberCapabilities
	binary.Write(buf, binary.LittleEndian, uint16(0))  // pad2Octets

	// Write capability sets
	capsData := capsBuf.Bytes()
	buf.Write(capsData)

	// Update lengths
	data := buf.Bytes()
	binary.LittleEndian.PutUint16(data[0:2], uint16(len(data)))         // totalLength
	binary.LittleEndian.PutUint16(data[10:12], uint16(len(capsData)+4)) // lengthCombinedCapabilities

	return data, nil
}

// addGeneralCapabilitySet adds a General Capability Set
func addGeneralCapabilitySet(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint16(CAPSTYPE_GENERAL))
	binary.Write(buf, binary.LittleEndian, uint16(24)) // length

	binary.Write(buf, binary.LittleEndian, uint16(1))                       // osMajorType (Windows)
	binary.Write(buf, binary.LittleEndian, uint16(3))                       // osMinorType (NT)
	binary.Write(buf, binary.LittleEndian, uint16(TS_CAPS_PROTOCOLVERSION)) // protocolVersion
	binary.Write(buf, binary.LittleEndian, uint16(0))                       // pad2octetsA
	binary.Write(buf, binary.LittleEndian, uint16(0))                       // generalCompressionTypes
	binary.Write(buf, binary.LittleEndian, uint16(0))                       // extraFlags
	binary.Write(buf, binary.LittleEndian, uint16(0))                       // updateCapabilityFlag
	binary.Write(buf, binary.LittleEndian, uint16(0))                       // remoteUnshareFlag
	binary.Write(buf, binary.LittleEndian, uint16(0))                       // generalCompressionLevel
	binary.Write(buf, binary.LittleEndian, uint8(0))                        // refreshRectSupport
	binary.Write(buf, binary.LittleEndian, uint8(0))                        // suppressOutputSupport
}

// addBitmapCapabilitySet adds a Bitmap Capability Set
func addBitmapCapabilitySet(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint16(CAPSTYPE_BITMAP))
	binary.Write(buf, binary.LittleEndian, uint16(28)) // length

	binary.Write(buf, binary.LittleEndian, uint16(16))   // preferredBitsPerPixel
	binary.Write(buf, binary.LittleEndian, uint16(1))    // receive1BitPerPixel
	binary.Write(buf, binary.LittleEndian, uint16(1))    // receive4BitsPerPixel
	binary.Write(buf, binary.LittleEndian, uint16(1))    // receive8BitsPerPixel
	binary.Write(buf, binary.LittleEndian, uint16(1024)) // desktopWidth
	binary.Write(buf, binary.LittleEndian, uint16(768))  // desktopHeight
	binary.Write(buf, binary.LittleEndian, uint16(0))    // pad2octets
	binary.Write(buf, binary.LittleEndian, uint16(1))    // desktopResizeFlag
	binary.Write(buf, binary.LittleEndian, uint16(1))    // bitmapCompressionFlag
	binary.Write(buf, binary.LittleEndian, uint8(0))     // highColorFlags
	binary.Write(buf, binary.LittleEndian, uint8(0))     // drawingFlags
	binary.Write(buf, binary.LittleEndian, uint16(1))    // multipleRectangleSupport
	binary.Write(buf, binary.LittleEndian, uint16(0))    // pad2octetsB
}

// addOrderCapabilitySet adds an Order Capability Set
func addOrderCapabilitySet(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint16(CAPSTYPE_ORDER))
	binary.Write(buf, binary.LittleEndian, uint16(88)) // length

	// Terminal descriptor (16 bytes)
	buf.Write(make([]byte, 16))

	binary.Write(buf, binary.LittleEndian, uint32(0))                     // pad4octetsA
	binary.Write(buf, binary.LittleEndian, uint16(1))                     // desktopSaveXGranularity
	binary.Write(buf, binary.LittleEndian, uint16(20))                    // desktopSaveYGranularity
	binary.Write(buf, binary.LittleEndian, uint16(0))                     // pad2octetsA
	binary.Write(buf, binary.LittleEndian, uint16(1))                     // maximumOrderLevel
	binary.Write(buf, binary.LittleEndian, uint16(0))                     // numberFonts
	binary.Write(buf, binary.LittleEndian, uint16(NEGOTIATEORDERSUPPORT)) // orderFlags

	// Order support (32 bytes) - all disabled for now
	buf.Write(make([]byte, 32))

	binary.Write(buf, binary.LittleEndian, uint16(0))       // textFlags
	binary.Write(buf, binary.LittleEndian, uint16(0))       // orderSupportExFlags
	binary.Write(buf, binary.LittleEndian, uint32(0))       // pad4octetsB
	binary.Write(buf, binary.LittleEndian, uint32(480*480)) // desktopSaveSize
	binary.Write(buf, binary.LittleEndian, uint16(0))       // pad2octetsC
	binary.Write(buf, binary.LittleEndian, uint16(0))       // pad2octetsD
	binary.Write(buf, binary.LittleEndian, uint16(0))       // textANSICodePage
	binary.Write(buf, binary.LittleEndian, uint16(0))       // pad2octetsE
}

// Helper functions for other capability sets
func addBitmapCacheCapabilitySet(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint16(CAPSTYPE_BITMAPCACHE))
	binary.Write(buf, binary.LittleEndian, uint16(40)) // length
	buf.Write(make([]byte, 36))                        // Simplified - all zeros
}

func addPointerCapabilitySet(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint16(CAPSTYPE_POINTER))
	binary.Write(buf, binary.LittleEndian, uint16(10)) // length
	binary.Write(buf, binary.LittleEndian, uint16(0))  // colorPointerFlag
	binary.Write(buf, binary.LittleEndian, uint16(20)) // colorPointerCacheSize
	binary.Write(buf, binary.LittleEndian, uint16(21)) // pointerCacheSize
}

func addInputCapabilitySet(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint16(CAPSTYPE_INPUT))
	binary.Write(buf, binary.LittleEndian, uint16(88)) // length

	flags := uint16(INPUT_FLAG_SCANCODES | INPUT_FLAG_MOUSEX | INPUT_FLAG_UNICODE)
	binary.Write(buf, binary.LittleEndian, flags)
	binary.Write(buf, binary.LittleEndian, uint16(0))     // pad2octetsA
	binary.Write(buf, binary.LittleEndian, uint32(0x409)) // keyboardLayout (US)
	binary.Write(buf, binary.LittleEndian, uint32(4))     // keyboardType (IBM enhanced)
	binary.Write(buf, binary.LittleEndian, uint32(0))     // keyboardSubType
	binary.Write(buf, binary.LittleEndian, uint32(12))    // keyboardFunctionKey

	// IME file name (64 bytes)
	buf.Write(make([]byte, 64))
}

func addBrushCapabilitySet(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint16(CAPSTYPE_BRUSH))
	binary.Write(buf, binary.LittleEndian, uint16(8)) // length
	binary.Write(buf, binary.LittleEndian, uint32(1)) // brushSupportLevel
}

func addGlyphCacheCapabilitySet(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint16(CAPSTYPE_GLYPHCACHE))
	binary.Write(buf, binary.LittleEndian, uint16(52)) // length

	// 10 cache entries (4 bytes each)
	for i := 0; i < 10; i++ {
		binary.Write(buf, binary.LittleEndian, uint16(254)) // CacheEntries
		binary.Write(buf, binary.LittleEndian, uint16(4))   // CacheMaximumCellSize
	}

	binary.Write(buf, binary.LittleEndian, uint32(0)) // FragCache
	binary.Write(buf, binary.LittleEndian, uint16(4)) // GlyphSupportLevel
	binary.Write(buf, binary.LittleEndian, uint16(0)) // pad2octets
}

func addOffscreenCacheCapabilitySet(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint16(CAPSTYPE_OFFSCREENCACHE))
	binary.Write(buf, binary.LittleEndian, uint16(12)) // length
	binary.Write(buf, binary.LittleEndian, uint32(0))  // offscreenSupportLevel
	binary.Write(buf, binary.LittleEndian, uint16(0))  // offscreenCacheSize
	binary.Write(buf, binary.LittleEndian, uint16(0))  // offscreenCacheEntries
}

func addVirtualChannelCapabilitySet(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint16(CAPSTYPE_VIRTUALCHANNEL))
	binary.Write(buf, binary.LittleEndian, uint16(12)) // length
	binary.Write(buf, binary.LittleEndian, uint32(1))  // flags (VCCAPS_COMPR_SC)
	binary.Write(buf, binary.LittleEndian, uint32(0))  // VCChunkSize (optional)
}

func addSoundCapabilitySet(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint16(CAPSTYPE_SOUND))
	binary.Write(buf, binary.LittleEndian, uint16(8)) // length
	binary.Write(buf, binary.LittleEndian, uint16(0)) // soundFlags
	binary.Write(buf, binary.LittleEndian, uint16(0)) // pad2octetsA
}

// parseDemandActivePDU parses a Server Demand Active PDU
func parseDemandActivePDU(data []byte) (*DemandActivePDU, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("demand active PDU too short: %d bytes", len(data))
	}

	pdu := &DemandActivePDU{}
	r := bytes.NewReader(data)

	// Read fixed fields
	binary.Read(r, binary.LittleEndian, &pdu.ShareID)
	binary.Read(r, binary.LittleEndian, &pdu.LengthSourceDescriptor)
	binary.Read(r, binary.LittleEndian, &pdu.LengthCombinedCapabilities)

	// Read source descriptor
	if pdu.LengthSourceDescriptor > 0 {
		srcDesc := make([]byte, pdu.LengthSourceDescriptor)
		r.Read(srcDesc)
		pdu.SourceDescriptor = string(srcDesc)
	}

	// Read capability sets header
	binary.Read(r, binary.LittleEndian, &pdu.NumberCapabilities)
	binary.Read(r, binary.LittleEndian, &pdu.Pad2Octets)

	// Parse capability sets
	pdu.CapabilitySets = make([]CapabilitySet, 0, pdu.NumberCapabilities)
	for i := uint16(0); i < pdu.NumberCapabilities; i++ {
		var capSet CapabilitySet
		if err := binary.Read(r, binary.LittleEndian, &capSet.Type); err != nil {
			break
		}
		if err := binary.Read(r, binary.LittleEndian, &capSet.Length); err != nil {
			break
		}

		// Read capability data (length includes the 4-byte header)
		if capSet.Length >= 4 {
			capSet.Data = make([]byte, capSet.Length-4)
			r.Read(capSet.Data)
		}

		pdu.CapabilitySets = append(pdu.CapabilitySets, capSet)

		// Log capability type for debugging
		fmt.Printf("  Capability: Type=0x%04X, Length=%d\n", capSet.Type, capSet.Length)
	}

	// Read session ID if present
	if r.Len() >= 4 {
		binary.Read(r, binary.LittleEndian, &pdu.SessionID)
	}

	return pdu, nil
}
