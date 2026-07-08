// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 x-stp

package rdp

import (
	"bytes"
	"encoding/binary"
)

// buildConfirmActivePDU emits TS_CONFIRM_ACTIVE_PDU per [MS-RDPBCGR] §2.2.1.13.2.
// originatorId is fixed at 0x03EA (1002). sourceDescriptor carries the ASCII
// tag mstsc.exe sends; servers don't validate the value but require non-zero
// length. lengthCombinedCapabilities covers numberCapabilities + pad + sets.
func buildConfirmActivePDU(shareID uint32, userID uint16) ([]byte, error) {
	caps := new(bytes.Buffer)
	const numberCapabilities = 13

	writeGeneralCapabilitySet(caps)
	writeBitmapCapabilitySet(caps)
	writeOrderCapabilitySet(caps)
	writeBitmapCacheCapabilitySet(caps)
	writePointerCapabilitySet(caps)
	writeInputCapabilitySet(caps)
	writeBrushCapabilitySet(caps)
	writeGlyphCacheCapabilitySet(caps)
	writeOffscreenBitmapCacheCapabilitySet(caps)
	writeVirtualChannelCapabilitySet(caps)
	writeSoundCapabilitySet(caps)
	writeShareCapabilitySet(caps)
	writeFontCapabilitySet(caps)

	const sourceDescriptor = "MSTSC\x00"

	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, shareID)
	binary.Write(body, binary.LittleEndian, uint16(0x03EA))
	binary.Write(body, binary.LittleEndian, uint16(len(sourceDescriptor)))
	binary.Write(body, binary.LittleEndian, uint16(caps.Len()+4))
	body.WriteString(sourceDescriptor)
	binary.Write(body, binary.LittleEndian, uint16(numberCapabilities))
	binary.Write(body, binary.LittleEndian, uint16(0))
	body.Write(caps.Bytes())

	bodyBytes := body.Bytes()
	out := new(bytes.Buffer)
	binary.Write(out, binary.LittleEndian, uint16(len(bodyBytes)+6))
	binary.Write(out, binary.LittleEndian, uint16(PDUTYPE_CONFIRMACTIVEPDU|0x10))
	binary.Write(out, binary.LittleEndian, userID)
	out.Write(bodyBytes)
	return out.Bytes(), nil
}

// capabilitySet writes a capability set TLV header followed by body.
func capabilitySet(buf *bytes.Buffer, capType uint16, body []byte) {
	binary.Write(buf, binary.LittleEndian, capType)
	binary.Write(buf, binary.LittleEndian, uint16(len(body)+4))
	buf.Write(body)
}

// TS_GENERAL_CAPABILITYSET per [MS-RDPBCGR] §2.2.7.1.1. extraFlags omits
// NO_BITMAP_COMPRESSION_HDR (0x0400) so the server emits the no-compression
// marker our bitmap decoder expects.
func writeGeneralCapabilitySet(buf *bytes.Buffer) {
	const (
		FASTPATH_OUTPUT_SUPPORTED  = 0x0001
		LONG_CREDENTIALS_SUPPORTED = 0x0004
		AUTORECONNECT_SUPPORTED    = 0x0008
		ENC_SALTED_CHECKSUM        = 0x0010
	)
	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, uint16(1))      /* osMajorType: Windows */
	binary.Write(body, binary.LittleEndian, uint16(3))      /* osMinorType: Windows NT */
	binary.Write(body, binary.LittleEndian, uint16(0x0200)) /* protocolVersion */
	binary.Write(body, binary.LittleEndian, uint16(0))      /* pad2OctetsA */
	binary.Write(body, binary.LittleEndian, uint16(0))      /* generalCompressionTypes */
	binary.Write(body, binary.LittleEndian, uint16(FASTPATH_OUTPUT_SUPPORTED|LONG_CREDENTIALS_SUPPORTED))
	binary.Write(body, binary.LittleEndian, uint16(0)) /* updateCapabilityFlag */
	binary.Write(body, binary.LittleEndian, uint16(0)) /* remoteUnshareFlag */
	binary.Write(body, binary.LittleEndian, uint16(0)) /* generalCompressionLevel */
	binary.Write(body, binary.LittleEndian, uint8(1))  /* refreshRectSupport */
	binary.Write(body, binary.LittleEndian, uint8(1))  /* suppressOutputSupport */
	capabilitySet(buf, CAPSTYPE_GENERAL, body.Bytes())
}

// TS_BITMAP_CAPABILITYSET per [MS-RDPBCGR] §2.2.7.1.2.
func writeBitmapCapabilitySet(buf *bytes.Buffer) {
	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, uint16(16))   /* preferredBitsPerPixel */
	binary.Write(body, binary.LittleEndian, uint16(1))    /* receive1BitPerPixel */
	binary.Write(body, binary.LittleEndian, uint16(1))    /* receive4BitsPerPixel */
	binary.Write(body, binary.LittleEndian, uint16(1))    /* receive8BitsPerPixel */
	binary.Write(body, binary.LittleEndian, uint16(1024)) /* desktopWidth */
	binary.Write(body, binary.LittleEndian, uint16(768))  /* desktopHeight */
	binary.Write(body, binary.LittleEndian, uint16(0))    /* pad2Octets */
	binary.Write(body, binary.LittleEndian, uint16(1))    /* desktopResizeFlag */
	binary.Write(body, binary.LittleEndian, uint16(1))    /* bitmapCompressionFlag */
	binary.Write(body, binary.LittleEndian, uint8(0))     /* highColorFlags */
	binary.Write(body, binary.LittleEndian, uint8(0))     /* drawingFlags */
	binary.Write(body, binary.LittleEndian, uint16(1))    /* multipleRectangleSupport */
	binary.Write(body, binary.LittleEndian, uint16(0))    /* pad2OctetsB */
	capabilitySet(buf, CAPSTYPE_BITMAP, body.Bytes())
}

// TS_ORDER_CAPABILITYSET per [MS-RDPBCGR] §2.2.7.1.3. All-zero orderSupport
// tells the server to use plain bitmap updates only, no GDI primary orders.
func writeOrderCapabilitySet(buf *bytes.Buffer) {
	body := new(bytes.Buffer)
	body.Write(make([]byte, 16))                            /* terminalDescriptor */
	binary.Write(body, binary.LittleEndian, uint32(0))      /* pad4OctetsA */
	binary.Write(body, binary.LittleEndian, uint16(1))      /* desktopSaveXGranularity */
	binary.Write(body, binary.LittleEndian, uint16(20))     /* desktopSaveYGranularity */
	binary.Write(body, binary.LittleEndian, uint16(0))      /* pad2OctetsA */
	binary.Write(body, binary.LittleEndian, uint16(1))      /* maximumOrderLevel */
	binary.Write(body, binary.LittleEndian, uint16(0))      /* numberFonts */
	binary.Write(body, binary.LittleEndian, uint16(0x002A)) /* orderFlags: NEGOTIATE_ORDER_SUPPORT | ZERO_BOUNDS_DELTA_SUPPORT | COLOR_INDEX_SUPPORT */
	body.Write(make([]byte, 32))                            /* orderSupport */
	binary.Write(body, binary.LittleEndian, uint16(0))      /* textFlags */
	binary.Write(body, binary.LittleEndian, uint16(0))      /* orderSupportExFlags */
	binary.Write(body, binary.LittleEndian, uint32(0))      /* pad4OctetsB */
	binary.Write(body, binary.LittleEndian, uint32(230400)) /* desktopSaveSize */
	binary.Write(body, binary.LittleEndian, uint16(0))      /* pad2OctetsC */
	binary.Write(body, binary.LittleEndian, uint16(0))      /* pad2OctetsD */
	binary.Write(body, binary.LittleEndian, uint16(0))      /* textANSICodePage */
	binary.Write(body, binary.LittleEndian, uint16(0))      /* pad2OctetsE */
	capabilitySet(buf, CAPSTYPE_ORDER, body.Bytes())
}

// TS_BITMAPCACHE_CAPABILITYSET (revision 1) per [MS-RDPBCGR] §2.2.7.1.4.1.
func writeBitmapCacheCapabilitySet(buf *bytes.Buffer) {
	body := new(bytes.Buffer)
	body.Write(make([]byte, 24)) /* pad1..pad6 */
	binary.Write(body, binary.LittleEndian, uint16(200))
	binary.Write(body, binary.LittleEndian, uint16(0x600))
	binary.Write(body, binary.LittleEndian, uint16(600))
	binary.Write(body, binary.LittleEndian, uint16(0x1000))
	binary.Write(body, binary.LittleEndian, uint16(1000))
	binary.Write(body, binary.LittleEndian, uint16(0x4000))
	capabilitySet(buf, CAPSTYPE_BITMAPCACHE, body.Bytes())
}

// TS_POINTER_CAPABILITYSET per [MS-RDPBCGR] §2.2.7.1.5.
func writePointerCapabilitySet(buf *bytes.Buffer) {
	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, uint16(1))  /* colorPointerFlag */
	binary.Write(body, binary.LittleEndian, uint16(20)) /* colorPointerCacheSize */
	binary.Write(body, binary.LittleEndian, uint16(20)) /* pointerCacheSize */
	capabilitySet(buf, CAPSTYPE_POINTER, body.Bytes())
}

// TS_INPUT_CAPABILITYSET per [MS-RDPBCGR] §2.2.7.1.6. INPUT_FLAG_SCANCODES is
// required. keyboardLayout 0x409 = en-US, keyboardType 4 = IBM enhanced 101/102.
func writeInputCapabilitySet(buf *bytes.Buffer) {
	const (
		INPUT_FLAG_SCANCODES      = 0x0001
		INPUT_FLAG_MOUSEX         = 0x0004
		INPUT_FLAG_FASTPATH_INPUT = 0x0008
	)
	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, uint16(INPUT_FLAG_SCANCODES))
	binary.Write(body, binary.LittleEndian, uint16(0))     /* pad2OctetsA */
	binary.Write(body, binary.LittleEndian, uint32(0x409)) /* keyboardLayout */
	binary.Write(body, binary.LittleEndian, uint32(4))     /* keyboardType */
	binary.Write(body, binary.LittleEndian, uint32(0))     /* keyboardSubType */
	binary.Write(body, binary.LittleEndian, uint32(12))    /* keyboardFunctionKey */
	body.Write(make([]byte, 64))                           /* imeFileName */
	capabilitySet(buf, CAPSTYPE_INPUT, body.Bytes())
}

// TS_BRUSH_CAPABILITYSET per [MS-RDPBCGR] §2.2.7.1.7. Level 0 = solid colour only.
func writeBrushCapabilitySet(buf *bytes.Buffer) {
	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, uint32(0))
	capabilitySet(buf, CAPSTYPE_BRUSH, body.Bytes())
}

// TS_CACHE_DEFINITION used inside the glyph cache capability set.
func writeCacheDefinition(buf *bytes.Buffer, entries, cellSize uint16) {
	binary.Write(buf, binary.LittleEndian, entries)
	binary.Write(buf, binary.LittleEndian, cellSize)
}

// TS_GLYPHCACHE_CAPABILITYSET per [MS-RDPBCGR] §2.2.7.1.8.
// glyphSupportLevel = GLYPH_SUPPORT_NONE; cell sizes match the mstsc defaults.
func writeGlyphCacheCapabilitySet(buf *bytes.Buffer) {
	body := new(bytes.Buffer)
	writeCacheDefinition(body, 254, 4)
	writeCacheDefinition(body, 254, 4)
	writeCacheDefinition(body, 254, 8)
	writeCacheDefinition(body, 254, 8)
	writeCacheDefinition(body, 254, 16)
	writeCacheDefinition(body, 254, 32)
	writeCacheDefinition(body, 254, 64)
	writeCacheDefinition(body, 254, 128)
	writeCacheDefinition(body, 254, 256)
	writeCacheDefinition(body, 64, 2048)
	writeCacheDefinition(body, 256, 256)               /* fragCache */
	binary.Write(body, binary.LittleEndian, uint16(0)) /* glyphSupportLevel */
	binary.Write(body, binary.LittleEndian, uint16(0)) /* pad2Octets */
	capabilitySet(buf, CAPSTYPE_GLYPHCACHE, body.Bytes())
}

// TS_OFFSCREEN_CAPABILITYSET per [MS-RDPBCGR] §2.2.7.1.9. Level 0 disables.
func writeOffscreenBitmapCacheCapabilitySet(buf *bytes.Buffer) {
	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, uint32(0)) /* offscreenSupportLevel */
	binary.Write(body, binary.LittleEndian, uint16(0)) /* offscreenCacheSize */
	binary.Write(body, binary.LittleEndian, uint16(0)) /* offscreenCacheEntries */
	capabilitySet(buf, CAPSTYPE_OFFSCREENCACHE, body.Bytes())
}

// TS_VIRTUALCHANNEL_CAPABILITYSET per [MS-RDPBCGR] §2.2.7.1.10. flags=0 means
// no compression supported; VCChunkSize is optional in v1.
func writeVirtualChannelCapabilitySet(buf *bytes.Buffer) {
	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, uint32(0)) /* flags */
	binary.Write(body, binary.LittleEndian, uint32(0)) /* VCChunkSize */
	capabilitySet(buf, CAPSTYPE_VIRTUALCHANNEL, body.Bytes())
}

// TS_SOUND_CAPABILITYSET per [MS-RDPBCGR] §2.2.7.1.11.
func writeSoundCapabilitySet(buf *bytes.Buffer) {
	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, uint16(0)) /* soundFlags */
	binary.Write(body, binary.LittleEndian, uint16(0)) /* pad2OctetsA */
	capabilitySet(buf, CAPSTYPE_SOUND, body.Bytes())
}

// TS_SHARE_CAPABILITYSET per [MS-RDPBCGR] §2.2.7.2.4. nodeId is 0 from client.
func writeShareCapabilitySet(buf *bytes.Buffer) {
	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, uint16(0))
	binary.Write(body, binary.LittleEndian, uint16(0))
	capabilitySet(buf, CAPSTYPE_SHARE, body.Bytes())
}

// TS_FONT_CAPABILITYSET per [MS-RDPBCGR] §2.2.7.2.5.
func writeFontCapabilitySet(buf *bytes.Buffer) {
	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, uint16(1)) /* FONTSUPPORT_FONTLIST */
	binary.Write(body, binary.LittleEndian, uint16(0))
	capabilitySet(buf, CAPSTYPE_FONT, body.Bytes())
}
