package rdp

import (
	"bytes"
	"encoding/binary"
)

func buildConfirmActivePDU(shareID uint32) ([]byte, error) {
	capsBuf := new(bytes.Buffer)

	addGeneralCapabilitySet(capsBuf)
	addBitmapCapabilitySet(capsBuf)
	addOrderCapabilitySet(capsBuf)
	addPointerCapabilitySet(capsBuf)

	capsData := capsBuf.Bytes()

	pdu := new(bytes.Buffer)
	binary.Write(pdu, binary.LittleEndian, shareID)
	binary.Write(pdu, binary.LittleEndian, uint16(1002))
	binary.Write(pdu, binary.LittleEndian, uint16(4))
	binary.Write(pdu, binary.LittleEndian, uint16(len(capsData)))
	pdu.WriteString("RDP\x00")
	binary.Write(pdu, binary.LittleEndian, uint16(4))
	binary.Write(pdu, binary.LittleEndian, uint16(0))
	pdu.Write(capsData)

	finalPDU := new(bytes.Buffer)
	pduBytes := pdu.Bytes()
	totalLength := uint16(len(pduBytes) + 6)
	binary.Write(finalPDU, binary.LittleEndian, totalLength)
	binary.Write(finalPDU, binary.LittleEndian, uint16(PDUTYPE_CONFIRMACTIVEPDU|0x10))
	binary.Write(finalPDU, binary.LittleEndian, uint16(1002))
	finalPDU.Write(pduBytes)

	return finalPDU.Bytes(), nil
}

func addGeneralCapabilitySet(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint16(CAPSTYPE_GENERAL))
	binary.Write(buf, binary.LittleEndian, uint16(24))
	binary.Write(buf, binary.LittleEndian, uint16(1))
	binary.Write(buf, binary.LittleEndian, uint16(3))
	binary.Write(buf, binary.LittleEndian, uint16(0x0200))
	
	// extraFlags: matching Rust client
	// LONG_CREDENTIALS_SUPPORTED | NO_BITMAP_COMPRESSION_HDR | ENC_SALTED_CHECKSUM | FASTPATH_OUTPUT_SUPPORTED
	extraFlags := uint16(LONG_CREDENTIALS_SUPPORTED | NO_BITMAP_COMPRESSION_HDR | ENC_SALTED_CHECKSUM | FASTPATH_OUTPUT_SUPPORTED)
	binary.Write(buf, binary.LittleEndian, extraFlags)
	buf.Write(make([]byte, 12))
}

func addBitmapCapabilitySet(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint16(CAPSTYPE_BITMAP))
	binary.Write(buf, binary.LittleEndian, uint16(28))
	binary.Write(buf, binary.LittleEndian, uint16(16)) // Changed to 16bpp to match CS_CORE
	binary.Write(buf, binary.LittleEndian, uint16(1))
	binary.Write(buf, binary.LittleEndian, uint16(1))
	binary.Write(buf, binary.LittleEndian, uint16(1))
	binary.Write(buf, binary.LittleEndian, uint16(1024))
	binary.Write(buf, binary.LittleEndian, uint16(768))
	buf.Write(make([]byte, 2))
	binary.Write(buf, binary.LittleEndian, uint16(1))
	binary.Write(buf, binary.LittleEndian, uint16(1))
	buf.Write(make([]byte, 8))
}


func addOrderCapabilitySet(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint16(CAPSTYPE_ORDER))
	binary.Write(buf, binary.LittleEndian, uint16(88))
	buf.Write(make([]byte, 30)) // Terminal descriptor (16 bytes) + Pad (2) + Cache sizes ... skipping for now to match offset
	// Actually, the Rust code has a complex struct. Let's just set the flags at the correct offset.
	// Order capability set is 88 bytes.
	// flags are at offset 80 (byte 84 in the struct?)?
	// Wait, looking at Rust code:
	// capability_set(Some(capability::ts_order_capability_set(Some(capability::OrderFlag::NEGOTIATEORDERSUPPORT as u16 | capability::OrderFlag::ZEROBOUNDSDELTASSUPPORT as u16))))
	// We need to be careful about the layout.
	// For now, we'll write the flags at the beginning of the "OrderSupport" array or "OrderFlags" field.
	// TS_ORDER_CAPABILITYSET:
	// terminalDescriptor (16 bytes)
	// pad4octets (4 bytes)
	// desktopSaveXGranularity (2 bytes)
	// desktopSaveYGranularity (2 bytes)
	// pad2octets (2 bytes)
	// maximumOrderLevel (2 bytes)
	// numberFonts (2 bytes)
	// orderFlags (2 bytes) <-- This is what we want?
	// orderSupport (32 bytes)
	// textFlags (2 bytes)
	// orderSupportExFlags (2 bytes)
	// ...
	
	// 16 + 4 + 2 + 2 + 2 + 2 + 2 = 30 bytes offset to orderFlags.
	
	// Writing 30 bytes of zeros (Terminal Descriptor...NumberFonts)
	buf.Write(make([]byte, 30)) 
	
	// orderFlags
	orderFlags := uint16(NEGOTIATEORDERSUPPORT | ZEROBOUNDSDELTASSUPPORT)
	binary.Write(buf, binary.LittleEndian, orderFlags)
	
	// Remaining bytes: 88 - 4 - 30 - 2 = 52 bytes
	buf.Write(make([]byte, 52))
}

func addPointerCapabilitySet(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint16(CAPSTYPE_POINTER))
	binary.Write(buf, binary.LittleEndian, uint16(10))
	binary.Write(buf, binary.LittleEndian, uint16(1))
	binary.Write(buf, binary.LittleEndian, uint16(20))
	binary.Write(buf, binary.LittleEndian, uint16(20))
}
