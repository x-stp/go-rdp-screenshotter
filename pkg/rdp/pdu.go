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

// Fast-Path Update Types
const (
	FASTPATH_UPDATETYPE_ORDERS       = 0x0
	FASTPATH_UPDATETYPE_BITMAP       = 0x1
	FASTPATH_UPDATETYPE_PALETTE      = 0x2
	FASTPATH_UPDATETYPE_SYNCHRONIZE  = 0x3
	FASTPATH_UPDATETYPE_SURFCMDS     = 0x4
	FASTPATH_UPDATETYPE_PTR_NULL     = 0x5
	FASTPATH_UPDATETYPE_PTR_DEFAULT  = 0x6
	FASTPATH_UPDATETYPE_PTR_POSITION = 0x8
	FASTPATH_UPDATETYPE_COLOR        = 0x9
	FASTPATH_UPDATETYPE_CACHED       = 0xA
	FASTPATH_UPDATETYPE_POINTER      = 0xB
)

// ShareControlHeader represents TS_SHARECONTROLHEADER
type ShareControlHeader struct {
	TotalLength uint16
	PDUType     uint16
	PDUSource   uint16
}

// ShareDataHeader represents TS_SHAREDATAHEADER
type ShareDataHeader struct {
	ShareID            uint32
	Pad1               uint8
	StreamID           uint8
	UncompressedLength uint16
	PDUType2           uint8
	CompressedType     uint8
	CompressedLength   uint16
}

// SynchronizePDU represents the Synchronize PDU (MS-RDPBCGR 2.2.1.14)
type SynchronizePDU struct {
	MessageType uint16
	TargetUser  uint16
}

// ControlPDU represents the Control PDU (MS-RDPBCGR 2.2.1.15)
type ControlPDU struct {
	Action    uint16
	GrantID   uint16
	ControlID uint32
}

// Control PDU Actions
const (
	CTRLACTION_REQUEST_CONTROL = 0x0001
	CTRLACTION_GRANTED_CONTROL = 0x0002
	CTRLACTION_DETACH          = 0x0003
	CTRLACTION_COOPERATE       = 0x0004
)

// FontListPDU represents the Font List PDU (MS-RDPBCGR 2.2.1.18)
type FontListPDU struct {
	NumberFonts   uint16
	TotalNumFonts uint16
	ListFlags     uint16
	EntrySize     uint16
}

// buildSynchronizePDU creates a Client Synchronize PDU
func buildSynchronizePDU(targetUser uint16) []byte {
	buf := new(bytes.Buffer)

	// TS_SYNCHRONIZE_PDU
	binary.Write(buf, binary.LittleEndian, uint16(1)) // messageType (SYNCMSGTYPE_SYNC)
	binary.Write(buf, binary.LittleEndian, targetUser)

	return wrapInShareDataPDU(buf.Bytes(), PDUTYPE2_SYNCHRONIZE, 0)
}

// buildControlPDU creates a Control PDU
func buildControlPDU(action uint16) []byte {
	buf := new(bytes.Buffer)

	// TS_CONTROL_PDU
	binary.Write(buf, binary.LittleEndian, action)
	binary.Write(buf, binary.LittleEndian, uint16(0)) // grantId
	binary.Write(buf, binary.LittleEndian, uint32(0)) // controlId

	return wrapInShareDataPDU(buf.Bytes(), PDUTYPE2_CONTROL, 0)
}

// buildFontListPDU creates a Font List PDU
func buildFontListPDU() []byte {
	buf := new(bytes.Buffer)

	// TS_FONT_LIST_PDU
	binary.Write(buf, binary.LittleEndian, uint16(0))  // numberFonts
	binary.Write(buf, binary.LittleEndian, uint16(0))  // totalNumFonts
	binary.Write(buf, binary.LittleEndian, uint16(3))  // listFlags (FONTLIST_FIRST | FONTLIST_LAST)
	binary.Write(buf, binary.LittleEndian, uint16(50)) // entrySize

	return wrapInShareDataPDU(buf.Bytes(), PDUTYPE2_FONTLIST, 0)
}

// wrapInShareDataPDU wraps data in a Share Data PDU
func wrapInShareDataPDU(data []byte, pduType2 uint8, shareID uint32) []byte {
	buf := new(bytes.Buffer)

	// TS_SHARECONTROLHEADER
	binary.Write(buf, binary.LittleEndian, uint16(0))                    // totalLength - will be filled
	binary.Write(buf, binary.LittleEndian, uint16(PDUTYPE_DATAPDU|0x10)) // pduType
	binary.Write(buf, binary.LittleEndian, uint16(MCS_CHANNEL_GLOBAL))   // pduSource

	// TS_SHAREDATAHEADER
	binary.Write(buf, binary.LittleEndian, shareID)
	binary.Write(buf, binary.LittleEndian, uint8(0))            // pad1
	binary.Write(buf, binary.LittleEndian, uint8(1))            // streamId (STREAM_LOW)
	binary.Write(buf, binary.LittleEndian, uint16(len(data)+8)) // uncompressedLength
	binary.Write(buf, binary.LittleEndian, pduType2)
	binary.Write(buf, binary.LittleEndian, uint8(0))  // compressedType (not compressed)
	binary.Write(buf, binary.LittleEndian, uint16(0)) // compressedLength

	// Data
	buf.Write(data)

	// Update total length
	result := buf.Bytes()
	binary.LittleEndian.PutUint16(result[0:2], uint16(len(result)))

	return result
}

// parseShareControlHeader parses a TS_SHARECONTROLHEADER
func parseShareControlHeader(r io.Reader) (*ShareControlHeader, error) {
	hdr := &ShareControlHeader{}
	if err := binary.Read(r, binary.LittleEndian, hdr); err != nil {
		return nil, err
	}
	return hdr, nil
}

// parseShareDataHeader parses a TS_SHAREDATAHEADER
func parseShareDataHeader(r io.Reader) (*ShareDataHeader, error) {
	hdr := &ShareDataHeader{}
	if err := binary.Read(r, binary.LittleEndian, hdr); err != nil {
		return nil, err
	}
	return hdr, nil
}

// BitmapData represents TS_BITMAP_DATA (MS-RDPBCGR 2.2.9.1.1.3.1.2)
type BitmapData struct {
	DestLeft         uint16
	DestTop          uint16
	DestRight        uint16
	DestBottom       uint16
	Width            uint16
	Height           uint16
	BitsPerPixel     uint16
	Flags            uint16
	BitmapLength     uint16
	BitmapDataStream []byte
}

// BitmapUpdateData represents TS_BITMAP_UPDATE (MS-RDPBCGR 2.2.9.1.1.3.1.1)
type BitmapUpdateData struct {
	UpdateType       uint16
	NumberRectangles uint16
	Rectangles       []BitmapData
}

// parseBitmapUpdateData parses bitmap update data
func parseBitmapUpdateData(data []byte) (*BitmapUpdateData, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("bitmap update data too short")
	}

	update := &BitmapUpdateData{}
	r := bytes.NewReader(data)

	// Read header
	binary.Read(r, binary.LittleEndian, &update.UpdateType)
	binary.Read(r, binary.LittleEndian, &update.NumberRectangles)

	// Read rectangles
	update.Rectangles = make([]BitmapData, update.NumberRectangles)
	for i := uint16(0); i < update.NumberRectangles; i++ {
		rect := &update.Rectangles[i]

		// Read bitmap header
		binary.Read(r, binary.LittleEndian, &rect.DestLeft)
		binary.Read(r, binary.LittleEndian, &rect.DestTop)
		binary.Read(r, binary.LittleEndian, &rect.DestRight)
		binary.Read(r, binary.LittleEndian, &rect.DestBottom)
		binary.Read(r, binary.LittleEndian, &rect.Width)
		binary.Read(r, binary.LittleEndian, &rect.Height)
		binary.Read(r, binary.LittleEndian, &rect.BitsPerPixel)
		binary.Read(r, binary.LittleEndian, &rect.Flags)
		binary.Read(r, binary.LittleEndian, &rect.BitmapLength)

		// Read bitmap data
		if rect.BitmapLength > 0 {
			rect.BitmapDataStream = make([]byte, rect.BitmapLength)
			r.Read(rect.BitmapDataStream)
		}

		fmt.Printf("  Bitmap rectangle %d: (%d,%d)-(%d,%d), %dx%d, %d bpp, %d bytes\n",
			i, rect.DestLeft, rect.DestTop, rect.DestRight, rect.DestBottom,
			rect.Width, rect.Height, rect.BitsPerPixel, rect.BitmapLength)
	}

	return update, nil
}
