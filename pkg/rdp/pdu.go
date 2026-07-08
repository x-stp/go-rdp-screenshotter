// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 x-stp

package rdp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// FASTPATH_UPDATETYPE_BITMAP is the fast-path output update type for bitmap
// data per [MS-RDPBCGR] §2.2.9.1.2.1. It is the only update type the
// screenshotter consumes; handleFastPathPDUInto recognises and skips the rest.
const FASTPATH_UPDATETYPE_BITMAP = 0x1

type ShareControlHeader struct {
	TotalLength uint16
	PDUType     uint16
	PDUSource   uint16
}

type ShareDataHeader struct {
	ShareID            uint32
	Pad1               uint8
	StreamID           uint8
	UncompressedLength uint16
	PDUType2           uint8
	CompressedType     uint8
	CompressedLength   uint16
}

type SynchronizePDU struct {
	MessageType uint16
	TargetUser  uint16
}

type ControlPDU struct {
	Action    uint16
	GrantID   uint16
	ControlID uint32
}

// Control PDU actions per [MS-RDPBCGR] §2.2.1.15.1.
const (
	CTRLACTION_REQUEST_CONTROL = 0x0001
	CTRLACTION_COOPERATE       = 0x0004
)

type FontListPDU struct {
	NumberFonts   uint16
	TotalNumFonts uint16
	ListFlags     uint16
	EntrySize     uint16
}

// Client Synchronize PDU per [MS-RDPBCGR] §2.2.1.14. messageType is fixed to
// SYNCMSGTYPE_SYNC; targetUser carries the client's mcsUserID by convention,
// since the server ignores the field for client→server sync.
func buildSynchronizePDU(userID uint16, shareID uint32) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(1))
	binary.Write(buf, binary.LittleEndian, userID)
	return buildShareDataPDU(buf.Bytes(), PDUTYPE2_SYNCHRONIZE, userID, shareID)
}

// Client Control PDU per [MS-RDPBCGR] §2.2.1.15.
func buildControlPDU(action uint16, userID uint16, shareID uint32) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, action)
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	return buildShareDataPDU(buf.Bytes(), PDUTYPE2_CONTROL, userID, shareID)
}

// Client Font List PDU per [MS-RDPBCGR] §2.2.1.18 with listFlags =
// FONTLIST_FIRST|FONTLIST_LAST (empty list, single packet).
func buildFontListPDU(userID uint16, shareID uint32) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(0))  /* numberFonts */
	binary.Write(buf, binary.LittleEndian, uint16(0))  /* totalNumFonts */
	binary.Write(buf, binary.LittleEndian, uint16(3))  /* listFlags */
	binary.Write(buf, binary.LittleEndian, uint16(50)) /* entrySize */
	return buildShareDataPDU(buf.Bytes(), PDUTYPE2_FONTLIST, userID, shareID)
}

// buildShareDataPDU wraps data in a TS_SHARECONTROLHEADER ([MS-RDPBCGR]
// §2.2.8.1.1.1.1) + TS_SHAREDATAHEADER (§2.2.8.1.1.1.2). uncompressedLength
// covers both headers and the data, matching what mstsc and Windows servers
// emit; some servers reject the body-only form.
func buildShareDataPDU(data []byte, pduType2 uint8, userID uint16, shareID uint32) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(PDUTYPE_DATAPDU|0x10))
	binary.Write(buf, binary.LittleEndian, userID)
	binary.Write(buf, binary.LittleEndian, shareID)
	binary.Write(buf, binary.LittleEndian, uint8(0))
	binary.Write(buf, binary.LittleEndian, uint8(1))
	binary.Write(buf, binary.LittleEndian, uint16(len(data)+18))
	binary.Write(buf, binary.LittleEndian, pduType2)
	binary.Write(buf, binary.LittleEndian, uint8(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	buf.Write(data)
	out := buf.Bytes()
	binary.LittleEndian.PutUint16(out[0:2], uint16(len(out)))
	return out
}

func parseShareControlHeader(r io.Reader) (*ShareControlHeader, error) {
	hdr := &ShareControlHeader{}
	if err := binary.Read(r, binary.LittleEndian, hdr); err != nil {
		return nil, err
	}
	return hdr, nil
}

func parseShareDataHeader(r io.Reader) (*ShareDataHeader, error) {
	hdr := &ShareDataHeader{}
	if err := binary.Read(r, binary.LittleEndian, hdr); err != nil {
		return nil, err
	}
	return hdr, nil
}

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

type BitmapUpdateData struct {
	UpdateType       uint16
	NumberRectangles uint16
	Rectangles       []BitmapData
}

// parseBitmapUpdateData parses a TS_UPDATE_BITMAP per [MS-RDPBCGR] §2.2.9.1.1.3.1.2
// or its fast-path counterpart (TS_FP_UPDATE_BITMAP, 2.2.9.1.2.1.2).
//
// Bitmap rectangles can be compressed using RDP RLE bitmap compression
// ([MS-RDPBCGR] §3.1.9.1), which is unrelated to MPPC. We pass the data
// through untouched and leave decoding to pkg/bitmap.
func parseBitmapUpdateData(data []byte) (*BitmapUpdateData, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("bitmap update data too short: %d bytes", len(data))
	}

	update := &BitmapUpdateData{}
	r := bytes.NewReader(data)

	binary.Read(r, binary.LittleEndian, &update.UpdateType)
	binary.Read(r, binary.LittleEndian, &update.NumberRectangles)

	update.Rectangles = make([]BitmapData, update.NumberRectangles)
	for i := uint16(0); i < update.NumberRectangles; i++ {
		rect := &update.Rectangles[i]

		if r.Len() < 18 {
			return nil, fmt.Errorf("insufficient data for rectangle %d header", i)
		}

		binary.Read(r, binary.LittleEndian, &rect.DestLeft)
		binary.Read(r, binary.LittleEndian, &rect.DestTop)
		binary.Read(r, binary.LittleEndian, &rect.DestRight)
		binary.Read(r, binary.LittleEndian, &rect.DestBottom)
		binary.Read(r, binary.LittleEndian, &rect.Width)
		binary.Read(r, binary.LittleEndian, &rect.Height)
		binary.Read(r, binary.LittleEndian, &rect.BitsPerPixel)
		binary.Read(r, binary.LittleEndian, &rect.Flags)
		binary.Read(r, binary.LittleEndian, &rect.BitmapLength)

		if rect.BitmapLength > 0 {
			if r.Len() < int(rect.BitmapLength) {
				return nil, fmt.Errorf("insufficient data for rectangle %d bitmap: need %d, have %d",
					i, rect.BitmapLength, r.Len())
			}
			rect.BitmapDataStream = make([]byte, rect.BitmapLength)
			r.Read(rect.BitmapDataStream)
		}
	}

	return update, nil
}
