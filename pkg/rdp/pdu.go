package rdp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

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

const (
	CTRLACTION_REQUEST_CONTROL = 0x0001
	CTRLACTION_GRANTED_CONTROL = 0x0002
	CTRLACTION_DETACH          = 0x0003
	CTRLACTION_COOPERATE       = 0x0004
)

type FontListPDU struct {
	NumberFonts   uint16
	TotalNumFonts uint16
	ListFlags     uint16
	EntrySize     uint16
}

const (
	INPUT_EVENT_SYNC     = 0x0000
	INPUT_EVENT_SCANCODE = 0x0004
	INPUT_EVENT_UNICODE  = 0x0005
	INPUT_EVENT_MOUSE    = 0x8001
	INPUT_EVENT_MOUSEX   = 0x8002
)

const (
	PTRFLAGS_MOVE    = 0x0800
	PTRFLAGS_DOWN    = 0x8000
	PTRFLAGS_BUTTON1 = 0x1000
	PTRFLAGS_BUTTON2 = 0x2000
	PTRFLAGS_BUTTON3 = 0x4000
)

func buildSynchronizePDU(targetUser uint16, shareID uint32) []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, uint16(1))
	binary.Write(buf, binary.LittleEndian, targetUser)

	return wrapInShareDataPDU(buf.Bytes(), PDUTYPE2_SYNCHRONIZE, shareID)
}

func buildControlPDU(action uint16, grantID uint16, shareID uint32) []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, action)
	binary.Write(buf, binary.LittleEndian, grantID)
	binary.Write(buf, binary.LittleEndian, uint32(0))

	return wrapInShareDataPDU(buf.Bytes(), PDUTYPE2_CONTROL, shareID)
}

func buildFontListPDU(userID uint16, shareID uint32) []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(3))
	binary.Write(buf, binary.LittleEndian, uint16(50))

	return wrapInShareDataPDU(buf.Bytes(), PDUTYPE2_FONTLIST, shareID)
}


func buildRefreshRectanglePDU(userID, channelID uint16, shareID uint32) []byte {
	buf := new(bytes.Buffer)

	// numberOfAreas (1 byte)
	buf.WriteByte(1)

	// pad3Octets (3 bytes)
	buf.Write([]byte{0, 0, 0})

	// areasToRefresh (InclusiveRectangle)
	// Left, Top, Right, Bottom (2 bytes each)
	binary.Write(buf, binary.LittleEndian, uint16(0))    // Left
	binary.Write(buf, binary.LittleEndian, uint16(0))    // Top
	binary.Write(buf, binary.LittleEndian, uint16(2000)) // Right (wide enough)
	binary.Write(buf, binary.LittleEndian, uint16(2000)) // Bottom (tall enough)

	shareDataPDU := wrapInShareDataPDU(buf.Bytes(), PDUTYPE2_REFRESH_RECT, shareID)

	// Wrap in MCS Send Data Request
	return buildMCSSendDataRequest(userID, channelID, shareDataPDU)
}

func buildPersistentKeyListPDU(bitmapCacheEntries []PersistentCacheEntry, userID uint16, shareID uint32) []byte {
	buf := new(bytes.Buffer)

	numEntries := uint16(len(bitmapCacheEntries))
	if numEntries > 169 {
		numEntries = 169
	}

	binary.Write(buf, binary.LittleEndian, numEntries)
	binary.Write(buf, binary.LittleEndian, numEntries)
	binary.Write(buf, binary.LittleEndian, uint8(0x03))
	binary.Write(buf, binary.LittleEndian, uint8(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))

	for i := uint16(0); i < numEntries; i++ {
		if i < uint16(len(bitmapCacheEntries)) {
			entry := bitmapCacheEntries[i]
			binary.Write(buf, binary.LittleEndian, entry.Key1)
			binary.Write(buf, binary.LittleEndian, entry.Key2)
		} else {

			binary.Write(buf, binary.LittleEndian, uint64(0))
		}
	}

	return wrapInShareDataPDU(buf.Bytes(), PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST, shareID)
}

type PersistentCacheEntry struct {
	Key1 uint32
	Key2 uint32
}

func wrapInShareDataPDU(data []byte, pduType2 uint8, shareID uint32) []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, uint16(0))
	binary.Write(buf, binary.LittleEndian, uint16(PDUTYPE_DATAPDU|0x10))
	binary.Write(buf, binary.LittleEndian, uint16(MCS_CHANNEL_GLOBAL))

	binary.Write(buf, binary.LittleEndian, shareID)
	binary.Write(buf, binary.LittleEndian, uint8(0))
	binary.Write(buf, binary.LittleEndian, uint8(1))
	binary.Write(buf, binary.LittleEndian, uint16(len(data)+8))
	binary.Write(buf, binary.LittleEndian, pduType2)
	binary.Write(buf, binary.LittleEndian, uint8(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))

	buf.Write(data)

	result := buf.Bytes()
	binary.LittleEndian.PutUint16(result[0:2], uint16(len(result)))

	return result
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

func parseBitmapUpdateData(data []byte) (*BitmapUpdateData, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("bitmap update data too short: %d bytes", len(data))
	}

	update := &BitmapUpdateData{}
	r := bytes.NewReader(data)

	binary.Read(r, binary.LittleEndian, &update.UpdateType)
	binary.Read(r, binary.LittleEndian, &update.NumberRectangles)

	fmt.Printf("Bitmap update: type=0x%04X, rectangles=%d\n", update.UpdateType, update.NumberRectangles)

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

		if rect.Flags&0x0001 != 0 {
			fmt.Printf("  Rectangle %d: compressed bitmap detected (not supported yet)\n", i)
		}

		if rect.BitmapLength > 0 {
			if r.Len() < int(rect.BitmapLength) {
				return nil, fmt.Errorf("insufficient data for rectangle %d bitmap: need %d, have %d",
					i, rect.BitmapLength, r.Len())
			}
			rect.BitmapDataStream = make([]byte, rect.BitmapLength)
			r.Read(rect.BitmapDataStream)
		}

		fmt.Printf("  Rectangle %d: (%d,%d)-(%d,%d), %dx%d, %d bpp, %d bytes\n",
			i, rect.DestLeft, rect.DestTop, rect.DestRight, rect.DestBottom,
			rect.Width, rect.Height, rect.BitsPerPixel, rect.BitmapLength)
	}

	return update, nil
}

func buildRefreshRectPDU(left, top, right, bottom uint16, userID uint16, shareID uint32) []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, uint8(1))

	binary.Write(buf, binary.LittleEndian, uint8(0))
	binary.Write(buf, binary.LittleEndian, uint16(0))

	binary.Write(buf, binary.LittleEndian, left)
	binary.Write(buf, binary.LittleEndian, top)
	binary.Write(buf, binary.LittleEndian, right)
	binary.Write(buf, binary.LittleEndian, bottom)

	return wrapInShareDataPDU(buf.Bytes(), PDUTYPE2_REFRESH_RECT, shareID)
}

func buildSuppressOutputPDU(allowDisplayUpdates bool, userID uint16, shareID uint32) []byte {
	buf := new(bytes.Buffer)

	if allowDisplayUpdates {
		binary.Write(buf, binary.LittleEndian, uint8(0))
		binary.Write(buf, binary.LittleEndian, uint8(0))
		binary.Write(buf, binary.LittleEndian, uint16(0))

		binary.Write(buf, binary.LittleEndian, uint16(0))
		binary.Write(buf, binary.LittleEndian, uint16(0))
		binary.Write(buf, binary.LittleEndian, uint16(1920))
		binary.Write(buf, binary.LittleEndian, uint16(1080))
	} else {
		binary.Write(buf, binary.LittleEndian, uint8(1))
		binary.Write(buf, binary.LittleEndian, uint8(0))
		binary.Write(buf, binary.LittleEndian, uint16(0))
	}

	return wrapInShareDataPDU(buf.Bytes(), PDUTYPE2_SUPPRESS_OUTPUT, shareID)
}

func buildInputEventPDU(events []InputEvent, userID uint16, shareID uint32) []byte {
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.LittleEndian, uint16(len(events)))

	binary.Write(buf, binary.LittleEndian, uint16(0))

	for _, event := range events {
		event.WriteTo(buf)
	}

	return wrapInShareDataPDU(buf.Bytes(), PDUTYPE2_INPUT, shareID)
}

type InputEvent struct {
	EventTime   uint32
	MessageType uint16
	DeviceFlags uint16
	Param1      uint16
	Param2      uint16
}

func (e *InputEvent) WriteTo(w io.Writer) {
	binary.Write(w, binary.LittleEndian, e.EventTime)
	binary.Write(w, binary.LittleEndian, e.MessageType)
	binary.Write(w, binary.LittleEndian, e.DeviceFlags)
	binary.Write(w, binary.LittleEndian, e.Param1)
	binary.Write(w, binary.LittleEndian, e.Param2)
}

func buildMouseMoveEvent(x, y uint16) InputEvent {
	return InputEvent{
		EventTime:   0,
		MessageType: INPUT_EVENT_MOUSE,
		DeviceFlags: PTRFLAGS_MOVE,
		Param1:      x,
		Param2:      y,
	}
}

func buildMouseClickEvent(x, y uint16, button uint16, down bool) InputEvent {
	flags := button
	if down {
		flags |= PTRFLAGS_DOWN
	}
	return InputEvent{
		EventTime:   0,
		MessageType: INPUT_EVENT_MOUSE,
		DeviceFlags: flags,
		Param1:      x,
		Param2:      y,
	}
}

func buildMockDemandActivePDU(userID uint16) []byte {
	buf := new(bytes.Buffer)

	buf.WriteByte(0x64)
	binary.Write(buf, binary.BigEndian, userID)
	binary.Write(buf, binary.BigEndian, uint16(1004))
	buf.WriteByte(0x70)

	shareCtrlBuf := new(bytes.Buffer)
	binary.Write(shareCtrlBuf, binary.LittleEndian, uint16(0))
	binary.Write(shareCtrlBuf, binary.LittleEndian, uint16(PDUTYPE_DEMANDACTIVEPDU|0x10))
	binary.Write(shareCtrlBuf, binary.LittleEndian, userID)

	binary.Write(shareCtrlBuf, binary.LittleEndian, uint32(0x12345678))

	binary.Write(shareCtrlBuf, binary.LittleEndian, uint16(1))

	binary.Write(shareCtrlBuf, binary.LittleEndian, uint16(CAPSTYPE_GENERAL))
	binary.Write(shareCtrlBuf, binary.LittleEndian, uint16(24))
	binary.Write(shareCtrlBuf, binary.LittleEndian, uint16(0x0103))
	binary.Write(shareCtrlBuf, binary.LittleEndian, uint16(0x0400))
	binary.Write(shareCtrlBuf, binary.LittleEndian, uint16(0x0200))
	binary.Write(shareCtrlBuf, binary.LittleEndian, uint16(0))
	binary.Write(shareCtrlBuf, binary.LittleEndian, uint16(0))
	binary.Write(shareCtrlBuf, binary.LittleEndian, uint16(0))
	binary.Write(shareCtrlBuf, binary.LittleEndian, uint16(0))
	binary.Write(shareCtrlBuf, binary.LittleEndian, uint16(0))
	binary.Write(shareCtrlBuf, binary.LittleEndian, uint16(0))
	binary.Write(shareCtrlBuf, binary.LittleEndian, uint8(0))
	binary.Write(shareCtrlBuf, binary.LittleEndian, uint8(0))

	shareCtrlData := shareCtrlBuf.Bytes()
	binary.LittleEndian.PutUint16(shareCtrlData[0:2], uint16(len(shareCtrlData)))

	if len(shareCtrlData) < 128 {
		buf.WriteByte(byte(len(shareCtrlData)))
	} else {
		buf.WriteByte(0x81)
		buf.WriteByte(byte(len(shareCtrlData)))
	}

	buf.Write(shareCtrlData)
	return buf.Bytes()
}

type FastPathUpdatePDU struct {
	UpdateCode       uint8
	Size             uint16
	Data             []byte
}

func parseFastPathUpdatePDU(data []byte) (*FastPathUpdatePDU, error) {
	if len(data) < 2 { // Need at least Header + 1 byte of potential data or size
		return nil, fmt.Errorf("fastpath PDU too short")
	}

	// Note: data[0] is the FastPath Header (action/sec flags)
	// data[1] is the Size or UpdateHeader?
	// Actually, structure is:
	// 1. FP Output Header (1 byte) - Action/Sec flags
	// 2. Length (1 or 2 bytes)
	// 3. FP Update PDU (Payload)
	//    - updateHeader (1 byte)
	//    - compressionFlags (optional 1 byte)
	//    - size (2 bytes)
	//    - updateData
	
	// BUT client.go's readFastPathPDU returns: [Header Byte] + [Decrypted Payload]
	// So data[0] = Header Byte
	// data[1:] = Payload (which starts with UpdateHeader)
	
	if len(data) < 2 {
		return nil, fmt.Errorf("fastpath data too short")
	}

	pdu := &FastPathUpdatePDU{
		UpdateCode: data[1],
	}
	offset := 2

	compression := (pdu.UpdateCode >> 6) & 0x03
	if compression == 0 && len(data) >= offset+2 {
		pdu.Size = binary.LittleEndian.Uint16(data[offset:])
		offset += 2
	}

	if len(data) > offset {
		pdu.Data = data[offset:]
	}

	return pdu, nil
}

func parseFastPathBitmapUpdate(data []byte) (*BitmapUpdateData, error) {
	// TS_FP_UPDATE_BITMAP
	// It does NOT contain an UpdateType field at the start.
	// It starts directly with fields specific to the update type.
	// For Bitmap: TS_FP_UPDATE_BITMAP
	// numberRectangles (2 bytes) - wait, verify this.
	
	// [MS-RDPBCGR] 2.2.9.1.2.1.1 Fast-Path Bitmap Update (TS_FP_UPDATE_BITMAP)
	// updateHeader (1 byte) - we already read this in PDU parser
	// numberRectangles (2 bytes, optional?? No, spec says:)
	// "The updateData field of the Fast-Path Update structure contains a TS_FP_UPDATE_BITMAP structure."
	// TS_FP_UPDATE_BITMAP:
	//   updateHeader (1 byte): same as PDU header? No.
	//   Actually, the UpdateCode in the PDU Header tells us it's a Bitmap Update.
	//   The payload IS the TS_FP_UPDATE_BITMAP (excluding the common header?)
	
	// Let's look at Rust implementation of `read_fast_path_bitmap_update`:
	// `let number_rectangles = stream.read_u16()?;` (Little Endian)
	// Then loop rectangles.
	
	// So there is NO `updateType` field in the payload.
	
	if len(data) < 2 {
		return nil, fmt.Errorf("fastpath bitmap update too short")
	}
	
	update := &BitmapUpdateData{
		UpdateType: FASTPATH_UPDATETYPE_BITMAP,
	}
	
	r := bytes.NewReader(data)
	
	binary.Read(r, binary.LittleEndian, &update.NumberRectangles)
	
	update.Rectangles = make([]BitmapData, update.NumberRectangles)
	for i := uint16(0); i < update.NumberRectangles; i++ {
		rect := &update.Rectangles[i]
		
		if r.Len() < 18 {
			return nil, fmt.Errorf("insufficient data for fastpath rectangle %d", i)
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
		
		if rect.Flags&BITMAP_COMPRESSION != 0 {
			// Check for optional BitmapComprHdr
			// We'll just skip it if we can guess the size or if it's fixed. 
			// But for NO_BITMAP_COMPRESSION_HDR (which we set in caps), it shouldn't be there?
			// Actually we set NO_BITMAP_COMPRESSION_HDR, so we expect NO header.
			// But if we receive compression, we might need to handle it.
			// For now, assume uncompressed or simple RLE without header if NO_BITMAP_COMPRESSION_HDR is set.
		}
		
		if rect.BitmapLength > 0 {
			if r.Len() < int(rect.BitmapLength) {
				return nil, fmt.Errorf("insufficient data for rectangle %d bitmap", i)
			}
			rect.BitmapDataStream = make([]byte, rect.BitmapLength)
			r.Read(rect.BitmapDataStream)
		}
	}
	
	return update, nil
}
