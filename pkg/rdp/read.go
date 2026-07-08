// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 x-stp

package rdp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/draw"
	"io"
	"net"
	"time"

	"github.com/x-stp/go-rdp-screenshotter/pkg/bitmap"
)

// canvasWidth / canvasHeight match the GCC client core data we advertise in
// CS_CORE; receiveBitmapUpdate composites every incoming bitmap rectangle
// here regardless of where the server places it.
const (
	canvasWidth  = 1024
	canvasHeight = 768
)

// frameTimings controls the receiveBitmapUpdate poll loop. idleTimeout is how
// long we'll wait without any new pixels before we declare the screenshot
// done; hardTimeout caps the total wait so a stuck server doesn't pin a
// worker forever.
type frameTimings struct {
	idle, hard time.Duration
}

var defaultFrameTimings = frameTimings{
	idle: 2 * time.Second,
	hard: 18 * time.Second, // headroom for a Deactivate/Reactivate cycle on modern hosts
}

// receiveBitmapUpdate composites incoming bitmap rectangles onto a 1024x768
// canvas and returns a PNG once the server idles or the hard deadline hits.
func (c *Client) receiveBitmapUpdate() ([]byte, error) {
	canvas := image.NewRGBA(image.Rect(0, 0, canvasWidth, canvasHeight))
	deadline := time.Now().Add(defaultFrameTimings.hard)
	idle := time.Now().Add(defaultFrameTimings.idle)
	gotAny := false

	for time.Now().Before(deadline) {
		pasted, err := c.pollOneFrame(canvas, idle, gotAny)
		if err != nil {
			return nil, err
		}
		switch {
		case pasted == frameDone:
			if !gotAny {
				return nil, fmt.Errorf("no bitmap update received")
			}
			return bitmap.EncodePNG(canvas)
		case pasted == frameReactivated:
			// The server tore down the share and handed us a new one
			// ([MS-RDPBCGR] §1.3.1.3). Give it a fresh idle window so the
			// reactivation gap doesn't count as "server went quiet"; keep
			// the hard deadline as the overall safety cap.
			idle = time.Now().Add(defaultFrameTimings.idle)
		case pasted > 0:
			gotAny = true
			idle = time.Now().Add(defaultFrameTimings.idle)
		}
	}

	if !gotAny {
		return nil, fmt.Errorf("no bitmap update received")
	}
	return bitmap.EncodePNG(canvas)
}

// frameDone is the sentinel pollOneFrame returns when the idle window has
// closed and we already have at least one rectangle: receiveBitmapUpdate
// PNG-encodes what's on the canvas.
const frameDone = -1

// frameReactivated is the sentinel returned when we handled a Deactivate All
// or a new Demand Active mid-capture. It carries no pixels but tells the
// caller to reset the idle window rather than treat the quiet as "done".
const frameReactivated = -2

// pollOneFrame waits up to (idle - now) for one TPKT or fast-path PDU,
// dispatches it, and reports the number of rectangles composited. Returns
// frameDone when the idle window is exhausted with at least one frame in
// hand.
func (c *Client) pollOneFrame(canvas *image.RGBA, idle time.Time, gotAny bool) (int, error) {
	remaining := time.Until(idle)
	if remaining <= 0 && gotAny {
		return frameDone, nil
	}
	if remaining <= 0 {
		remaining = 250 * time.Millisecond
	}
	c.conn.SetReadDeadline(time.Now().Add(remaining))
	peek := make([]byte, 1)
	_, err := io.ReadFull(c.conn, peek)
	c.conn.SetReadDeadline(time.Time{})
	if err != nil {
		return c.handleFrameReadError(err, gotAny)
	}

	if peek[0] != TPKTVersion {
		n, err := c.handleFastPathPDUInto(peek[0], canvas)
		if err != nil {
			Logger.Debug().Err(err).Msg("fast-path PDU")
			return 0, nil
		}
		return n, nil
	}
	raw, err := c.readSlowPathRemainder()
	if err != nil {
		Logger.Debug().Err(err).Msg("slow-path read")
		return 0, nil
	}
	return c.handleSlowPathPDUInto(raw, canvas), nil
}

// handleFrameReadError translates an i/o error from the peek byte into the
// poll-loop's three-way decision: stop the loop (frameDone), stop with an
// error to the caller, or skip and try the next iteration.
func (c *Client) handleFrameReadError(err error, gotAny bool) (int, error) {
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		if gotAny {
			return frameDone, nil
		}
		return 0, nil
	}
	if gotAny {
		return frameDone, nil
	}
	return 0, fmt.Errorf("read header byte: %w", err)
}

// readSlowPathRemainder reads the remainder of a TPKT/X.224 framed PDU after
// the version byte (0x03) has already been consumed.
func (c *Client) readSlowPathRemainder() ([]byte, error) {
	tail := make([]byte, 3)
	if _, err := io.ReadFull(c.conn, tail); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(tail[1:3])
	if length < 7 {
		return nil, fmt.Errorf("invalid TPKT length %d", length)
	}
	payload := make([]byte, length-4)
	if _, err := io.ReadFull(c.conn, payload); err != nil {
		return nil, err
	}
	if len(payload) >= 3 && payload[0] == 0x02 && payload[1] == 0xf0 && payload[2] == 0x80 {
		return payload[3:], nil
	}
	return payload, nil
}

// handleSlowPathPDUInto decodes one slow-path PDU and pastes any bitmap
// rectangles it contains onto canvas. The function is a thin pipeline:
// strip MCS Send-Data-Indication -> strip basic security header -> dispatch
// the share-control PDU to the appropriate handler.
func (c *Client) handleSlowPathPDUInto(raw []byte, canvas *image.RGBA) int {
	inner, ok := stripMCSSendDataIndication(raw)
	if !ok {
		return 0
	}
	secFlags, data, err := c.consumeSecurityHeader(inner)
	if err != nil || data == nil {
		return 0
	}
	if c.handleControlChannelPDU(secFlags, data) {
		return 0
	}
	return c.dispatchShareControl(data, canvas)
}

// stripMCSSendDataIndication unwraps the MCS Send-Data-Indication envelope
// when the raw PDU starts with one. PDUs that already arrived unwrapped (some
// pre-active server traffic) are passed through.
func stripMCSSendDataIndication(raw []byte) ([]byte, bool) {
	if len(raw) > 0 && raw[0]>>2 == mcsDomainSendDataIndication {
		sdi, err := parseMCSSendDataIndication(raw)
		if err != nil {
			return nil, false
		}
		return sdi.UserData, true
	}
	return raw, true
}

// handleControlChannelPDU consumes PDUs that carry licensing / auto-detect /
// heartbeat / redirection traffic in their security flags and returns true
// when one was matched (the caller should skip share-control parsing).
func (c *Client) handleControlChannelPDU(secFlags uint16, data []byte) bool {
	switch {
	case secFlags&SEC_LICENSE_PKT != 0:
		_ = c.handleLicensingPDU(data)
		return true
	case secFlags&(SEC_AUTODETECT_REQ|SEC_HEARTBEAT|SEC_REDIRECTION_PKT) != 0:
		return true
	}
	return false
}

// dispatchShareControl peels off the share-control header and fans out on the
// PDU type. Data PDUs carry the bitmap updates we want; Deactivate All and a
// subsequent Demand Active drive the reactivation sequence
// ([MS-RDPBCGR] §1.3.1.3) that modern Windows servers run mid-session.
func (c *Client) dispatchShareControl(data []byte, canvas *image.RGBA) int {
	if len(data) < 6 {
		return 0
	}
	hdr, err := parseShareControlHeader(bytes.NewReader(data))
	if err != nil {
		return 0
	}
	switch hdr.PDUType & 0x0F {
	case PDUTYPE_DATAPDU:
		return c.dispatchDataPDU(data, canvas)
	case PDUTYPE_DEACTIVATEALLPDU:
		// Server dropped the current share; the next Demand Active will set
		// up a new one. Nothing to paste, but signal a reactivation so the
		// poll loop resets its idle window.
		Logger.Debug().Msg("reactivation: received Deactivate All")
		return frameReactivated
	case PDUTYPE_DEMANDACTIVEPDU:
		return c.handleMidCaptureDemandActive(data)
	}
	return 0
}

// dispatchDataPDU handles a PDUTYPE_DATAPDU: bitmap updates paint the canvas,
// server synchronize is echoed back, everything else is ignored.
func (c *Client) dispatchDataPDU(data []byte, canvas *image.RGBA) int {
	if len(data) < 18 {
		return 0
	}
	dh, err := parseShareDataHeader(bytes.NewReader(data[6:]))
	if err != nil {
		return 0
	}
	switch dh.PDUType2 {
	case PDUTYPE2_UPDATE:
		return c.compositeUpdate(data[18:], canvas)
	case PDUTYPE2_SYNCHRONIZE:
		// Echo the server's Synchronize ([MS-RDPBCGR] §2.2.1.14). A write
		// failure here just means the peer is gone; the next read surfaces
		// it, so log and continue rather than aborting the capture.
		if err := c.sendChannelData(buildSynchronizePDU(c.mcsUserID, c.shareID)); err != nil {
			Logger.Debug().Err(err).Msg("synchronize echo")
		}
	}
	return 0
}

// handleMidCaptureDemandActive re-runs the activation handshake against a
// share the server re-advertised mid-capture ([MS-RDPBCGR] §1.3.1.3): parse
// the new Demand Active, Confirm Active on the new shareID, and re-send the
// finalization PDUs so bitmap output resumes. Returns frameReactivated on
// success (no pixels yet) or 0 if any step fails (best-effort; the caller's
// hard deadline still bounds the wait).
func (c *Client) handleMidCaptureDemandActive(data []byte) int {
	c.unreadData = data
	shareID, err := c.receiveDemandActive()
	if err != nil {
		Logger.Debug().Err(err).Msg("reactivation: parse Demand Active")
		return 0
	}
	if err := c.sendConfirmActive(shareID); err != nil {
		Logger.Debug().Err(err).Msg("reactivation: Confirm Active")
		return 0
	}
	if err := c.sendFinalizationPDUs(); err != nil {
		Logger.Debug().Err(err).Msg("reactivation: finalization")
		return 0
	}
	Logger.Debug().Uint32("shareID", shareID).Msg("reactivation: re-activated on new share")
	return frameReactivated
}

// compositeUpdate decodes a TS_UPDATE_BITMAP payload (slow-path or fast-path)
// and composites each rectangle into canvas at (DestLeft, DestTop).
func (c *Client) compositeUpdate(data []byte, canvas *image.RGBA) int {
	if len(data) < 2 || binary.LittleEndian.Uint16(data) != UPDATETYPE_BITMAP {
		return 0
	}
	upd, err := parseBitmapUpdateData(data)
	if err != nil {
		return 0
	}
	pasted := 0
	for _, rect := range upd.Rectangles {
		if len(rect.BitmapDataStream) == 0 {
			continue
		}
		compressed := rect.Flags&BITMAP_COMPRESSION != 0
		img, err := bitmap.DecodeRect(rect.Width, rect.Height, rect.BitsPerPixel, compressed, rect.BitmapDataStream)
		if err != nil {
			continue
		}
		dst := image.Rect(int(rect.DestLeft), int(rect.DestTop),
			int(rect.DestLeft)+int(rect.Width), int(rect.DestTop)+int(rect.Height))
		draw.Draw(canvas, dst, img, image.Point{}, draw.Src)
		pasted++
	}
	return pasted
}

// handleFastPathPDUInto consumes a server fast-path PDU ([MS-RDPBCGR]
// §2.2.9.1.2) and composites any FASTPATH_UPDATETYPE_BITMAP rectangles into
// canvas. Returns the number of rectangles successfully pasted.
func (c *Client) handleFastPathPDUInto(firstByte byte, canvas *image.RGBA) (int, error) {
	body, err := c.readFastPathBody(firstByte)
	if err != nil {
		return 0, err
	}
	return c.compositeFastPathUpdates(body, canvas)
}

// readFastPathBody reads the variable-length fast-path header and body
// following the already-consumed firstByte, decrypting if SEC_FP_FASTPATH_HDR
// signalled encryption.
func (c *Client) readFastPathBody(firstByte byte) ([]byte, error) {
	totalLen, headerLen, err := c.readFastPathLength()
	if err != nil {
		return nil, err
	}
	if totalLen < headerLen {
		return nil, fmt.Errorf("fast-path length %d < header %d", totalLen, headerLen)
	}
	body := make([]byte, totalLen-headerLen)
	if _, err := io.ReadFull(c.conn, body); err != nil {
		return nil, err
	}
	if firstByte&0x80 != 0 && c.decryptor != nil {
		if len(body) < 8 {
			return nil, fmt.Errorf("fast-path encrypted body too short")
		}
		body = body[8:]
		c.decryptor.XORKeyStream(body, body)
	}
	return body, nil
}

// readFastPathLength reads the 1- or 2-byte fast-path length determinant
// per [MS-RDPBCGR] §5.5 and returns (totalLen, headerLen) where headerLen
// counts the firstByte we already peeked.
func (c *Client) readFastPathLength() (totalLen, headerLen int, err error) {
	lenByte := make([]byte, 1)
	if _, err = io.ReadFull(c.conn, lenByte); err != nil {
		return 0, 0, err
	}
	if lenByte[0]&0x80 == 0 {
		return int(lenByte[0]), 2, nil
	}
	lenByte2 := make([]byte, 1)
	if _, err = io.ReadFull(c.conn, lenByte2); err != nil {
		return 0, 0, err
	}
	return int(lenByte[0]&0x7F)<<8 | int(lenByte2[0]), 3, nil
}

// compositeFastPathUpdates walks the concatenated TS_FP_UPDATE blocks in body
// and pastes any bitmap rectangles into canvas. Non-bitmap update types
// (orders, palettes, pointers) are skipped.
func (c *Client) compositeFastPathUpdates(body []byte, canvas *image.RGBA) (int, error) {
	pasted := 0
	for len(body) >= 1 {
		updateCode := body[0] & 0x0F
		compression := (body[0] >> 6) & 0x03
		off := 1
		if compression != 0 {
			off++
		}
		if len(body) < off+2 {
			return pasted, fmt.Errorf("fast-path update truncated header")
		}
		size := int(binary.LittleEndian.Uint16(body[off : off+2]))
		off += 2
		if len(body) < off+size {
			return pasted, fmt.Errorf("fast-path update truncated body: need %d have %d", size, len(body)-off)
		}
		updData := body[off : off+size]
		body = body[off+size:]
		if updateCode == FASTPATH_UPDATETYPE_BITMAP {
			pasted += c.compositeUpdate(updData, canvas)
		}
	}
	return pasted, nil
}

// readRawPDU reads one TPKT or fast-path PDU and returns the body with the
// X.224 Data TPDU header (slow path) or the fast-path header stripped.
func (c *Client) readRawPDU() ([]byte, error) {
	peek := make([]byte, 1)
	if _, err := io.ReadFull(c.conn, peek); err != nil {
		return nil, err
	}

	// [MS-RDPBCGR] §5.5: 0x03 = TPKT, anything else with low-2-bits == 00 is
	// a fast-path output PDU.
	if peek[0] != TPKTVersion {
		return c.readFastPathPDU(peek[0])
	}

	tail := make([]byte, 3)
	if _, err := io.ReadFull(c.conn, tail); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint16(tail[1:3])
	if length < 7 {
		return nil, fmt.Errorf("invalid TPKT length: %d", length)
	}

	payload := make([]byte, length-4)
	if _, err := io.ReadFull(c.conn, payload); err != nil {
		return nil, err
	}
	if len(payload) >= 3 && payload[0] == 0x02 && payload[1] == 0xf0 && payload[2] == 0x80 {
		return payload[3:], nil
	}
	return payload, nil
}

func (c *Client) readFastPathPDU(firstByte byte) ([]byte, error) {
	lenByte := make([]byte, 1)
	if _, err := io.ReadFull(c.conn, lenByte); err != nil {
		return nil, err
	}
	length := int(lenByte[0])
	if lenByte[0]&0x80 != 0 {
		lenByte2 := make([]byte, 1)
		if _, err := io.ReadFull(c.conn, lenByte2); err != nil {
			return nil, err
		}
		length = int(lenByte[0]&0x7F)<<8 | int(lenByte2[0])
	}

	data := make([]byte, length-2)
	if _, err := io.ReadFull(c.conn, data); err != nil {
		return nil, err
	}
	if firstByte&0x80 != 0 && c.decryptor != nil && len(data) > 8 {
		c.decryptor.XORKeyStream(data[8:], data[8:])
		return data[8:], nil
	}
	return data, nil
}

// readSecurePayload reads one slow-path MCS SendDataIndication and returns
// (securityFlags, payload) with the MCS and (when present) basic security
// headers stripped.
func (c *Client) readSecurePayload() (uint16, []byte, error) {
	raw, err := c.readRawPDU()
	if err != nil {
		return 0, nil, err
	}
	if len(raw) == 0 {
		return 0, raw, nil
	}
	inner := raw
	switch raw[0] >> 2 {
	case mcsDomainSendDataIndication, mcsDomainSendDataRequest:
		sdi, err := parseMCSSendDataIndication(raw)
		if err != nil {
			return 0, nil, err
		}
		inner = sdi.UserData
	}
	return c.consumeSecurityHeader(inner)
}
