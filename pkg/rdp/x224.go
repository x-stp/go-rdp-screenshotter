// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 x-stp

package rdp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

type X224ConnectionRequest struct {
	LengthIndicator uint8
	TPDUCode        uint8
	DstRef          uint16
	SrcRef          uint16
	ClassOptions    uint8
	Cookie          []byte
}

func NewX224ConnectionRequest(cookie string) *X224ConnectionRequest {
	return newX224ConnectionRequest(cookie, PROTOCOL_RDP|PROTOCOL_SSL|PROTOCOL_HYBRID)
}

func NewX224ConnectionRequestNoNLA(cookie string) *X224ConnectionRequest {
	return newX224ConnectionRequest(cookie, PROTOCOL_RDP|PROTOCOL_SSL)
}

func NewX224ConnectionRequestRDPOnly(cookie string) *X224ConnectionRequest {
	return newX224ConnectionRequest(cookie, PROTOCOL_RDP)
}

// clientSrcRef is the X.224 SRC-REF the client sticks into its CR. ITU-T X.224
// §13.3.4 only requires the value to be unique across in-flight TPDUs from the
// same NSAP; the actual value is otherwise opaque to the server. mstsc uses
// 0x1234 too.
const clientSrcRef uint16 = 0x1234

func newX224ConnectionRequest(cookie string, protocols uint32) *X224ConnectionRequest {
	cr := &X224ConnectionRequest{
		TPDUCode: X224_TPDU_CONNECTION_REQUEST,
		SrcRef:   clientSrcRef,
	}

	negReq := RDPNegReq{
		Type:      TYPE_RDP_NEG_REQ,
		Flags:     0,
		Length:    8,
		Protocols: protocols,
	}

	var cookieData bytes.Buffer
	if cookie != "" {
		fmt.Fprintf(&cookieData, "Cookie: mstshash=%s\r\n", cookie)
	}
	binary.Write(&cookieData, binary.LittleEndian, negReq)
	cr.Cookie = cookieData.Bytes()
	cr.LengthIndicator = uint8(6 + len(cr.Cookie))

	return cr
}

func (cr *X224ConnectionRequest) WriteTo(w io.Writer) (int64, error) {
	buf := make([]byte, 0, 7+len(cr.Cookie))
	buf = append(buf, cr.LengthIndicator, cr.TPDUCode)
	buf = binary.BigEndian.AppendUint16(buf, cr.DstRef)
	buf = binary.BigEndian.AppendUint16(buf, cr.SrcRef)
	buf = append(buf, cr.ClassOptions)
	buf = append(buf, cr.Cookie...)
	n, err := w.Write(buf)
	return int64(n), err
}

type X224ConnectionConfirm struct {
	LengthIndicator uint8
	TPDUCode        uint8
	DstRef          uint16
	SrcRef          uint16
	ClassOptions    uint8

	NegotiatedProtocol uint32
}

const (
	TYPE_RDP_NEG_REQ     = 0x01
	TYPE_RDP_NEG_RSP     = 0x02
	TYPE_RDP_NEG_FAILURE = 0x03

	PROTOCOL_RDP       = 0x00000000
	PROTOCOL_SSL       = 0x00000001
	PROTOCOL_HYBRID    = 0x00000002
	PROTOCOL_RDSTLS    = 0x00000004
	PROTOCOL_HYBRID_EX = 0x00000008

	SSL_REQUIRED_BY_SERVER      = 0x00000001
	SSL_NOT_ALLOWED_BY_SERVER   = 0x00000002
	SSL_CERT_NOT_ON_SERVER      = 0x00000003
	INCONSISTENT_FLAGS          = 0x00000004
	HYBRID_REQUIRED_BY_SERVER   = 0x00000005
	SSL_WITH_USER_AUTH_REQUIRED = 0x00000006
)

type RDPNegReq struct {
	Type      uint8
	Flags     uint8
	Length    uint16
	Protocols uint32
}

type RDPNegRsp struct {
	Type      uint8
	Flags     uint8
	Length    uint16
	Protocols uint32
}

type RDPNegFailure struct {
	Type        uint8
	Flags       uint8
	Length      uint16
	FailureCode uint32
}

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

// X224NegFailure carries an RDP_NEG_FAILURE failure code per [MS-RDPBCGR]
// §2.2.1.2.2. The TCP connection is dead; the caller must reconnect with a
// reduced protocol mask.
type X224NegFailure struct {
	Code uint32
}

func (e *X224NegFailure) Error() string {
	return "x224: " + failureReason(e.Code)
}

// parseRDPNegotiationResponse decodes the variable part of an X.224 Connection
// Confirm per [MS-RDPBCGR] §2.2.1.2. RDP_NEG_RSP returns the protocol mask;
// RDP_NEG_FAILURE returns *X224NegFailure.
func parseRDPNegotiationResponse(data []byte) (uint32, error) {
	if len(data) < 1 {
		return 0, nil
	}

	switch data[0] {
	case TYPE_RDP_NEG_RSP:
		if len(data) >= 8 {
			return binary.LittleEndian.Uint32(data[4:8]), nil
		}
	case TYPE_RDP_NEG_FAILURE:
		if len(data) >= 8 {
			return 0, &X224NegFailure{Code: binary.LittleEndian.Uint32(data[4:8])}
		}
	}
	return 0, nil
}

func ReadX224ConnectionConfirm(r io.Reader) (*X224ConnectionConfirm, error) {
	var fixed [7]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return nil, fmt.Errorf("read X.224 CC fixed header: %w", err)
	}

	cc := X224ConnectionConfirm{
		LengthIndicator: fixed[0],
		TPDUCode:        fixed[1],
		DstRef:          binary.BigEndian.Uint16(fixed[2:4]),
		SrcRef:          binary.BigEndian.Uint16(fixed[4:6]),
		ClassOptions:    fixed[6],
	}
	if cc.TPDUCode != X224_TPDU_CONNECTION_CONFIRM {
		return nil, fmt.Errorf("invalid TPDU code for CC: expected 0x%02X, got 0x%02X",
			X224_TPDU_CONNECTION_CONFIRM, cc.TPDUCode)
	}

	if cc.LengthIndicator > 6 {
		negData := make([]byte, int(cc.LengthIndicator)-6)
		if _, err := io.ReadFull(r, negData); err != nil {
			return nil, fmt.Errorf("read X.224 CC variable part: %w", err)
		}
		proto, err := parseRDPNegotiationResponse(negData)
		if err != nil {
			return nil, err
		}
		cc.NegotiatedProtocol = proto
	}
	return &cc, nil
}

func (c *Client) sendX224ConnectionRequest(cookie string) error {
	cr := pickConnectionRequest(cookie, c.opts)

	crSize := int(cr.LengthIndicator) + 1
	tpkt := NewTPKTHeader(crSize)

	buf := new(bytes.Buffer)
	if _, err := tpkt.WriteTo(buf); err != nil {
		return err
	}
	if _, err := cr.WriteTo(buf); err != nil {
		return err
	}

	if _, err := c.conn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to send X.224 Connection Request: %w", err)
	}

	Logger.Debug().Str("target", c.target).Msg("x224: sent connection request")
	return nil
}

// pickConnectionRequest chooses the protocol mask to advertise in the X.224
// NegReq based on opts. Order matters: disableSSL wins (forced fallback after
// SSL_NOT_ALLOWED_BY_SERVER), disableNLA next (forced fallback after anonymous
// CredSSP rejection), then HYBRID when we have a way to authenticate, else
// SSL-only.
func pickConnectionRequest(cookie string, opts *ClientOptions) *X224ConnectionRequest {
	switch {
	case opts == nil:
		return NewX224ConnectionRequestNoNLA(cookie)
	case opts.disableSSL:
		return NewX224ConnectionRequestRDPOnly(cookie)
	case opts.disableNLA:
		return NewX224ConnectionRequestNoNLA(cookie)
	case opts.Password != "" || opts.AnonymousNLA:
		return NewX224ConnectionRequest(cookie)
	default:
		return NewX224ConnectionRequestNoNLA(cookie)
	}
}

func (c *Client) receiveX224ConnectionConfirm() (uint32, error) {

	tpkt, err := ReadTPKTHeader(c.conn)
	if err != nil {
		return 0, fmt.Errorf("failed to read TPKT header: %w", err)
	}
	packetData := make([]byte, tpkt.Length-4)
	if _, err := io.ReadFull(c.conn, packetData); err != nil {
		return 0, fmt.Errorf("failed to read packet data: %w", err)
	}

	buf := bytes.NewReader(packetData)
	cc, err := ReadX224ConnectionConfirm(buf)
	if err != nil {
		return 0, err
	}

	c.x224SrcRef = cc.SrcRef
	Logger.Debug().Uint32("protocol", cc.NegotiatedProtocol).Msg("x224: negotiated")
	return cc.NegotiatedProtocol, nil
}
