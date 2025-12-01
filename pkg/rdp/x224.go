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
	cr := &X224ConnectionRequest{
		TPDUCode:     0xE0,
		DstRef:       0,
		SrcRef:       0x1234,
		ClassOptions: 0,
	}

	negReq := RDPNegReq{
		Type:      TYPE_RDP_NEG_REQ,
		Flags:     0,
		Length:    8,
		Protocols: PROTOCOL_SSL, // Try to force TLS without NLA (CredSSP)
	}

	var cookieData bytes.Buffer
	if cookie != "" {
		cookieData.WriteString(fmt.Sprintf("Cookie: mstshash=%s\r\n", cookie))
	}
	binary.Write(&cookieData, binary.LittleEndian, negReq)
	cr.Cookie = cookieData.Bytes()
	cr.LengthIndicator = uint8(6 + len(cr.Cookie))

	return cr
}

func (cr *X224ConnectionRequest) WriteTo(w io.Writer) (int64, error) {

	buf := new(bytes.Buffer)

	fields := []interface{}{
		cr.LengthIndicator,
		cr.TPDUCode,
		cr.DstRef,
		cr.SrcRef,
		cr.ClassOptions,
	}

	for _, field := range fields {
		if err := binary.Write(buf, binary.BigEndian, field); err != nil {
			return 0, fmt.Errorf("failed to write X.224 CR field: %w", err)
		}
	}

	if len(cr.Cookie) > 0 {
		if _, err := buf.Write(cr.Cookie); err != nil {
			return 0, fmt.Errorf("failed to write RDP cookie: %w", err)
		}
	}

	n, err := w.Write(buf.Bytes())
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

func protocolName(protocol uint32) string {
	switch protocol {
	case PROTOCOL_RDP:
		return "Standard RDP (no security)"
	case PROTOCOL_SSL:
		return "TLS/SSL Security"
	case PROTOCOL_HYBRID:
		return "CredSSP (NLA)"
	case PROTOCOL_RDSTLS:
		return "RDSTLS"
	case PROTOCOL_HYBRID_EX:
		return "CredSSP with Early User Auth"
	default:
		return fmt.Sprintf("Unknown (0x%08X)", protocol)
	}
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

func parseRDPNegotiationResponse(data []byte) uint32 {
	if len(data) < 1 {
		return 0
	}

	negType := data[0]

	switch negType {
	case TYPE_RDP_NEG_RSP:
		if len(data) >= 8 {
			var rsp RDPNegRsp
			rsp.Type = data[0]
			rsp.Flags = data[1]
			rsp.Length = binary.LittleEndian.Uint16(data[2:4])
			rsp.Protocols = binary.LittleEndian.Uint32(data[4:8])

			fmt.Printf("\n=== RDP Negotiation Response ===\n")
			fmt.Printf("Server selected protocol: %s\n", protocolName(rsp.Protocols))
			fmt.Printf("This means the server requires: ")

			switch rsp.Protocols {
			case PROTOCOL_RDP:
				fmt.Println("No special security (legacy RDP)")
			case PROTOCOL_SSL:
				fmt.Println("TLS/SSL encryption")
			case PROTOCOL_HYBRID:
				fmt.Println("Network Level Authentication (NLA) with CredSSP")
			case PROTOCOL_HYBRID_EX:
				fmt.Println("Enhanced NLA with early user authentication")
			}
			fmt.Println("================================")

			return rsp.Protocols
		}

	case TYPE_RDP_NEG_FAILURE:
		if len(data) >= 8 {
			var fail RDPNegFailure
			fail.Type = data[0]
			fail.Flags = data[1]
			fail.Length = binary.LittleEndian.Uint16(data[2:4])
			fail.FailureCode = binary.LittleEndian.Uint32(data[4:8])

			fmt.Printf("\n=== RDP Negotiation Failure ===\n")
			fmt.Printf("Server rejected connection: %s\n", failureReason(fail.FailureCode))
			fmt.Printf("===============================\n\n")
		}
	}

	return 0
}

func ReadX224ConnectionConfirm(r io.Reader) (*X224ConnectionConfirm, error) {
	var cc X224ConnectionConfirm

	if err := binary.Read(r, binary.BigEndian, &cc.LengthIndicator); err != nil {
		return nil, fmt.Errorf("failed to read CC length indicator: %w", err)
	}

	fields := []interface{}{
		&cc.TPDUCode,
		&cc.DstRef,
		&cc.SrcRef,
		&cc.ClassOptions,
	}

	for _, field := range fields {
		if err := binary.Read(r, binary.BigEndian, field); err != nil {
			return nil, fmt.Errorf("failed to read CC field: %w", err)
		}
	}

	if cc.TPDUCode != X224_TPDU_CONNECTION_CONFIRM {
		return nil, fmt.Errorf("invalid TPDU code for CC: expected 0x%02X, got 0x%02X",
			X224_TPDU_CONNECTION_CONFIRM, cc.TPDUCode)
	}

	if cc.LengthIndicator > 6 {
		remaining := int(cc.LengthIndicator) - 6
		negData := make([]byte, remaining)
		if _, err := io.ReadFull(r, negData); err != nil {
			return nil, fmt.Errorf("failed to read CC variable part: %w", err)
		}

		cc.NegotiatedProtocol = parseRDPNegotiationResponse(negData)
	}

	return &cc, nil
}

type X224DataTPDU struct {
	LengthIndicator uint8
	TPDUCode        uint8
	EOT             uint8
}

func (dt *X224DataTPDU) WriteTo(w io.Writer) (int64, error) {
	data := []byte{
		dt.LengthIndicator,
		dt.TPDUCode,
		dt.EOT,
	}
	n, err := w.Write(data)
	return int64(n), err
}

func (c *Client) sendX224ConnectionRequest(cookie string) error {
	fmt.Printf("\n=== SENDING X.224 CONNECTION REQUEST ===\n")
	fmt.Printf("Cookie: %q\n", cookie)

	cr := NewX224ConnectionRequest(cookie)

	crSize := int(cr.LengthIndicator) + 1
	tpkt := NewTPKTHeader(crSize)

	buf := new(bytes.Buffer)
	if _, err := tpkt.WriteTo(buf); err != nil {
		return err
	}
	if _, err := cr.WriteTo(buf); err != nil {
		return err
	}

	fmt.Printf("TPKT Header: Version=%d, Length=%d\n", tpkt.Version, tpkt.Length)
	fmt.Printf("X.224 CR: LI=%d, TPDU=0x%02X, DstRef=0x%04X, SrcRef=0x%04X\n",
		cr.LengthIndicator, cr.TPDUCode, cr.DstRef, cr.SrcRef)
	fmt.Printf("Total packet size: %d bytes\n", buf.Len())
	fmt.Printf("\nX.224 CR Packet Hex:\n")
	hexDump(buf.Bytes())

	if _, err := c.conn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to send X.224 Connection Request: %w", err)
	}

	fmt.Printf("X.224 Connection Request sent successfully\n\n")
	return nil
}

func (c *Client) receiveX224ConnectionConfirm() (uint32, error) {
	fmt.Printf("\n=== RECEIVING X.224 CONNECTION CONFIRM ===\n")

	tpkt, err := ReadTPKTHeader(c.conn)
	if err != nil {
		return 0, fmt.Errorf("failed to read TPKT header: %w", err)
	}
	fmt.Printf("TPKT Header: Version=%d, Length=%d\n", tpkt.Version, tpkt.Length)

	packetData := make([]byte, tpkt.Length-4)
	if _, err := io.ReadFull(c.conn, packetData); err != nil {
		return 0, fmt.Errorf("failed to read packet data: %w", err)
	}

	fmt.Printf("\nX.224 CC Packet Hex (after TPKT):\n")
	hexDump(packetData)

	buf := bytes.NewReader(packetData)
	cc, err := ReadX224ConnectionConfirm(buf)
	if err != nil {
		return 0, err
	}

	c.x224SrcRef = cc.SrcRef

	fmt.Printf("\nX.224 CC Fields:\n")
	fmt.Printf("  Length Indicator: %d\n", cc.LengthIndicator)
	fmt.Printf("  TPDU Code: 0x%02X\n", cc.TPDUCode)
	fmt.Printf("  Dst Reference: 0x%04X\n", cc.DstRef)
	fmt.Printf("  Src Reference: 0x%04X\n", cc.SrcRef)
	fmt.Printf("  Class Options: 0x%02X\n", cc.ClassOptions)
	fmt.Printf("  Negotiated Protocol: 0x%08X\n", cc.NegotiatedProtocol)

	return cc.NegotiatedProtocol, nil
}
