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
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package rdp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/x-stp/rdp-screenshotter-go/pkg/bitmap"
)

// Client represents an RDP client connection.
type Client struct {
	conn   net.Conn
	target string
	opts   *ClientOptions

	x224SrcRef         uint16
	mcsUserID          uint16
	ioChannel          uint16
	serverSecurityData *SecurityData
	clientRandom       []byte
	sessionKeys        *SessionKeys
	encryptor          *RC4Encryptor
	decryptor          *RC4Encryptor
	tlsEnabled         bool
	negotiatedProtocol uint32
}

// ClientOptions contains configuration options for the RDP client.
type ClientOptions struct {
	Timeout  time.Duration
	Username string
	Password string
	Domain   string
}

// DefaultClientOptions returns sensible default options.
func DefaultClientOptions() *ClientOptions {
	return &ClientOptions{
		Timeout: 10 * time.Second,
	}
}

// NewClient creates a new RDP client and establishes a TCP connection.
func NewClient(target string, opts *ClientOptions) (*Client, error) {
	if opts == nil {
		opts = DefaultClientOptions()
	}
	dialer := net.Dialer{Timeout: opts.Timeout}
	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", target, err)
	}

	client := &Client{
		conn:   conn,
		target: target,
		opts:   opts,
	}

	if err := client.establishX224Connection(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("X.224 connection failed: %w", err)
	}
	return client, nil
}

// establishX224Connection performs the initial X.224 handshake to determine security requirements.
func (c *Client) establishX224Connection() error {
	if err := c.sendX224ConnectionRequest(c.opts.Username); err != nil {
		return err
	}
	negotiatedProtocol, err := c.receiveX224ConnectionConfirm()
	if err != nil {
		return err
	}
	c.negotiatedProtocol = negotiatedProtocol

	if isTLSRequired(c.negotiatedProtocol) {
		fmt.Println("\nServer requires TLS, upgrading connection...")
		host, _, _ := net.SplitHostPort(c.target)
		if err := c.upgradeTLSConnection(DefaultTLSConfig(host)); err != nil {
			return fmt.Errorf("TLS upgrade failed: %w", err)
		}
		fmt.Println("TLS connection established successfully")
	}
	return nil
}

// Screenshot is the main function to perform the entire RDP handshake and capture an image.
func (c *Client) Screenshot() ([]byte, error) {
	if isNLA(c.negotiatedProtocol) {
		return nil, fmt.Errorf("server requires Network Level Authentication (NLA/CredSSP), which is not supported")
	}

	if err := c.sendMCSConnectInitial(); err != nil {
		return nil, err
	}
	if err := c.receiveMCSConnectResponse(); err != nil {
		return nil, err
	}
	if err := c.sendSecurityExchange(); err != nil {
		return nil, err
	}
	if err := c.performMCSDomainJoin(); err != nil {
		return nil, err
	}
	if err := c.handleLicensing(); err != nil {
		fmt.Printf("Warning: Licensing sequence failed: %v. Continuing...\n", err)
	}
	shareID, err := c.receiveDemandActive()
	if err != nil {
		return nil, err
	}
	if err := c.sendConfirmActive(shareID); err != nil {
		return nil, err
	}
	if err := c.finalizeConnection(); err != nil {
		return nil, err
	}
	return c.receiveBitmapUpdate()
}

// isNLA is a helper to check if the protocol requires Network Level Authentication.
func isNLA(protocol uint32) bool {
	return protocol == PROTOCOL_HYBRID || protocol == PROTOCOL_HYBRID_EX
}

func (c *Client) sendMCSConnectInitial() error {
	mcsData, err := buildMCSConnectInitial(c.negotiatedProtocol)
	if err != nil {
		return fmt.Errorf("failed to build MCS Connect Initial: %w", err)
	}
	return c.sendPDU(mcsData)
}

func (c *Client) receiveMCSConnectResponse() error {
	data, err := c.readRawPDU()
	if err != nil {
		return err
	}
	securityData, err := parseMCSConnectResponse(data)
	if err != nil {
		return err
	}
	c.serverSecurityData = securityData
	fmt.Println("MCS Connect Response received")
	return nil
}

func (c *Client) sendSecurityExchange() error {
	if c.serverSecurityData == nil {
		return fmt.Errorf("server security data is missing for security exchange")
	}
	pdu, clientRandom, err := buildSecurityExchangePDU(c.serverSecurityData)
	if err != nil {
		return fmt.Errorf("failed to build security exchange PDU: %w", err)
	}
	c.clientRandom = clientRandom

	// The security exchange PDU is wrapped in a security header but not encrypted itself
	wrappedPDU := c.secureWrap(SEC_EXCHANGE_PKT, pdu)
	if err := c.sendPDU(wrappedPDU); err != nil {
		return fmt.Errorf("failed to send security exchange PDU: %w", err)
	}
	fmt.Println("Security Exchange PDU sent")

	// If encryption is required, derive the session keys now
	if c.serverSecurityData.EncryptionMethod != ENCRYPTION_METHOD_NONE &&
		c.serverSecurityData.ServerRandom != nil &&
		c.clientRandom != nil {

		c.sessionKeys, err = deriveSessionKeys(c.clientRandom, c.serverSecurityData.ServerRandom, c.serverSecurityData.EncryptionMethod)
		if err != nil {
			return fmt.Errorf("failed to derive session keys: %w", err)
		}
		c.encryptor, err = NewRC4Encryptor(c.sessionKeys.EncryptKey)
		if err != nil {
			return fmt.Errorf("failed to create encryptor: %w", err)
		}
		c.decryptor, err = NewRC4Encryptor(c.sessionKeys.DecryptKey)
		if err != nil {
			return fmt.Errorf("failed to create decryptor: %w", err)
		}
		fmt.Printf("Session keys derived, encryption enabled (method: 0x%08X)\n", c.serverSecurityData.EncryptionMethod)
	}
	return nil
}

func (c *Client) performMCSDomainJoin() error {
	if err := c.sendEncryptedPDU(buildMCSErectDomainRequest()); err != nil {
		return err
	}
	if err := c.sendEncryptedPDU(buildMCSAttachUserRequest()); err != nil {
		return err
	}
	userID, err := c.receiveMCSAttachUserConfirm()
	if err != nil {
		return err
	}
	c.mcsUserID = userID
	if err := c.sendEncryptedPDU(buildMCSChannelJoinRequest(c.mcsUserID, c.mcsUserID)); err != nil {
		return err
	}
	if err := c.receiveMCSChannelJoinConfirm(); err != nil {
		return err
	}
	c.ioChannel = 1003
	if err := c.sendEncryptedPDU(buildMCSChannelJoinRequest(c.mcsUserID, c.ioChannel)); err != nil {
		return err
	}
	if err := c.receiveMCSChannelJoinConfirm(); err != nil {
		return err
	}
	return nil
}

func (c *Client) handleLicensing() error {
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	pdu, err := c.readSecurePayload()
	c.conn.SetReadDeadline(time.Time{})
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil // No license packet is fine
		}
		return err
	}
	if len(pdu) < 4 || binary.LittleEndian.Uint16(pdu[0:])&SEC_LICENSE_PKT == 0 {
		return fmt.Errorf("expected licensing PDU, got something else")
	}
	return c.sendLicenseErrorAlert(STATUS_VALID_CLIENT)
}

func (c *Client) receiveDemandActive() (uint32, error) {
	data, err := c.readSecurePayload()
	if err != nil {
		return 0, err
	}
	shareCtrlHdr, err := parseShareControlHeader(bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	if shareCtrlHdr.PDUType&0x0F != PDUTYPE_DEMANDACTIVEPDU {
		return 0, fmt.Errorf("expected demand active PDU, got type 0x%04X", shareCtrlHdr.PDUType)
	}
	pdu, err := parseDemandActivePDU(data[6:])
	if err != nil {
		return 0, err
	}
	return pdu.ShareID, nil
}

func (c *Client) sendConfirmActive(shareID uint32) error {
	pdu, err := buildConfirmActivePDU(shareID)
	if err != nil {
		return err
	}
	return c.sendEncryptedPDU(pdu)
}

func (c *Client) finalizeConnection() error {
	if err := c.sendEncryptedPDU(buildSynchronizePDU(c.mcsUserID)); err != nil {
		return err
	}
	if err := c.sendEncryptedPDU(buildControlPDU(CTRLACTION_COOPERATE)); err != nil {
		return err
	}
	if err := c.sendEncryptedPDU(buildControlPDU(CTRLACTION_REQUEST_CONTROL)); err != nil {
		return err
	}
	if err := c.sendEncryptedPDU(buildFontListPDU()); err != nil {
		return err
	}
	return nil
}

func (c *Client) receiveBitmapUpdate() ([]byte, error) {
	c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{})

	for {
		data, err := c.readSecurePayload()
		if err != nil {
			return nil, fmt.Errorf("failed to read secure payload for bitmap: %w", err)
		}
		shareCtrlHdr, err := parseShareControlHeader(bytes.NewReader(data))
		if err != nil {
			continue
		}
		if shareCtrlHdr.PDUType&0x0F == PDUTYPE_DATAPDU {
			shareDataHdr, err := parseShareDataHeader(bytes.NewReader(data[6:]))
			if err != nil {
				continue
			}
			if shareDataHdr.PDUType2 == PDUTYPE2_UPDATE {
				bitmapUpdate, err := parseBitmapUpdateData(data[14:])
				if err == nil && bitmapUpdate.UpdateType == UPDATETYPE_BITMAP && len(bitmapUpdate.Rectangles) > 0 {
					rect := &bitmapUpdate.Rectangles[0]
					if len(rect.BitmapDataStream) > 0 {
						return bitmap.ConvertBitmapToImage(rect)
					}
				}
			}
		}
	}
}

func (c *Client) sendEncryptedPDU(pdu []byte) error {
	wrappedPDU := c.secureWrap(SEC_ENCRYPT, pdu)
	return c.sendPDU(wrappedPDU)
}

func (c *Client) sendPDU(pdu []byte) error {
	tpkt := NewTPKTHeader(len(pdu) + 3)
	x224 := []byte{0x02, 0xf0, 0x80}
	buf := new(bytes.Buffer)
	tpkt.WriteTo(buf)
	buf.Write(x224)
	buf.Write(pdu)
	if _, err := c.conn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to write PDU: %w", err)
	}
	return nil
}

func (c *Client) readRawPDU() ([]byte, error) {
	tpkt, err := ReadTPKTHeader(c.conn)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, tpkt.PayloadSize())
	if _, err := io.ReadFull(c.conn, buf); err != nil {
		return nil, err
	}
	if len(buf) < 3 {
		return nil, fmt.Errorf("packet too short for X.224 header")
	}
	return buf[3:], nil
}

func (c *Client) readSecurePayload() ([]byte, error) {
	payload, err := c.readRawPDU()
	if err != nil {
		return nil, err
	}
	return c.secureUnwrap(payload)
}

func (c *Client) receiveMCSAttachUserConfirm() (uint16, error) {
	pdu, err := c.readSecurePayload()
	if err != nil {
		return 0, err
	}
	return parseMCSAttachUserConfirm(pdu)
}

func (c *Client) receiveMCSChannelJoinConfirm() error {
	pdu, err := c.readSecurePayload()
	if err != nil {
		return err
	}
	return parseMCSChannelJoinConfirm(pdu)
}

func (c *Client) secureWrap(flags uint16, payload []byte) []byte {
	head := make([]byte, 4)
	binary.LittleEndian.PutUint16(head, flags)
	binary.LittleEndian.PutUint16(head[2:], 0) // flagsHi
	fullPDU := append(head, payload...)
	if c.encryptor != nil && flags&SEC_ENCRYPT != 0 {
		c.encryptor.Encrypt(fullPDU[4:])
	}
	return fullPDU
}

func (c *Client) secureUnwrap(data []byte) ([]byte, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("data too short for security header")
	}
	flags := binary.LittleEndian.Uint16(data)
	if c.decryptor != nil && flags&SEC_ENCRYPT != 0 {
		c.decryptor.Decrypt(data[4:])
	}
	return data[4:], nil
}

// Close gracefully closes the client connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

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

// CapabilitySet represents a generic capability set
type CapabilitySet struct {
	Type   uint16
	Length uint16
	Data   []byte
}

// parseDemandActivePDU parses a Server Demand Active PDU
func parseDemandActivePDU(data []byte) (*DemandActivePDU, error) {
	if len(data) < 4 { // Minimum size for ShareID
		return nil, fmt.Errorf("demand active PDU too short for ShareID: %d bytes", len(data))
	}

	pdu := &DemandActivePDU{}
	r := bytes.NewReader(data)

	binary.Read(r, binary.LittleEndian, &pdu.ShareID)
	binary.Read(r, binary.LittleEndian, &pdu.LengthSourceDescriptor)
	binary.Read(r, binary.LittleEndian, &pdu.LengthCombinedCapabilities)

	if pdu.LengthSourceDescriptor > 0 {
		srcDesc := make([]byte, pdu.LengthSourceDescriptor)
		if _, err := io.ReadFull(r, srcDesc); err != nil {
			return nil, fmt.Errorf("failed to read source descriptor: %w", err)
		}
		pdu.SourceDescriptor = string(srcDesc)
	}

	if r.Len() < 4 {
		return pdu, nil // No capabilities present, which is valid
	}

	binary.Read(r, binary.LittleEndian, &pdu.NumberCapabilities)
	binary.Read(r, binary.LittleEndian, &pdu.Pad2Octets)

	pdu.CapabilitySets = make([]CapabilitySet, 0, pdu.NumberCapabilities)
	for i := uint16(0); i < pdu.NumberCapabilities; i++ {
		var capSet CapabilitySet
		if r.Len() < 4 {
			break
		}
		binary.Read(r, binary.LittleEndian, &capSet.Type)
		binary.Read(r, binary.LittleEndian, &capSet.Length)

		if capSet.Length >= 4 {
			capDataLen := int(capSet.Length) - 4
			if r.Len() < capDataLen {
				break
			}
			capSet.Data = make([]byte, capDataLen)
			r.Read(capSet.Data)
		}
		pdu.CapabilitySets = append(pdu.CapabilitySets, capSet)
	}

	if r.Len() >= 4 {
		binary.Read(r, binary.LittleEndian, &pdu.SessionID)
	}

	return pdu, nil
}
