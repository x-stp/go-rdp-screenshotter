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
	"fmt"
	"io"
	"net"
	"time"

	"github.com/x-stp/rdp-screenshotter-go/pkg/bitmap"
)

// Client represents an RDP client connection.
// It manages the TCP connection and protocol state for RDP communication.
type Client struct {
	conn   net.Conn
	target string

	// Protocol state
	x224SrcRef uint16 // Source reference from X.224 CC
	mcsUserID  uint16 // MCS user channel ID
	ioChannel  uint16 // I/O channel ID

	// Security state
	serverSecurityData *SecurityData
	clientRandom       []byte
	sessionKeys        *SessionKeys
	encryptor          *RC4Encryptor
	decryptor          *RC4Encryptor
}

// ClientOptions contains configuration options for the RDP client.
type ClientOptions struct {
	Timeout  time.Duration // Connection timeout
	Username string        // Username for RDP negotiation cookie
}

// DefaultClientOptions returns sensible default options.
func DefaultClientOptions() *ClientOptions {
	return &ClientOptions{
		Timeout: 10 * time.Second,
	}
}

// NewClient creates a new RDP client and establishes a TCP connection to the target.
// can't RDP be more like MIME :-/
func NewClient(target string, opts *ClientOptions) (*Client, error) {
	if opts == nil {
		opts = DefaultClientOptions()
	}

	// Establish TCP connection with timeout
	dialer := net.Dialer{Timeout: opts.Timeout}
	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", target, err)
	}

	client := &Client{
		conn:   conn,
		target: target,
	}

	// Perform X.224 connection establishment
	if err := client.establishX224Connection(opts.Username); err != nil {
		conn.Close()
		return nil, fmt.Errorf("X.224 connection failed: %w", err)
	}

	return client, nil
}

// establishX224Connection performs the X.224 connection handshake.
func (c *Client) establishX224Connection(username string) error {
	// Send Connection Request
	if err := c.sendX224ConnectionRequest(username); err != nil {
		return err
	}

	// Receive Connection Confirm
	negotiatedProtocol, err := c.receiveX224ConnectionConfirm()
	if err != nil {
		return err
	}

	// Store the negotiated protocol for later use
	if negotiatedProtocol != 0 {
		fmt.Printf("Negotiated protocol: 0x%08X\n", negotiatedProtocol)
	}

	return nil
}

// sendMCSConnectInitial sends the MCS Connect Initial PDU
func (c *Client) sendMCSConnectInitial() error {
	// Build MCS Connect Initial PDU
	mcsData, err := buildMCSConnectInitial()
	if err != nil {
		return fmt.Errorf("failed to build MCS Connect Initial: %w", err)
	}

	// Wrap in X.224 Data TPDU
	x224Data := &X224DataTPDU{
		LengthIndicator: uint8(2), // LI for DT TPDU
		TPDUCode:        X224_TPDU_DATA,
		EOT:             0x80, // End of transmission
	}

	// Calculate total size for TPKT
	totalSize := 3 + len(mcsData) // X224 DT header (3) + MCS data
	tpkt := NewTPKTHeader(totalSize)

	// Send the packet
	buf := new(bytes.Buffer)
	tpkt.WriteTo(buf)
	x224Data.WriteTo(buf)
	buf.Write(mcsData)

	if _, err := c.conn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to send MCS Connect Initial: %w", err)
	}

	fmt.Printf("MCS Connect Initial sent (%d bytes)\n", buf.Len())
	return nil
}

// receiveMCSConnectResponse receives and parses the MCS Connect Response
func (c *Client) receiveMCSConnectResponse() error {
	// Read TPKT header
	tpkt, err := ReadTPKTHeader(c.conn)
	if err != nil {
		return fmt.Errorf("failed to read TPKT header: %w", err)
	}

	fmt.Printf("MCS Response TPKT: version=%d, length=%d\n", tpkt.Version, tpkt.Length)

	// Read the rest of the packet
	data := make([]byte, tpkt.PayloadSize())
	if _, err := io.ReadFull(c.conn, data); err != nil {
		return fmt.Errorf("failed to read MCS response data: %w", err)
	}

	fmt.Printf("MCS Response raw data (%d bytes): %x\n", len(data), data)

	// Skip X.224 Data header (3 bytes)
	if len(data) < 3 {
		return fmt.Errorf("MCS response too short for X.224 header")
	}

	// Parse X.224 header
	x224LI := data[0]
	x224Code := data[1]
	x224EOT := data[2]

	fmt.Printf("X.224 Data: LI=%d, Code=0x%02X, EOT=0x%02X\n", x224LI, x224Code, x224EOT)

	if x224Code != X224_TPDU_DATA {
		return fmt.Errorf("expected X.224 Data TPDU (0xF0), got 0x%02X", x224Code)
	}

	mcsData := data[3:]

	// Parse MCS Connect Response and extract security data
	securityData, err := parseMCSConnectResponse(mcsData)
	if err != nil {
		return err
	}

	// Store server security data
	c.serverSecurityData = securityData

	fmt.Println("MCS Connect Response received")
	return nil
}

// performMCSDomainJoin performs the MCS domain join sequence
func (c *Client) performMCSDomainJoin() error {
	// 1. Send Erect Domain Request
	if err := c.sendMCSPDU(buildMCSErectDomainRequest()); err != nil {
		return fmt.Errorf("failed to send Erect Domain Request: %w", err)
	}
	fmt.Println("MCS Erect Domain Request sent")

	// 2. Send Attach User Request
	if err := c.sendMCSPDU(buildMCSAttachUserRequest()); err != nil {
		return fmt.Errorf("failed to send Attach User Request: %w", err)
	}
	fmt.Println("MCS Attach User Request sent")

	// 3. Receive Attach User Confirm
	userID, err := c.receiveMCSAttachUserConfirm()
	if err != nil {
		return err
	}
	c.mcsUserID = userID
	c.ioChannel = MCS_CHANNEL_GLOBAL // Default I/O channel
	fmt.Printf("MCS Attach User Confirm received (User ID: %d)\n", userID)

	// 4. Join user channel
	if err := c.sendMCSPDU(buildMCSChannelJoinRequest(c.mcsUserID, c.mcsUserID)); err != nil {
		return fmt.Errorf("failed to send Channel Join Request (user): %w", err)
	}

	// 5. Receive Channel Join Confirm (user)
	if err := c.receiveMCSChannelJoinConfirm(); err != nil {
		return fmt.Errorf("failed to join user channel: %w", err)
	}
	fmt.Printf("Joined user channel %d\n", c.mcsUserID)

	// 6. Join I/O channel
	if err := c.sendMCSPDU(buildMCSChannelJoinRequest(c.mcsUserID, c.ioChannel)); err != nil {
		return fmt.Errorf("failed to send Channel Join Request (I/O): %w", err)
	}

	// 7. Receive Channel Join Confirm (I/O)
	if err := c.receiveMCSChannelJoinConfirm(); err != nil {
		return fmt.Errorf("failed to join I/O channel: %w", err)
	}
	fmt.Printf("Joined I/O channel %d\n", c.ioChannel)

	return nil
}

// sendMCSPDU sends an MCS PDU wrapped in X.224 Data and TPKT
func (c *Client) sendMCSPDU(pdu []byte) error {
	// Wrap in X.224 Data TPDU
	x224Data := &X224DataTPDU{
		LengthIndicator: uint8(2),
		TPDUCode:        X224_TPDU_DATA,
		EOT:             0x80,
	}

	// Calculate total size for TPKT
	totalSize := 3 + len(pdu) // X224 DT header (3) + MCS PDU
	tpkt := NewTPKTHeader(totalSize)

	// Send the packet
	buf := new(bytes.Buffer)
	tpkt.WriteTo(buf)
	x224Data.WriteTo(buf)
	buf.Write(pdu)

	if _, err := c.conn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to send MCS PDU: %w", err)
	}

	return nil
}

// receiveMCSAttachUserConfirm receives and parses MCS Attach User Confirm
func (c *Client) receiveMCSAttachUserConfirm() (uint16, error) {
	// Read TPKT header
	tpkt, err := ReadTPKTHeader(c.conn)
	if err != nil {
		return 0, fmt.Errorf("failed to read TPKT header: %w", err)
	}

	// Read the rest of the packet
	data := make([]byte, tpkt.PayloadSize())
	if _, err := io.ReadFull(c.conn, data); err != nil {
		return 0, fmt.Errorf("failed to read MCS data: %w", err)
	}

	// Skip X.224 Data header (3 bytes)
	if len(data) < 3 {
		return 0, fmt.Errorf("MCS PDU too short")
	}
	mcsData := data[3:]

	return parseMCSAttachUserConfirm(mcsData)
}

// receiveMCSChannelJoinConfirm receives and parses MCS Channel Join Confirm
func (c *Client) receiveMCSChannelJoinConfirm() error {
	// Read TPKT header
	tpkt, err := ReadTPKTHeader(c.conn)
	if err != nil {
		return fmt.Errorf("failed to read TPKT header: %w", err)
	}

	// Read the rest of the packet
	data := make([]byte, tpkt.PayloadSize())
	if _, err := io.ReadFull(c.conn, data); err != nil {
		return fmt.Errorf("failed to read MCS data: %w", err)
	}

	// Skip X.224 Data header (3 bytes)
	if len(data) < 3 {
		return fmt.Errorf("MCS PDU too short")
	}
	mcsData := data[3:]

	return parseMCSChannelJoinConfirm(mcsData)
}

// Screenshot captures a screenshot from the RDP server.
func (c *Client) Screenshot() ([]byte, error) {
	// Send MCS Connect Initial
	if err := c.sendMCSConnectInitial(); err != nil {
		return nil, err
	}

	// Receive MCS Connect Response
	if err := c.receiveMCSConnectResponse(); err != nil {
		return nil, err
	}

	// Perform MCS Domain Join sequence
	if err := c.performMCSDomainJoin(); err != nil {
		return nil, err
	}

	// Send Security Exchange PDU
	if err := c.sendSecurityExchange(); err != nil {
		return nil, err
	}

	// Handle licensing phase
	if err := c.receiveLicensingPDUs(); err != nil {
		// Some servers skip licensing, so we'll continue even if this fails
		fmt.Printf("Licensing phase ended: %v\n", err)
	}

	// Receive Server Demand Active PDU
	shareID, err := c.receiveDemandActive()
	if err != nil {
		return nil, err
	}

	// Send Client Confirm Active PDU
	if err := c.sendConfirmActive(shareID); err != nil {
		return nil, err
	}

	// Complete connection finalization sequence
	if err := c.finalizeConnection(); err != nil {
		return nil, err
	}

	// Wait for bitmap updates
	bitmap, err := c.receiveBitmapUpdate()
	if err != nil {
		return nil, err
	}

	fmt.Println("Screenshot capture completed")
	return bitmap, nil
}

// sendSecurityExchange sends the Client Security Exchange PDU
func (c *Client) sendSecurityExchange() error {
	// Use server security data if available
	if c.serverSecurityData == nil {
		c.serverSecurityData = &SecurityData{
			EncryptionMethod: ENCRYPTION_METHOD_NONE,
			EncryptionLevel:  ENCRYPTION_LEVEL_NONE,
		}
	}

	pdu, clientRandom, err := buildSecurityExchangePDU(c.serverSecurityData)
	if err != nil {
		return fmt.Errorf("failed to build security exchange PDU: %w", err)
	}

	// Store client random for key derivation
	c.clientRandom = clientRandom

	// Wrap in X.224 Data TPDU
	x224Data := &X224DataTPDU{
		LengthIndicator: uint8(2),
		TPDUCode:        X224_TPDU_DATA,
		EOT:             0x80,
	}

	// Calculate total size for TPKT
	totalSize := 3 + len(pdu) // X224 DT header (3) + PDU
	tpkt := NewTPKTHeader(totalSize)

	// Send the packet
	buf := new(bytes.Buffer)
	tpkt.WriteTo(buf)
	x224Data.WriteTo(buf)
	buf.Write(pdu)

	if _, err := c.conn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to send security exchange: %w", err)
	}

	fmt.Println("Security Exchange PDU sent")

	// If encryption is enabled, derive session keys
	if c.serverSecurityData.EncryptionMethod != ENCRYPTION_METHOD_NONE &&
		c.serverSecurityData.ServerRandom != nil {
		c.sessionKeys, err = deriveSessionKeys(c.clientRandom, c.serverSecurityData.ServerRandom,
			c.serverSecurityData.EncryptionMethod)
		if err != nil {
			return fmt.Errorf("failed to derive session keys: %w", err)
		}

		// Initialize encryptors
		c.encryptor, err = NewRC4Encryptor(c.sessionKeys.EncryptKey)
		if err != nil {
			return fmt.Errorf("failed to create encryptor: %w", err)
		}

		c.decryptor, err = NewRC4Encryptor(c.sessionKeys.DecryptKey)
		if err != nil {
			return fmt.Errorf("failed to create decryptor: %w", err)
		}

		fmt.Printf("Session keys derived, encryption enabled (method: 0x%08X)\n",
			c.serverSecurityData.EncryptionMethod)
	}

	return nil
}

// receiveDemandActive receives and parses the Server Demand Active PDU
func (c *Client) receiveDemandActive() (uint32, error) {
	// Read TPKT header
	tpkt, err := ReadTPKTHeader(c.conn)
	if err != nil {
		return 0, fmt.Errorf("failed to read TPKT header: %w", err)
	}

	// Read the rest of the packet
	data := make([]byte, tpkt.PayloadSize())
	if _, err := io.ReadFull(c.conn, data); err != nil {
		return 0, fmt.Errorf("failed to read demand active data: %w", err)
	}

	// Skip X.224 Data header (3 bytes)
	if len(data) < 3 {
		return 0, fmt.Errorf("demand active PDU too short")
	}
	data = data[3:]

	// Parse Share Control Header
	r := bytes.NewReader(data)
	shareCtrlHdr, err := parseShareControlHeader(r)
	if err != nil {
		return 0, fmt.Errorf("failed to parse share control header: %w", err)
	}

	// Verify PDU type
	if shareCtrlHdr.PDUType&0x0F != PDUTYPE_DEMANDACTIVEPDU {
		return 0, fmt.Errorf("expected demand active PDU, got type 0x%02X", shareCtrlHdr.PDUType)
	}

	// Parse Demand Active PDU
	demandActive, err := parseDemandActivePDU(data[6:]) // Skip share control header
	if err != nil {
		return 0, fmt.Errorf("failed to parse demand active PDU: %w", err)
	}

	fmt.Printf("Demand Active PDU received (Share ID: 0x%08X)\n", demandActive.ShareID)
	return demandActive.ShareID, nil
}

// sendConfirmActive sends the Client Confirm Active PDU
func (c *Client) sendConfirmActive(shareID uint32) error {
	pdu, err := buildConfirmActivePDU(shareID)
	if err != nil {
		return fmt.Errorf("failed to build confirm active PDU: %w", err)
	}

	// Wrap in X.224 Data TPDU
	x224Data := &X224DataTPDU{
		LengthIndicator: uint8(2),
		TPDUCode:        X224_TPDU_DATA,
		EOT:             0x80,
	}

	// Calculate total size for TPKT
	totalSize := 3 + len(pdu) // X224 DT header (3) + PDU
	tpkt := NewTPKTHeader(totalSize)

	// Send the packet
	buf := new(bytes.Buffer)
	tpkt.WriteTo(buf)
	x224Data.WriteTo(buf)
	buf.Write(pdu)

	if _, err := c.conn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to send confirm active: %w", err)
	}

	fmt.Println("Confirm Active PDU sent")
	return nil
}

// finalizeConnection completes the RDP connection finalization sequence
func (c *Client) finalizeConnection() error {
	// Send Client Synchronize PDU
	if err := c.sendPDU(buildSynchronizePDU(c.mcsUserID)); err != nil {
		return fmt.Errorf("failed to send synchronize PDU: %w", err)
	}
	fmt.Println("Client Synchronize PDU sent")

	// Send Control PDU - Cooperate
	if err := c.sendPDU(buildControlPDU(CTRLACTION_COOPERATE)); err != nil {
		return fmt.Errorf("failed to send control cooperate PDU: %w", err)
	}
	fmt.Println("Control Cooperate PDU sent")

	// Send Control PDU - Request Control
	if err := c.sendPDU(buildControlPDU(CTRLACTION_REQUEST_CONTROL)); err != nil {
		return fmt.Errorf("failed to send control request PDU: %w", err)
	}
	fmt.Println("Control Request PDU sent")

	// Send Font List PDU
	if err := c.sendPDU(buildFontListPDU()); err != nil {
		return fmt.Errorf("failed to send font list PDU: %w", err)
	}
	fmt.Println("Font List PDU sent")

	// TODO: Receive and process server PDUs (synchronize, control granted, font map)
	// For now, we'll just wait a bit
	time.Sleep(100 * time.Millisecond)

	return nil
}

// sendPDU sends a PDU wrapped in X.224 and TPKT
func (c *Client) sendPDU(pdu []byte) error {
	// Wrap in X.224 Data TPDU
	x224Data := &X224DataTPDU{
		LengthIndicator: uint8(2),
		TPDUCode:        X224_TPDU_DATA,
		EOT:             0x80,
	}

	// Calculate total size for TPKT
	totalSize := 3 + len(pdu) // X224 DT header (3) + PDU
	tpkt := NewTPKTHeader(totalSize)

	// Send the packet
	buf := new(bytes.Buffer)
	tpkt.WriteTo(buf)
	x224Data.WriteTo(buf)
	buf.Write(pdu)

	if _, err := c.conn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to send PDU: %w", err)
	}

	return nil
}

// receiveBitmapUpdate waits for and receives a bitmap update
func (c *Client) receiveBitmapUpdate() ([]byte, error) {
	// Set a timeout for receiving bitmap data
	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{})

	for {
		// Read TPKT header
		tpkt, err := ReadTPKTHeader(c.conn)
		if err != nil {
			return nil, fmt.Errorf("failed to read TPKT header: %w", err)
		}

		// Read the rest of the packet
		data := make([]byte, tpkt.PayloadSize())
		if _, err := io.ReadFull(c.conn, data); err != nil {
			return nil, fmt.Errorf("failed to read PDU data: %w", err)
		}

		// Skip X.224 Data header (3 bytes)
		if len(data) < 3 {
			continue
		}
		data = data[3:]

		// Parse Share Control Header
		r := bytes.NewReader(data)
		shareCtrlHdr, err := parseShareControlHeader(r)
		if err != nil {
			continue
		}

		// Check if it's a data PDU
		if shareCtrlHdr.PDUType&0x0F != PDUTYPE_DATAPDU {
			continue
		}

		// Parse Share Data Header
		shareDataHdr, err := parseShareDataHeader(r)
		if err != nil {
			continue
		}

		// Check if it's an update PDU
		if shareDataHdr.PDUType2 == PDUTYPE2_UPDATE {
			// Read the update data
			updateData := make([]byte, shareDataHdr.UncompressedLength-8) // Subtract header size
			r.Read(updateData)

			// Parse bitmap update
			bitmapUpdate, err := parseBitmapUpdateData(updateData)
			if err != nil {
				fmt.Printf("Failed to parse bitmap update: %v\n", err)
				continue
			}

			// Check if it's a bitmap update
			if bitmapUpdate.UpdateType == UPDATETYPE_BITMAP && len(bitmapUpdate.Rectangles) > 0 {
				fmt.Printf("Received bitmap update with %d rectangles\n", len(bitmapUpdate.Rectangles))

				// For now, return the first bitmap rectangle
				// In a full implementation, we'd composite all rectangles into a framebuffer
				rect := &bitmapUpdate.Rectangles[0]
				if len(rect.BitmapDataStream) > 0 {
					// Convert bitmap data to image
					img, err := bitmap.ConvertBitmapToImage(rect)
					if err != nil {
						return nil, fmt.Errorf("failed to convert bitmap: %w", err)
					}
					return img, nil
				}
			}
		}
	}
}

// Close closes the RDP client connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// SetDeadline sets the read and write deadlines for the connection.
func (c *Client) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
