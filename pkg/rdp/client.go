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

	// Only send security exchange if encryption is enabled
	if c.serverSecurityData != nil && c.serverSecurityData.EncryptionMethod != ENCRYPTION_METHOD_NONE {
		if err := c.sendSecurityExchange(); err != nil {
			return nil, err
		}
	}

	if err := c.performMCSDomainJoin(); err != nil {
		return nil, err
	}

	// Handle licensing - but don't fail if it doesn't work
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

	// Send some input events to trigger screen updates
	fmt.Println("Sending input events to trigger screen update...")

	// Send mouse move events
	events := []InputEvent{
		buildMouseMoveEvent(100, 100),
		buildMouseMoveEvent(200, 200),
	}
	if err := c.sendEncryptedPDU(buildInputEventPDU(events)); err != nil {
		fmt.Printf("Warning: Failed to send input events: %v\n", err)
	}

	// Give server time to process
	time.Sleep(200 * time.Millisecond)

	// Try to receive bitmap update
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
	fmt.Println("Sending MCS Erect Domain Request...")
	if err := c.sendEncryptedPDU(buildMCSErectDomainRequest()); err != nil {
		return err
	}

	fmt.Println("Sending MCS Attach User Request...")
	if err := c.sendEncryptedPDU(buildMCSAttachUserRequest()); err != nil {
		return err
	}

	fmt.Println("Waiting for MCS Attach User Confirm...")
	userID, err := c.receiveMCSAttachUserConfirm()
	if err != nil {
		return err
	}
	c.mcsUserID = userID
	fmt.Printf("Got user ID: %d\n", userID)

	fmt.Printf("Joining user channel %d...\n", c.mcsUserID)
	if err := c.sendEncryptedPDU(buildMCSChannelJoinRequest(c.mcsUserID, c.mcsUserID)); err != nil {
		return err
	}
	if err := c.receiveMCSChannelJoinConfirm(); err != nil {
		return err
	}

	c.ioChannel = 1003
	fmt.Printf("Joining I/O channel %d...\n", c.ioChannel)
	if err := c.sendEncryptedPDU(buildMCSChannelJoinRequest(c.mcsUserID, c.ioChannel)); err != nil {
		return err
	}
	if err := c.receiveMCSChannelJoinConfirm(); err != nil {
		return err
	}

	fmt.Println("MCS Domain Join completed successfully")
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

	// Send suppress output PDU to allow display updates
	if err := c.sendEncryptedPDU(buildSuppressOutputPDU(true)); err != nil {
		return err
	}

	// Send refresh rectangle PDU to request full screen update
	if err := c.sendEncryptedPDU(buildRefreshRectPDU(0, 0, 1920, 1080)); err != nil {
		return err
	}

	// Give server time to process
	time.Sleep(100 * time.Millisecond)

	return nil
}

func (c *Client) receiveBitmapUpdate() ([]byte, error) {
	c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{})

	// Try multiple times to receive bitmap updates
	maxAttempts := 20
	for attempt := 0; attempt < maxAttempts; attempt++ {
		data, err := c.readSecurePayload()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() && attempt > 5 {
				// If we've tried a few times and still no bitmap, return error
				return nil, fmt.Errorf("timeout waiting for bitmap update after %d attempts", attempt)
			}
			continue
		}

		// Skip if data is too short
		if len(data) < 6 {
			continue
		}

		shareCtrlHdr, err := parseShareControlHeader(bytes.NewReader(data))
		if err != nil {
			continue
		}

		// Check for data PDU
		if shareCtrlHdr.PDUType&0x0F == PDUTYPE_DATAPDU {
			if len(data) < 14 {
				continue
			}

			shareDataHdr, err := parseShareDataHeader(bytes.NewReader(data[6:]))
			if err != nil {
				continue
			}

			// Handle different PDU types
			switch shareDataHdr.PDUType2 {
			case PDUTYPE2_UPDATE:
				// Parse update data
				updateData := data[14:]
				if len(updateData) < 2 {
					continue
				}

				updateType := binary.LittleEndian.Uint16(updateData)
				fmt.Printf("Received update type: 0x%04X\n", updateType)

				if updateType == UPDATETYPE_BITMAP {
					bitmapUpdate, err := parseBitmapUpdateData(updateData)
					if err != nil {
						fmt.Printf("Failed to parse bitmap update: %v\n", err)
						continue
					}

					if len(bitmapUpdate.Rectangles) > 0 {
						// Try to convert the first rectangle
						for _, rect := range bitmapUpdate.Rectangles {
							if len(rect.BitmapDataStream) > 0 {
								fmt.Printf("Converting bitmap: %dx%d, %d bpp, %d bytes\n",
									rect.Width, rect.Height, rect.BitsPerPixel, len(rect.BitmapDataStream))

								imageData, err := bitmap.ConvertBitmapToImage(&rect)
								if err != nil {
									fmt.Printf("Failed to convert bitmap: %v\n", err)
									continue
								}
								return imageData, nil
							}
						}
					}
				}

			case PDUTYPE2_SYNCHRONIZE:
				fmt.Println("Received synchronize PDU")
				// Send synchronize response
				c.sendEncryptedPDU(buildSynchronizePDU(c.mcsUserID))

			case PDUTYPE2_CONTROL:
				fmt.Println("Received control PDU")
				// May need to respond to control PDUs

			default:
				fmt.Printf("Received PDU type2: 0x%02X\n", shareDataHdr.PDUType2)
			}
		} else if shareCtrlHdr.PDUType&0x0F == PDUTYPE_DEACTIVATEALLPDU {
			fmt.Println("Received deactivate all PDU")
			// Server is deactivating, may need to reconnect
			return nil, fmt.Errorf("server deactivated connection")
		}

		// Also check for fast-path updates
		if len(data) > 0 && (data[0]&0x3) == 0 {
			// This might be a fast-path update
			fmt.Println("Possible fast-path update detected")
			// TODO: Implement fast-path parsing
		}
	}

	return nil, fmt.Errorf("no bitmap update received after %d attempts", maxAttempts)
}

func (c *Client) sendEncryptedPDU(pdu []byte) error {
	// Check if encryption is enabled
	if c.encryptor != nil && c.serverSecurityData != nil && c.serverSecurityData.EncryptionMethod != ENCRYPTION_METHOD_NONE {
		wrappedPDU := c.secureWrap(SEC_ENCRYPT, pdu)
		return c.sendPDU(wrappedPDU)
	} else {
		// No encryption, just wrap with basic security header
		wrappedPDU := c.secureWrap(0, pdu)
		return c.sendPDU(wrappedPDU)
	}
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
	// Peek at the first byte to determine PDU type
	peekBuf := make([]byte, 1)
	if _, err := io.ReadFull(c.conn, peekBuf); err != nil {
		return nil, err
	}

	// Check if this is a fast-path PDU
	if (peekBuf[0] & 0x3) == 0 {
		// Fast-path PDU
		return c.readFastPathPDU(peekBuf[0])
	}

	// Regular TPKT PDU - read the rest of the header
	tpktBuf := make([]byte, 3)
	if _, err := io.ReadFull(c.conn, tpktBuf); err != nil {
		return nil, err
	}

	// Parse TPKT header
	length := binary.BigEndian.Uint16(append([]byte{peekBuf[0]}, tpktBuf...)[2:])
	if length < 4 {
		return nil, fmt.Errorf("invalid TPKT length: %d", length)
	}

	// Read the payload
	payload := make([]byte, length-4)
	if _, err := io.ReadFull(c.conn, payload); err != nil {
		return nil, err
	}

	// Skip X.224 header if present
	if len(payload) >= 3 && payload[0] == 0x02 && payload[1] == 0xf0 && payload[2] == 0x80 {
		return payload[3:], nil
	}

	return payload, nil
}

func (c *Client) readFastPathPDU(firstByte byte) ([]byte, error) {
	// Fast-path header parsing
	var length int
	lengthByte1 := make([]byte, 1)
	if _, err := io.ReadFull(c.conn, lengthByte1); err != nil {
		return nil, err
	}

	if lengthByte1[0]&0x80 != 0 {
		// Two-byte length
		lengthByte2 := make([]byte, 1)
		if _, err := io.ReadFull(c.conn, lengthByte2); err != nil {
			return nil, err
		}
		length = int(lengthByte1[0]&0x7F)<<8 | int(lengthByte2[0])
	} else {
		// One-byte length
		length = int(lengthByte1[0])
	}

	// Read the PDU data
	data := make([]byte, length-2) // Subtract header bytes
	if _, err := io.ReadFull(c.conn, data); err != nil {
		return nil, err
	}

	// Check if encrypted
	if firstByte&0x80 != 0 && c.decryptor != nil {
		// Skip MAC signature if present
		if len(data) > 8 {
			c.decryptor.Decrypt(data[8:])
			return data[8:], nil
		}
	}

	return data, nil
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

	// Debug: print the PDU data
	fmt.Printf("MCS Attach User Confirm PDU: %x\n", pdu)

	return parseMCSAttachUserConfirm(pdu)
}

func (c *Client) receiveMCSChannelJoinConfirm() error {
	pdu, err := c.readSecurePayload()
	if err != nil {
		return err
	}

	fmt.Printf("MCS Channel Join Confirm PDU: %x\n", pdu)

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
		// Some PDUs might not have security headers even when encryption is enabled
		// This happens especially during the initial handshake
		return data, nil
	}

	flags := binary.LittleEndian.Uint16(data)

	// Check if this PDU has a security header
	if flags&(SEC_ENCRYPT|SEC_LICENSE_PKT|SEC_EXCHANGE_PKT) == 0 && flags != 0 {
		// No security header, return data as-is
		return data, nil
	}

	// Skip security header
	payload := data[4:]

	// Decrypt if needed
	if c.decryptor != nil && flags&SEC_ENCRYPT != 0 && len(payload) > 0 {
		c.decryptor.Decrypt(payload)
	}

	return payload, nil
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
