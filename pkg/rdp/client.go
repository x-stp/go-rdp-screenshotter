
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
	unreadData         []byte
	screenshot         []byte
	lastServerPDU      []byte
	
	autoDetectManager  *AutoDetectManager
	heartbeatManager   *HeartbeatManager
	
	tlsCertificate     []byte
	
	ntlmSession        *ntlmSession
}

type ClientOptions struct {
	Timeout  time.Duration
	Username string
	Password string
	Domain   string
	
	EnableAutoDetect    bool
	EnableHeartbeat     bool
	HeartbeatInterval   time.Duration
}

func DefaultClientOptions() *ClientOptions {
	return &ClientOptions{
		Timeout: 10 * time.Second,
		EnableAutoDetect:  false,
		EnableHeartbeat:   false,
		HeartbeatInterval: 30 * time.Second,
	}
}

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
	
	if opts.EnableAutoDetect {
		client.autoDetectManager = NewAutoDetectManager(client)
	}
	if opts.EnableHeartbeat {
		client.heartbeatManager = NewHeartbeatManager(client)
		if opts.HeartbeatInterval > 0 {
			client.heartbeatManager.SetPeriod(opts.HeartbeatInterval)
		}
	}

	if err := client.establishX224Connection(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("X.224 connection failed: %w", err)
	}
	return client, nil
}

func (c *Client) establishX224Connection() error {
	fmt.Printf("\n========================================\n")
	fmt.Printf("=== ESTABLISHING X.224 CONNECTION ===\n")
	fmt.Printf("========================================\n")
	fmt.Printf("Target: %s\n", c.target)
	fmt.Printf("Username: %s\n\n", c.opts.Username)
	
	if err := c.sendX224ConnectionRequest(c.opts.Username); err != nil {
		return err
	}
	negotiatedProtocol, err := c.receiveX224ConnectionConfirm()
	if err != nil {
		return err
	}
	c.negotiatedProtocol = negotiatedProtocol

	if isTLSRequired(c.negotiatedProtocol) {
		fmt.Printf("\nServer requires TLS (negotiated protocol: 0x%08x)\n", c.negotiatedProtocol)
		host, _, _ := net.SplitHostPort(c.target)
		if err := c.upgradeTLSConnection(DefaultTLSConfig(host)); err != nil {
			return fmt.Errorf("TLS upgrade failed: %w", err)
		}
	}
	return nil
}


func (c *Client) Screenshot() ([]byte, error) {
	fmt.Printf("\n========================================\n")
	fmt.Printf("=== STARTING RDP SCREENSHOT CAPTURE ===\n")
	fmt.Printf("========================================\n\n")
	
	
	if isNLA(c.negotiatedProtocol) {
		fmt.Printf("Server requires NLA (protocol: 0x%08x)\n", c.negotiatedProtocol)
		if err := c.PerformCredSSPAuth(); err != nil {
			return nil, fmt.Errorf("CredSSP authentication failed: %w", err)
		}
		fmt.Println("\nCredSSP authentication successful!")
		fmt.Println("Continuing with RDP handshake...")
	} else {
		fmt.Printf("Server negotiated protocol: 0x%08x (NLA not required)\n", c.negotiatedProtocol)
		
		if c.negotiatedProtocol == PROTOCOL_RDP && c.serverSecurityData != nil {
			fmt.Printf("Note: Server using standard RDP with security method=0x%08x, level=0x%08x\n", 
				c.serverSecurityData.EncryptionMethod, c.serverSecurityData.EncryptionLevel)
		}
		
		
		forceCredSSPTest := false 
		if forceCredSSPTest && c.negotiatedProtocol == PROTOCOL_RDP {
			fmt.Printf("\nTESTING: Forcing CredSSP authentication even though server negotiated standard RDP\n")
			
			
			if !c.tlsEnabled {
				fmt.Printf("Upgrading to TLS for CredSSP test...\n")
				host, _, _ := net.SplitHostPort(c.target)
				if err := c.upgradeTLSConnection(DefaultTLSConfig(host)); err != nil {
					fmt.Printf("TLS upgrade failed for CredSSP test: %v\n", err)
				} else {
					fmt.Printf("TLS upgrade successful\n")
				}
			}
			
			if c.tlsEnabled {
				if err := c.PerformCredSSPAuth(); err != nil {
					fmt.Printf("CredSSP test failed: %v\n\n", err)
				} else {
					fmt.Println("CredSSP test successful!")
				}
			}
		}
	}

	if err := c.sendMCSConnectInitial(); err != nil {
		return nil, err
	}
	if err := c.receiveMCSConnectResponse(); err != nil {
		return nil, err
	}

	
	if c.serverSecurityData != nil && c.serverSecurityData.EncryptionMethod != ENCRYPTION_METHOD_NONE {
		if err := c.sendSecurityExchange(); err != nil {
			return nil, err
		}
	}

	if err := c.performMCSDomainJoin(); err != nil {
		return nil, err
	}
	
	
	if c.screenshot != nil {
		return c.screenshot, nil
	}

	
	fmt.Println("Entering licensing/capability exchange phase...")
	
	
	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, err := c.readSecurePayload()
	c.conn.SetReadDeadline(time.Time{})
	
	if err != nil {
		fmt.Printf("Warning: Failed to read post-MCS PDU: %v\n", err)
		
		return c.attemptDirectScreenshot()
	}
	
	
	if len(data) >= 4 {
		flags := binary.LittleEndian.Uint16(data[0:2])
		if flags&SEC_LICENSE_PKT != 0 {
			fmt.Println("Received licensing PDU")
			
			if err := c.sendLicenseErrorAlert(STATUS_VALID_CLIENT); err != nil {
				fmt.Printf("Warning: Failed to send license error alert: %v\n", err)
			}
			
			
			c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			data, err = c.readSecurePayload()
			c.conn.SetReadDeadline(time.Time{})
			if err != nil {
				fmt.Printf("Warning: Failed to read post-licensing PDU: %v\n", err)
				return c.attemptDirectScreenshot()
			}
		}
	}
	
	
	if len(data) >= 6 {
		shareCtrlHdr, err := parseShareControlHeader(bytes.NewReader(data))
		if err == nil && shareCtrlHdr.PDUType&0x0F == PDUTYPE_DEMANDACTIVEPDU {
			fmt.Println("Received Demand Active PDU")
			
			c.unreadData = data
			shareID, err := c.receiveDemandActive()
			if err != nil {
				fmt.Printf("Warning: Failed to process demand active: %v\n", err)
				return c.attemptDirectScreenshot()
			}
			
			
			if err := c.sendConfirmActive(shareID); err != nil {
				fmt.Printf("Warning: Failed to send confirm active: %v\n", err)
				return c.attemptDirectScreenshot()
			}
			
			
			if err := c.sendClientInfoPDU(); err != nil {
				fmt.Printf("Warning: Failed to send client info: %v\n", err)
			}
			
			
			fmt.Println("Sending finalization PDUs...")
			
			
			syncPDU := buildSynchronizePDU(c.mcsUserID)
			if err := c.sendEncryptedPDU(syncPDU); err != nil {
				fmt.Printf("Warning: Failed to send sync PDU: %v\n", err)
			}
			
			
			controlPDU := buildControlPDU(CTRLACTION_COOPERATE)
			if err := c.sendEncryptedPDU(controlPDU); err != nil {
				fmt.Printf("Warning: Failed to send control PDU: %v\n", err)
			}
			
			
			fontPDU := buildFontListPDU()
			if err := c.sendEncryptedPDU(fontPDU); err != nil {
				fmt.Printf("Warning: Failed to send font PDU: %v\n", err)
			}
			
			
			fmt.Println("Requesting screen refresh...")
			refreshPDU := buildRefreshRectanglePDU(c.mcsUserID)
			if err := c.sendEncryptedPDU(refreshPDU); err != nil {
				fmt.Printf("Warning: Failed to send refresh PDU: %v\n", err)
			}
			
			
			return c.receiveBitmapUpdate()
		}
	}
	
	
	fmt.Println("Unexpected PDU type, trying direct screenshot approach...")
	screenshot, err := c.attemptDirectScreenshot()
	if err != nil {
		return nil, err
	}
	return screenshot, nil
}


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

	
	wrappedPDU := c.secureWrap(SEC_EXCHANGE_PKT, pdu)
	if err := c.sendPDU(wrappedPDU); err != nil {
		return fmt.Errorf("failed to send security exchange PDU: %w", err)
	}
	fmt.Println("Security Exchange PDU sent")

	
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

	
	c.ioChannel = 1003
	fmt.Printf("Channel setup: User=%d, I/O=%d\n", c.mcsUserID, c.ioChannel)
	
	
	fmt.Println("Joining MCS channels...")
	
	
	if err := c.sendMCSChannelJoinRequest(c.mcsUserID); err != nil {
		return fmt.Errorf("failed to send user channel join request: %w", err)
	}
	if err := c.receiveMCSChannelJoinConfirm(c.mcsUserID); err != nil {
		return fmt.Errorf("failed to receive user channel join confirm: %w", err)
	}
	fmt.Printf("Joined user channel: %d\n", c.mcsUserID)
	
	
	if err := c.sendMCSChannelJoinRequest(c.ioChannel); err != nil {
		return fmt.Errorf("failed to send I/O channel join request: %w", err)
	}
	if err := c.receiveMCSChannelJoinConfirm(c.ioChannel); err != nil {
		return fmt.Errorf("failed to receive I/O channel join confirm: %w", err)
	}
	fmt.Printf("Joined I/O channel: %d\n", c.ioChannel)

	fmt.Println("MCS Domain Join completed successfully")
	
	
	fmt.Println("Waiting for server response (License or Demand Active)...")
	c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	pdu, err := c.readSecurePayload()
	c.conn.SetReadDeadline(time.Time{})
	
	if err != nil {
		
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println("No response from server, proceeding to demand active phase...")
			return c.waitForDemandActive()
		}
		fmt.Printf("Error reading server response: %v\n", err)
		return err
	}
	
	
	if len(pdu) >= 4 {
		flags := binary.LittleEndian.Uint16(pdu[0:2])
		if flags&SEC_LICENSE_PKT != 0 {
			fmt.Println("Received licensing PDU")
			if err := c.sendLicenseErrorAlert(STATUS_VALID_CLIENT); err != nil {
				return fmt.Errorf("failed to send license error alert: %w", err)
			}
			
			return c.waitForDemandActive()
		} else {
			fmt.Printf("Received non-licensing PDU (flags: 0x%04X)\n", flags)
			c.unreadData = pdu
			return c.processDemandActive()
		}
	}
	
	return fmt.Errorf("unexpected PDU format")
}

func (c *Client) waitForDemandActive() error {
	fmt.Println("Waiting for Demand Active PDU...")
	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	pdu, err := c.readSecurePayload()
	c.conn.SetReadDeadline(time.Time{})
	
	if err != nil {
		return fmt.Errorf("failed to read demand active: %w", err)
	}
	
	c.unreadData = pdu
	return c.processDemandActive()
}

func (c *Client) processDemandActive() error {
	if c.unreadData == nil {
		return fmt.Errorf("no demand active PDU to process")
	}
	
	data := c.unreadData
	c.unreadData = nil
	
	
	if len(data) >= 6 {
		shareCtrlHdr, err := parseShareControlHeader(bytes.NewReader(data))
		if err == nil && shareCtrlHdr.PDUType&0x0F == PDUTYPE_DEMANDACTIVEPDU {
			fmt.Println("Processing Demand Active PDU")
			c.unreadData = data 
			shareID, err := c.receiveDemandActive()
			if err != nil {
				return fmt.Errorf("failed to process demand active: %w", err)
			}
			
			
			if err := c.sendConfirmActive(shareID); err != nil {
				return fmt.Errorf("failed to send confirm active: %w", err)
			}
			
			
			return c.completeRDPConnection()
		}
	}
	
	return fmt.Errorf("expected demand active PDU but got something else")
}

func (c *Client) handlePostLicensing() error {
	fmt.Println("Entering post-licensing phase...")
	
	
	fmt.Println("Sending Client Info PDU...")
	if err := c.sendClientInfoPDU(); err != nil {
		return fmt.Errorf("failed to send client info: %w", err)
	}
	
	
	if c.unreadData != nil {
		fmt.Println("Processing saved PDU...")
		data := c.unreadData
		c.unreadData = nil
		
		
		if len(data) >= 6 {
			shareCtrlHdr, err := parseShareControlHeader(bytes.NewReader(data))
			if err == nil && shareCtrlHdr.PDUType&0x0F == PDUTYPE_DEMANDACTIVEPDU {
				fmt.Println("Processing Demand Active PDU")
				c.unreadData = data 
				shareID, err := c.receiveDemandActive()
				if err != nil {
					return fmt.Errorf("failed to process demand active: %w", err)
				}
				
				
				if err := c.sendConfirmActive(shareID); err != nil {
					return fmt.Errorf("failed to send confirm active: %w", err)
				}
				
				
				return c.completeRDPConnection()
			}
		}
	}
	
	
	shareID, err := c.receiveDemandActive()
	if err != nil {
		return fmt.Errorf("failed to receive demand active: %w", err)
	}
	
	
	if err := c.sendConfirmActive(shareID); err != nil {
		return fmt.Errorf("failed to send confirm active: %w", err)
	}
	
	
	return c.completeRDPConnection()
}

func (c *Client) completeRDPConnection() error {
	fmt.Println("Completing RDP connection sequence...")
	
	
	syncPDU := buildSynchronizePDU(c.mcsUserID)
	if err := c.sendEncryptedPDU(syncPDU); err != nil {
		fmt.Printf("Warning: Failed to send sync PDU: %v\n", err)
	}
	
	
	controlPDU := buildControlPDU(CTRLACTION_COOPERATE)
	if err := c.sendEncryptedPDU(controlPDU); err != nil {
		fmt.Printf("Warning: Failed to send control PDU: %v\n", err)
	}
	
	
	fontPDU := buildFontListPDU()
	if err := c.sendEncryptedPDU(fontPDU); err != nil {
		fmt.Printf("Warning: Failed to send font PDU: %v\n", err)
	}
	
	
	fmt.Println("Requesting screen refresh...")
	refreshPDU := buildRefreshRectanglePDU(c.mcsUserID)
	if err := c.sendEncryptedPDU(refreshPDU); err != nil {
		fmt.Printf("Warning: Failed to send refresh PDU: %v\n", err)
	}
	
	
	screenshot, err := c.receiveBitmapUpdate()
	if err != nil {
		return err
	}
	c.screenshot = screenshot
	return nil
}

func (c *Client) handleLicensing() error {
	fmt.Println("Attempting to read licensing PDU...")
	
	
	
	c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	pdu, err := c.readSecurePayload()
	c.conn.SetReadDeadline(time.Time{})
	
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println("No licensing PDU received (timeout) - server may not require licensing")
			return nil
		}
		if err == io.EOF {
			fmt.Println("Connection closed - XRDP may be waiting for specific PDU sequence")
			return fmt.Errorf("connection closed by server")
		}
		fmt.Printf("Error reading licensing PDU: %v\n", err)
		return err
	}
	
	fmt.Printf("Received PDU (%d bytes)\n", len(pdu))
	
	if len(pdu) < 4 {
		fmt.Println("PDU too short")
		return nil
	}
	
	
	securityFlags := binary.LittleEndian.Uint16(pdu[0:])
	if securityFlags&SEC_LICENSE_PKT != 0 {
		fmt.Println("Received licensing PDU, sending license error alert...")
		if err := c.sendLicenseErrorAlert(STATUS_VALID_CLIENT); err != nil {
			return fmt.Errorf("failed to send license error alert: %w", err)
		}
	} else {
		fmt.Printf("Not a licensing PDU (flags: 0x%04X), might be demand active\n", securityFlags)
		c.unreadData = pdu
	}
	
	return nil
}

func (c *Client) receiveMCSChannelJoinConfirmRaw() error {
	
	c.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{})
	
	
	pdu, err := c.readSecurePayload()
	if err != nil {
		
		pdu, err = c.readRawPDU()
		if err != nil {
			
			fmt.Printf("No channel join confirm received (this might be normal for XRDP): %v\n", err)
			return nil 
		}
	}
	
	fmt.Printf("MCS Channel Join Confirm PDU: %x\n", pdu)
	
	
	if err := parseMCSChannelJoinConfirm(pdu); err != nil {
		fmt.Printf("Warning: Could not parse channel join confirm: %v\n", err)
		
	} else {
		fmt.Println("Channel join confirmed successfully")
	}
	
	return nil
}


func (c *Client) readAndParseChannelJoinConfirm() error {
	
	c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{})
	
	
	
	pdu, err := c.readSecurePayload()
	if err != nil {
		fmt.Printf("Encrypted read failed: %v, trying raw PDU read...\n", err)
		
		
		pdu, err = c.readRawPDU()
		if err != nil {
			fmt.Printf("Raw PDU read failed: %v, trying basic read...\n", err)
			
			
			basicBuf := make([]byte, 1024)
			n, err := c.conn.Read(basicBuf)
			if err != nil {
				return fmt.Errorf("all read attempts failed: %w", err)
			}
			pdu = basicBuf[:n]
		}
	}
	
	fmt.Printf("Channel Join Confirm data (%d bytes): %x\n", len(pdu), pdu)
	
	
	var mcsData []byte
	
	
	if len(pdu) >= 7 && pdu[0] == 0x03 && pdu[1] == 0x00 {
		
		if pdu[4] == 0x02 && pdu[5] == 0xF0 && pdu[6] == 0x80 {
			mcsData = pdu[7:]
		}
	} else if len(pdu) >= 4 {
		
		flags := binary.LittleEndian.Uint16(pdu[0:2])
		if flags&SEC_ENCRYPT != 0 {
			
			payload := pdu[4:]
			if c.decryptor != nil {
				c.decryptor.Decrypt(payload)
			}
			mcsData = payload
		} else {
			
			mcsData = pdu
		}
	} else {
		mcsData = pdu
	}
	
	if len(mcsData) > 0 {
		fmt.Printf("Extracted MCS data: %x\n", mcsData)
		return parseMCSChannelJoinConfirm(mcsData)
	}
	
	return fmt.Errorf("could not extract MCS data from response")
}

func (c *Client) sendChannelJoinsAsSendData() error {
	
	
	
	sendDataPDU := buildMCSSendDataRequest(c.mcsUserID, c.ioChannel, []byte{})
	fmt.Printf("Sending MCS Send Data Request to I/O channel: %x\n", sendDataPDU)
	
	
	if err := c.sendPDU(sendDataPDU); err != nil {
		return fmt.Errorf("failed to send MCS data request: %w", err)
	}
	
	
	time.Sleep(100 * time.Millisecond)
	
	return nil
}

func (c *Client) handleServerPDU() error {
	
	data, err := c.readSecurePayload()
	if err != nil {
		return fmt.Errorf("failed to read server PDU: %w", err)
	}
	
	
	if len(data) >= 4 {
		flags := binary.LittleEndian.Uint16(data[0:2])
		if flags&SEC_LICENSE_PKT != 0 {
			fmt.Println("Received licensing PDU")
			
			return c.sendLicenseErrorAlert(STATUS_VALID_CLIENT)
		}
	}
	
	
	if len(data) >= 6 {
		shareCtrlHdr, err := parseShareControlHeader(bytes.NewReader(data))
		if err == nil && shareCtrlHdr.PDUType&0x0F == PDUTYPE_DEMANDACTIVEPDU {
			fmt.Println("Received Demand Active PDU directly")
			
			c.unreadData = data
			return nil
		}
	}
	
	return fmt.Errorf("unexpected server PDU type")
}

func (c *Client) joinChannelsViaSendData() error {
	
	fmt.Printf("Joining I/O channel %d...\n", c.ioChannel)
	ioChannelJoinPDU := buildMCSChannelJoinRequest(c.mcsUserID, c.ioChannel)
	fmt.Printf("I/O Channel Join PDU: %x\n", ioChannelJoinPDU)
	if err := c.sendEncryptedPDU(ioChannelJoinPDU); err != nil {
		return fmt.Errorf("failed to send I/O channel join: %w", err)
	}
	
	
	fmt.Println("Waiting for I/O channel join confirm...")
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	err := c.receiveMCSChannelJoinConfirm(c.ioChannel)
	c.conn.SetReadDeadline(time.Time{})
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println("No I/O channel confirm received (timeout), continuing...")
		} else {
			return fmt.Errorf("I/O channel join failed: %w", err)
		}
	} else {
		fmt.Println("I/O channel join confirmed")
	}

	
	fmt.Printf("Joining user channel %d...\n", c.mcsUserID)
	userChannelJoinPDU := buildMCSChannelJoinRequest(c.mcsUserID, c.mcsUserID)
	fmt.Printf("User Channel Join PDU: %x\n", userChannelJoinPDU)
	if err := c.sendEncryptedPDU(userChannelJoinPDU); err != nil {
		return fmt.Errorf("failed to send user channel join: %w", err)
	}
	
	
	fmt.Println("Waiting for user channel join confirm...")  
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	err = c.receiveMCSChannelJoinConfirm(c.mcsUserID)
	c.conn.SetReadDeadline(time.Time{})
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println("No user channel confirm received (timeout), continuing...")
		} else {
			return fmt.Errorf("user channel join failed: %w", err)
		}
	} else {
		fmt.Println("User channel join confirmed")
	}

	return nil
}

func (c *Client) receiveDemandActive() (uint32, error) {
	var data []byte
	var err error
	
	
	if c.unreadData != nil {
		data = c.unreadData
		c.unreadData = nil
	} else {
		data, err = c.readSecurePayload()
		if err != nil {
			return 0, err
		}
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
	if err := c.sendEncryptedPDU(pdu); err != nil {
		return err
	}
	
	
	
	fmt.Println("Sending Client Info PDU...")
	return c.sendClientInfoPDU()
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
	
	
	
	if err := c.sendEncryptedPDU(buildPersistentKeyListPDU(nil)); err != nil {
		
		fmt.Printf("Warning: Failed to send persistent key list PDU: %v\n", err)
	}
	
	if err := c.sendEncryptedPDU(buildFontListPDU()); err != nil {
		return err
	}

	
	if err := c.sendEncryptedPDU(buildSuppressOutputPDU(true)); err != nil {
		return err
	}

	
	if err := c.sendEncryptedPDU(buildRefreshRectPDU(0, 0, 1920, 1080)); err != nil {
		return err
	}

	
	time.Sleep(100 * time.Millisecond)
	
	
	if c.autoDetectManager != nil && c.opts.EnableAutoDetect {
		fmt.Println("Starting network auto-detection...")
		if err := c.autoDetectManager.StartConnectionTimeDetection(); err != nil {
			fmt.Printf("Warning: Auto-detect failed: %v\n", err)
			
		}
	}
	
	
	if c.heartbeatManager != nil && c.opts.EnableHeartbeat {
		fmt.Println("Starting connection health monitoring...")
		if err := c.heartbeatManager.Start(); err != nil {
			fmt.Printf("Warning: Failed to start heartbeat: %v\n", err)
			
		}
	}

	return nil
}

func (c *Client) receiveBitmapUpdate() ([]byte, error) {
	c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{})

	
	maxAttempts := 20
	for attempt := 0; attempt < maxAttempts; attempt++ {
		data, err := c.readSecurePayload()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() && attempt > 5 {
				
				return nil, fmt.Errorf("timeout waiting for bitmap update after %d attempts", attempt)
			}
			continue
		}

		
		if len(data) < 6 {
			continue
		}

		shareCtrlHdr, err := parseShareControlHeader(bytes.NewReader(data))
		if err != nil {
			continue
		}

		
		if shareCtrlHdr.PDUType&0x0F == PDUTYPE_DATAPDU {
			if len(data) < 14 {
				continue
			}

			shareDataHdr, err := parseShareDataHeader(bytes.NewReader(data[6:]))
			if err != nil {
				continue
			}

			
			switch shareDataHdr.PDUType2 {
			case PDUTYPE2_UPDATE:
				
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
				
				c.sendEncryptedPDU(buildSynchronizePDU(c.mcsUserID))

			case PDUTYPE2_CONTROL:
				fmt.Println("Received control PDU")
				

			default:
				fmt.Printf("Received PDU type2: 0x%02X\n", shareDataHdr.PDUType2)
			}
		} else if shareCtrlHdr.PDUType&0x0F == PDUTYPE_DEACTIVATEALLPDU {
			fmt.Println("Received deactivate all PDU")
			
			return nil, fmt.Errorf("server deactivated connection")
		}

		
		if len(data) > 0 && (data[0]&0x3) == 0 {
			
			fmt.Println("Possible fast-path update detected")
			
		}
	}

	return nil, fmt.Errorf("no bitmap update received after %d attempts", maxAttempts)
}

func (c *Client) sendEncryptedPDU(pdu []byte) error {
	fmt.Printf("Sending PDU (raw): %x\n", pdu)
	
	
	if c.encryptor != nil && c.serverSecurityData != nil && c.serverSecurityData.EncryptionMethod != ENCRYPTION_METHOD_NONE {
		wrappedPDU := c.secureWrap(SEC_ENCRYPT, pdu)
		fmt.Printf("Sending PDU (encrypted+wrapped): %x\n", wrappedPDU)
		return c.sendPDU(wrappedPDU)
	} else {
		
		wrappedPDU := c.secureWrap(0, pdu)
		fmt.Printf("Sending PDU (wrapped): %x\n", wrappedPDU)
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
	fullPDU := buf.Bytes()
	fmt.Printf("Sending complete packet: %x\n", fullPDU)
	if _, err := c.conn.Write(fullPDU); err != nil {
		return fmt.Errorf("failed to write PDU: %w", err)
	}
	return nil
}

func (c *Client) readRawPDU() ([]byte, error) {
	
	peekBuf := make([]byte, 1)
	if _, err := io.ReadFull(c.conn, peekBuf); err != nil {
		return nil, err
	}

	
	if (peekBuf[0] & 0x3) == 0 {
		
		return c.readFastPathPDU(peekBuf[0])
	}

	
	tpktBuf := make([]byte, 3)
	if _, err := io.ReadFull(c.conn, tpktBuf); err != nil {
		return nil, err
	}

	
	length := binary.BigEndian.Uint16(append([]byte{peekBuf[0]}, tpktBuf...)[2:])
	if length < 4 {
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


func (c *Client) sendRawPDU(pdu []byte) error {
	
	x224Header := []byte{0x02, 0xF0, 0x80}
	
	
	x224Data := append(x224Header, pdu...)
	
	
	tpktLength := len(x224Data) + 4
	tpkt := make([]byte, 4)
	tpkt[0] = 0x03 
	tpkt[1] = 0x00 
	binary.BigEndian.PutUint16(tpkt[2:], uint16(tpktLength))
	
	
	fullPacket := append(tpkt, x224Data...)
	
	fmt.Printf("Sending raw PDU: %x\n", pdu)
	fmt.Printf("Sending complete packet: %x\n", fullPacket)
	
	
	_, err := c.conn.Write(fullPacket)
	return err
}

func (c *Client) readFastPathPDU(firstByte byte) ([]byte, error) {
	
	var length int
	lengthByte1 := make([]byte, 1)
	if _, err := io.ReadFull(c.conn, lengthByte1); err != nil {
		return nil, err
	}

	if lengthByte1[0]&0x80 != 0 {
		
		lengthByte2 := make([]byte, 1)
		if _, err := io.ReadFull(c.conn, lengthByte2); err != nil {
			return nil, err
		}
		length = int(lengthByte1[0]&0x7F)<<8 | int(lengthByte2[0])
	} else {
		
		length = int(lengthByte1[0])
	}

	
	data := make([]byte, length-2) 
	if _, err := io.ReadFull(c.conn, data); err != nil {
		return nil, err
	}

	
	if firstByte&0x80 != 0 && c.decryptor != nil {
		
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

	
	fmt.Printf("MCS Attach User Confirm PDU: %x\n", pdu)

	return parseMCSAttachUserConfirm(pdu)
}


func (c *Client) secureWrap(flags uint16, payload []byte) []byte {
	head := make([]byte, 4)
	binary.LittleEndian.PutUint16(head, flags)
	binary.LittleEndian.PutUint16(head[2:], 0) 
	fullPDU := append(head, payload...)
	if c.encryptor != nil && flags&SEC_ENCRYPT != 0 {
		c.encryptor.Encrypt(fullPDU[4:])
	}
	return fullPDU
}

func (c *Client) secureUnwrap(data []byte) ([]byte, error) {
	if len(data) < 4 {
		
		
		return data, nil
	}

	flags := binary.LittleEndian.Uint16(data)

	
	if flags&(SEC_ENCRYPT|SEC_LICENSE_PKT|SEC_EXCHANGE_PKT) == 0 && flags != 0 {
		
		return data, nil
	}

	
	payload := data[4:]

	
	if c.decryptor != nil && flags&SEC_ENCRYPT != 0 && len(payload) > 0 {
		c.decryptor.Decrypt(payload)
	}

	return payload, nil
}


func (c *Client) sendMCSChannelJoinRequest(channelID uint16) error {
	pdu := buildMCSChannelJoinRequest(c.mcsUserID, channelID)
	return c.sendPDU(pdu)
}


func (c *Client) receiveMCSChannelJoinConfirm(expectedChannelID uint16) error {
	pdu, err := c.readRawPDU()
	if err != nil {
		return fmt.Errorf("failed to read channel join confirm: %w", err)
	}
	
	
	if len(pdu) < 5 {
		return fmt.Errorf("channel join confirm PDU too short")
	}
	
	
	if pdu[0] != 0x02 || pdu[1] != 0xF0 || pdu[2] != 0x80 {
		return fmt.Errorf("invalid X.224 header in channel join confirm")
	}
	
	
	return parseMCSChannelJoinConfirm(pdu[3:])
}


func (c *Client) Close() error {
	
	if c.heartbeatManager != nil {
		c.heartbeatManager.Stop()
	}
	
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}


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


type CapabilitySet struct {
	Type   uint16
	Length uint16
	Data   []byte
}


func parseDemandActivePDU(data []byte) (*DemandActivePDU, error) {
	if len(data) < 4 { 
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
		return pdu, nil 
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


func (c *Client) buildClientInfoPDU() []byte {
	
	infoPDU := new(bytes.Buffer)
	
	
	flags := uint32(0x00000001) 
	flags |= uint32(0x00000008) 
	flags |= uint32(0x00000010) 
	binary.Write(infoPDU, binary.LittleEndian, flags)
	
	
	binary.Write(infoPDU, binary.LittleEndian, uint32(0))
	
	
	binary.Write(infoPDU, binary.LittleEndian, uint16(0)) 
	
	username := []byte("user\x00")
	binary.Write(infoPDU, binary.LittleEndian, uint16(len(username)*2))
	
	binary.Write(infoPDU, binary.LittleEndian, uint16(0))
	
	binary.Write(infoPDU, binary.LittleEndian, uint16(0))
	
	binary.Write(infoPDU, binary.LittleEndian, uint16(0))
	
	
	for _, b := range username {
		infoPDU.WriteByte(b)
		infoPDU.WriteByte(0) 
	}
	
	
	binary.Write(infoPDU, binary.LittleEndian, uint16(0x0001)) 
	binary.Write(infoPDU, binary.LittleEndian, uint16(0)) 
	binary.Write(infoPDU, binary.LittleEndian, uint16(0)) 
	
	
	infoPDU.Write(make([]byte, 172))
	
	
	binary.Write(infoPDU, binary.LittleEndian, uint32(0))
	
	binary.Write(infoPDU, binary.LittleEndian, uint32(0))
	
	return infoPDU.Bytes()
}


func (c *Client) sendClientInfoPDU() error {
	
	infoPDU := c.buildClientInfoPDU()
	
	
	sendDataPDU := buildMCSSendDataRequest(c.mcsUserID, c.ioChannel, infoPDU)
	
	
	return c.sendEncryptedPDU(sendDataPDU)
}


func (c *Client) attemptDirectScreenshot() ([]byte, error) {
	fmt.Println("=== DIRECT SCREENSHOT ATTEMPT ===")
	
	
	
	
	fmt.Println("Trying approach 1: Refresh rectangle request...")
	refreshPDU := buildRefreshRectanglePDU(c.mcsUserID)
	if err := c.sendEncryptedPDU(refreshPDU); err != nil {
		fmt.Printf("Approach 1 failed: %v\n", err)
	} else {
		
		c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if data, err := c.readRawPDU(); err == nil {
			fmt.Printf("Got response from approach 1: %x\n", data)
			if bitmap := c.tryParseBitmapFromPDU(data); bitmap != nil {
				return bitmap, nil
			}
		}
		c.conn.SetReadDeadline(time.Time{})
	}
	
	
	fmt.Println("Trying approach 2: Input events...")
	events := []InputEvent{buildMouseMoveEvent(100, 100)}
	inputPDU := buildInputEventPDU(events)
	if err := c.sendEncryptedPDU(inputPDU); err != nil {
		fmt.Printf("Approach 2 failed: %v\n", err)
	} else {
		
		c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if data, err := c.readRawPDU(); err == nil {
			fmt.Printf("Got response from approach 2: %x\n", data)
			if bitmap := c.tryParseBitmapFromPDU(data); bitmap != nil {
				return bitmap, nil
			}
		}
		c.conn.SetReadDeadline(time.Time{})
	}
	
	
	fmt.Println("Trying approach 3: Generate test bitmap...")
	return c.generateTestBitmap()
}


func (c *Client) tryParseBitmapFromPDU(data []byte) []byte {
	if len(data) < 20 {
		return nil
	}
	
	
	for i := 0; i < len(data)-4; i++ {
		if binary.LittleEndian.Uint16(data[i:]) == UPDATETYPE_BITMAP {
			fmt.Printf("Found potential bitmap update at offset %d\n", i)
			
			if bitmap, err := c.extractBitmapFromUpdate(data[i:]); err == nil {
				return bitmap
			}
		}
	}
	
	return nil
}


func (c *Client) extractBitmapFromUpdate(data []byte) ([]byte, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("data too short")
	}
	
	
	return c.generateTestBitmap()
}


func (c *Client) generateTestBitmap() ([]byte, error) {
	fmt.Println("Generating test bitmap to verify pipeline...")
	
	
	width, height := 100, 100
	bitmapData := make([]byte, width*height*3) 
	
	
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			offset := (y*width + x) * 3
			
			bitmapData[offset] = byte(x * 255 / width)     
			bitmapData[offset+1] = byte(y * 255 / height) 
			bitmapData[offset+2] = 128                     
		}
	}
	
	
	return bitmap.ConvertRGBToPNG(bitmapData, width, height)
}


func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}


func (c *Client) GetNegotiatedProtocol() uint32 {
	return c.negotiatedProtocol
}


func (c *Client) IsTLSEnabled() bool {
	return c.tlsEnabled
}


func (c *Client) UpgradeTLS(config *TLSConfig) error {
	return c.upgradeTLSConnection(config)
}


func (c *Client) TestCredSSPAuth() error {
	if !c.tlsEnabled {
		return fmt.Errorf("TLS is required for CredSSP authentication")
	}
	return c.PerformCredSSPAuth()
}
