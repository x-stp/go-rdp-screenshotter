package rdp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// errCredSSPRejected wraps any CredSSP failure so the anonymous-fallback path
// can recognise it and reconnect without HYBRID.
type errCredSSPRejected struct{ err error }

func (e *errCredSSPRejected) Error() string { return "credssp: " + e.err.Error() }
func (e *errCredSSPRejected) Unwrap() error { return e.err }

func (c *Client) establishX224Connection() error {
	if err := c.handshake(); err == nil {
		return nil
	} else if !c.shouldRetry(err) {
		return err
	}
	// One retry on a fresh TCP connection. disableSSL / disableNLA were set
	// by shouldRetry to constrain the next NegReq.
	c.conn.Close()
	dialer := net.Dialer{Timeout: c.opts.Timeout}
	conn, derr := dialer.Dial("tcp", c.target)
	if derr != nil {
		return fmt.Errorf("reconnect after handshake retry: %w", derr)
	}
	c.conn = conn
	c.tlsEnabled = false
	return c.handshake()
}

// handshake runs the full pre-screenshot pipeline: X.224 negotiation, optional
// TLS upgrade, optional CredSSP. Anything before MCS lives here so the retry
// loop in establishX224Connection has a single seam to re-run.
func (c *Client) handshake() error {
	if err := c.x224Negotiate(); err != nil {
		return err
	}
	if isNLA(c.negotiatedProtocol) {
		Logger.Info().Uint32("protocol", c.negotiatedProtocol).Msg("server requires NLA")
		if err := c.PerformCredSSPAuth(); err != nil {
			return &errCredSSPRejected{err: err}
		}
	}
	return nil
}

// shouldRetry inspects err and, if a single reconnect would help, sets the
// appropriate `disable*` flag on opts and reports true. It encodes both the
// [MS-RDPBCGR] §3.3.5.3.2 SSL_NOT_ALLOWED_BY_SERVER fallback and the
// AnonymousNLA-on-CredSSP-rejection fallback in one place.
func (c *Client) shouldRetry(err error) bool {
	var nf *X224NegFailure
	if errors.As(err, &nf) && nf.Code == SSL_NOT_ALLOWED_BY_SERVER {
		Logger.Debug().Str("reason", nf.Error()).Msg("x224: retrying with PROTOCOL_RDP-only")
		c.opts.disableSSL = true
		return true
	}
	var cred *errCredSSPRejected
	if errors.As(err, &cred) && c.opts != nil && c.opts.AnonymousNLA {
		Logger.Debug().Err(cred.err).Msg("anonymous CredSSP rejected; retrying without HYBRID")
		c.opts.disableNLA = true
		return true
	}
	return false
}

func (c *Client) x224Negotiate() error {
	if err := c.sendX224ConnectionRequest(c.opts.Username); err != nil {
		return err
	}
	negotiatedProtocol, err := c.receiveX224ConnectionConfirm()
	if err != nil {
		return err
	}
	c.negotiatedProtocol = negotiatedProtocol
	c.useRdpEncryption = (negotiatedProtocol == PROTOCOL_RDP)

	if isTLSRequired(c.negotiatedProtocol) {
		host, _, _ := net.SplitHostPort(c.target)
		if err := c.upgradeTLSConnection(DefaultTLSConfig(host)); err != nil {
			return fmt.Errorf("TLS upgrade failed: %w", err)
		}
	}
	return nil
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
	Logger.Debug().Msg("MCS Connect Response received")
	return nil
}

func (c *Client) performMCSDomainJoin() error {
	if err := c.sendPDU(buildMCSErectDomainRequest()); err != nil {
		return err
	}
	if err := c.sendPDU(buildMCSAttachUserRequest()); err != nil {
		return err
	}

	userID, err := c.receiveMCSAttachUserConfirm()
	if err != nil {
		return err
	}
	c.mcsUserID = userID
	c.ioChannel = MCS_CHANNEL_GLOBAL
	Logger.Debug().Uint16("user", c.mcsUserID).Uint16("io", c.ioChannel).Msg("MCS: channels assigned")

	if err := c.sendMCSChannelJoinRequest(c.mcsUserID); err != nil {
		return fmt.Errorf("failed to send user channel join: %w", err)
	}
	if err := c.receiveMCSChannelJoinConfirm(c.mcsUserID); err != nil {
		return fmt.Errorf("user channel join failed: %w", err)
	}
	if err := c.sendMCSChannelJoinRequest(c.ioChannel); err != nil {
		return fmt.Errorf("failed to send I/O channel join: %w", err)
	}
	if err := c.receiveMCSChannelJoinConfirm(c.ioChannel); err != nil {
		return fmt.Errorf("I/O channel join failed: %w", err)
	}

	Logger.Debug().Msg("MCS domain join completed")
	return nil
}

func (c *Client) receiveMCSAttachUserConfirm() (uint16, error) {
	pdu, err := c.readRawPDU()
	if err != nil {
		return 0, err
	}
	return parseMCSAttachUserConfirm(pdu)
}

func (c *Client) sendMCSChannelJoinRequest(channelID uint16) error {
	return c.sendPDU(buildMCSChannelJoinRequest(c.mcsUserID, channelID))
}

func (c *Client) receiveMCSChannelJoinConfirm(_ uint16) error {
	pdu, err := c.readRawPDU()
	if err != nil {
		return fmt.Errorf("failed to read channel join confirm: %w", err)
	}
	if len(pdu) < 1 {
		return fmt.Errorf("channel join confirm PDU too short")
	}
	return parseMCSChannelJoinConfirm(pdu)
}

// sendFinalizationPDUs runs the post-Confirm-Active sequence per [MS-RDPBCGR]
// §1.3.1.1 step 11: Synchronize, Control Cooperate, Control Request Control,
// Font List. Server then begins streaming bitmap updates.
func (c *Client) sendFinalizationPDUs() error {
	steps := []struct {
		name string
		pdu  []byte
	}{
		{"synchronize", buildSynchronizePDU(c.mcsUserID, c.shareID)},
		{"control cooperate", buildControlPDU(CTRLACTION_COOPERATE, c.mcsUserID, c.shareID)},
		{"control request", buildControlPDU(CTRLACTION_REQUEST_CONTROL, c.mcsUserID, c.shareID)},
		{"font list", buildFontListPDU(c.mcsUserID, c.shareID)},
	}
	for _, step := range steps {
		if err := c.sendChannelData(step.pdu); err != nil {
			return fmt.Errorf("%s PDU: %w", step.name, err)
		}
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
		_, data, err = c.readSecurePayload()
		if err != nil {
			return 0, err
		}
	}
	hdr, err := parseShareControlHeader(bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	if hdr.PDUType&0x0F != PDUTYPE_DEMANDACTIVEPDU {
		return 0, fmt.Errorf("expected demand active PDU, got type 0x%04X", hdr.PDUType)
	}
	pdu, err := parseDemandActivePDU(data[6:])
	if err != nil {
		return 0, err
	}
	return pdu.ShareID, nil
}

func (c *Client) sendConfirmActive(shareID uint32) error {
	c.shareID = shareID
	pdu, err := buildConfirmActivePDU(shareID, c.mcsUserID)
	if err != nil {
		return err
	}
	return c.sendChannelData(pdu)
}

// --- Demand Active PDU parsing (kept here because it's part of the activation
// hand-off between handshake and bitmap streaming). [MS-RDPBCGR] §2.2.1.13.1.

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
		return nil, fmt.Errorf("demand active PDU too short: %d bytes", len(data))
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
	pdu.CapabilitySets = parseCapabilitySets(r, pdu.NumberCapabilities)

	if r.Len() >= 4 {
		binary.Read(r, binary.LittleEndian, &pdu.SessionID)
	}
	return pdu, nil
}

// parseCapabilitySets walks the TS_CAPS_SET array per [MS-RDPBCGR] §2.2.7.
// Truncated tail records are silently ignored: we treat the wire as
// best-effort because we never inspect the capabilities beyond logging
// (the screenshotter doesn't react to most of them).
func parseCapabilitySets(r *bytes.Reader, n uint16) []CapabilitySet {
	out := make([]CapabilitySet, 0, n)
	for i := uint16(0); i < n; i++ {
		var capSet CapabilitySet
		if r.Len() < 4 {
			return out
		}
		binary.Read(r, binary.LittleEndian, &capSet.Type)
		binary.Read(r, binary.LittleEndian, &capSet.Length)
		if capSet.Length >= 4 {
			capDataLen := int(capSet.Length) - 4
			if r.Len() < capDataLen {
				return out
			}
			capSet.Data = make([]byte, capDataLen)
			r.Read(capSet.Data)
		}
		out = append(out, capSet)
	}
	return out
}

// Info Packet flag bits per [MS-RDPBCGR] §2.2.1.11.1.1.1. Only the values we
// emit are listed; the rest of the bit-field is left at zero.
const (
	infoMouse             uint32 = 0x00000001
	infoDisableCtrlAltDel uint32 = 0x00000002
	infoAutoLogon         uint32 = 0x00000008
	infoUnicode           uint32 = 0x00000010
	infoMaximizeShell     uint32 = 0x00000020
	infoLogonNotify       uint32 = 0x00000040
	infoEnableWindowsKey  uint32 = 0x00000100
	infoLogonErrors       uint32 = 0x00010000
	infoMouseHasWheel     uint32 = 0x00020000
)

// infoPacketFlags returns the Flags bitmask we ship in TS_INFO_PACKET. The
// mstsc-equivalent baseline is always set; INFO_AUTOLOGON is only added when
// we actually have a password to ship.
func infoPacketFlags(password string) uint32 {
	flags := infoMouse | infoDisableCtrlAltDel | infoUnicode |
		infoMaximizeShell | infoEnableWindowsKey | infoLogonErrors |
		infoLogonNotify | infoMouseHasWheel
	if password != "" {
		flags |= infoAutoLogon
	}
	return flags
}

// buildClientInfoPDU emits a TS_INFO_PACKET ([MS-RDPBCGR] §2.2.1.11.1.1)
// followed by a TS_EXTENDED_INFO_PACKET (§2.2.1.11.1.1.1). Strings are
// NUL-terminated UTF-16LE; cbX fields are the byte count of the value
// excluding the terminator.
func (c *Client) buildClientInfoPDU() []byte {
	domain, username, password := c.credentialsForInfoPacket()
	encoded := encodedInfoStrings(domain, username, password)

	buf := new(bytes.Buffer)
	writeInfoPacketHeader(buf, password, encoded)
	for _, w := range encoded {
		buf.Write(w)
		buf.Write([]byte{0x00, 0x00})
	}
	writeExtendedInfoPacket(buf)
	return buf.Bytes()
}

func (c *Client) credentialsForInfoPacket() (domain, username, password string) {
	if c.opts == nil {
		return "", "", ""
	}
	return c.opts.Domain, c.opts.Username, c.opts.Password
}

// encodedInfoStrings UTF-16LE-encodes the five TS_INFO_PACKET strings in
// wire order: Domain, UserName, Password, AlternateShell, WorkingDir.
// Returning the encoded bytes lets writeInfoPacketHeader emit the matching
// cbX fields without re-encoding (which matters for surrogate-pair input
// where utf16.Encode produces twice the rune count).
func encodedInfoStrings(domain, username, password string) [5][]byte {
	return [5][]byte{
		toUnicode(domain),
		toUnicode(username),
		toUnicode(password),
		toUnicode(""),
		toUnicode(""),
	}
}

// writeInfoPacketHeader serialises the fixed prefix of TS_INFO_PACKET:
// codePage(4) + flags(4) + cbDomain/User/Password/Shell/WorkingDir(2 each).
// The cb values count the encoded bytes excluding the NUL terminator.
func writeInfoPacketHeader(buf *bytes.Buffer, password string, encoded [5][]byte) {
	binary.Write(buf, binary.LittleEndian, uint32(0)) // codePage
	binary.Write(buf, binary.LittleEndian, infoPacketFlags(password))
	for _, w := range encoded {
		binary.Write(buf, binary.LittleEndian, uint16(len(w)))
	}
}

// writeExtendedInfoPacket appends TS_EXTENDED_INFO_PACKET ([MS-RDPBCGR]
// §2.2.1.11.1.1.1) with mstsc-equivalent default values: AF_INET,
// "0.0.0.0" client address, the canonical mstscax.dll client dir, and an
// all-zero TIME_ZONE_INFORMATION + clientSessionId + performanceFlags +
// cbAutoReconnectCookie tail.
func writeExtendedInfoPacket(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint16(0x0002)) // clientAddressFamily AF_INET
	writeCountedUtf16(buf, "0.0.0.0")
	writeCountedUtf16(buf, "C:\\Windows\\System32\\mstscax.dll") // clientDir
	buf.Write(make([]byte, 172))                                 // clientTimeZone (TIME_ZONE_INFORMATION)
	binary.Write(buf, binary.LittleEndian, uint32(0))            // clientSessionId
	binary.Write(buf, binary.LittleEndian, uint32(0))            // performanceFlags
	binary.Write(buf, binary.LittleEndian, uint16(0))            // cbAutoReconnectCookie
}

// writeCountedUtf16 emits a uint16 length-prefixed UTF-16LE NUL-terminated
// string in the layout used by clientAddress / clientDir in
// TS_EXTENDED_INFO_PACKET. The length field counts the NUL terminator.
func writeCountedUtf16(buf *bytes.Buffer, s string) {
	w := toUnicode(s)
	binary.Write(buf, binary.LittleEndian, uint16(len(w)+2))
	buf.Write(w)
	buf.Write([]byte{0x00, 0x00})
}

// sendClientInfoPDU wraps the TS_INFO_PACKET in a SEC_INFO_PKT (+SEC_ENCRYPT
// under standard RDP security) basic security header. [MS-RDPBCGR] §2.2.1.11.
func (c *Client) sendClientInfoPDU() error {
	flags := uint16(SEC_INFO_PKT)
	if c.useRdpEncryption {
		flags |= SEC_ENCRYPT
	}
	sealed := c.buildSecurePayload(flags, c.buildClientInfoPDU())
	return c.sendPDU(buildMCSSendDataRequest(c.mcsUserID, c.ioChannel, sealed))
}
