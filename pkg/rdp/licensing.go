package rdp

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
)

const (
	LICENSE_REQUEST             = 0x01
	PLATFORM_CHALLENGE          = 0x02
	NEW_LICENSE                 = 0x03
	UPGRADE_LICENSE             = 0x04
	LICENSE_INFO                = 0x12
	NEW_LICENSE_REQUEST         = 0x13
	PLATFORM_CHALLENGE_RESPONSE = 0x15
	ERROR_ALERT                 = 0xFF
)

const (
	ERR_INVALID_SERVER_CERTIFICATE = 0x00000001
	ERR_NO_LICENSE                 = 0x00000002
	ERR_INVALID_SCOPE              = 0x00000004
	ERR_NO_LICENSE_SERVER          = 0x00000006
	ST_NO_TRANSITION               = 0x00000001
	ERR_INVALID_CLIENT             = 0x00000008
	ERR_INVALID_PRODUCTID          = 0x0000000B
	ERR_INVALID_MESSAGE_LEN        = 0x0000000C
	ERR_INVALID_MAC                = 0x00000003
	STATUS_VALID_CLIENT            = 0x00000007
	ST_TOTAL_ABORT                 = 0x00000002
)

// LicensingPDU is the LICENSE_PREAMBLE per [MS-RDPBCGR] §2.2.1.12.1.1.
type LicensingPDU struct {
	PDUType uint8
	Flags   uint8
	Size    uint16
}

// handleLicensingPDU dispatches a licensing PDU. data starts at the
// LICENSE_PREAMBLE; the basic security header has already been stripped.
func (c *Client) handleLicensingPDU(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("licensing PDU too short: %d bytes", len(data))
	}

	// LICENSE_PREAMBLE is 4 bytes; the len(data) >= 4 guard above guarantees
	// these binary.Read calls cannot fail with io.EOF on a bytes.Reader.
	r := bytes.NewReader(data)
	var hdr LicensingPDU
	binary.Read(r, binary.LittleEndian, &hdr.PDUType)
	binary.Read(r, binary.LittleEndian, &hdr.Flags)
	binary.Read(r, binary.LittleEndian, &hdr.Size)

	Logger.Debug().
		Uint8("type", hdr.PDUType).
		Uint8("flags", hdr.Flags).
		Uint16("size", hdr.Size).
		Msg("licensing: pdu received")

	switch hdr.PDUType {
	case LICENSE_REQUEST:
		return c.handleLicenseRequest(data[4:])
	case PLATFORM_CHALLENGE:
		return c.handlePlatformChallenge(data[4:])
	case NEW_LICENSE, UPGRADE_LICENSE:
		Logger.Debug().Msg("licensing: NEW_LICENSE/UPGRADE_LICENSE accepted, exchange complete")
		return nil
	case ERROR_ALERT:
		return c.handleLicenseError(data[4:])
	default:
		Logger.Warn().Uint8("type", hdr.PDUType).Msg("licensing: unhandled message type")
	}

	return nil
}

// handleLicenseRequest runs the full [MS-RDPELE] §3.2.5 licensing exchange
// (NEW_LICENSE_REQUEST -> PLATFORM_CHALLENGE_RESPONSE -> NEW_LICENSE). Falls
// back to STATUS_VALID_CLIENT when any step fails; some Windows servers reject
// the shortcut with ERRINFO_LICENSE_CLIENT_ENDED_PROTOCOL ([MS-RDPBCGR]
// §2.2.5.1.1).
func (c *Client) handleLicenseRequest(data []byte) error {
	serverRandom, certData, err := parseServerLicenseRequest(data)
	if err != nil {
		Logger.Warn().Err(err).Msg("license: parse LICENSE_REQUEST failed; falling back to STATUS_VALID_CLIENT")
		return c.sendLicenseErrorAlert(STATUS_VALID_CLIENT)
	}

	var pubKey *rsa.PublicKey
	if len(certData) > 0 {
		pubKey, err = extractLicenseServerCertKey(certData)
		if err != nil {
			Logger.Debug().Err(err).Msg("license: extract embedded cert failed; trying connection cert")
		}
	}
	// [MS-RDPELE] §3.2.5.1: the server may omit the embedded ServerCertificate
	// when the GCC server-data exchange already supplied one; reuse it.
	if pubKey == nil && c.serverSecurityData != nil && c.serverSecurityData.ServerPublicKey != nil {
		pubKey = c.serverSecurityData.ServerPublicKey
	}
	if pubKey == nil {
		Logger.Warn().Msg("license: no usable server public key; falling back to error alert")
		return c.sendLicenseErrorAlert(STATUS_VALID_CLIENT)
	}

	ls := &licenseSession{serverPubKey: pubKey}
	copy(ls.serverRandom[:], serverRandom)
	if err := generateLicenseRandoms(ls); err != nil {
		return c.sendLicenseErrorAlert(STATUS_VALID_CLIENT)
	}
	ls.deriveLicenseKeys()
	ls.hardwareID = generateHardwareID(platformIDWinPost, "rdp-go")

	modulusLen := (pubKey.N.BitLen() + 7) / 8
	encryptedPMS, err := rsaEncryptRDP(pubKey, ls.premasterSecret[:])
	if err != nil {
		Logger.Warn().Err(err).Msg("license: rsa encrypt premaster failed; falling back")
		return c.sendLicenseErrorAlert(STATUS_VALID_CLIENT)
	}

	c.licenseSession = ls
	body := buildNewLicenseRequest(ls, encryptedPMS, modulusLen, "rdp-go", "rdp-go")
	return c.sendLicensePDU(NEW_LICENSE_REQUEST, body)
}

func (c *Client) handlePlatformChallenge(data []byte) error {
	if c.licenseSession == nil {
		return fmt.Errorf("platform challenge without license session")
	}
	challenge, err := parsePlatformChallenge(c.licenseSession, data)
	if err != nil {
		Logger.Warn().Err(err).Msg("license: parse platform challenge failed; fallback")
		return c.sendLicenseErrorAlert(STATUS_VALID_CLIENT)
	}
	body := buildPlatformChallengeResponse(c.licenseSession, challenge)
	return c.sendLicensePDU(PLATFORM_CHALLENGE_RESPONSE, body)
}

// sendLicensePDU wraps body in a LICENSE_PREAMBLE + basic security header and
// sends it on the I/O channel.
func (c *Client) sendLicensePDU(msgType uint8, body []byte) error {
	const (
		PREAMBLE_VERSION_3_0         = 0x03
		EXTENDED_ERROR_MSG_SUPPORTED = 0x80
	)
	out := new(bytes.Buffer)
	binary.Write(out, binary.LittleEndian, msgType)
	binary.Write(out, binary.LittleEndian, uint8(EXTENDED_ERROR_MSG_SUPPORTED|PREAMBLE_VERSION_3_0))
	binary.Write(out, binary.LittleEndian, uint16(4+len(body)))
	out.Write(body)

	flags := uint16(SEC_LICENSE_PKT)
	sealed := c.buildSecurePayload(flags, out.Bytes())
	mcs := buildMCSSendDataRequest(c.mcsUserID, c.ioChannel, sealed)
	return c.sendPDU(mcs)
}

func (c *Client) handleLicenseError(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("license error PDU too short")
	}
	errorCode := binary.LittleEndian.Uint32(data[0:4])
	if errorCode == STATUS_VALID_CLIENT {
		return nil
	}
	return fmt.Errorf("licensing error: 0x%08X", errorCode)
}

// sendLicenseErrorAlert emits the LICENSE_ERROR_MESSAGE per [MS-RDPBCGR]
// §2.2.1.12.1.3 used to short-circuit licensing (STATUS_VALID_CLIENT +
// ST_NO_TRANSITION + empty BB_ERROR_BLOB).
//
//	bMsgType(1)=0xFF                                    -- ERROR_ALERT
//	bMsgFlags(1)=EXTENDED_ERROR_MSG_SUPPORTED|PREAMBLE_VERSION_3_0
//	wMsgSize(2)=16
//	dwErrorCode(4)=STATUS_VALID_CLIENT (0x00000007)     -- "I'm good"
//	dwStateTransition(4)=ST_NO_TRANSITION (0x00000001)  -- "don't advance"
//	bbErrorInfo: wBlobType(2)=BB_ERROR_BLOB wBlobLen(2)=0
//
// Yes: the bypass is an *error alert* whose payload says STATUS_VALID_CLIENT.
// The server receives an ERROR_ALERT, reads "valid client", and transitions
// into the "this peer has a license, carry on" branch. Per-Device CALs
// across the planet have been silently not-incrementing for two decades
// because nobody in the licensing-protocol review chain noticed that
// 0xFF + 0x07 means "trust me bro". Per [MS-RDPELE] §3.2.5.10, this is the
// canonical path for clients that don't want a license.
func (c *Client) sendLicenseErrorAlert(errorCode uint32) error {
	const (
		PREAMBLE_VERSION_3_0         = 0x03
		EXTENDED_ERROR_MSG_SUPPORTED = 0x80
		BB_ERROR_BLOB                = 0x0004
	)

	body := new(bytes.Buffer)
	binary.Write(body, binary.LittleEndian, uint8(ERROR_ALERT))
	binary.Write(body, binary.LittleEndian, uint8(EXTENDED_ERROR_MSG_SUPPORTED|PREAMBLE_VERSION_3_0))
	binary.Write(body, binary.LittleEndian, uint16(16))
	binary.Write(body, binary.LittleEndian, errorCode)
	binary.Write(body, binary.LittleEndian, uint32(ST_NO_TRANSITION))
	binary.Write(body, binary.LittleEndian, uint16(BB_ERROR_BLOB))
	binary.Write(body, binary.LittleEndian, uint16(0))

	// [MS-RDPBCGR] §5.4.2: licensing PDUs are not RC4-sealed at the basic
	// security layer; SEC_LICENSE_ENCRYPT_CS would seal the body separately
	// but the unencrypted form is what every server we care about accepts.
	sealed := c.buildSecurePayload(uint16(SEC_LICENSE_PKT), body.Bytes())
	return c.sendPDU(buildMCSSendDataRequest(c.mcsUserID, c.ioChannel, sealed))
}
