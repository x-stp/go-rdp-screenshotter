package rdp

import (
	"bytes"
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

type LicensingPDU struct {
	SecurityHeader uint32
	PDUType        uint8
	Flags          uint8
	Size           uint16
}

func (c *Client) handleLicensingPDU(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("licensing PDU too short")
	}

	r := bytes.NewReader(data)
	var hdr LicensingPDU
	binary.Read(r, binary.LittleEndian, &hdr.SecurityHeader)
	binary.Read(r, binary.LittleEndian, &hdr.PDUType)
	binary.Read(r, binary.LittleEndian, &hdr.Flags)
	binary.Read(r, binary.LittleEndian, &hdr.Size)

	fmt.Printf("Licensing PDU: Type=0x%02X, Flags=0x%02X, Size=%d\n",
		hdr.PDUType, hdr.Flags, hdr.Size)

	switch hdr.PDUType {
	case LICENSE_REQUEST:
		return c.handleLicenseRequest(data[8:])
	case ERROR_ALERT:
		return c.handleLicenseError(data[8:])
	default:
		fmt.Printf("Unhandled licensing PDU type: 0x%02X\n", hdr.PDUType)
	}

	return nil
}

func (c *Client) handleLicenseRequest(data []byte) error {
	fmt.Println("Received License Request")
	return c.sendLicenseErrorAlert(STATUS_VALID_CLIENT)
}

func (c *Client) handleLicenseError(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("license error PDU too short")
	}

	errorCode := binary.LittleEndian.Uint32(data[0:4])
	stateTransition := binary.LittleEndian.Uint32(data[4:8])

	fmt.Printf("License Error: Code=0x%08X, StateTransition=0x%08X\n",
		errorCode, stateTransition)

	if errorCode == STATUS_VALID_CLIENT {
		fmt.Println("Licensing completed successfully (valid client)") // ms: ERROR_ALERT with STATUS_VALID_CLIENT, great idea
		return nil
	}

	return fmt.Errorf("licensing error: 0x%08X", errorCode)
}

func (c *Client) sendLicenseErrorAlert(errorCode uint32) error {

	pduBuf := new(bytes.Buffer)
	binary.Write(pduBuf, binary.LittleEndian, uint8(ERROR_ALERT))
	binary.Write(pduBuf, binary.LittleEndian, uint8(0x03))
	binary.Write(pduBuf, binary.LittleEndian, uint16(12))
	binary.Write(pduBuf, binary.LittleEndian, errorCode)
	binary.Write(pduBuf, binary.LittleEndian, uint32(ST_NO_TRANSITION))

	wrappedPDU := c.secureWrap(SEC_ENCRYPT|SEC_LICENSE_PKT, pduBuf.Bytes())

	return c.sendPDU(wrappedPDU)
}
