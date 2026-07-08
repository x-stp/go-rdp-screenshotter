// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 x-stp

package rdp

import (
	"bytes"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
)

// sendSecurityExchange sends the Security Exchange PDU and derives session
// keys per [MS-RDPBCGR] §3.2.5.3.10. Only relevant under PROTOCOL_RDP with a
// non-zero EncryptionMethod from the SC_SECURITY block.
func (c *Client) sendSecurityExchange() error {
	if c.serverSecurityData == nil {
		return fmt.Errorf("server security data is missing for security exchange")
	}
	pdu, clientRandom, err := buildSecurityExchangePDU(c.serverSecurityData)
	if err != nil {
		return fmt.Errorf("failed to build security exchange PDU: %w", err)
	}
	c.clientRandom = clientRandom

	wrapped := c.buildSecurePayload(SEC_EXCHANGE_PKT, pdu)
	mcs := buildMCSSendDataRequest(c.mcsUserID, c.ioChannel, wrapped)
	if err := c.sendPDU(mcs); err != nil {
		return fmt.Errorf("failed to send security exchange PDU: %w", err)
	}

	if c.serverSecurityData.EncryptionMethod == ENCRYPTION_METHOD_NONE ||
		c.serverSecurityData.ServerRandom == nil ||
		c.clientRandom == nil {
		return nil
	}

	c.sessionKeys, err = deriveSessionKeys(c.clientRandom, c.serverSecurityData.ServerRandom, c.serverSecurityData.EncryptionMethod)
	if err != nil {
		return fmt.Errorf("failed to derive session keys: %w", err)
	}
	if c.encryptor, err = rc4.NewCipher(c.sessionKeys.EncryptKey); err != nil {
		return fmt.Errorf("rc4 encryptor: %w", err)
	}
	if c.decryptor, err = rc4.NewCipher(c.sessionKeys.DecryptKey); err != nil {
		return fmt.Errorf("rc4 decryptor: %w", err)
	}
	Logger.Debug().Uint32("method", c.serverSecurityData.EncryptionMethod).Msg("session keys derived")
	return nil
}

// sendChannelData ships a share-data PDU on the I/O channel inside an MCS
// SendDataRequest, RC4-sealing the payload when standard RDP security is
// active. [MS-RDPBCGR] §2.2.8.1.1.1.
func (c *Client) sendChannelData(payload []byte) error {
	sealed := payload
	if c.useRdpEncryption && c.encryptor != nil {
		sealed = c.buildSecurePayload(SEC_ENCRYPT, payload)
	}
	return c.sendPDU(buildMCSSendDataRequest(c.mcsUserID, c.ioChannel, sealed))
}

// buildSecurePayload prepends the basic security header (12 bytes incl. MAC
// for SEC_ENCRYPT, 4 bytes otherwise) and RC4-encrypts in place.
// [MS-RDPBCGR] §2.2.8.1.1.2.1 + §5.3.6.
func (c *Client) buildSecurePayload(flags uint16, payload []byte) []byte {
	if flags&SEC_ENCRYPT == 0 || c.encryptor == nil || c.sessionKeys == nil {
		buf := make([]byte, 4+len(payload))
		binary.LittleEndian.PutUint16(buf[0:2], flags)
		copy(buf[4:], payload)
		return buf
	}
	mac := rdpMacSignature(c.sessionKeys.MACKey, payload)
	enc := append([]byte(nil), payload...)
	c.encryptor.XORKeyStream(enc, enc)
	buf := make([]byte, 12+len(enc))
	binary.LittleEndian.PutUint16(buf[0:2], flags)
	copy(buf[4:12], mac[:8])
	copy(buf[12:], enc)
	return buf
}

// consumeSecurityHeader strips and returns the basic security header if one
// precedes the share-control PDU. Standard-RDP-security PDUs always have a
// 4-byte (or 12-byte when SEC_ENCRYPT is set) security header; under TLS/NLA
// only specific PDU types do ([MS-RDPBCGR] §5.4.1). A bare share-control header
// is disambiguated by its first u16 (totalLength) equalling the inner length.
func (c *Client) consumeSecurityHeader(inner []byte) (uint16, []byte, error) {
	if len(inner) < 4 {
		return 0, inner, nil
	}
	if c.useRdpEncryption {
		flags := binary.LittleEndian.Uint16(inner[0:2])
		if flags&SEC_ENCRYPT != 0 && c.decryptor != nil && len(inner) >= 12 {
			body := append([]byte(nil), inner[12:]...)
			c.decryptor.XORKeyStream(body, body)
			return flags, body, nil
		}
		return flags, inner[4:], nil
	}

	first := binary.LittleEndian.Uint16(inner[0:2])
	if int(first) == len(inner) {
		return 0, inner, nil
	}

	const secPduMask = uint16(SEC_LICENSE_PKT | SEC_REDIRECTION_PKT |
		SEC_AUTODETECT_REQ | SEC_AUTODETECT_RSP | SEC_HEARTBEAT)
	if first&secPduMask != 0 {
		return first, inner[4:], nil
	}
	return 0, inner, nil
}

// sendPDU wraps an MCS PDU in TPKT + X.224 Data TPDU and writes it.
func (c *Client) sendPDU(pdu []byte) error {
	tpkt := NewTPKTHeader(len(pdu) + 3)
	buf := new(bytes.Buffer)
	tpkt.WriteTo(buf)
	buf.Write([]byte{0x02, 0xf0, 0x80})
	buf.Write(pdu)
	if _, err := c.conn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to write PDU: %w", err)
	}
	return nil
}
