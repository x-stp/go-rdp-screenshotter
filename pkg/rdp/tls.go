// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 x-stp

package rdp

import (
	"fmt"
	"net"
	"time"

	ztls "github.com/zmap/zcrypto/tls"
)

type TLSConfig struct {
	ServerName string

	InsecureSkipVerify bool

	Timeout time.Duration
}

func DefaultTLSConfig(serverName string) *TLSConfig {
	return &TLSConfig{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		Timeout:            10 * time.Second,
	}
}

func (c *Client) upgradeTLSConnection(tlsConfig *TLSConfig) error {
	tlsConfig.ServerName = c.resolveSNI(tlsConfig.ServerName)
	zcfg := buildZTLSConfig(tlsConfig)

	tlsConn, err := c.runTLSHandshake(zcfg, tlsConfig.Timeout)
	if err != nil {
		return err
	}
	c.captureTLSState(tlsConn)
	return nil
}

// resolveSNI picks the SNI (RFC 6066 §3, server_name extension) we'll send:
// the explicit configured value if present, otherwise the host portion of
// c.target (or the whole target if it has no port). RDP-over-TLS carries the
// X.224 negotiation before the TLS ClientHello per [MS-RDPBCGR] §5.4.5.1.
func (c *Client) resolveSNI(configured string) string {
	if configured != "" {
		return configured
	}
	host, _, err := net.SplitHostPort(c.target)
	if err != nil {
		return c.target
	}
	return host
}

// buildZTLSConfig returns the zcrypto ztls.Config we hand to the handshake.
// We pin TLS 1.0 (RFC 2246) .. TLS 1.2 (RFC 5246) because a large share of
// public RDP targets are still on Server 2008/2012 era stacks that never
// learned TLS 1.3; modern Server 2019+ negotiates 1.2 happily inside this
// band. The RFC 8996 deprecation of TLS 1.0/1.1 is acknowledged but not
// enforced: this is a screenshot tool against arbitrary Internet hosts, not
// a security-critical client, and InsecureSkipVerify is on for the same
// reason ([MS-RDPBCGR] §5.4.5.1 lets the server present a self-signed cert).
func buildZTLSConfig(cfg *TLSConfig) *ztls.Config {
	return &ztls.Config{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		MinVersion:         ztls.VersionTLS10,
		MaxVersion:         ztls.VersionTLS12,
		CipherSuites:       rdpCompatibleCipherSuites,
	}
}

// rdpCompatibleCipherSuites is the cipher list mstsc / xfreerdp send. The
// RSA key-transport suites (RFC 5246 §A.5) come first because many RDP
// servers in the wild lack ECDHE (RFC 8422 §6); the ECDHE_RSA suites follow
// for hosts that support forward secrecy. All are TLS 1.2-and-below suites.
var rdpCompatibleCipherSuites = []uint16{
	ztls.TLS_RSA_WITH_AES_128_CBC_SHA,
	ztls.TLS_RSA_WITH_AES_256_CBC_SHA,
	ztls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	ztls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	ztls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	ztls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	ztls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	ztls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}

// runTLSHandshake wraps the existing TCP connection in a TLS client and
// drives the handshake under the supplied wall-clock budget. The deadline
// is cleared on success so subsequent reads/writes use their own deadlines.
func (c *Client) runTLSHandshake(cfg *ztls.Config, timeout time.Duration) (*ztls.Conn, error) {
	if err := c.conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("set TLS deadline: %w", err)
	}
	tlsConn := ztls.Client(c.conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear TLS deadline: %w", err)
	}
	return tlsConn, nil
}

// captureTLSState swaps c.conn for the TLS-wrapped conn and records the
// post-handshake state we'll need later: the peer's leaf certificate (used
// by CredSSP for pubKeyAuth binding) and the negotiated version/cipher
// (logged at debug for wire-trace correlation).
func (c *Client) captureTLSState(tlsConn *ztls.Conn) {
	state := tlsConn.ConnectionState()
	Logger.Debug().
		Str("version", tlsVersionString(state.Version)).
		Uint16("cipher", state.CipherSuite).
		Msg("tls: handshake complete")

	if len(state.PeerCertificates) > 0 {
		c.tlsCertificate = state.PeerCertificates[0].Raw
	}
	c.conn = tlsConn
	c.tlsEnabled = true
}

// tlsVersionString renders a TLS/SSL ProtocolVersion (RFC 5246 §A.1: the
// two-byte {major, minor} on the wire) for debug logging.
func tlsVersionString(version uint16) string {
	switch version {
	case 0x0002:
		return "SSL 2.0"
	case ztls.VersionSSL30:
		return "SSL 3.0"
	case ztls.VersionTLS10:
		return "TLS 1.0"
	case ztls.VersionTLS11:
		return "TLS 1.1"
	case ztls.VersionTLS12:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// isTLSRequired reports whether the negotiated protocol runs the RDP stream
// inside a TLS transport ([MS-RDPBCGR] §5.4.5.1): PROTOCOL_SSL and both
// CredSSP variants do; PROTOCOL_RDP (Standard RDP Security) does not.
func isTLSRequired(protocol uint32) bool {
	return protocol == PROTOCOL_SSL || protocol == PROTOCOL_HYBRID || protocol == PROTOCOL_HYBRID_EX
}
