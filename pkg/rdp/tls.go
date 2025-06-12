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
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package rdp

import (
	"fmt"
	"net"
	"time"

	ztls "github.com/zmap/zcrypto/tls"
)

// TLSConfig holds TLS configuration for RDP connections
type TLSConfig struct {
	// ServerName for SNI
	ServerName string

	// InsecureSkipVerify allows connections to servers with invalid certificates
	InsecureSkipVerify bool

	// Timeout for TLS handshake
	Timeout time.Duration
}

// DefaultTLSConfig returns a default TLS configuration for RDP
func DefaultTLSConfig(serverName string) *TLSConfig {
	return &TLSConfig{
		ServerName:         serverName,
		InsecureSkipVerify: true, // RDP servers often have self-signed certs
		Timeout:            10 * time.Second,
	}
}

// upgradeTLSConnection upgrades an existing TCP connection to TLS
func (c *Client) upgradeTLSConnection(tlsConfig *TLSConfig) error {
	// Extract hostname from target if not provided
	if tlsConfig.ServerName == "" {
		host, _, err := net.SplitHostPort(c.target)
		if err != nil {
			tlsConfig.ServerName = c.target
		} else {
			tlsConfig.ServerName = host
		}
	}

	// Create zcrypto TLS configuration
	config := &ztls.Config{
		ServerName:         tlsConfig.ServerName,
		InsecureSkipVerify: tlsConfig.InsecureSkipVerify,
		MinVersion:         ztls.VersionTLS10,
		MaxVersion:         ztls.VersionTLS12,
		CipherSuites: []uint16{
			// Include common cipher suites that RDP servers use
			ztls.TLS_RSA_WITH_AES_128_CBC_SHA,
			ztls.TLS_RSA_WITH_AES_256_CBC_SHA,
			ztls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			ztls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			ztls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			ztls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			ztls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			ztls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}

	// Set deadline for TLS handshake
	if err := c.conn.SetDeadline(time.Now().Add(tlsConfig.Timeout)); err != nil {
		return fmt.Errorf("failed to set TLS deadline: %w", err)
	}

	// Upgrade connection to TLS
	tlsConn := ztls.Client(c.conn, config)

	// Perform TLS handshake
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("TLS handshake failed: %w", err)
	}

	// Clear deadline
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("failed to clear TLS deadline: %w", err)
	}

	// Log TLS connection details
	state := tlsConn.ConnectionState()
	fmt.Printf("TLS connection established:\n")
	fmt.Printf("  Version: %s\n", tlsVersionString(state.Version))
	fmt.Printf("  Cipher Suite: 0x%04X\n", state.CipherSuite)
	fmt.Printf("  Server Name: %s\n", tlsConfig.ServerName)

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		fmt.Printf("  Certificate Subject: %s\n", cert.Subject)
		fmt.Printf("  Certificate Issuer: %s\n", cert.Issuer)
	}

	// Replace the connection with TLS connection
	c.conn = tlsConn
	c.tlsEnabled = true

	return nil
}

// tlsVersionString returns a human-readable TLS version string
func tlsVersionString(version uint16) string {
	switch version {
	case 0x0002:
		return "SSL 2.0" // solaris? RISC should be banned from the internet
	case ztls.VersionSSL30:
		return "SSL 3.0"
	case ztls.VersionTLS10:
		return "TLS 1.0"
	case ztls.VersionTLS11:
		return "TLS 1.1"
	case ztls.VersionTLS12:
		return "TLS 1.2"
	case 0x0304: // TLS 1.3 constant - likely fake RDP service as TLS1.3 and MS don't go hand in hand
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// isTLSRequired checks if the negotiated protocol requires TLS
func isTLSRequired(protocol uint32) bool {
	return protocol == PROTOCOL_SSL || protocol == PROTOCOL_HYBRID || protocol == PROTOCOL_HYBRID_EX
}
