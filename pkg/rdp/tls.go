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
	"crypto/tls"
	"fmt"
)

// StartTLS upgrades the connection to TLS
// @todo drop store []certs as we drop the cert validation
// so can at least inspect chain and such.
func (c *Client) StartTLS() error {
	fmt.Println("Starting TLS handshake...")

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // accepted risk; this isn't a offsec exercise. we take screenshots.
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12,
	}

	// Upgrade the connection to TLS
	tlsConn := tls.Client(c.conn, tlsConfig)

	// Perform TLS handshake
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("TLS handshake failed: %w", err)
	}

	// Swap in-flight no close, reopen.. @TODO needs profiling
	c.conn = tlsConn

	state := tlsConn.ConnectionState()
	fmt.Printf("TLS handshake completed!! Handshake details: Version=0x%04X, CipherSuite=0x%04X\n",
		state.Version, state.CipherSuite)

	return nil
}

// isTLSRequired checks if the server requires TLS based on negotiation
// @TODO implement this
func isTLSRequired(negotiatedProtocol uint32) bool {
	return negotiatedProtocol&PROTOCOL_SSL != 0 ||
		negotiatedProtocol&PROTOCOL_HYBRID != 0 ||
		negotiatedProtocol&PROTOCOL_HYBRID_EX != 0
}
