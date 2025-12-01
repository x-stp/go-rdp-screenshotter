package rdp

import (
	"crypto/sha256"
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
	fmt.Printf("\n=== UPGRADING CONNECTION TO TLS ===\n")

	if tlsConfig.ServerName == "" {
		host, _, err := net.SplitHostPort(c.target)
		if err != nil {
			tlsConfig.ServerName = c.target
		} else {
			tlsConfig.ServerName = host
		}
	}

	fmt.Printf("TLS Configuration:\n")
	fmt.Printf("  Server Name: %s\n", tlsConfig.ServerName)
	fmt.Printf("  Skip Verify: %v\n", tlsConfig.InsecureSkipVerify)
	fmt.Printf("  Timeout: %v\n", tlsConfig.Timeout)

	config := &ztls.Config{
		ServerName:         tlsConfig.ServerName,
		InsecureSkipVerify: tlsConfig.InsecureSkipVerify,
		MinVersion:         ztls.VersionTLS10,
		MaxVersion:         ztls.VersionTLS12,
		CipherSuites: []uint16{
			ztls.TLS_RSA_WITH_RC4_128_SHA,
			ztls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			ztls.TLS_RSA_WITH_AES_128_CBC_SHA,
			ztls.TLS_RSA_WITH_AES_256_CBC_SHA,
			ztls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			ztls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			ztls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			ztls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			ztls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			ztls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			ztls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			ztls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			ztls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			ztls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			ztls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			ztls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			ztls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			ztls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			ztls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			ztls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	}

	if err := c.conn.SetDeadline(time.Now().Add(tlsConfig.Timeout)); err != nil {
		return fmt.Errorf("failed to set TLS deadline: %w", err)
	}

	tlsConn := ztls.Client(c.conn, config)

	fmt.Printf("\nPerforming TLS handshake...\n")
	if err := tlsConn.Handshake(); err != nil {
		fmt.Printf("TLS handshake failed: %v\n", err)
		return fmt.Errorf("TLS handshake failed: %w", err)
	}

	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("failed to clear TLS deadline: %w", err)
	}

	state := tlsConn.ConnectionState()
	fmt.Printf("\nTLS handshake completed successfully!\n")
	fmt.Printf("TLS Connection Details:\n")
	fmt.Printf("  Version: %s\n", tlsVersionString(state.Version))
	fmt.Printf("  Cipher Suite: 0x%04X (%s)\n", state.CipherSuite, cipherSuiteName(state.CipherSuite))
	fmt.Printf("  Server Name: %s\n", tlsConfig.ServerName)
	fmt.Printf("  Handshake Complete: %v\n", state.HandshakeComplete)
	fmt.Printf("  NegotiatedProtocol: %q\n", state.NegotiatedProtocol)
	fmt.Printf("  NegotiatedProtocolIsMutual: %v\n", state.NegotiatedProtocolIsMutual)

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		fmt.Printf("\nServer Certificate:\n")
		fmt.Printf("  Subject: %s\n", cert.Subject)
		fmt.Printf("  Issuer: %s\n", cert.Issuer)
		fmt.Printf("  Serial Number: %s\n", cert.SerialNumber)
		fmt.Printf("  Not Before: %s\n", cert.NotBefore)
		fmt.Printf("  Not After: %s\n", cert.NotAfter)
		fmt.Printf("  DNS Names: %v\n", cert.DNSNames)
		fmt.Printf("  IP Addresses: %v\n", cert.IPAddresses)
	}

	if len(state.PeerCertificates) > 0 {
		c.tlsCertificate = state.PeerCertificates[0].Raw
		fmt.Printf("\nStored server certificate for NLA (%d bytes)\n", len(c.tlsCertificate))
		fmt.Printf("Certificate SHA256: ")
		hash := sha256.Sum256(c.tlsCertificate)
		for i, b := range hash {
			if i > 0 {
				fmt.Print(":")
			}
			fmt.Printf("%02x", b)
		}
		fmt.Println()
	}

	c.conn = tlsConn
	c.tlsEnabled = true

	fmt.Printf("\nTLS upgrade completed successfully\n")
	fmt.Printf("======================================\n\n")

	return nil
}

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

func isTLSRequired(protocol uint32) bool {
	return protocol == PROTOCOL_SSL || protocol == PROTOCOL_HYBRID || protocol == PROTOCOL_HYBRID_EX
}

func cipherSuiteName(suite uint16) string {
	switch suite {
	case ztls.TLS_RSA_WITH_AES_128_CBC_SHA:
		return "RSA_WITH_AES_128_CBC_SHA"
	case ztls.TLS_RSA_WITH_AES_256_CBC_SHA:
		return "RSA_WITH_AES_256_CBC_SHA"
	case ztls.TLS_RSA_WITH_AES_128_GCM_SHA256:
		return "RSA_WITH_AES_128_GCM_SHA256"
	case ztls.TLS_RSA_WITH_AES_256_GCM_SHA384:
		return "RSA_WITH_AES_256_GCM_SHA384"
	case ztls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		return "ECDHE_RSA_WITH_AES_128_CBC_SHA"
	case ztls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case ztls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case ztls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	default:
		return "Unknown"
	}
}
