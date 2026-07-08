// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 x-stp

package rdp

import (
	"bytes"
	"crypto/rc4"
	"fmt"
	"net"
	"time"
)

// Client owns one RDP connection from initial TCP through screenshot.
//
// The connection state machine lives across four files in this package:
// connect.go (X.224 + TLS + CredSSP + MCS), secure.go (Standard RDP MAC +
// RC4 wrap), read.go (slow-path / fast-path receive + bitmap compositing),
// and this file (public surface + Screenshot orchestration).
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
	encryptor          *rc4.Cipher
	decryptor          *rc4.Cipher
	tlsEnabled         bool
	negotiatedProtocol uint32
	// useRdpEncryption is true when Standard RDP Security (RC4 + MAC) wraps
	// every data PDU; only set under PROTOCOL_RDP. TLS and CredSSP transports
	// leave it false.
	useRdpEncryption bool
	// shareID is captured from the server's Demand Active and threaded
	// through every share data PDU we send.
	shareID    uint32
	unreadData []byte
	screenshot []byte

	tlsCertificate []byte
	ntlmSession    *ntlmSession
	kerberosSess   *kerberosSession
	licenseSession *licenseSession
}

type ClientOptions struct {
	Timeout  time.Duration
	Username string
	Password string
	Domain   string

	// AnonymousNLA offers PROTOCOL_HYBRID in the X.224 NegReq even when no
	// credentials are supplied, then runs the CredSSP/NTLMSSP exchange with
	// the anonymous-message form ([MS-NLMP] §3.1.5.1.2): Type 1 with
	// NEGOTIATE_ANONYMOUS, Type 3 with empty NtChallengeResponse and a
	// 1-byte 0x00 LmChallengeResponse. Servers that allow null-session NLA
	// (RestrictedAdmin, LegacyAuthLevel relaxed, or anonymous-permitting
	// xrdp builds) will render the lock screen to us; everything else
	// rejects with STATUS_LOGON_FAILURE. When CredSSP rejects us we
	// reconnect once with PROTOCOL_RDP|SSL only so we don't downgrade
	// hosts that would have answered without NLA in the first place.
	AnonymousNLA bool

	// disableSSL forces the X.224 NegReq to advertise PROTOCOL_RDP only.
	// Set automatically after a server returns SSL_NOT_ALLOWED_BY_SERVER per
	// [MS-RDPBCGR] §2.2.1.2.2.
	disableSSL bool

	// disableNLA forces the X.224 NegReq to advertise PROTOCOL_RDP|PROTOCOL_SSL
	// only (no HYBRID). Set automatically after anonymous CredSSP fails so we
	// reattempt with the legacy non-NLA path.
	disableNLA bool

	// Kerberos, when true, makes CredSSP advertise the Kerberos V5 mech OID
	// (1.2.840.113554.1.2.2) in front of NTLMSSP and -- if a credential
	// cache is available -- emit an AP-REQ for SPN `TERMSRV/<host>` instead
	// of an NTLM Type 1 negotiate. On any Kerberos failure (no ccache, KDC
	// unreachable, server returns KRB-ERROR) the CredSSP path falls back to
	// the existing NTLM exchange so AD-bound and standalone hosts both work
	// from the same flag.
	Kerberos bool

	// KerberosCCache overrides the credential-cache path for Kerberos
	// auth. Empty string means "use $KRB5CCNAME or /tmp/krb5cc_<uid>".
	KerberosCCache string

	// KerberosConfig overrides the krb5.conf path. Empty means "$KRB5_CONFIG
	// or /etc/krb5.conf".
	KerberosConfig string
}

func DefaultClientOptions() *ClientOptions {
	return &ClientOptions{Timeout: 10 * time.Second}
}

func NewClient(target string, opts *ClientOptions) (*Client, error) {
	if opts == nil {
		opts = DefaultClientOptions()
	}
	conn, err := (&net.Dialer{Timeout: opts.Timeout}).Dial("tcp", target)
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

// Screenshot drives the post-handshake RDP state machine: MCS connect, MCS
// domain join, optional security exchange, Client Info PDU, the licensing
// dance, Demand/Confirm Active, finalisation, and bitmap compositing.
func (c *Client) Screenshot() ([]byte, error) {
	if err := c.sendMCSConnectInitial(); err != nil {
		return nil, err
	}
	if err := c.receiveMCSConnectResponse(); err != nil {
		return nil, err
	}
	// [MS-RDPBCGR] §1.3.1.1: MCS domain join precedes security exchange.
	if err := c.performMCSDomainJoin(); err != nil {
		return nil, err
	}
	if c.serverSecurityData != nil && c.serverSecurityData.EncryptionMethod != ENCRYPTION_METHOD_NONE {
		if err := c.sendSecurityExchange(); err != nil {
			return nil, err
		}
	}
	if err := c.sendClientInfoPDU(); err != nil {
		return nil, fmt.Errorf("client info PDU failed: %w", err)
	}
	if c.screenshot != nil {
		return c.screenshot, nil
	}
	return c.activateAndCapture()
}

// activationTimeout caps the total wall time spent waiting for the server to
// walk licensing / auto-detect chatter and reach Demand Active. Shared across
// all read attempts so a slow server can't multiply a per-read timeout into a
// worker-pinning stall.
const activationTimeout = 20 * time.Second

// activateAndCapture loops on server PDUs after Client Info: licensing,
// auto-detect / heartbeat / redirection chatter, and finally Demand Active.
// On Demand Active it sends Confirm Active + finalisation and hands off to
// receiveBitmapUpdate.
func (c *Client) activateAndCapture() ([]byte, error) {
	deadline := time.Now().Add(activationTimeout)
	for attempts := 0; attempts < 12 && time.Now().Before(deadline); attempts++ {
		c.conn.SetReadDeadline(deadline)
		secFlags, data, err := c.readSecurePayload()
		c.conn.SetReadDeadline(time.Time{})
		if err != nil {
			return nil, fmt.Errorf("failed to read server PDU: %w", err)
		}

		if secFlags&SEC_LICENSE_PKT != 0 {
			if err := c.handleLicensingPDU(data); err != nil {
				Logger.Warn().Err(err).Msg("licensing PDU handling")
			}
			continue
		}
		if secFlags&(SEC_AUTODETECT_REQ|SEC_HEARTBEAT|SEC_REDIRECTION_PKT) != 0 {
			Logger.Debug().Uint16("flags", secFlags).Msg("ignoring server PDU")
			continue
		}

		if len(data) >= 6 {
			hdr, err := parseShareControlHeader(bytes.NewReader(data))
			if err == nil && hdr.PDUType&0x0F == PDUTYPE_DEMANDACTIVEPDU {
				c.unreadData = data
				shareID, err := c.receiveDemandActive()
				if err != nil {
					return nil, fmt.Errorf("demand active failed: %w", err)
				}
				if err := c.sendConfirmActive(shareID); err != nil {
					return nil, fmt.Errorf("confirm active failed: %w", err)
				}
				if err := c.sendFinalizationPDUs(); err != nil {
					return nil, err
				}
				return c.receiveBitmapUpdate()
			}
		}

		dump := data
		if len(dump) > 32 {
			dump = dump[:32]
		}
		Logger.Debug().Uint16("flags", secFlags).Int("len", len(data)).Hex("head", dump).Msg("ignoring unexpected pre-active PDU")
	}
	return nil, fmt.Errorf("did not receive Demand Active PDU within %s", activationTimeout)
}

func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// GetNegotiatedProtocol returns the negotiated security protocol mask.
func (c *Client) GetNegotiatedProtocol() uint32 { return c.negotiatedProtocol }

// IsTLSEnabled reports whether TLS was negotiated.
func (c *Client) IsTLSEnabled() bool { return c.tlsEnabled }

// UpgradeTLS upgrades the connection to TLS using the supplied config.
func (c *Client) UpgradeTLS(config *TLSConfig) error { return c.upgradeTLSConnection(config) }

// TestCredSSPAuth runs CredSSP against the (already-TLS-upgraded) connection.
// Used by cmd/credssp-test as a single-target diagnostic harness.
func (c *Client) TestCredSSPAuth() error {
	if !c.tlsEnabled {
		return fmt.Errorf("TLS is required for CredSSP authentication")
	}
	return c.PerformCredSSPAuth()
}
