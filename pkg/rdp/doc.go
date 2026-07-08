// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 x-stp

// Package rdp implements a small Remote Desktop Protocol client whose only
// purpose is to walk an RDP connection far enough to capture the first
// server-supplied bitmap update and return it as a PNG.
//
// # Connection sequence
//
// The client follows [MS-RDPBCGR] §1.3.1.1:
//
//  1. X.224 negotiation; on RDP_NEG_FAILURE/SSL_NOT_ALLOWED reconnect with
//     PROTOCOL_RDP-only.
//  2. TLS upgrade (zcrypto/tls) when negotiated.
//  3. CredSSP/NLA via NTLM in SPNEGO when negotiated.
//  4. MCS Connect Initial / Connect Response.
//  5. MCS domain join (Erect Domain, Attach User, Channel Join).
//  6. Standard RDP security exchange (raw RSA per [MS-RDPBCGR] §5.3.4) when the
//     server selected ENCRYPTION_METHOD_*.
//  7. Client Info PDU with SEC_INFO_PKT.
//  8. Full licensing dance per MS-RDPELE: NEW_LICENSE_REQUEST,
//     PLATFORM_CHALLENGE_RESPONSE, NEW_LICENSE.
//  9. Demand Active / Confirm Active capability negotiation.
//  10. Synchronize / Control / Font List finalisation.
//  11. Refresh Rect, then composite incoming bitmap rectangles into a 1024x768
//     canvas.
//
// # Library use
//
//	client, err := rdp.NewClient("1.2.3.4:3389", &rdp.ClientOptions{Timeout: 15*time.Second})
//	if err != nil { return err }
//	defer client.Close()
//	png, err := client.Screenshot()
//
// Logging is via the package zerolog.Logger exposed as rdp.Logger; tune via
// SetLogLevel, SetLogger or SetLogOutput. Default level is INFO.
//
// # Limitations
//
// See TODO.md in the repo root. Headlines: no Kerberos in CredSSP, no
// RemoteFX or Graphics Pipeline, no dynamic virtual channels.
package rdp
