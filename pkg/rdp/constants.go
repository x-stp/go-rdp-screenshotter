// RDP Screenshotter - Capture screenshots from RDP servers
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

// RDP Protocol Constants with RFC/MS-RDPBCGR references

// Default RDP port as per MS-RDPBCGR section 2.2.1.1
const DefaultRDPPort = 3389

// TPKT Header Constants (RFC 1006)
const (
	TPKTVersion    = 3 // RFC 1006 section 6
	TPKTHeaderSize = 4 // Version(1) + Reserved(1) + Length(2)
)

// X.224 Connection Request/Response Constants (ITU-T X.224)
const (
	// TPDU Codes (ITU-T X.224 Table 13)
	X224_TPDU_CONNECTION_REQUEST = 0xE0 // CR - Connection Request
	X224_TPDU_CONNECTION_CONFIRM = 0xD0 // CC - Connection Confirm
	X224_TPDU_DATA               = 0xF0 // DT - Data

	// Fixed header size for CR TPDU: LI(1) + Code(1) + DST-REF(2) + SRC-REF(2) + Class(1)
	X224_CR_FIXED_SIZE = 7
)

// MCS Protocol Constants (ITU-T T.125)
const (
	// MCS PDU Types (T.125 section 11.1)
	MCS_TYPE_CONNECT_INITIAL  = 0x7F65
	MCS_TYPE_CONNECT_RESPONSE = 0x7F66

	// Channel IDs
	MCS_CHANNEL_GLOBAL = 1003 // MS-RDPBCGR section 2.2.1.3.2
	MCS_CHANNEL_USER   = 1001 // User channel base

	// MCS PDU Types for domain operations
	MCS_ERECT_DOMAIN_REQUEST = 0x04
	MCS_ATTACH_USER_REQUEST  = 0x10
	MCS_ATTACH_USER_CONFIRM  = 0x11
	MCS_CHANNEL_JOIN_REQUEST = 0x14
	MCS_CHANNEL_JOIN_CONFIRM = 0x15
	MCS_SEND_DATA_REQUEST    = 0x1A
	MCS_SEND_DATA_INDICATION = 0x1B
)

// T.124 GCC Constants
const (
	// Conference Create Request/Response
	GCC_CONFERENCE_CREATE_REQUEST  = 0x00
	GCC_CONFERENCE_CREATE_RESPONSE = 0x14
)

// RDP Protocol Constants (MS-RDPBCGR)
const (
	// RDP PDU Types (MS-RDPBCGR section 2.2.8.1.1.1.1)
	PDUTYPE_DEMANDACTIVEPDU  = 0x11
	PDUTYPE_CONFIRMACTIVEPDU = 0x13
	PDUTYPE_DEACTIVATEALLPDU = 0x16
	PDUTYPE_DATAPDU          = 0x17
	PDUTYPE_SERVER_REDIR_PKT = 0x1A

	// Data PDU Types (MS-RDPBCGR section 2.2.8.1.1.1.2)
	PDUTYPE2_UPDATE                      = 0x02
	PDUTYPE2_CONTROL                     = 0x14
	PDUTYPE2_POINTER                     = 0x1B
	PDUTYPE2_INPUT                       = 0x1C
	PDUTYPE2_SYNCHRONIZE                 = 0x1F
	PDUTYPE2_REFRESH_RECT                = 0x21
	PDUTYPE2_PLAY_SOUND                  = 0x22
	PDUTYPE2_SUPPRESS_OUTPUT             = 0x23
	PDUTYPE2_SHUTDOWN_REQUEST            = 0x24
	PDUTYPE2_SHUTDOWN_DENIED             = 0x25
	PDUTYPE2_SAVE_SESSION_INFO           = 0x26
	PDUTYPE2_FONTLIST                    = 0x27
	PDUTYPE2_FONTMAP                     = 0x28
	PDUTYPE2_SET_KEYBOARD_INDICATORS     = 0x29
	PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST = 0x2B
	PDUTYPE2_BITMAPCACHE_ERROR_PDU       = 0x2C
	PDUTYPE2_SET_KEYBOARD_IME_STATUS     = 0x2D
	PDUTYPE2_OFFSCRCACHE_ERROR_PDU       = 0x2E
	PDUTYPE2_SET_ERROR_INFO_PDU          = 0x2F
	PDUTYPE2_DRAWNINEGRID_ERROR_PDU      = 0x30
	PDUTYPE2_DRAWGDIPLUS_ERROR_PDU       = 0x31
	PDUTYPE2_ARC_STATUS_PDU              = 0x32
	PDUTYPE2_STATUS_INFO_PDU             = 0x36
	PDUTYPE2_MONITOR_LAYOUT_PDU          = 0x37

	// Update PDU Types (MS-RDPBCGR section 2.2.9.1.1.3.1.1)
	UPDATETYPE_ORDERS      = 0x0000
	UPDATETYPE_BITMAP      = 0x0001
	UPDATETYPE_PALETTE     = 0x0002
	UPDATETYPE_SYNCHRONIZE = 0x0003
)

// Bitmap Compression Types
const (
	BITMAP_COMPRESSION_NONE = 0x0000
	BITMAP_COMPRESSION      = 0x0001
)

// RDP Security Constants (MS-RDPBCGR)
const (
	// Encryption Methods (MS-RDPBCGR section 2.2.1.4.3)
	ENCRYPTION_METHOD_NONE   = 0x00000000
	ENCRYPTION_METHOD_40BIT  = 0x00000001
	ENCRYPTION_METHOD_128BIT = 0x00000002
	ENCRYPTION_METHOD_56BIT  = 0x00000008
	ENCRYPTION_METHOD_FIPS   = 0x00000010

	// Encryption Levels (MS-RDPBCGR section 2.2.1.4.3)
	ENCRYPTION_LEVEL_NONE              = 0x00000000
	ENCRYPTION_LEVEL_LOW               = 0x00000001
	ENCRYPTION_LEVEL_CLIENT_COMPATIBLE = 0x00000002
	ENCRYPTION_LEVEL_HIGH              = 0x00000003
	ENCRYPTION_LEVEL_FIPS              = 0x00000004
)

// Capability Set Types (MS-RDPBCGR section 2.2.1.13.1)
const (
	CAPSTYPE_GENERAL                 = 0x0001
	CAPSTYPE_BITMAP                  = 0x0002
	CAPSTYPE_ORDER                   = 0x0003
	CAPSTYPE_BITMAPCACHE             = 0x0004
	CAPSTYPE_CONTROL                 = 0x0005
	CAPSTYPE_ACTIVATION              = 0x0007
	CAPSTYPE_POINTER                 = 0x0008
	CAPSTYPE_SHARE                   = 0x0009
	CAPSTYPE_COLORCACHE              = 0x000A
	CAPSTYPE_SOUND                   = 0x000C
	CAPSTYPE_INPUT                   = 0x000D
	CAPSTYPE_FONT                    = 0x000E
	CAPSTYPE_BRUSH                   = 0x000F
	CAPSTYPE_GLYPHCACHE              = 0x0010
	CAPSTYPE_OFFSCREENCACHE          = 0x0011
	CAPSTYPE_BITMAPCACHE_HOSTSUPPORT = 0x0012
	CAPSTYPE_BITMAPCACHE_REV2        = 0x0013
	CAPSTYPE_VIRTUALCHANNEL          = 0x0014
	CAPSTYPE_DRAWNINEGRIDCACHE       = 0x0015
	CAPSTYPE_DRAWGDIPLUS             = 0x0016
	CAPSTYPE_RAIL                    = 0x0017
	CAPSTYPE_WINDOW                  = 0x0018
	CAPSTYPE_COMPDESK                = 0x0019
	CAPSTYPE_MULTIFRAGMENTUPDATE     = 0x001A
	CAPSTYPE_LARGE_POINTER           = 0x001B
	CAPSTYPE_SURFACE_COMMANDS        = 0x001C
	CAPSTYPE_BITMAP_CODECS           = 0x001D
)
