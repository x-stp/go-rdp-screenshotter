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
	"encoding/binary"
	"fmt"
	"io"
)

// TPKTHeader represents a TPKT packet header as defined in RFC 1006.
// TPKT is used to transport OSI TSAP over TCP.
//
// Header format (4 bytes):
//   - Version (1 byte): Always 3
//   - Reserved (1 byte): Always 0
//   - Length (2 bytes): Total packet length including header (big-endian)
type TPKTHeader struct {
	Version  uint8
	Reserved uint8
	Length   uint16 // Total length including this 4-byte header
}

// NewTPKTHeader creates a TPKT header for a payload of the given size.
// The length field will be set to payloadSize + 4 (header size.)
func NewTPKTHeader(payloadSize int) *TPKTHeader {
	return &TPKTHeader{
		Version:  TPKTVersion,
		Reserved: 0,
		Length:   uint16(payloadSize + TPKTHeaderSize),
	}
}

// WriteTo implements io.WriterTo interface for TPKTHeader.
// It writes the header in network byte order (big-endian.)
func (h *TPKTHeader) WriteTo(w io.Writer) (int64, error) {
	if err := binary.Write(w, binary.BigEndian, h); err != nil {
		return 0, fmt.Errorf("failed to write TPKT header: %w", err)
	}
	return TPKTHeaderSize, nil
}

// ReadTPKTHeader reads a TPKT header from the reader.
// Returns the header and any error encountered.
func ReadTPKTHeader(r io.Reader) (*TPKTHeader, error) {
	var h TPKTHeader
	if err := binary.Read(r, binary.BigEndian, &h); err != nil {
		return nil, fmt.Errorf("failed to read TPKT header: %w", err)
	}

	if h.Version != TPKTVersion {
		return nil, fmt.Errorf("invalid TPKT version: expected %d, got %d", TPKTVersion, h.Version)
	}

	if h.Length < TPKTHeaderSize {
		return nil, fmt.Errorf("invalid TPKT length: %d (must be at least %d)", h.Length, TPKTHeaderSize)
	}

	return &h, nil
}

// PayloadSize returns the size of the payload (excluding the TPKT header).
func (h *TPKTHeader) PayloadSize() int {
	return int(h.Length) - TPKTHeaderSize
}
