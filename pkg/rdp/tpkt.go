// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 x-stp

package rdp

import (
	"encoding/binary"
	"fmt"
	"io"
)

// TPKTHeader is the 4-byte TPKT framing header per RFC 1006 §6: version=3,
// reserved=0, length is the total packet size including the 4-byte header,
// big-endian.
type TPKTHeader struct {
	Version  uint8
	Reserved uint8
	Length   uint16
}

func NewTPKTHeader(payloadSize int) *TPKTHeader {
	return &TPKTHeader{
		Version: TPKTVersion,
		Length:  uint16(payloadSize + TPKTHeaderSize),
	}
}

func (h *TPKTHeader) WriteTo(w io.Writer) (int64, error) {
	if err := binary.Write(w, binary.BigEndian, h); err != nil {
		return 0, fmt.Errorf("failed to write TPKT header: %w", err)
	}
	return TPKTHeaderSize, nil
}

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

func (h *TPKTHeader) PayloadSize() int {
	return int(h.Length) - TPKTHeaderSize
}
