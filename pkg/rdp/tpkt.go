package rdp

import (
	"encoding/binary"
	"fmt"
	"io"
)

type TPKTHeader struct {
	Version  uint8
	Reserved uint8
	Length   uint16
}

func NewTPKTHeader(payloadSize int) *TPKTHeader {
	return &TPKTHeader{
		Version:  TPKTVersion,
		Reserved: 0,
		Length:   uint16(payloadSize + TPKTHeaderSize),
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
