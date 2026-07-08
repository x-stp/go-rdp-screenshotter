// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 x-stp

// Package per implements the subset of ITU-T X.691 PACKED ENCODING RULES
// (PER, aligned variant) needed by RDP's MCS layer ([MS-RDPBCGR] §2.2.1.3).
//
// Three helpers are enough for everything we send / receive:
//
//   - WriteLength / ReadLength: aligned length determinant (X.691 §10.9).
//     Short form (n < 128) is one byte; long form (128 <= n < 16384) is two
//     bytes with the high bit set. The fragmented form (n >= 16384) is not
//     supported -- MCS PDUs never reach that size in practice and the
//     encoders panic if they're asked to.
//   - WriteInteger: unconstrained PER INTEGER, length determinant followed
//     by the minimum number of big-endian octets.
//   - WriteInteger16 / ReadInteger16: constrained 16-bit PER INTEGER with a
//     lower bound (X.691 §10.5). The wire encoding is (value - min) as a
//     big-endian uint16; reads add min back.
package per

import (
	"encoding/binary"
	"fmt"
	"io"
)

// MaxShortLength is the largest length representable in PER short form
// (one byte). Lengths up to MaxLongLength use two bytes.
const (
	MaxShortLength = 0x7F   // 127
	MaxLongLength  = 0x3FFF // 16383 -- fragmented form starts above this
)

// WriteLength writes a PER aligned length determinant per X.691 §10.9.
// Panics for length < 0 or length > MaxLongLength: the fragmented form
// (multiple 16K chunks) is not implemented because no MCS PDU we emit
// reaches that size.
func WriteLength(w io.Writer, length int) {
	if length < 0 || length > MaxLongLength {
		panic(fmt.Sprintf("per: length %d out of representable range [0, %d]", length, MaxLongLength))
	}
	if length > MaxShortLength {
		binary.Write(w, binary.BigEndian, uint16(length|0x8000))
		return
	}
	binary.Write(w, binary.BigEndian, uint8(length))
}

// ReadLength reads a PER aligned length determinant and returns the length
// plus the number of bytes consumed (1 or 2).
func ReadLength(r io.Reader) (length, n int, err error) {
	var first [1]byte
	if _, err = io.ReadFull(r, first[:]); err != nil {
		return 0, 0, err
	}
	if first[0]&0x80 == 0 {
		return int(first[0]), 1, nil
	}
	var second [1]byte
	if _, err = io.ReadFull(r, second[:]); err != nil {
		return 0, 1, err
	}
	return int(first[0]&0x7F)<<8 | int(second[0]), 2, nil
}

// WriteInteger writes an unconstrained PER INTEGER: a length determinant
// followed by the minimum number of big-endian octets.
func WriteInteger(w io.Writer, value uint32) {
	switch {
	case value <= 0xFF:
		WriteLength(w, 1)
		binary.Write(w, binary.BigEndian, uint8(value))
	case value <= 0xFFFF:
		WriteLength(w, 2)
		binary.Write(w, binary.BigEndian, uint16(value))
	default:
		WriteLength(w, 4)
		binary.Write(w, binary.BigEndian, value)
	}
}

// WriteInteger16 writes a constrained 16-bit PER INTEGER as a big-endian
// (value - min) uint16. Used for MCS user / channel IDs.
func WriteInteger16(w io.Writer, value, min uint16) {
	binary.Write(w, binary.BigEndian, value-min)
}

// ReadInteger16 reads a constrained 16-bit PER INTEGER and adds min back.
func ReadInteger16(r io.Reader, min uint16) (uint16, error) {
	var raw [2]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(raw[:]) + min, nil
}
