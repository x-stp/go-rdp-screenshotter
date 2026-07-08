// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 x-stp

package bitmap

import (
	"bytes"
	"testing"
)

// Each case decodes a single short RLE_BITMAP_STREAM ([MS-RDPBCGR] §3.1.9.1)
// at a specific bpp and pins the byte-exact output. The vectors are minimal
// hand-crafted opcode patterns that exercise one opcode family each;
// regenerating them manually from the spec is straightforward, which is the
// point -- if a future port-tweak changes a branch, the relevant test fails
// in isolation rather than as a "screenshot looks weird" report.

func TestDecompressRLE_16bpp_BlackMega(t *testing.T) {
	// MEGA_MEGA_BLACK (0xFE) = opcode 0xE with implicit count=1; emit four
	// times to fill a 4x1 row of black pixels.
	got := DecompressRLE([]byte{0xFE, 0xFE, 0xFE, 0xFE}, 4, 1, 2)
	want := bytes.Repeat([]byte{0x00}, 8)
	if !bytes.Equal(got, want) {
		t.Fatalf("BLACK_MEGA: got % X want % X", got, want)
	}
}

func TestDecompressRLE_16bpp_WhiteMega(t *testing.T) {
	// MEGA_MEGA_WHITE (0xFD) = opcode 0xD; same shape as BLACK_MEGA but the
	// inner switch writes 0xFFFF instead of 0.
	got := DecompressRLE([]byte{0xFD, 0xFD, 0xFD, 0xFD}, 4, 1, 2)
	want := bytes.Repeat([]byte{0xFF}, 8)
	if !bytes.Equal(got, want) {
		t.Fatalf("WHITE_MEGA: got % X want % X", got, want)
	}
}

func TestDecompressRLE_16bpp_RegularColorRun(t *testing.T) {
	// REGULAR_COLOR_RUN: upper 3 bits = 011 -> top nibble 0x6 with count in
	// the low 5 bits. count=4, colour=0x1234 (LE).
	got := DecompressRLE([]byte{0x64, 0x34, 0x12}, 4, 1, 2)
	want := bytes.Repeat([]byte{0x34, 0x12}, 4)
	if !bytes.Equal(got, want) {
		t.Fatalf("REGULAR_COLOR_RUN/16bpp: got % X want % X", got, want)
	}
}

func TestDecompressRLE_16bpp_RegularBgRun(t *testing.T) {
	// REGULAR_BG_RUN on the first scanline writes literal zeros (no prevline
	// to copy from). Top nibble 0x0, count=4 in low 5 bits.
	got := DecompressRLE([]byte{0x04}, 4, 1, 2)
	want := bytes.Repeat([]byte{0x00}, 8)
	if !bytes.Equal(got, want) {
		t.Fatalf("REGULAR_BG_RUN/16bpp: got % X want % X", got, want)
	}
}

func TestDecompressRLE_24bpp_RegularColorRun(t *testing.T) {
	// REGULAR_COLOR_RUN at 24bpp: count=2, colour=BGR 0xCC 0xBB 0xAA (the
	// in-memory order matches the RDP wire order).
	got := DecompressRLE([]byte{0x62, 0xCC, 0xBB, 0xAA}, 2, 1, 3)
	want := []byte{0xCC, 0xBB, 0xAA, 0xCC, 0xBB, 0xAA}
	if !bytes.Equal(got, want) {
		t.Fatalf("REGULAR_COLOR_RUN/24bpp: got % X want % X", got, want)
	}
}

func TestDecompressRLE_32bpp_PlanePacked(t *testing.T) {
	// 32bpp uses the RDP 6.0 plane encoding ([MS-RDPBCGR] §3.1.9.2): leading
	// 0x10 marker, then four planes (alpha, red, green, blue) each as a
	// scanline literal+run stream. For a 2x1 image with BGRA = CC BB AA FF:
	//
	//   per-plane code 0x20 -> collen=2, replen=0
	//   followed by two literal bytes per plane.
	input := []byte{
		0x10,             // header
		0x20, 0xFF, 0xFF, // alpha plane
		0x20, 0xAA, 0xAA, // red plane
		0x20, 0xBB, 0xBB, // green plane
		0x20, 0xCC, 0xCC, // blue plane
	}
	got := DecompressRLE(input, 2, 1, 4)
	want := []byte{
		0xCC, 0xBB, 0xAA, 0xFF,
		0xCC, 0xBB, 0xAA, 0xFF,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("32bpp plane: got % X want % X", got, want)
	}
}

func TestDecompressRLE_8bpp_WhiteMega(t *testing.T) {
	// Smoke test for the 1-byte-per-pixel decode path.
	got := DecompressRLE([]byte{0xFD, 0xFD}, 2, 1, 1)
	want := []byte{0xFF, 0xFF}
	if !bytes.Equal(got, want) {
		t.Fatalf("8bpp WHITE_MEGA: got % X want % X", got, want)
	}
}

func TestDecompressRLE_RejectsInvalidArgs(t *testing.T) {
	cases := []struct {
		name             string
		w, h, bpp        int
		input            []byte
		wantNil          bool
		wantOutputLength int
	}{
		{"negative width", -1, 1, 2, []byte{0xFE}, true, 0},
		{"zero height", 4, 0, 2, []byte{0xFE}, true, 0},
		{"unsupported bpp", 4, 1, 5, []byte{0xFE}, true, 0},
		{"zero bpp", 4, 1, 0, []byte{0xFE}, true, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DecompressRLE(tc.input, tc.w, tc.h, tc.bpp)
			if tc.wantNil && got != nil {
				t.Fatalf("expected nil, got % X", got)
			}
		})
	}
}

func TestDecompressRLE_32bpp_RejectsBadHeader(t *testing.T) {
	// 32bpp plane encoding requires a 0x10 marker byte. Anything else -> nil.
	if got := DecompressRLE([]byte{0x00, 0x20, 0xFF}, 1, 1, 4); got != nil {
		t.Fatalf("32bpp without 0x10 header should fail, got % X", got)
	}
}
