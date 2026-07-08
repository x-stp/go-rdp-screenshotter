// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2024-2026 x-stp

package bitmap

// RDP bitmap RLE decompression per [MS-RDPBCGR] §3.1.9.1 +
// §2.2.9.1.1.3.1.2.4 (RLE_BITMAP_STREAM). Ported with adaptations from
// github.com/tomatome/grdp (core/rle.go, GPL-3.0).
// Output bytes are little-endian raw pixels, matching the format expected
// by ConvertBitmapRect's convert16/24/32BitToRGBA helpers.

import "encoding/binary"

// DecompressRLE expands a compressed RDP bitmap rectangle. bpp is bytes per
// pixel (1, 2, 3, or 4). Returns nil on failure.
func DecompressRLE(input []byte, width, height, bytesPerPixel int) []byte {
	if width <= 0 || height <= 0 || bytesPerPixel <= 0 {
		return nil
	}
	size := width * height * bytesPerPixel
	out := make([]byte, size)
	switch bytesPerPixel {
	case 1:
		if !decompress1(out, width, height, input) {
			return nil
		}
	case 2:
		if !decompress2(out, width, height, input) {
			return nil
		}
	case 3:
		if !decompress3(out, width, height, input) {
			return nil
		}
	case 4:
		if !decompress4(out, width, height, input) {
			return nil
		}
	default:
		return nil
	}
	return out
}

func cval(p *[]byte) int {
	if len(*p) == 0 {
		return 0
	}
	a := int((*p)[0])
	*p = (*p)[1:]
	return a
}

// parseRLEHeader decodes one RLE_BITMAP_STREAM command per [MS-RDPBCGR]
// §3.1.9.1.4 and resolves count to its final value (running-length escalation
// for FILL/MIX runs). The control byte's upper nibble selects the encoding
// family (REGULAR / LITE / MEGA) and the lower bits encode count or opcode.
//
// Returns the canonical opcode (0..0xa, with the LITE bias removed) and the
// resolved pixel count. Per-bpp callers still have to consume any colour /
// mix / mask bytes themselves -- those payload widths differ by bpp.
func parseRLEHeader(input *[]byte) (opcode, count int) {
	code := cval(input)
	opcode = code >> 4
	var offset int
	switch opcode {
	case 0xc, 0xd, 0xe: // LITE: count4 in low nibble, offset=16
		opcode -= 6
		count = code & 0xf
		offset = 16
	case 0xf: // MEGA: opcode in low nibble
		opcode = code & 0xf
		switch {
		case opcode < 9:
			count = cval(input) | (cval(input) << 8)
		case opcode < 0xb:
			count = 8
		default:
			count = 1
		}
		offset = 0
	default: // REGULAR: opcode in upper 3 bits, count in low 5
		opcode >>= 1
		count = code & 0x1f
		offset = 32
	}
	if offset != 0 {
		isfillormix := opcode == 2 || opcode == 7
		switch {
		case count == 0 && isfillormix:
			count = cval(input) + 1
		case count == 0:
			count = cval(input) + offset
		case isfillormix:
			count <<= 3
		}
	}
	return opcode, count
}

// applySpecialFGBG handles the SPECIAL_FGBG_1 (opcode 9) and _2 (opcode 0xa)
// rewrites: both collapse to opcode 2 (FGBG_IMAGE) with a fixed pre-set mask
// per [MS-RDPBCGR] §3.1.9.1.4. Called after parseRLEHeader if the first
// per-bpp setup switch sees opcode 9 or 0xa.
func applySpecialFGBG(opcode int) (newOpcode int, mask, fomMask uint8) {
	switch opcode {
	case 9:
		return 2, 0x03, 3
	case 0xa:
		return 2, 0x05, 5
	}
	return opcode, 0, 0
}

func cval2le(p *[]byte) uint16 {
	if len(*p) < 2 {
		return 0
	}
	v := binary.LittleEndian.Uint16((*p)[:2])
	*p = (*p)[2:]
	return v
}

func cval3(p *[]byte) [3]uint8 {
	var v [3]uint8
	if len(*p) < 3 {
		return v
	}
	v[0], v[1], v[2] = (*p)[0], (*p)[1], (*p)[2]
	*p = (*p)[3:]
	return v
}

func repeat(action func(), count *int, x *int, width int) {
	for (*count & ^0x7) != 0 && (*x+8) < width {
		for range 8 {
			action()
			*count--
			*x++
		}
	}
	for *count > 0 && *x < width {
		action()
		*count--
		*x++
	}
}

func decompress1(out []byte, width, height int, input []byte) bool {
	var (
		prevline, line, count int
		x                     = width
		opcode                int
		lastopcode            int8 = -1
		insertmix, bicolour   bool
		mixmask, mask         uint8
		colour1, colour2      uint8
		mix                   uint8 = 0xff
		fomMask               uint8
	)
	for len(input) > 0 {
		fomMask = 0
		opcode, count = parseRLEHeader(&input)
		switch opcode {
		case 0:
			if lastopcode == int8(opcode) && !(x == width && prevline == 0) {
				insertmix = true
			}
		case 8:
			colour1 = uint8(cval(&input))
			colour2 = uint8(cval(&input))
		case 3:
			colour2 = uint8(cval(&input))
		case 6, 7:
			mix = uint8(cval(&input))
			opcode -= 5
		case 9, 0xa:
			opcode, mask, fomMask = applySpecialFGBG(opcode)
		}
		lastopcode = int8(opcode)
		mixmask = 0
		for count > 0 {
			if x >= width {
				if height <= 0 {
					return false
				}
				x = 0
				height--
				prevline = line
				line = height * width
			}
			switch opcode {
			case 0:
				if insertmix {
					if prevline == 0 {
						out[x+line] = mix
					} else {
						out[x+line] = out[prevline+x] ^ mix
					}
					insertmix = false
					count--
					x++
				}
				if prevline == 0 {
					repeat(func() { out[x+line] = 0 }, &count, &x, width)
				} else {
					repeat(func() { out[x+line] = out[prevline+x] }, &count, &x, width)
				}
			case 1:
				if prevline == 0 {
					repeat(func() { out[x+line] = mix }, &count, &x, width)
				} else {
					repeat(func() { out[x+line] = out[prevline+x] ^ mix }, &count, &x, width)
				}
			case 2:
				if prevline == 0 {
					repeat(func() {
						mixmask <<= 1
						if mixmask == 0 {
							mask = fomMask
							if fomMask == 0 {
								mask = uint8(cval(&input))
								mixmask = 1
							}
						}
						if mask&mixmask != 0 {
							out[x+line] = mix
						} else {
							out[x+line] = 0
						}
					}, &count, &x, width)
				} else {
					repeat(func() {
						mixmask <<= 1
						if mixmask == 0 {
							mask = fomMask
							if fomMask == 0 {
								mask = uint8(cval(&input))
								mixmask = 1
							}
						}
						if mask&mixmask != 0 {
							out[x+line] = out[prevline+x] ^ mix
						} else {
							out[x+line] = out[prevline+x]
						}
					}, &count, &x, width)
				}
			case 3:
				repeat(func() { out[x+line] = colour2 }, &count, &x, width)
			case 4:
				repeat(func() { out[x+line] = uint8(cval(&input)) }, &count, &x, width)
			case 8:
				repeat(func() {
					if bicolour {
						out[x+line] = colour2
						bicolour = false
					} else {
						out[x+line] = colour1
						bicolour = true
						count++
					}
				}, &count, &x, width)
			case 0xd:
				repeat(func() { out[x+line] = 0xff }, &count, &x, width)
			case 0xe:
				repeat(func() { out[x+line] = 0 }, &count, &x, width)
			default:
				return false
			}
		}
	}
	return true
}

func decompress2(out []byte, width, height int, input []byte) bool {
	pixels := make([]uint16, width*height)
	var (
		prevline, line, count int
		x                     = width
		opcode                int
		lastopcode            = -1
		insertmix, bicolour   bool
		mixmask, mask         uint8
		colour1, colour2      uint16
		mix                   uint16 = 0xffff
		fomMask               uint8
	)
	for len(input) > 0 {
		fomMask = 0
		opcode, count = parseRLEHeader(&input)
		switch opcode {
		case 0:
			if lastopcode == opcode && !(x == width && prevline == 0) {
				insertmix = true
			}
		case 8:
			colour1 = cval2le(&input)
			colour2 = cval2le(&input)
		case 3:
			colour2 = cval2le(&input)
		case 6, 7:
			mix = cval2le(&input)
			opcode -= 5
		case 9, 0xa:
			opcode, mask, fomMask = applySpecialFGBG(opcode)
		}
		lastopcode = opcode
		mixmask = 0
		for count > 0 {
			if x >= width {
				if height <= 0 {
					return false
				}
				x = 0
				height--
				prevline = line
				line = height * width
			}
			switch opcode {
			case 0:
				if insertmix {
					if prevline == 0 {
						pixels[x+line] = mix
					} else {
						pixels[x+line] = pixels[prevline+x] ^ mix
					}
					insertmix = false
					count--
					x++
				}
				if prevline == 0 {
					repeat(func() { pixels[x+line] = 0 }, &count, &x, width)
				} else {
					repeat(func() { pixels[x+line] = pixels[prevline+x] }, &count, &x, width)
				}
			case 1:
				if prevline == 0 {
					repeat(func() { pixels[x+line] = mix }, &count, &x, width)
				} else {
					repeat(func() { pixels[x+line] = pixels[prevline+x] ^ mix }, &count, &x, width)
				}
			case 2:
				if prevline == 0 {
					repeat(func() {
						mixmask <<= 1
						if mixmask == 0 {
							mask = fomMask
							if fomMask == 0 {
								mask = uint8(cval(&input))
								mixmask = 1
							}
						}
						if mask&mixmask != 0 {
							pixels[x+line] = mix
						} else {
							pixels[x+line] = 0
						}
					}, &count, &x, width)
				} else {
					repeat(func() {
						mixmask <<= 1
						if mixmask == 0 {
							mask = fomMask
							if fomMask == 0 {
								mask = uint8(cval(&input))
								mixmask = 1
							}
						}
						if mask&mixmask != 0 {
							pixels[x+line] = pixels[prevline+x] ^ mix
						} else {
							pixels[x+line] = pixels[prevline+x]
						}
					}, &count, &x, width)
				}
			case 3:
				repeat(func() { pixels[x+line] = colour2 }, &count, &x, width)
			case 4:
				repeat(func() { pixels[x+line] = cval2le(&input) }, &count, &x, width)
			case 8:
				repeat(func() {
					if bicolour {
						pixels[x+line] = colour2
						bicolour = false
					} else {
						pixels[x+line] = colour1
						bicolour = true
						count++
					}
				}, &count, &x, width)
			case 0xd:
				repeat(func() { pixels[x+line] = 0xffff }, &count, &x, width)
			case 0xe:
				repeat(func() { pixels[x+line] = 0 }, &count, &x, width)
			default:
				return false
			}
		}
	}
	for i, v := range pixels {
		binary.LittleEndian.PutUint16(out[i*2:], v)
	}
	return true
}

func decompress3(out []byte, width, height int, input []byte) bool {
	var (
		prevline, line, count int
		opcode                int
		x                     = width
		lastopcode            = -1
		insertmix, bicolour   bool
		mixmask, mask         uint8
		colour1               = [3]uint8{}
		colour2               = [3]uint8{}
		mix                   = [3]uint8{0xff, 0xff, 0xff}
		fomMask               uint8
	)
	for len(input) > 0 {
		fomMask = 0
		opcode, count = parseRLEHeader(&input)
		switch opcode {
		case 0:
			if lastopcode == opcode && !(x == width && prevline == 0) {
				insertmix = true
			}
		case 8:
			colour1 = cval3(&input)
			colour2 = cval3(&input)
		case 3:
			colour2 = cval3(&input)
		case 6, 7:
			mix = cval3(&input)
			opcode -= 5
		case 9, 0xa:
			opcode, mask, fomMask = applySpecialFGBG(opcode)
		}
		lastopcode = opcode
		mixmask = 0
		for count > 0 {
			if x >= width {
				if height <= 0 {
					return false
				}
				x = 0
				height--
				prevline = line
				line = height * width * 3
			}
			switch opcode {
			case 0:
				if insertmix {
					if prevline == 0 {
						out[3*x+line] = mix[0]
						out[3*x+line+1] = mix[1]
						out[3*x+line+2] = mix[2]
					} else {
						out[3*x+line] = out[prevline+3*x] ^ mix[0]
						out[3*x+line+1] = out[prevline+3*x+1] ^ mix[1]
						out[3*x+line+2] = out[prevline+3*x+2] ^ mix[2]
					}
					insertmix = false
					count--
					x++
				}
				if prevline == 0 {
					repeat(func() {
						out[3*x+line] = 0
						out[3*x+line+1] = 0
						out[3*x+line+2] = 0
					}, &count, &x, width)
				} else {
					repeat(func() {
						out[3*x+line] = out[prevline+3*x]
						out[3*x+line+1] = out[prevline+3*x+1]
						out[3*x+line+2] = out[prevline+3*x+2]
					}, &count, &x, width)
				}
			case 1:
				if prevline == 0 {
					repeat(func() {
						out[3*x+line] = mix[0]
						out[3*x+line+1] = mix[1]
						out[3*x+line+2] = mix[2]
					}, &count, &x, width)
				} else {
					repeat(func() {
						out[3*x+line] = out[prevline+3*x] ^ mix[0]
						out[3*x+line+1] = out[prevline+3*x+1] ^ mix[1]
						out[3*x+line+2] = out[prevline+3*x+2] ^ mix[2]
					}, &count, &x, width)
				}
			case 2:
				if prevline == 0 {
					repeat(func() {
						mixmask <<= 1
						if mixmask == 0 {
							mask = fomMask
							if fomMask == 0 {
								mask = uint8(cval(&input))
								mixmask = 1
							}
						}
						if mask&mixmask != 0 {
							out[3*x+line] = mix[0]
							out[3*x+line+1] = mix[1]
							out[3*x+line+2] = mix[2]
						} else {
							out[3*x+line] = 0
							out[3*x+line+1] = 0
							out[3*x+line+2] = 0
						}
					}, &count, &x, width)
				} else {
					repeat(func() {
						mixmask <<= 1
						if mixmask == 0 {
							mask = fomMask
							if fomMask == 0 {
								mask = uint8(cval(&input))
								mixmask = 1
							}
						}
						if mask&mixmask != 0 {
							out[3*x+line] = out[prevline+3*x] ^ mix[0]
							out[3*x+line+1] = out[prevline+3*x+1] ^ mix[1]
							out[3*x+line+2] = out[prevline+3*x+2] ^ mix[2]
						} else {
							out[3*x+line] = out[prevline+3*x]
							out[3*x+line+1] = out[prevline+3*x+1]
							out[3*x+line+2] = out[prevline+3*x+2]
						}
					}, &count, &x, width)
				}
			case 3:
				repeat(func() {
					out[3*x+line] = colour2[0]
					out[3*x+line+1] = colour2[1]
					out[3*x+line+2] = colour2[2]
				}, &count, &x, width)
			case 4:
				repeat(func() {
					out[3*x+line] = uint8(cval(&input))
					out[3*x+line+1] = uint8(cval(&input))
					out[3*x+line+2] = uint8(cval(&input))
				}, &count, &x, width)
			case 8:
				repeat(func() {
					if bicolour {
						out[3*x+line] = colour2[0]
						out[3*x+line+1] = colour2[1]
						out[3*x+line+2] = colour2[2]
						bicolour = false
					} else {
						out[3*x+line] = colour1[0]
						out[3*x+line+1] = colour1[1]
						out[3*x+line+2] = colour1[2]
						bicolour = true
						count++
					}
				}, &count, &x, width)
			case 0xd:
				repeat(func() {
					out[3*x+line] = 0xff
					out[3*x+line+1] = 0xff
					out[3*x+line+2] = 0xff
				}, &count, &x, width)
			case 0xe:
				repeat(func() {
					out[3*x+line] = 0
					out[3*x+line+1] = 0
					out[3*x+line+2] = 0
				}, &count, &x, width)
			default:
				return false
			}
		}
	}
	return true
}

func processPlane(in *[]byte, width, height int, out []byte, j int) int {
	startLen := len(*in)
	lastline := 0
	indexh := 0
	for indexh < height {
		thisline := j + width*height*4 - (indexh+1)*width*4
		var color uint8
		indexw := 0
		i := thisline
		if lastline == 0 {
			for indexw < width {
				code := cval(in)
				replen := code & 0xf
				collen := (code >> 4) & 0xf
				revcode := (replen << 4) | collen
				if revcode <= 47 && revcode >= 16 {
					replen = revcode
					collen = 0
				}
				for collen > 0 {
					color = uint8(cval(in))
					out[i] = color
					i += 4
					indexw++
					collen--
				}
				for replen > 0 {
					out[i] = color
					i += 4
					indexw++
					replen--
				}
			}
		} else {
			for indexw < width {
				code := cval(in)
				replen := code & 0xf
				collen := (code >> 4) & 0xf
				revcode := (replen << 4) | collen
				if revcode <= 47 && revcode >= 16 {
					replen = revcode
					collen = 0
				}
				for collen > 0 {
					x := uint8(cval(in))
					if x&1 != 0 {
						x = (x >> 1) + 1
						color = ^x + 1
					} else {
						color = x >> 1
					}
					out[i] = out[indexw*4+lastline] + color
					i += 4
					indexw++
					collen--
				}
				for replen > 0 {
					out[i] = out[indexw*4+lastline] + color
					i += 4
					indexw++
					replen--
				}
			}
		}
		indexh++
		lastline = thisline
	}
	return startLen - len(*in)
}

func decompress4(out []byte, width, height int, input []byte) bool {
	code := cval(&input)
	if code != 0x10 {
		return false
	}
	processPlane(&input, width, height, out, 3)
	processPlane(&input, width, height, out, 2)
	processPlane(&input, width, height, out, 1)
	processPlane(&input, width, height, out, 0)
	return true
}
