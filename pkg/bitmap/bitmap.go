// Package bitmap decodes RDP bitmap update rectangles ([MS-RDPBCGR] §2.2.9.1)
// into Go images and encodes the composited canvas to PNG. It handles the
// 15/16/24/32-bpp uncompressed layouts and the RLE-compressed stream
// ([MS-RDPBCGR] §3.1.9) via DecompressRLE.
package bitmap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
)

// DecodeRect returns the rectangle as an *image.RGBA without PNG encoding so
// callers can composite multiple rectangles into a larger canvas.
//
// RDP uncompressed bitmap pixel data is laid out bottom-up (last row of bytes
// = top row of image; [MS-RDPBCGR] §2.2.9.1.1.3.1.2.2). The RLE decompressor in
// rle.go emits the pixels in the natural decoded order, which is top-down,
// so we reverse them to match the uncompressed layout before handing off to
// the 15/16/24/32-bpp converters.
func DecodeRect(width, height, bpp uint16, compressed bool, data []byte) (*image.RGBA, error) {
	pixels := data
	if compressed {
		bytesPerPixel := (int(bpp) + 7) / 8
		body := data
		if len(body) >= 8 {
			body = body[8:]
		}
		expanded := DecompressRLE(body, int(width), int(height), bytesPerPixel)
		if expanded == nil {
			return nil, fmt.Errorf("RLE decompression failed for %dx%d bpp=%d", width, height, bpp)
		}
		pixels = flipRows(expanded, int(width), int(height), bytesPerPixel)
	}
	img := image.NewRGBA(image.Rect(0, 0, int(width), int(height)))
	switch bpp {
	case 15, 16:
		if err := convert16BitToRGBA(pixels, img, width, height); err != nil {
			return nil, err
		}
	case 24:
		if err := convert24BitToRGBA(pixels, img, width, height); err != nil {
			return nil, err
		}
	case 32:
		if err := convert32BitToRGBA(pixels, img, width, height); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported bits per pixel: %d", bpp)
	}
	return img, nil
}

// flipRows reverses the row order of a tightly-packed raster so the resulting
// buffer matches the bottom-up DIB layout that convert16/24/32BitToRGBA expects. Microsoft.
func flipRows(data []byte, width, height, bytesPerPixel int) []byte {
	rowSize := width * bytesPerPixel
	out := make([]byte, len(data))
	for y := 0; y < height; y++ {
		src := y * rowSize
		dst := (height - 1 - y) * rowSize
		if src+rowSize > len(data) || dst+rowSize > len(out) {
			break
		}
		copy(out[dst:dst+rowSize], data[src:src+rowSize])
	}
	return out
}

// EncodePNG encodes an image as PNG bytes.
func EncodePNG(img image.Image) ([]byte, error) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("png encode: %w", err)
	}
	return buf.Bytes(), nil
}

func convert16BitToRGBA(data []byte, img *image.RGBA, width, height uint16) error {
	if len(data) < int(width*height*2) {
		return fmt.Errorf("insufficient data for 16-bit image")
	}

	for y := range height {
		for x := range width {

			srcY := height - y - 1
			offset := int((srcY*width + x) * 2)

			if offset+1 >= len(data) {
				continue
			}

			pixel := binary.LittleEndian.Uint16(data[offset : offset+2])

			r := uint8((pixel >> 11) & 0x1F)
			g := uint8((pixel >> 5) & 0x3F)
			b := uint8(pixel & 0x1F)

			r = (r << 3) | (r >> 2)
			g = (g << 2) | (g >> 4)
			b = (b << 3) | (b >> 2)

			img.Set(int(x), int(y), color.RGBA{r, g, b, 255})
		}
	}

	return nil
}

func convert24BitToRGBA(data []byte, img *image.RGBA, width, height uint16) error {

	rowSize := int(width) * 3
	padding := (4 - (rowSize % 4)) % 4
	paddedRowSize := rowSize + padding

	expectedSize := paddedRowSize * int(height)
	if len(data) < expectedSize {
		// No 4-byte row padding present: fall back to a tight rowSize. Some
		// servers omit the DIB scanline alignment on 24bpp rectangles.
		if len(data) < int(width*height*3) {
			return fmt.Errorf("insufficient data for 24-bit image")
		}
		paddedRowSize = rowSize
	}

	for y := range height {
		for x := range width {

			srcY := height - y - 1
			offset := int(srcY)*paddedRowSize + int(x)*3

			if offset+2 >= len(data) {
				continue
			}

			b := data[offset]
			g := data[offset+1]
			r := data[offset+2]

			img.Set(int(x), int(y), color.RGBA{r, g, b, 255})
		}
	}

	return nil
}

func convert32BitToRGBA(data []byte, img *image.RGBA, width, height uint16) error {
	if len(data) < int(width*height*4) {
		return fmt.Errorf("insufficient data for 32-bit image")
	}

	for y := range height {
		for x := range width {

			srcY := height - y - 1
			offset := int((srcY*width + x) * 4)

			if offset+3 >= len(data) {
				continue
			}

			b := data[offset]
			g := data[offset+1]
			r := data[offset+2]
			a := data[offset+3]

			img.Set(int(x), int(y), color.RGBA{r, g, b, a})
		}
	}

	return nil
}
