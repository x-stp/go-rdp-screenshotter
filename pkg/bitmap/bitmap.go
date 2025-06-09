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

package bitmap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
)

// BitmapData represents a parsed RDP bitmap
type BitmapData struct {
	DestLeft   uint16
	DestTop    uint16
	DestRight  uint16
	DestBottom uint16
	Width      uint16
	Height     uint16
	BitsPerPel uint16
	Compressed bool
	DataLength uint16
	Data       []byte
}

// ParseBitmapUpdateData parses RDP bitmap update data
// MS-RDPBCGR section 2.2.9.1.1.3.1.2
func ParseBitmapUpdateData(data []byte) ([]*BitmapData, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("bitmap update data too short")
	}

	r := bytes.NewReader(data)

	// Read update type (should be UPDATETYPE_BITMAP = 0x0001)
	var updateType uint16
	if err := binary.Read(r, binary.LittleEndian, &updateType); err != nil {
		return nil, err
	}

	if updateType != 0x0001 {
		return nil, fmt.Errorf("invalid update type: %04X", updateType)
	}

	// Read number of rectangles
	var numRects uint16
	if err := binary.Read(r, binary.LittleEndian, &numRects); err != nil {
		return nil, err
	}

	bitmaps := make([]*BitmapData, 0, numRects)

	for i := uint16(0); i < numRects; i++ {
		bitmap := &BitmapData{}

		// Read rectangle coordinates
		binary.Read(r, binary.LittleEndian, &bitmap.DestLeft)
		binary.Read(r, binary.LittleEndian, &bitmap.DestTop)
		binary.Read(r, binary.LittleEndian, &bitmap.DestRight)
		binary.Read(r, binary.LittleEndian, &bitmap.DestBottom)
		binary.Read(r, binary.LittleEndian, &bitmap.Width)
		binary.Read(r, binary.LittleEndian, &bitmap.Height)
		binary.Read(r, binary.LittleEndian, &bitmap.BitsPerPel)

		// Read compression flags
		var flags uint16
		binary.Read(r, binary.LittleEndian, &flags)
		bitmap.Compressed = (flags & 0x0001) != 0

		// Read bitmap data length
		binary.Read(r, binary.LittleEndian, &bitmap.DataLength)

		// Read bitmap data
		bitmap.Data = make([]byte, bitmap.DataLength)
		if _, err := io.ReadFull(r, bitmap.Data); err != nil {
			return nil, fmt.Errorf("failed to read bitmap data: %w", err)
		}

		bitmaps = append(bitmaps, bitmap)
	}

	return bitmaps, nil
}

// DecodeRawBitmap decodes raw bitmap data into an image
func DecodeRawBitmap(bitmap *BitmapData) (image.Image, error) {
	if bitmap.Compressed {
		// TODO: Implement RLE decompression
		return nil, fmt.Errorf("compressed bitmaps not yet supported")
	}

	width := int(bitmap.Width)
	height := int(bitmap.Height)
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	switch bitmap.BitsPerPel {
	case 8:
		// 8-bit indexed color (would need palette)
		return nil, fmt.Errorf("8-bit color not yet supported")

	case 15, 16:
		// 16-bit RGB (5-5-5 or 5-6-5)
		if len(bitmap.Data) < width*height*2 {
			return nil, fmt.Errorf("insufficient bitmap data for 16-bit color")
		}

		for y := 0; y < height; y++ {
			for x := 0; x < width; x++ {
				// RDP bitmaps are bottom-up
				srcY := height - y - 1
				offset := (srcY*width + x) * 2

				pixel := binary.LittleEndian.Uint16(bitmap.Data[offset:])

				var r, g, b uint8
				if bitmap.BitsPerPel == 15 {
					// 5-5-5 format
					r = uint8((pixel>>10)&0x1F) << 3
					g = uint8((pixel>>5)&0x1F) << 3
					b = uint8(pixel&0x1F) << 3
				} else {
					// 5-6-5 format
					r = uint8((pixel>>11)&0x1F) << 3
					g = uint8((pixel>>5)&0x3F) << 2
					b = uint8(pixel&0x1F) << 3
				}

				img.Set(x, y, color.RGBA{r, g, b, 255})
			}
		}

	case 24:
		// 24-bit RGB
		if len(bitmap.Data) < width*height*3 {
			return nil, fmt.Errorf("insufficient bitmap data for 24-bit color")
		}

		for y := 0; y < height; y++ {
			for x := 0; x < width; x++ {
				// RDP bitmaps are bottom-up
				srcY := height - y - 1
				offset := (srcY*width + x) * 3

				// BGR format
				b := bitmap.Data[offset]
				g := bitmap.Data[offset+1]
				r := bitmap.Data[offset+2]

				img.Set(x, y, color.RGBA{r, g, b, 255})
			}
		}

	case 32:
		// 32-bit RGBA
		if len(bitmap.Data) < width*height*4 {
			return nil, fmt.Errorf("insufficient bitmap data for 32-bit color")
		}

		for y := 0; y < height; y++ {
			for x := 0; x < width; x++ {
				// RDP bitmaps are bottom-up
				srcY := height - y - 1
				offset := (srcY*width + x) * 4

				// BGRA format
				b := bitmap.Data[offset]
				g := bitmap.Data[offset+1]
				r := bitmap.Data[offset+2]
				a := bitmap.Data[offset+3]

				img.Set(x, y, color.RGBA{r, g, b, a})
			}
		}

	default:
		return nil, fmt.Errorf("unsupported bits per pixel: %d", bitmap.BitsPerPel)
	}

	return img, nil
}

// SavePNG saves an image as a PNG file
func SavePNG(img image.Image, filename string) error {
	buf := new(bytes.Buffer)
	if err := png.Encode(buf, img); err != nil {
		return fmt.Errorf("failed to encode PNG: %w", err)
	}

	// TODO: Write to file
	// For now, just return the size
	fmt.Printf("PNG encoded: %d bytes for %s\n", buf.Len(), filename)
	return nil
}

// CombineBitmaps combines multiple bitmap updates into a single image
func CombineBitmaps(bitmaps []*BitmapData, width, height int) (image.Image, error) {
	// Create a full-screen image
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// Apply each bitmap update
	for _, bitmap := range bitmaps {
		bmpImg, err := DecodeRawBitmap(bitmap)
		if err != nil {
			fmt.Printf("Warning: failed to decode bitmap: %v\n", err)
			continue
		}

		// Draw the bitmap at its destination
		for y := 0; y < int(bitmap.Height); y++ {
			for x := 0; x < int(bitmap.Width); x++ {
				destX := int(bitmap.DestLeft) + x
				destY := int(bitmap.DestTop) + y

				if destX < width && destY < height {
					img.Set(destX, destY, bmpImg.At(x, y))
				}
			}
		}
	}

	return img, nil
}

// ConvertBitmapToImage converts RDP bitmap data to a PNG image
func ConvertBitmapToImage(bitmapData interface{}) ([]byte, error) {
	// Type assertion to get the actual bitmap data structure
	rect, ok := bitmapData.(*BitmapData)
	if !ok {
		// Try to get it from the rdp package type
		type rdpBitmapData struct {
			DestLeft         uint16
			DestTop          uint16
			DestRight        uint16
			DestBottom       uint16
			Width            uint16
			Height           uint16
			BitsPerPixel     uint16
			Flags            uint16
			BitmapLength     uint16
			BitmapDataStream []byte
		}

		rdpRect, ok := bitmapData.(*rdpBitmapData)
		if !ok {
			return nil, fmt.Errorf("invalid bitmap data type")
		}

		// Convert to our BitmapData type
		rect = &BitmapData{
			Width:      rdpRect.Width,
			Height:     rdpRect.Height,
			BitsPerPel: rdpRect.BitsPerPixel,
			Data:       rdpRect.BitmapDataStream,
		}
	}

	// Create RGBA image
	img := image.NewRGBA(image.Rect(0, 0, int(rect.Width), int(rect.Height)))

	// Convert pixel data based on bits per pixel
	switch rect.BitsPerPel {
	case 15, 16:
		// 16-bit RGB (5-6-5 or 5-5-5)
		if err := convert16BitToRGBA(rect.Data, img, rect.Width, rect.Height); err != nil {
			return nil, err
		}
	case 24:
		// 24-bit BGR
		if err := convert24BitToRGBA(rect.Data, img, rect.Width, rect.Height); err != nil {
			return nil, err
		}
	case 32:
		// 32-bit BGRA
		if err := convert32BitToRGBA(rect.Data, img, rect.Width, rect.Height); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported bits per pixel: %d", rect.BitsPerPel)
	}

	// Encode to PNG
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("failed to encode PNG: %w", err)
	}

	return buf.Bytes(), nil
}

// convert16BitToRGBA converts 16-bit RGB data to RGBA
func convert16BitToRGBA(data []byte, img *image.RGBA, width, height uint16) error {
	if len(data) < int(width*height*2) {
		return fmt.Errorf("insufficient data for 16-bit image")
	}

	for y := uint16(0); y < height; y++ {
		for x := uint16(0); x < width; x++ {
			offset := int((y*width + x) * 2)
			pixel := binary.LittleEndian.Uint16(data[offset : offset+2])

			// RGB565 format
			r := uint8((pixel >> 11) & 0x1F)
			g := uint8((pixel >> 5) & 0x3F)
			b := uint8(pixel & 0x1F)

			// Scale to 8-bit
			r = (r << 3) | (r >> 2)
			g = (g << 2) | (g >> 4)
			b = (b << 3) | (b >> 2)

			img.Set(int(x), int(y), color.RGBA{r, g, b, 255})
		}
	}

	return nil
}

// convert24BitToRGBA converts 24-bit BGR data to RGBA
func convert24BitToRGBA(data []byte, img *image.RGBA, width, height uint16) error {
	if len(data) < int(width*height*3) {
		return fmt.Errorf("insufficient data for 24-bit image")
	}

	for y := uint16(0); y < height; y++ {
		for x := uint16(0); x < width; x++ {
			offset := int((y*width + x) * 3)

			b := data[offset]
			g := data[offset+1]
			r := data[offset+2]

			img.Set(int(x), int(y), color.RGBA{r, g, b, 255})
		}
	}

	return nil
}

// convert32BitToRGBA converts 32-bit BGRA data to RGBA
func convert32BitToRGBA(data []byte, img *image.RGBA, width, height uint16) error {
	if len(data) < int(width*height*4) {
		return fmt.Errorf("insufficient data for 32-bit image")
	}

	for y := uint16(0); y < height; y++ {
		for x := uint16(0); x < width; x++ {
			offset := int((y*width + x) * 4)

			b := data[offset]
			g := data[offset+1]
			r := data[offset+2]
			a := data[offset+3]

			img.Set(int(x), int(y), color.RGBA{r, g, b, a})
		}
	}

	return nil
}
