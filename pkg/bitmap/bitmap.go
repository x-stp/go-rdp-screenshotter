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

func ParseBitmapUpdateData(data []byte) ([]*BitmapData, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("bitmap update data too short")
	}

	r := bytes.NewReader(data)

	var updateType uint16
	if err := binary.Read(r, binary.LittleEndian, &updateType); err != nil {
		return nil, err
	}

	if updateType != 0x0001 {
		return nil, fmt.Errorf("invalid update type: %04X", updateType)
	}

	var numRects uint16
	if err := binary.Read(r, binary.LittleEndian, &numRects); err != nil {
		return nil, err
	}

	bitmaps := make([]*BitmapData, 0, numRects)

	for i := uint16(0); i < numRects; i++ {
		bitmap := &BitmapData{}

		binary.Read(r, binary.LittleEndian, &bitmap.DestLeft)
		binary.Read(r, binary.LittleEndian, &bitmap.DestTop)
		binary.Read(r, binary.LittleEndian, &bitmap.DestRight)
		binary.Read(r, binary.LittleEndian, &bitmap.DestBottom)
		binary.Read(r, binary.LittleEndian, &bitmap.Width)
		binary.Read(r, binary.LittleEndian, &bitmap.Height)
		binary.Read(r, binary.LittleEndian, &bitmap.BitsPerPel)

		var flags uint16
		binary.Read(r, binary.LittleEndian, &flags)
		bitmap.Compressed = (flags & 0x0001) != 0

		binary.Read(r, binary.LittleEndian, &bitmap.DataLength)

		bitmap.Data = make([]byte, bitmap.DataLength)
		if _, err := io.ReadFull(r, bitmap.Data); err != nil {
			return nil, fmt.Errorf("failed to read bitmap data: %w", err)
		}

		bitmaps = append(bitmaps, bitmap)
	}

	return bitmaps, nil
}

func DecodeRawBitmap(bitmap *BitmapData) (image.Image, error) {
	if bitmap.Compressed {

		return nil, fmt.Errorf("compressed bitmaps not yet supported")
	}

	width := int(bitmap.Width)
	height := int(bitmap.Height)
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	switch bitmap.BitsPerPel {
	case 8:

		return nil, fmt.Errorf("8-bit color not yet supported")

	case 15, 16:

		if len(bitmap.Data) < width*height*2 {
			return nil, fmt.Errorf("insufficient bitmap data for 16-bit color")
		}

		for y := 0; y < height; y++ {
			for x := 0; x < width; x++ {

				srcY := height - y - 1
				offset := (srcY*width + x) * 2

				pixel := binary.LittleEndian.Uint16(bitmap.Data[offset:])

				var r, g, b uint8
				if bitmap.BitsPerPel == 15 {

					r = uint8((pixel>>10)&0x1F) << 3
					g = uint8((pixel>>5)&0x1F) << 3
					b = uint8(pixel&0x1F) << 3
				} else {

					r = uint8((pixel>>11)&0x1F) << 3
					g = uint8((pixel>>5)&0x3F) << 2
					b = uint8(pixel&0x1F) << 3
				}

				img.Set(x, y, color.RGBA{r, g, b, 255})
			}
		}

	case 24:

		if len(bitmap.Data) < width*height*3 {
			return nil, fmt.Errorf("insufficient bitmap data for 24-bit color")
		}

		for y := 0; y < height; y++ {
			for x := 0; x < width; x++ {

				srcY := height - y - 1
				offset := (srcY*width + x) * 3

				b := bitmap.Data[offset]
				g := bitmap.Data[offset+1]
				r := bitmap.Data[offset+2]

				img.Set(x, y, color.RGBA{r, g, b, 255})
			}
		}

	case 32:

		if len(bitmap.Data) < width*height*4 {
			return nil, fmt.Errorf("insufficient bitmap data for 32-bit color")
		}

		for y := 0; y < height; y++ {
			for x := 0; x < width; x++ {

				srcY := height - y - 1
				offset := (srcY*width + x) * 4

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

func SavePNG(img image.Image, filename string) error {
	buf := new(bytes.Buffer)
	if err := png.Encode(buf, img); err != nil {
		return fmt.Errorf("failed to encode PNG: %w", err)
	}

	fmt.Printf("PNG encoded: %d bytes for %s\n", buf.Len(), filename)
	return nil
}

func CombineBitmaps(bitmaps []*BitmapData, width, height int) (image.Image, error) {

	img := image.NewRGBA(image.Rect(0, 0, width, height))

	for _, bitmap := range bitmaps {
		bmpImg, err := DecodeRawBitmap(bitmap)
		if err != nil {
			fmt.Printf("Warning: failed to decode bitmap: %v\n", err)
			continue
		}

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

func ConvertBitmapToImage(bitmapData interface{}) ([]byte, error) {

	rect, ok := bitmapData.(*BitmapData)
	if !ok {

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

		rect = &BitmapData{
			Width:      rdpRect.Width,
			Height:     rdpRect.Height,
			BitsPerPel: rdpRect.BitsPerPixel,
			Data:       rdpRect.BitmapDataStream,
		}
	}

	img := image.NewRGBA(image.Rect(0, 0, int(rect.Width), int(rect.Height)))

	switch rect.BitsPerPel {
	case 15, 16:

		if err := convert16BitToRGBA(rect.Data, img, rect.Width, rect.Height); err != nil {
			return nil, err
		}
	case 24:

		if err := convert24BitToRGBA(rect.Data, img, rect.Width, rect.Height); err != nil {
			return nil, err
		}
	case 32:

		if err := convert32BitToRGBA(rect.Data, img, rect.Width, rect.Height); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported bits per pixel: %d", rect.BitsPerPel)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("failed to encode PNG: %w", err)
	}

	return buf.Bytes(), nil
}

func convert16BitToRGBA(data []byte, img *image.RGBA, width, height uint16) error {
	if len(data) < int(width*height*2) {
		return fmt.Errorf("insufficient data for 16-bit image")
	}

	for y := uint16(0); y < height; y++ {
		for x := uint16(0); x < width; x++ {

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

		if len(data) < int(width*height*3) {
			return fmt.Errorf("insufficient data for 24-bit image")
		}
		padding = 0
		paddedRowSize = rowSize
	}

	for y := uint16(0); y < height; y++ {
		for x := uint16(0); x < width; x++ {

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

	for y := uint16(0); y < height; y++ {
		for x := uint16(0); x < width; x++ {

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

func ConvertRGBToPNG(data []byte, width, height int) ([]byte, error) {
	if len(data) < width*height*3 {
		return nil, fmt.Errorf("insufficient data for %dx%d RGB image", width, height)
	}

	img := image.NewRGBA(image.Rect(0, 0, width, height))

	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			offset := (y*width + x) * 3
			r := data[offset]
			g := data[offset+1]
			b := data[offset+2]

			img.Set(x, y, color.RGBA{r, g, b, 255})
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("failed to encode PNG: %w", err)
	}

	return buf.Bytes(), nil
}
