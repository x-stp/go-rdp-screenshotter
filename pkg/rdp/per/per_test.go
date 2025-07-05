package per

import (
	"bytes"
	"testing"
)

func TestWriteLengthShortForm(t *testing.T) {
	cases := []struct {
		in   int
		want []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{0x7E, []byte{0x7E}},
		{0x7F, []byte{0x7F}},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		WriteLength(&buf, tc.in)
		if !bytes.Equal(buf.Bytes(), tc.want) {
			t.Fatalf("WriteLength(%d) = % X, want % X", tc.in, buf.Bytes(), tc.want)
		}
		got, n, err := ReadLength(bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatalf("ReadLength: %v", err)
		}
		if got != tc.in || n != 1 {
			t.Fatalf("ReadLength returned (%d,%d), want (%d,1)", got, n, tc.in)
		}
	}
}

func TestWriteLengthLongForm(t *testing.T) {
	cases := []struct {
		in   int
		want []byte
	}{
		{0x80, []byte{0x80, 0x80}},   // 128 -- first long-form value
		{0x100, []byte{0x81, 0x00}},  // 256
		{0x3FFF, []byte{0xBF, 0xFF}}, // 16383 -- max non-fragmented
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		WriteLength(&buf, tc.in)
		if !bytes.Equal(buf.Bytes(), tc.want) {
			t.Fatalf("WriteLength(%d) = % X, want % X", tc.in, buf.Bytes(), tc.want)
		}
		got, n, err := ReadLength(bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatalf("ReadLength: %v", err)
		}
		if got != tc.in || n != 2 {
			t.Fatalf("ReadLength returned (%d,%d), want (%d,2)", got, n, tc.in)
		}
	}
}

func TestPERLengthFragmentedFormRejected(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("WriteLength(0x4000) should panic (fragmented form not supported)")
		}
	}()
	var buf bytes.Buffer
	WriteLength(&buf, 0x4000)
}

func TestWriteIntegerEncodings(t *testing.T) {
	cases := []struct {
		in   uint32
		want []byte
	}{
		{0x00, []byte{0x01, 0x00}},
		{0x7F, []byte{0x01, 0x7F}},
		{0xFF, []byte{0x01, 0xFF}},
		{0x0100, []byte{0x02, 0x01, 0x00}},
		{0xFFFF, []byte{0x02, 0xFF, 0xFF}},
		{0x10000, []byte{0x04, 0x00, 0x01, 0x00, 0x00}},
		{0xDEADBEEF, []byte{0x04, 0xDE, 0xAD, 0xBE, 0xEF}},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		WriteInteger(&buf, tc.in)
		if !bytes.Equal(buf.Bytes(), tc.want) {
			t.Fatalf("WriteInteger(0x%X) = % X, want % X", tc.in, buf.Bytes(), tc.want)
		}
	}
}

func TestWriteInteger16Roundtrip(t *testing.T) {
	const mcsBaseChannelID uint16 = 1001
	cases := []struct {
		value, min uint16
		want       []byte
	}{
		{1001, mcsBaseChannelID, []byte{0x00, 0x00}},
		{1002, mcsBaseChannelID, []byte{0x00, 0x01}},
		{1003, mcsBaseChannelID, []byte{0x00, 0x02}},
		{0xFFFF, 0, []byte{0xFF, 0xFF}},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		WriteInteger16(&buf, tc.value, tc.min)
		if !bytes.Equal(buf.Bytes(), tc.want) {
			t.Fatalf("WriteInteger16(%d, %d) = % X, want % X", tc.value, tc.min, buf.Bytes(), tc.want)
		}
		got, err := ReadInteger16(bytes.NewReader(buf.Bytes()), tc.min)
		if err != nil {
			t.Fatalf("ReadInteger16: %v", err)
		}
		if got != tc.value {
			t.Fatalf("ReadInteger16 returned %d, want %d", got, tc.value)
		}
	}
}

func TestReadLengthShortRead(t *testing.T) {
	if _, _, err := ReadLength(bytes.NewReader(nil)); err == nil {
		t.Fatal("ReadLength on empty reader should fail")
	}
	if _, _, err := ReadLength(bytes.NewReader([]byte{0xBF})); err == nil {
		t.Fatal("ReadLength missing long-form trailer should fail")
	}
}
