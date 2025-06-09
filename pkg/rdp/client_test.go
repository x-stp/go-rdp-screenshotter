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

package rdp

import (
	"testing"
	"time"
)

func TestClientOptions(t *testing.T) {
	// Test DefaultClientOptions
	opts := DefaultClientOptions()
	if opts.Timeout != 10*time.Second {
		t.Errorf("DefaultClientOptions() timeout = %v, want %v", opts.Timeout, 10*time.Second)
	}
	if opts.Username != "" {
		t.Errorf("DefaultClientOptions() username = %v, want empty", opts.Username)
	}
}

func TestTPKTHeader(t *testing.T) {
	tests := []struct {
		name        string
		payloadSize int
		wantLength  uint16
	}{
		{
			name:        "small payload",
			payloadSize: 10,
			wantLength:  14, // 4 (TPKT header) + 10 (payload)
		},
		{
			name:        "medium payload",
			payloadSize: 100,
			wantLength:  104,
		},
		{
			name:        "large payload",
			payloadSize: 1000,
			wantLength:  1004,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tpkt := NewTPKTHeader(tt.payloadSize)
			if tpkt.Version != TPKTVersion {
				t.Errorf("NewTPKTHeader() version = %v, want %v", tpkt.Version, TPKTVersion)
			}
			if tpkt.Length != tt.wantLength {
				t.Errorf("NewTPKTHeader() length = %v, want %v", tpkt.Length, tt.wantLength)
			}
			if tpkt.PayloadSize() != tt.payloadSize {
				t.Errorf("PayloadSize() = %v, want %v", tpkt.PayloadSize(), tt.payloadSize)
			}
		})
	}
}

func TestX224ConnectionRequest(t *testing.T) {
	tests := []struct {
		name   string
		cookie string
	}{
		{
			name:   "empty cookie",
			cookie: "",
		},
		{
			name:   "with cookie",
			cookie: "testuser",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr := NewX224ConnectionRequest(tt.cookie)

			if cr.TPDUCode != X224_TPDU_CONNECTION_REQUEST {
				t.Errorf("TPDUCode = %v, want %v", cr.TPDUCode, X224_TPDU_CONNECTION_REQUEST)
			}
			if cr.DstRef != 0 {
				t.Errorf("DstRef = %v, want 0", cr.DstRef)
			}
			if cr.ClassOptions != 0 {
				t.Errorf("ClassOptions = %v, want 0", cr.ClassOptions)
			}

			// Verify length indicator calculation
			expectedLI := uint8(6 + len(cr.Cookie))
			if cr.LengthIndicator != expectedLI {
				t.Errorf("LengthIndicator = %v, want %v", cr.LengthIndicator, expectedLI)
			}
		})
	}
}
