// RDP Screenshotter Go - Capture screenshots from RDP servers
// Copyright (C) 2025 - Pepijn van der Stap, pepijn@neosecurity.nl
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package rdp

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"github.com/zmap/zcrypto/x509"
)

// BER encoding helpers (ITU-T X.690)
func berEncodeLength(w io.Writer, length int) error {
	if length < 128 {
		return binary.Write(w, binary.BigEndian, uint8(length))
	}
	if length < 256 {
		binary.Write(w, binary.BigEndian, uint8(0x81))
		return binary.Write(w, binary.BigEndian, uint8(length))
	}
	binary.Write(w, binary.BigEndian, uint8(0x82))
	return binary.Write(w, binary.BigEndian, uint16(length))
}

// buildMCSConnectInitial creates an MCS Connect Initial PDU
func buildMCSConnectInitial(negotiatedProtocol uint32) ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.WriteByte(0x7F)
	buf.WriteByte(0x65)
	lengthPos := buf.Len()
	buf.WriteByte(0x82)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)
	// callingDomainSelector
	buf.Write([]byte{0x04, 0x01, 0x01})
	// calledDomainSelector
	buf.Write([]byte{0x04, 0x01, 0x01})
	// upwardFlag
	buf.Write([]byte{0x01, 0x01, 0xFF})
	// targetParameters
	buf.Write([]byte{0x30, 0x19})
	buf.Write([]byte{0x02, 0x01, 0x22})       // maxChannelIds
	buf.Write([]byte{0x02, 0x01, 0x02})       // maxUserIds
	buf.Write([]byte{0x02, 0x01, 0x00})       // maxTokenIds
	buf.Write([]byte{0x02, 0x01, 0x01})       // numPriorities
	buf.Write([]byte{0x02, 0x01, 0x00})       // minThroughput
	buf.Write([]byte{0x02, 0x01, 0x01})       // maxHeight
	buf.Write([]byte{0x02, 0x02, 0xFF, 0xFF}) // maxMCSPDUsize
	buf.Write([]byte{0x02, 0x01, 0x02})       // protocolVersion
	// minimumParameters
	buf.Write([]byte{0x30, 0x19})
	buf.Write([]byte{0x02, 0x01, 0x01})       // maxChannelIds
	buf.Write([]byte{0x02, 0x01, 0x01})       // maxUserIds
	buf.Write([]byte{0x02, 0x01, 0x01})       // maxTokenIds
	buf.Write([]byte{0x02, 0x01, 0x01})       // numPriorities
	buf.Write([]byte{0x02, 0x01, 0x00})       // minThroughput
	buf.Write([]byte{0x02, 0x01, 0x01})       // maxHeight
	buf.Write([]byte{0x02, 0x02, 0x04, 0x00}) // maxMCSPDUsize
	buf.Write([]byte{0x02, 0x01, 0x02})       // protocolVersion
	// maximumParameters
	buf.Write([]byte{0x30, 0x1C})
	buf.Write([]byte{0x02, 0x02, 0xFF, 0xFF}) // maxChannelIds
	buf.Write([]byte{0x02, 0x02, 0xFC, 0x17}) // maxUserIds
	buf.Write([]byte{0x02, 0x02, 0xFF, 0xFF}) // maxTokenIds
	buf.Write([]byte{0x02, 0x01, 0x01})       // numPriorities
	buf.Write([]byte{0x02, 0x01, 0x00})       // minThroughput
	buf.Write([]byte{0x02, 0x01, 0x01})       // maxHeight
	buf.Write([]byte{0x02, 0x02, 0xFF, 0xFF}) // maxMCSPDUsize
	buf.Write([]byte{0x02, 0x01, 0x02})       // protocolVersion
	userData := buildRDPUserData(negotiatedProtocol)
	buf.WriteByte(0x04)
	berEncodeLength(buf, len(userData))
	buf.Write(userData)
	data := buf.Bytes()
	totalLength := len(data) - 4
	data[lengthPos+1] = byte(totalLength >> 8)
	data[lengthPos+2] = byte(totalLength & 0xFF)
	return data, nil
}

// buildRDPUserData creates the RDP-specific user data for MCS Connect Initial
func buildRDPUserData(negotiatedProtocol uint32) []byte {
	// Build client data blocks first
	csCore := buildCSCore(negotiatedProtocol)
	csSecurity := buildCSSecurity()

	// Build the GCC Conference Create Request
	buf := new(bytes.Buffer)

	// T.124 identifier string
	buf.Write([]byte{0x00, 0x05, 0x00, 0x14, 0x7C, 0x00, 0x01})

	// ConnectData::connectPDU length (PER encoded)
	// This is the length from here to the end
	connectPDUData := new(bytes.Buffer)

	// T.124 ConnectData structure
	connectPDUData.Write([]byte{0x2A, 0x14, 0x76, 0x0A}) // t124Identifier
	connectPDUData.WriteByte(0x01)                       // connectID (PER: minimum value 0 + 1 = 1)
	connectPDUData.WriteByte(0x01)                       // must be 1
	connectPDUData.WriteByte(0x00)                       // OPTIONAL userData is present

	// H.221 nonStandardIdentifier "McDn"
	connectPDUData.WriteByte(0x01) // h221NonStandard
	connectPDUData.WriteByte(0xC0) // length = 4 bytes
	connectPDUData.WriteByte(0x00) // t35CountryCode
	connectPDUData.WriteByte(0x4D) // t35Extension 'M'
	connectPDUData.WriteByte(0x63) // manufacturerCode 'c'
	connectPDUData.WriteByte(0x44) // 'D'
	connectPDUData.WriteByte(0x6E) // 'n'

	// Client data length
	clientDataLen := len(csCore) + len(csSecurity)
	binary.Write(connectPDUData, binary.BigEndian, uint16(clientDataLen))

	// Write client data blocks
	connectPDUData.Write(csCore)
	connectPDUData.Write(csSecurity)

	// Write the length of connectPDU
	connectPDUBytes := connectPDUData.Bytes()
	if len(connectPDUBytes) < 128 {
		buf.WriteByte(byte(len(connectPDUBytes)))
	} else {
		buf.WriteByte(0x81) // length > 127, use long form
		buf.WriteByte(byte(len(connectPDUBytes)))
	}
	buf.Write(connectPDUBytes)

	return buf.Bytes()
}

// buildCSCore creates the Client Core Data structure, requesting 24-bit color.
func buildCSCore(negotiatedProtocol uint32) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(0x01C0))     // type: CS_CORE
	binary.Write(buf, binary.LittleEndian, uint16(216))        // length
	binary.Write(buf, binary.LittleEndian, uint32(0x00080001)) // RDP 5.0
	binary.Write(buf, binary.LittleEndian, uint16(1024))       // width
	binary.Write(buf, binary.LittleEndian, uint16(768))        // height
	binary.Write(buf, binary.LittleEndian, uint16(0xCA01))
	binary.Write(buf, binary.LittleEndian, uint16(0xAA03)) // SAS Sequence
	binary.Write(buf, binary.LittleEndian, uint32(0x409))  // US English Keyboard
	binary.Write(buf, binary.LittleEndian, uint32(7601))   // Client Build (Windows 7 SP1)
	clientName := "rdp-go"
	for i := 0; i < 32; i++ {
		if i < len(clientName) {
			buf.WriteByte(clientName[i])
			buf.WriteByte(0)
		} else {
			binary.Write(buf, binary.LittleEndian, uint16(0))
		}
	}
	binary.Write(buf, binary.LittleEndian, uint32(0x04))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint32(12))
	buf.Write(make([]byte, 64))
	binary.Write(buf, binary.LittleEndian, uint16(16)) // postBeta2ColorDepth (16-bit like scrying)
	binary.Write(buf, binary.LittleEndian, uint16(1))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint16(16)) // highColorDepth (16-bit)
	binary.Write(buf, binary.LittleEndian, uint16(1))
	binary.Write(buf, binary.LittleEndian, uint16(1))
	buf.Write(make([]byte, 64))
	buf.WriteByte(0x07) // Connection Type
	buf.WriteByte(0)
	binary.Write(buf, binary.LittleEndian, negotiatedProtocol)
	return buf.Bytes()
}

// buildCSSecurity creates the Client Security Data structure
func buildCSSecurity() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(0x02C0))
	binary.Write(buf, binary.LittleEndian, uint16(12))
	// Support all encryption methods including NONE for servers that allow guest access
	binary.Write(buf, binary.LittleEndian, uint32(
		ENCRYPTION_METHOD_NONE|ENCRYPTION_METHOD_40BIT|ENCRYPTION_METHOD_56BIT|ENCRYPTION_METHOD_128BIT|ENCRYPTION_METHOD_FIPS))
	binary.Write(buf, binary.LittleEndian, uint32(0)) // extEncryptionMethods
	return buf.Bytes()
}

// buildCSCluster creates the Client Cluster Data structure
func buildCSCluster() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(0x04C0)) // type: CS_CLUSTER
	binary.Write(buf, binary.LittleEndian, uint16(12))     // length
	binary.Write(buf, binary.LittleEndian, uint32(0x0D))   // flags: console session, supported, version 3
	binary.Write(buf, binary.LittleEndian, uint32(0))      // redirectedSessionID
	return buf.Bytes()
}

// buildCSNet creates the Client Network Data structure
func buildCSNet() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(0x03C0)) // type: CS_NET
	binary.Write(buf, binary.LittleEndian, uint16(8))      // length (header + count)
	binary.Write(buf, binary.LittleEndian, uint32(0))      // channelCount = 0 (no custom channels)
	return buf.Bytes()
}

// buildMCSErectDomainRequest creates an MCS Erect Domain Request PDU
func buildMCSErectDomainRequest() []byte {
	return []byte{0x04, 0x04, 0x00, 0x00, 0x00, 0x00}
}

// buildMCSAttachUserRequest creates a validly-encoded MCS Attach User Request PDU.
func buildMCSAttachUserRequest() []byte {
	// A minimal PER encoding for an empty sequence. Some servers (like xrdp)
	// expect the hyper-compact version without an explicit length byte.
	return []byte{0x28}
}

// buildMCSChannelJoinRequest creates an MCS Channel Join Request PDU
func buildMCSChannelJoinRequest(userID, channelID uint16) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(0x38) // PER tag for [APPLICATION 14]
	binary.Write(buf, binary.BigEndian, userID)
	binary.Write(buf, binary.BigEndian, channelID)
	return buf.Bytes()
}

// parseMCSConnectResponse parses the MCS Connect Response to find the user data.
func parseMCSConnectResponse(data []byte) (*SecurityData, error) {
	if len(data) < 2 || data[0] != 0x7f || data[1] != 0x66 {
		return nil, fmt.Errorf("invalid MCS Connect Response tag")
	}
	r := bytes.NewReader(data[2:])
	length, err := readBERLength(r)
	if err != nil {
		return nil, err
	}
	if r.Len() < length {
		return nil, fmt.Errorf("length mismatch in MCS connect response")
	}
	return parseGCCConferenceCreateResponse(data[len(data)-length:])
}

// parseGCCConferenceCreateResponse finds and parses the security block from the GCC response.
func parseGCCConferenceCreateResponse(data []byte) (*SecurityData, error) {
	offset := -1
	for i := 0; i < len(data)-4; i++ {
		if binary.LittleEndian.Uint16(data[i:]) == 0x0C01 {
			offset = i
			break
		}
	}
	if offset == -1 {
		return nil, fmt.Errorf("could not find server core data block in GCC response")
	}

	r := bytes.NewReader(data[offset:])
	securityData := &SecurityData{}

	for r.Len() >= 4 {
		var headerType, length uint16
		binary.Read(r, binary.LittleEndian, &headerType)
		binary.Read(r, binary.LittleEndian, &length)

		if r.Len() < int(length-4) {
			break
		}

		blockData := make([]byte, length-4)
		r.Read(blockData)

		if headerType == 0x0C02 { // SC_SECURITY
			if len(blockData) >= 8 {
				securityData.EncryptionMethod = binary.LittleEndian.Uint32(blockData[0:])
				securityData.EncryptionLevel = binary.LittleEndian.Uint32(blockData[4:])
				fmt.Printf("Server Security: Method=0x%08X, Level=0x%08X\n",
					securityData.EncryptionMethod, securityData.EncryptionLevel)

				if len(blockData) > 8 {
					serverRandomLen := binary.LittleEndian.Uint32(blockData[8:])
					serverCertLen := binary.LittleEndian.Uint32(blockData[12:])
					if serverCertLen > 0 && 16+serverRandomLen+serverCertLen <= uint32(len(blockData)) {
						certData := blockData[16+serverRandomLen:]
						key, err := parseServerCertificate(certData)
						if err != nil {
							fmt.Printf("Warning: Failed to parse server certificate: %v\n", err)
						} else {
							securityData.ServerPublicKey = key
						}
					}
					if serverRandomLen > 0 && 16+serverRandomLen <= uint32(len(blockData)) {
						securityData.ServerRandom = blockData[16 : 16+serverRandomLen]
					}
				}
			}
		}
	}
	return securityData, nil
}

// parseServerCertificate first tries to parse a standard X.509 certificate,
// and falls back to a proprietary RDP certificate parser if that fails.
func parseServerCertificate(data []byte) (*rsa.PublicKey, error) {
	cert, err := x509.ParseCertificate(data)
	if err == nil {
		if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			fmt.Println("Successfully parsed X.509 certificate.")
			return rsaKey, nil
		}
		return nil, fmt.Errorf("certificate public key is not RSA")
	}

	fmt.Printf("Not a valid X.509 certificate, trying proprietary parser: %v\n", err)
	rsaKey, err := parseProprietaryServerCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse both X.509 and proprietary certificates: %w", err)
	}

	fmt.Println("Successfully parsed proprietary certificate.")
	return rsaKey, nil
}

// parseProprietaryServerCertificate parses the non-X509 cert format.
func parseProprietaryServerCertificate(data []byte) (*rsa.PublicKey, error) {
	r := bytes.NewReader(data)
	var magic, keylen, bitlen, datalen, pubExp uint32

	// Proprietary certs can be wrapped. Find the RSA1 magic number.
	offset := -1
	for i := 0; i < r.Len()-4; i++ {
		if binary.LittleEndian.Uint32(data[i:]) == 0x31415352 { // "RSA1"
			offset = i
			break
		}
	}
	if offset == -1 {
		return nil, fmt.Errorf("could not find RSA1 magic in proprietary certificate")
	}
	r.Seek(int64(offset), io.SeekStart)

	binary.Read(r, binary.LittleEndian, &magic)
	binary.Read(r, binary.LittleEndian, &keylen)
	binary.Read(r, binary.LittleEndian, &bitlen)
	binary.Read(r, binary.LittleEndian, &datalen)
	binary.Read(r, binary.LittleEndian, &pubExp)

	// Per MS-RDPBCGR 2.2.1.4.3.1.1.1, datalen is the length of the modulus.
	if r.Len() < int(datalen) {
		return nil, fmt.Errorf("not enough data for modulus")
	}
	modulusBytes := make([]byte, datalen)
	if _, err := io.ReadFull(r, modulusBytes); err != nil {
		return nil, err
	}

	// Modulus is little-endian, reverse for big.Int
	for i, j := 0, len(modulusBytes)-1; i < j; i, j = i+1, j-1 {
		modulusBytes[i], modulusBytes[j] = modulusBytes[j], modulusBytes[i]
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulusBytes),
		E: int(pubExp),
	}, nil
}

// readBERLength is a helper to read a BER-encoded length
func readBERLength(r *bytes.Reader) (int, error) {
	lenByte, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	if lenByte&0x80 == 0 {
		return int(lenByte), nil
	}
	lenBytes := int(lenByte & 0x7F)
	if lenBytes > r.Len() || lenBytes > 2 {
		return 0, fmt.Errorf("invalid BER length")
	}
	buf := make([]byte, lenBytes)
	r.Read(buf)
	if lenBytes == 1 {
		return int(buf[0]), nil
	}
	return int(binary.BigEndian.Uint16(buf)), nil
}

// parseMCSAttachUserConfirm parses the PER-encoded Attach User Confirm PDU.
func parseMCSAttachUserConfirm(data []byte) (uint16, error) {
	if len(data) < 2 {
		return 0, fmt.Errorf("MCS Attach User Confirm PDU too short")
	}
	if data[0] != 0 {
		return 0, fmt.Errorf("attach user failed with result 0x%x", data[0])
	}
	// The initiator ID is the user ID we need, offset by 1001 for user channels
	return binary.BigEndian.Uint16(data[1:]) + 1001, nil
}

// parseMCSChannelJoinConfirm parses the PER-encoded Channel Join Confirm PDU.
func parseMCSChannelJoinConfirm(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("channel join confirm PDU too short")
	}
	if data[0] != 0 {
		return fmt.Errorf("channel join failed with result 0x%x", data[0])
	}
	return nil
}
