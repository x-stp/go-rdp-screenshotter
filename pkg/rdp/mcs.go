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

func buildMCSConnectInitial(negotiatedProtocol uint32) ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.WriteByte(0x7F)
	buf.WriteByte(0x65)
	lengthPos := buf.Len()
	buf.WriteByte(0x82)
	buf.WriteByte(0x00)
	buf.WriteByte(0x00)

	buf.Write([]byte{0x04, 0x00}) // Calling Domain Selector (Empty)
	buf.Write([]byte{0x04, 0x00}) // Called Domain Selector (Empty)

	buf.Write([]byte{0x01, 0x01, 0x01}) // Upward Flag (TRUE)

	buf.Write([]byte{0x30, 0x19})
	buf.Write([]byte{0x02, 0x01, 0x22})
	buf.Write([]byte{0x02, 0x01, 0x02})
	buf.Write([]byte{0x02, 0x01, 0x00})
	buf.Write([]byte{0x02, 0x01, 0x01})
	buf.Write([]byte{0x02, 0x01, 0x00})
	buf.Write([]byte{0x02, 0x01, 0x01})
	buf.Write([]byte{0x02, 0x02, 0xFF, 0xFF})
	buf.Write([]byte{0x02, 0x01, 0x02})

	buf.Write([]byte{0x30, 0x19})
	buf.Write([]byte{0x02, 0x01, 0x01})
	buf.Write([]byte{0x02, 0x01, 0x01})
	buf.Write([]byte{0x02, 0x01, 0x01})
	buf.Write([]byte{0x02, 0x01, 0x01})
	buf.Write([]byte{0x02, 0x01, 0x00})
	buf.Write([]byte{0x02, 0x01, 0x01})
	buf.Write([]byte{0x02, 0x02, 0x04, 0x20})
	buf.Write([]byte{0x02, 0x01, 0x02})

	buf.Write([]byte{0x30, 0x1C})
	buf.Write([]byte{0x02, 0x02, 0xFF, 0xFF})
	buf.Write([]byte{0x02, 0x02, 0xFC, 0x17})
	buf.Write([]byte{0x02, 0x02, 0xFF, 0xFF})
	buf.Write([]byte{0x02, 0x01, 0x01})
	buf.Write([]byte{0x02, 0x01, 0x00})
	buf.Write([]byte{0x02, 0x01, 0x01})
	buf.Write([]byte{0x02, 0x02, 0xFF, 0xFF})
	buf.Write([]byte{0x02, 0x01, 0x02})
	userData := buildRDPUserData(negotiatedProtocol)
	buf.WriteByte(0x04)
	berEncodeLength(buf, len(userData))
	buf.Write(userData)
	data := buf.Bytes()
	totalLength := len(data) - 5
	fmt.Printf("DEBUG: MCS PDU Length: data=%d, payload=%d\n", len(data), totalLength)
	fmt.Printf("DEBUG: MCS PDU Hex:\n%X\n", data)
	data[lengthPos+1] = byte(totalLength >> 8)
	data[lengthPos+2] = byte(totalLength & 0xFF)
	return data, nil
}

// buildRDPUserData builds the User Data field of the MCS Connect-Initial PDU.
// References: [MS-RDPBCGR] 2.2.1.3, 2.2.1.4
func buildRDPUserData(negotiatedProtocol uint32) []byte {
	// 1. Build Client Core Data (TS_UD_CS_CORE)
	csCore := buildCSCore(negotiatedProtocol)

	// 2. Build Client Security Data (TS_UD_CS_SEC)
	csSecurity := buildCSSecurity(negotiatedProtocol)

	// 3. Build Client Network Data (TS_UD_CS_NET)
	// [MS-RDPBCGR] 2.2.1.3.4
	csNet := buildCSNet()

	// 4. Client Cluster Data (TS_UD_CS_CLUSTER)
	// Optional and not sent by rdp-rs/scrying. Removing to match working client.
	// csCluster := buildCSCluster()

	// Concatenate all data blocks
	userDataBytes := new(bytes.Buffer)
	userDataBytes.Write(csCore)
	userDataBytes.Write(csSecurity)
	userDataBytes.Write(csNet)
	// userDataBytes.Write(csCluster)

	// OID 0.0.20.124.0.1 encoded: 0x00 0x14 0x7C 0x00 0x01
	h224OID := []byte{0x00, 0x14, 0x7C, 0x00, 0x01}

	// Build ConnectData (SEQUENCE)
	// [MS-RDPBCGR] 2.2.1.3: ConnectData ::= SEQUENCE { t124Identifier Key, connectPDU OCTET STRING }
	connectDataContent := new(bytes.Buffer)
	// t124Identifier (Key) -> Tag 0x00 (standard OID)
	connectDataContent.WriteByte(0x00)
	connectDataContent.WriteByte(0x05)
	connectDataContent.Write(h224OID)

	// connectPDU (Octet String) -> Tag 0x04
	connectDataContent.WriteByte(0x04)
	berEncodeLength(connectDataContent, userDataBytes.Len())
	connectDataContent.Write(userDataBytes.Bytes())

	connectData := new(bytes.Buffer)
	connectData.WriteByte(0x30) // SEQUENCE
	berEncodeLength(connectData, connectDataContent.Len())
	connectData.Write(connectDataContent.Bytes())

	// Build GCCUserData (SEQUENCE)
	// [MS-RDPBCGR] 2.2.1.3: GCCUserData ::= SEQUENCE { key GCCObject, value [0] IMPLICIT OCTET STRING OPTIONAL }
	gccUserDataContent := new(bytes.Buffer)
	// key (GCCObject) -> Tag 0x00
	gccUserDataContent.WriteByte(0x00)
	gccUserDataContent.WriteByte(0x05)
	gccUserDataContent.Write(h224OID)

	// value (Octet String) -> Tag 0x04 (containing ConnectData)
	// Note: Although defined as [0] IMPLICIT, standard RDP often uses 0x04.
	gccUserDataContent.WriteByte(0x04)
	berEncodeLength(gccUserDataContent, connectData.Len())
	gccUserDataContent.Write(connectData.Bytes())

	gccUserData := new(bytes.Buffer)
	gccUserData.WriteByte(0x30) // SEQUENCE
	berEncodeLength(gccUserData, gccUserDataContent.Len())
	gccUserData.Write(gccUserDataContent.Bytes())

	// Build userData (SET OF GCCUserData)
	// [MS-RDPBCGR] 2.2.1.3: ConferenceCreateRequest ::= SEQUENCE { userData [3] IMPLICIT SET OF GCCUserData }
	userDataContent := new(bytes.Buffer)
	userDataContent.Write(gccUserData.Bytes())

	userDataSet := new(bytes.Buffer)
	userDataSet.WriteByte(0xA3) // [3] IMPLICIT SET OF (Context 3 + Constructed)
	berEncodeLength(userDataSet, userDataContent.Len())
	userDataSet.Write(userDataContent.Bytes())

	// Build ConferenceCreateRequest (SEQUENCE)
	confCreateReq := new(bytes.Buffer)
	confCreateReq.WriteByte(0x30) // SEQUENCE
	berEncodeLength(confCreateReq, userDataSet.Len())
	confCreateReq.Write(userDataSet.Bytes())

	return confCreateReq.Bytes()
}

func buildCSCore(negotiatedProtocol uint32) []byte {
	// Build the body first to calculate length
	body := new(bytes.Buffer)

	// clientName (32 bytes)
	// [MS-RDPBCGR] 2.2.1.3.2: clientName (32 bytes): A 32-byte array of Unicode characters...
	// "rdp-go" in UTF-16LE
	clientName := "rdp-go"
	nameBytes := make([]byte, 32)
	for i := 0; i < len(clientName) && i < 16; i++ {
		nameBytes[i*2] = clientName[i]
		nameBytes[i*2+1] = 0
	}
	body.Write(nameBytes)

	// keyboardType (4 bytes)
	binary.Write(body, binary.LittleEndian, uint32(0x04)) // IBM PC/XT or compatible (4)
	// keyboardSubType (4 bytes)
	binary.Write(body, binary.LittleEndian, uint32(0))
	// keyboardFunctionKey (4 bytes)
	binary.Write(body, binary.LittleEndian, uint32(12)) // 12 function keys

	// imeFileName (64 bytes)
	body.Write(make([]byte, 64))

	// postBeta2ColorDepth (2 bytes)
	binary.Write(body, binary.LittleEndian, uint16(0xCA03)) // RNS_UD_COLOR_16BPP_565 (0xCA03)

	// clientProductId (2 bytes)
	binary.Write(body, binary.LittleEndian, uint16(1))

	// serialNumber (4 bytes)
	binary.Write(body, binary.LittleEndian, uint32(0))

	// highColorDepth (2 bytes)
	binary.Write(body, binary.LittleEndian, uint16(0x0010)) // 16bpp

	// supportedColorDepths (2 bytes)
	binary.Write(body, binary.LittleEndian, uint16(0x0002)) // 16bpp supported (RNS_UD_16BPP_SUPPORT)

	// earlyCapabilityFlags (2 bytes)
	binary.Write(body, binary.LittleEndian, uint16(0x0001)) // RNS_UD_CS_SUPPORT_ERRINFO_PDU

	// clientDigProductId (64 bytes)
	body.Write(make([]byte, 64))

	// connectionType (1 byte)
	body.WriteByte(0)

	// pad1Octet (1 byte)
	body.WriteByte(0)

	// serverSelectedProtocol (4 bytes)
	binary.Write(body, binary.LittleEndian, negotiatedProtocol)

	// Construct the full CS_CORE block
	buf := new(bytes.Buffer)
	// type (2 bytes)
	binary.Write(buf, binary.LittleEndian, uint16(0xC001)) // TS_UD_CS_CORE (0xC001) - Note: Little Endian 0x01, 0xC0
	// length (2 bytes)
	// Header (8 bytes) + Body Length
	// Header: type(2) + length(2) + version(4) = 8 bytes
	// Pre-header fields:
	// desktopWidth (2), desktopHeight (2), colorDepth (2), SASSequence (2), keyboardLayout (4), clientBuild (4)
	// Total pre-body length: 2+2+2+2+4+4 = 16 bytes
	// Total length = 8 + 16 + body.Len()
	totalLength := 8 + 16 + body.Len()
	binary.Write(buf, binary.LittleEndian, uint16(totalLength))
	// version (4 bytes)
	binary.Write(buf, binary.LittleEndian, uint32(0x00080001))

	// Pre-body fields
	binary.Write(buf, binary.LittleEndian, uint16(1024)) // desktopWidth
	binary.Write(buf, binary.LittleEndian, uint16(768))  // desktopHeight
	binary.Write(buf, binary.LittleEndian, uint16(0xCA03)) // colorDepth (16bpp)
	binary.Write(buf, binary.LittleEndian, uint16(0xAA03)) // SASSequence (RNS_UD_SAS_DEL)
	binary.Write(buf, binary.LittleEndian, uint32(0x0409)) // keyboardLayout (US English)
	binary.Write(buf, binary.LittleEndian, uint32(7601))   // clientBuild

	// Write body
	buf.Write(body.Bytes())

	return buf.Bytes()
}

func buildCSSecurity(negotiatedProtocol uint32) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(0x02C0))
	binary.Write(buf, binary.LittleEndian, uint16(12))

	// [MS-RDPBCGR] 5.4.1: If TLS is selected, EncryptionMethod MUST be 0.
	// negotiatedProtocol > 0 implies TLS/Hybrid.
	if negotiatedProtocol > 0 {
		binary.Write(buf, binary.LittleEndian, uint32(ENCRYPTION_METHOD_NONE))
	} else {
		binary.Write(buf, binary.LittleEndian, uint32(
			ENCRYPTION_METHOD_NONE|ENCRYPTION_METHOD_40BIT|ENCRYPTION_METHOD_56BIT|ENCRYPTION_METHOD_128BIT|ENCRYPTION_METHOD_FIPS))
	}
	binary.Write(buf, binary.LittleEndian, uint32(0))
	return buf.Bytes()
}

func buildCSCluster() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(0x04C0))
	binary.Write(buf, binary.LittleEndian, uint16(12))
	binary.Write(buf, binary.LittleEndian, uint32(0x0D))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	return buf.Bytes()
}

func buildCSNet() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(0x03C0))
	binary.Write(buf, binary.LittleEndian, uint16(8))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	return buf.Bytes()
}

func buildMCSErectDomainRequest() []byte {
	return []byte{0x04, 0x04, 0x00, 0x00, 0x00, 0x00}
}

func buildMCSAttachUserRequest() []byte {
	return []byte{0x28}
}

func buildMCSChannelJoinRequest(userID, channelID uint16) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(0x38)
	offset := userID - 1001
	binary.Write(buf, binary.BigEndian, uint16(offset))
	binary.Write(buf, binary.BigEndian, channelID)

	return buf.Bytes()
}

func buildMCSSendDataRequest(userID, channelID uint16, data []byte) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(0x64)
	binary.Write(buf, binary.BigEndian, userID)
	binary.Write(buf, binary.BigEndian, channelID)
	buf.WriteByte(0x70)
	dataLen := len(data)
	if dataLen < 128 {
		buf.WriteByte(byte(dataLen))
	} else {
		buf.WriteByte(0x81)
		buf.WriteByte(byte(dataLen))
	}
	buf.Write(data)

	return buf.Bytes()
}

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

		if headerType == 0x0C02 {
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

func parseProprietaryServerCertificate(data []byte) (*rsa.PublicKey, error) {
	r := bytes.NewReader(data)
	var magic, keylen, bitlen, datalen, pubExp uint32

	offset := -1
	for i := 0; i < r.Len()-4; i++ {
		if binary.LittleEndian.Uint32(data[i:]) == 0x31415352 {
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

	if r.Len() < int(datalen) {
		return nil, fmt.Errorf("not enough data for modulus")
	}
	modulusBytes := make([]byte, datalen)
	if _, err := io.ReadFull(r, modulusBytes); err != nil {
		return nil, err
	}

	for i, j := 0, len(modulusBytes)-1; i < j; i, j = i+1, j-1 {
		modulusBytes[i], modulusBytes[j] = modulusBytes[j], modulusBytes[i]
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulusBytes),
		E: int(pubExp),
	}, nil
}

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

func parseMCSAttachUserConfirm(data []byte) (uint16, error) {
	if len(data) < 2 {
		return 0, fmt.Errorf("MCS Attach User Confirm PDU too short")
	}

	tag := data[0] >> 2
	if tag == 0x0B {

		result := data[0] & 0x03
		if result != 0 {
			return 0, fmt.Errorf("attach user failed with result 0x%x", result)
		}

		if len(data) < 3 {
			return 0, fmt.Errorf("MCS Attach User Confirm PDU too short for user ID")
		}

		if data[1]&0x80 != 0 {

			userID := uint16(data[1]&0x7F) << 8
			if len(data) >= 3 {
				userID |= uint16(data[2])
			}
			return userID, nil
		} else {

			return uint16(data[1]), nil
		}
	}

	if data[0] == 0x21 && len(data) >= 2 {
		if data[1] == 0x80 {
			return 1002, nil
		}

		userID := uint16(data[1])
		if userID < 1001 {
			userID += 1001
		}
		return userID, nil
	}

	return 0, fmt.Errorf("unknown MCS Attach User Confirm PDU format: %x", data)
}

func parseMCSChannelJoinConfirm(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("channel join confirm PDU too short")
	}

	tag := data[0] >> 2

	if tag == 0x0F {

		result := data[0] & 0x03
		if result != 0 {
			return fmt.Errorf("channel join failed with result 0x%x", result)
		}
		return nil
	}

	if data[0] == 0x3E {

		return nil
	}

	if data[0] == 0x3C {

		return nil
	}

	if data[0] != 0 {

		if (data[0] & 0xFC) == 0x3C {

			result := data[0] & 0x03
			if result != 0 {
				return fmt.Errorf("channel join failed with result 0x%x", result)
			}
			return nil
		}
		return fmt.Errorf("channel join failed with unknown format: 0x%x", data[0])
	}

	return nil
}
