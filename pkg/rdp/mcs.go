















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
	
	buf.Write([]byte{0x04, 0x01, 0x01})
	
	buf.Write([]byte{0x04, 0x01, 0x01})
	
	buf.Write([]byte{0x01, 0x01, 0xFF})
	
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
	buf.Write([]byte{0x02, 0x02, 0x04, 0x00}) 
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
	totalLength := len(data) - 4
	data[lengthPos+1] = byte(totalLength >> 8)
	data[lengthPos+2] = byte(totalLength & 0xFF)
	return data, nil
}


func buildRDPUserData(negotiatedProtocol uint32) []byte {
	
	csCore := buildCSCore(negotiatedProtocol)
	csSecurity := buildCSSecurity()

	
	buf := new(bytes.Buffer)

	
	buf.Write([]byte{0x00, 0x05, 0x00, 0x14, 0x7C, 0x00, 0x01})

	
	
	connectPDUData := new(bytes.Buffer)

	
	connectPDUData.Write([]byte{0x2A, 0x14, 0x76, 0x0A}) 
	connectPDUData.WriteByte(0x01)                       
	connectPDUData.WriteByte(0x01)                       
	connectPDUData.WriteByte(0x00)                       

	
	connectPDUData.WriteByte(0x01) 
	connectPDUData.WriteByte(0xC0) 
	connectPDUData.WriteByte(0x00) 
	connectPDUData.WriteByte(0x4D) 
	connectPDUData.WriteByte(0x63) 
	connectPDUData.WriteByte(0x44) 
	connectPDUData.WriteByte(0x6E) 

	
	clientDataLen := len(csCore) + len(csSecurity)
	binary.Write(connectPDUData, binary.BigEndian, uint16(clientDataLen))

	
	connectPDUData.Write(csCore)
	connectPDUData.Write(csSecurity)

	
	connectPDUBytes := connectPDUData.Bytes()
	if len(connectPDUBytes) < 128 {
		buf.WriteByte(byte(len(connectPDUBytes)))
	} else {
		buf.WriteByte(0x81) 
		buf.WriteByte(byte(len(connectPDUBytes)))
	}
	buf.Write(connectPDUBytes)

	return buf.Bytes()
}


func buildCSCore(negotiatedProtocol uint32) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(0x01C0))     
	binary.Write(buf, binary.LittleEndian, uint16(216))        
	binary.Write(buf, binary.LittleEndian, uint32(0x00080001)) 
	binary.Write(buf, binary.LittleEndian, uint16(1024))       
	binary.Write(buf, binary.LittleEndian, uint16(768))        
	binary.Write(buf, binary.LittleEndian, uint16(0xCA01))
	binary.Write(buf, binary.LittleEndian, uint16(0xAA03)) 
	binary.Write(buf, binary.LittleEndian, uint32(0x409))  
	binary.Write(buf, binary.LittleEndian, uint32(7601))   
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
	binary.Write(buf, binary.LittleEndian, uint16(16)) 
	binary.Write(buf, binary.LittleEndian, uint16(1))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	binary.Write(buf, binary.LittleEndian, uint16(16)) 
	binary.Write(buf, binary.LittleEndian, uint16(1))
	binary.Write(buf, binary.LittleEndian, uint16(1))
	buf.Write(make([]byte, 64))
	buf.WriteByte(0x07) 
	buf.WriteByte(0)
	binary.Write(buf, binary.LittleEndian, negotiatedProtocol)
	return buf.Bytes()
}


func buildCSSecurity() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(0x02C0))
	binary.Write(buf, binary.LittleEndian, uint16(12))
	
	binary.Write(buf, binary.LittleEndian, uint32(
		ENCRYPTION_METHOD_NONE|ENCRYPTION_METHOD_40BIT|ENCRYPTION_METHOD_56BIT|ENCRYPTION_METHOD_128BIT|ENCRYPTION_METHOD_FIPS))
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
