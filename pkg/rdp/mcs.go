package rdp

import (
	"bytes"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"slices"

	"github.com/x-stp/rdp-screenshotter-go/pkg/rdp/per"
	"github.com/zmap/zcrypto/x509"
)

// PER primitives (ITU-T X.691) live in pkg/rdp/per; mcs aliases those.
var (
	perWriteLength    = per.WriteLength
	perWriteInteger   = per.WriteInteger
	perWriteInteger16 = per.WriteInteger16
)

// buildMCSConnectInitial assembles the T.125 MCS Connect-Initial PDU
// ([ITU-T T.125] §11.1; [MS-RDPBCGR] §2.2.1.3) inside a BER application[101]
// envelope. The body order is fixed by the spec:
//
//	callingDomainSelector (OCTET STRING "\x01")
//	calledDomainSelector  (OCTET STRING "\x01")
//	upwardFlag            (BOOLEAN TRUE)
//	targetParameters      (DomainParameters, the client's wishlist)
//	minimumParameters     (DomainParameters, what the client will accept)
//	maximumParameters     (DomainParameters, the spec ceiling)
//	userData              (OCTET STRING, our GCC ConferenceCreateRequest)
func buildMCSConnectInitial(negotiatedProtocol uint32) ([]byte, error) {
	buf := new(bytes.Buffer)
	lengthPos := writeBEROuterEnvelope(buf)

	writeOctetString(buf, []byte{0x01}) // callingDomainSelector
	writeOctetString(buf, []byte{0x01}) // calledDomainSelector
	buf.Write([]byte{0x01, 0x01, 0xFF}) // upwardFlag = TRUE
	writeMCSDomainParameters(buf, dpTarget)
	writeMCSDomainParameters(buf, dpMinimum)
	writeMCSDomainParameters(buf, dpMaximum)
	writeMCSUserData(buf, buildRDPUserData(negotiatedProtocol))

	data := buf.Bytes()
	// Backfill the outer length (3-byte 0x82 long form, big-endian uint16).
	totalLength := len(data) - 5
	data[lengthPos+1] = byte(totalLength >> 8)
	data[lengthPos+2] = byte(totalLength & 0xFF)
	return data, nil
}

// writeBEROuterEnvelope writes the Connect-Initial application[101] tag
// (0x7F 0x65) and a placeholder 3-byte long-form length (0x82 hi lo) so the
// caller can backfill once the body length is known. Returns the byte offset
// of the 0x82 byte for the backfill.
func writeBEROuterEnvelope(buf *bytes.Buffer) (lengthPos int) {
	buf.Write([]byte{0x7F, 0x65})
	lengthPos = buf.Len()
	buf.Write([]byte{0x82, 0x00, 0x00})
	return lengthPos
}

// writeOctetString emits a BER OCTET STRING (tag 0x04). Length must be < 128
// since we only use it for fixed 1-byte selectors here.
func writeOctetString(buf *bytes.Buffer, data []byte) {
	buf.WriteByte(0x04)
	buf.WriteByte(byte(len(data)))
	buf.Write(data)
}

// mcsDomainParameters is the T.125 SET of MCS sizing constraints. Each field
// is a u16 because the spec lets the wire integer use 1 or 2 octets depending
// on magnitude (BER INTEGER is minimum-octets); writeMCSDomainParameters
// picks the right width per value to match mstsc byte-for-byte.
type mcsDomainParameters struct {
	maxChannelIDs uint16 // max simultaneous MCS channels we'll join
	maxUserIDs    uint16 // max simultaneous attached MCS users
	maxTokenIDs   uint16
	numPriorities uint16
	minThroughput uint16
	maxHeight     uint16 // tree height for cascaded MCS (always 1 for clients)
	maxMCSPDU     uint16 // bytes
	protocolVer   uint16
}

var (
	dpTarget  = mcsDomainParameters{0x0022, 0x0002, 0x0000, 0x0001, 0x0000, 0x0001, 0xFFFF, 0x0002}
	dpMinimum = mcsDomainParameters{0x0001, 0x0001, 0x0001, 0x0001, 0x0000, 0x0001, 0x0420, 0x0002} // 0x420 = 1056 = T.125 minimum
	dpMaximum = mcsDomainParameters{0xFFFF, 0xFC17, 0xFFFF, 0x0001, 0x0000, 0x0001, 0xFFFF, 0x0002}
)

// writeMCSDomainParameters emits a T.125 DomainParameters SEQUENCE. We don't
// care about strict BER signed-integer rules: every value here is a small
// non-negative magnitude, so 1-byte encoding is fine for v <= 0xFF and
// 2-byte otherwise. This matches mstsc on the wire.
func writeMCSDomainParameters(buf *bytes.Buffer, dp mcsDomainParameters) {
	body := new(bytes.Buffer)
	for _, v := range []uint16{dp.maxChannelIDs, dp.maxUserIDs, dp.maxTokenIDs, dp.numPriorities, dp.minThroughput, dp.maxHeight, dp.maxMCSPDU, dp.protocolVer} {
		writeBERIntegerCompact(body, v)
	}
	buf.WriteByte(0x30)
	buf.WriteByte(byte(body.Len()))
	buf.Write(body.Bytes())
}

// writeBERIntegerCompact writes a BER INTEGER (tag 0x02) using 1 or 2 octets
// depending on whether v fits in a byte. mstsc-compatible.
func writeBERIntegerCompact(buf *bytes.Buffer, v uint16) {
	if v <= 0xFF {
		buf.Write([]byte{0x02, 0x01, byte(v)})
	} else {
		buf.Write([]byte{0x02, 0x02, byte(v >> 8), byte(v)})
	}
}

// writeMCSUserData wraps the GCC ConferenceCreateRequest payload in the
// Connect-Initial userData OCTET STRING (tag 0x04, BER long-form length).
func writeMCSUserData(buf *bytes.Buffer, userData []byte) {
	buf.WriteByte(0x04)
	buf.Write(appendBERLength(nil, len(userData)))
	buf.Write(userData)
}

// buildRDPUserData builds the userData OCTET STRING that the
// MCS Connect-Initial PDU carries: a T.124 GCC ConferenceCreateRequest
// ([ITU-T T.124] §8.7) wrapping the four client data blocks in canonical
// order (CS_CORE, CS_SECURITY, CS_NET, CS_CLUSTER) per [MS-RDPBCGR] §2.2.1.3.
func buildRDPUserData(negotiatedProtocol uint32) []byte {
	clientBlocks := concatBytes(
		buildCSCore(negotiatedProtocol),
		buildCSSecurity(negotiatedProtocol),
		buildCSNet(),
		buildCSCluster(),
	)
	connectPDU := buildGCCConnectPDU(clientBlocks)

	buf := new(bytes.Buffer)
	buf.Write(t124ConnectDataPrefix)
	writePERLengthShortLong(buf, len(connectPDU))
	buf.Write(connectPDU)
	return buf.Bytes()
}

// t124ConnectDataPrefix is the fixed T.124 ConnectData OBJECT-IDENTIFIER +
// version header that prefaces every GCC ConferenceCreateRequest emitted by
// an MS-RDPBCGR client per §3.2.5.3.3.
var t124ConnectDataPrefix = []byte{0x00, 0x05, 0x00, 0x14, 0x7C, 0x00, 0x01}

// buildGCCConnectPDU assembles the GCC ConferenceCreateRequest body around
// the already-serialised RDP client data blocks. Layout per [MS-RDPBCGR]
// §4.1.3 + [ITU-T T.124] §8.7.
func buildGCCConnectPDU(clientBlocks []byte) []byte {
	buf := new(bytes.Buffer)
	// Extension + CHOICE + ConferenceCreateRequest flags / ConferenceName::
	// numeric value "1" / termination method / userData CHOICE = h221.
	buf.Write([]byte{
		0x00, 0x08, // extension + ConferenceCreateRequest flags
		0x00, 0x10, // ConferenceName::numeric length=1, value="1"
		0x00, 0x01, // termination method + padding
		0xC0, 0x00, // userData present + h221NonStandard CHOICE + length=4
	})
	// H.221 nonstandard key fixed by [MS-RDPBCGR] §3.2.5.3.3 for the
	// client side ("Duca" in ASCII).
	buf.Write([]byte{0x44, 0x75, 0x63, 0x61})
	writePERLengthShortLong(buf, len(clientBlocks))
	buf.Write(clientBlocks)
	return buf.Bytes()
}

// writePERLengthShortLong emits a T.124 PER length determinant in either
// short (1 byte, n < 128) or long (2 bytes, top bit of byte 0 set) form.
// The fragmented form (n >= 16K) is intentionally not implemented.
func writePERLengthShortLong(buf *bytes.Buffer, n int) {
	if n < 128 {
		buf.WriteByte(byte(n))
		return
	}
	buf.WriteByte(byte(0x80 | (n >> 8)))
	buf.WriteByte(byte(n))
}

// concatBytes returns the concatenation of every supplied slice. Used to
// avoid the four-line `b := new(bytes.Buffer); b.Write(...); ...` pattern
// when we just want a fresh contiguous slice.
func concatBytes(parts ...[]byte) []byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func buildCSCore(negotiatedProtocol uint32) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(0xC001))
	binary.Write(buf, binary.LittleEndian, uint16(0)) // placeholder, filled below
	binary.Write(buf, binary.LittleEndian, uint32(0x00080004))
	binary.Write(buf, binary.LittleEndian, uint16(1024))
	binary.Write(buf, binary.LittleEndian, uint16(768))
	binary.Write(buf, binary.LittleEndian, uint16(0xCA01))
	binary.Write(buf, binary.LittleEndian, uint16(0xAA03))
	binary.Write(buf, binary.LittleEndian, uint32(0x409))
	binary.Write(buf, binary.LittleEndian, uint32(2600))
	clientName := "rdp-go"
	for i := range 16 {
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
	buf.Write(make([]byte, 64)) // imeFileName[64]
	binary.Write(buf, binary.LittleEndian, uint16(postBeta2ColorDepth))
	binary.Write(buf, binary.LittleEndian, uint16(1)) // clientProductId
	binary.Write(buf, binary.LittleEndian, uint32(0)) // serialNumber
	// highColorDepth / supportedColorDepths / earlyCapabilityFlags must be
	// consistent with a modern mstsc, or Server 2012R2+ RSTs the connection
	// right after MCS Connect Initial ([MS-RDPBCGR] §2.2.1.3.2). We advertise
	// 24bpp preferred, all depths supported (15/16/24/32), and set
	// VALID_CONNECTION_TYPE alongside the connectionType byte below.
	// We deliberately do NOT set RNS_UD_CS_SUPPORT_DYNVC_GFX_PROTOCOL so the
	// server keeps using slow/fast-path bitmap updates our decoder handles.
	binary.Write(buf, binary.LittleEndian, uint16(highColorDepth24bpp))
	binary.Write(buf, binary.LittleEndian, uint16(supportAllColorDepths))
	binary.Write(buf, binary.LittleEndian, uint16(earlyCapErrInfo|earlyCapValidConnType))
	buf.Write(make([]byte, 64)) // clientDigProductId[64]
	buf.WriteByte(connectionTypeLAN)
	buf.WriteByte(0) // pad1octet
	binary.Write(buf, binary.LittleEndian, negotiatedProtocol)
	data := buf.Bytes()
	binary.LittleEndian.PutUint16(data[2:4], uint16(len(data)))
	return data
}

// TS_UD_CS_CORE field values per [MS-RDPBCGR] §2.2.1.3.2.
const (
	postBeta2ColorDepth   = 0xCA01 // RNS_UD_COLOR_8BPP (legacy field, ignored by modern servers)
	highColorDepth24bpp   = 0x0018 // 24bpp preferred session depth
	supportAllColorDepths = 0x000f // RNS_UD_{15,16,24,32}BPP_SUPPORT
	earlyCapErrInfo       = 0x0001 // RNS_UD_CS_SUPPORT_ERRINFO_PDU
	earlyCapValidConnType = 0x0020 // RNS_UD_CS_VALID_CONNECTION_TYPE
	connectionTypeLAN     = 0x06   // CONNECTION_TYPE_LAN
)

func buildCSSecurity(negotiatedProtocol uint32) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(0xC002))
	binary.Write(buf, binary.LittleEndian, uint16(12))

	// When TLS or NLA is negotiated, encryption is handled by TLS layer; use 0
	encryptionMethods := uint32(ENCRYPTION_METHOD_NONE | ENCRYPTION_METHOD_40BIT | ENCRYPTION_METHOD_56BIT | ENCRYPTION_METHOD_128BIT | ENCRYPTION_METHOD_FIPS)
	if negotiatedProtocol&(0x01|0x02|0x08) != 0 { // PROTOCOL_SSL | PROTOCOL_HYBRID | PROTOCOL_HYBRID_EX
		encryptionMethods = 0
	}
	binary.Write(buf, binary.LittleEndian, uint32(encryptionMethods))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	return buf.Bytes()
}

// buildCSCluster emits TS_UD_CS_CLUSTER per [MS-RDPBCGR] §2.2.1.3.5 with
// REDIRECTION_SUPPORTED|REDIRECTION_VERSION5; flags = 0x11 = 0x01|(4<<2).
func buildCSCluster() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(0xC004))
	binary.Write(buf, binary.LittleEndian, uint16(12))
	binary.Write(buf, binary.LittleEndian, uint32(0x11)) /* REDIRECTION_SUPPORTED | (VERSION5 << 2) */
	binary.Write(buf, binary.LittleEndian, uint32(0))
	return buf.Bytes()
}

func buildCSNet() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint16(0xC003))
	binary.Write(buf, binary.LittleEndian, uint16(8))
	binary.Write(buf, binary.LittleEndian, uint32(0))
	return buf.Bytes()
}

// MCS DomainMCSPDU choice codes per T.125. The first byte on the wire is
// (choice << 2) | options.
const (
	mcsDomainErectDomainRequest = 1
	mcsDomainAttachUserRequest  = 10
	mcsDomainAttachUserConfirm  = 11
	mcsDomainChannelJoinRequest = 14
	mcsDomainChannelJoinConfirm = 15
	mcsDomainSendDataRequest    = 25
	mcsDomainSendDataIndication = 26
)

const mcsBaseChannelID = 1001

// buildMCSErectDomainRequest emits T.125 ErectDomainRequest
// [APPLICATION 1] SEQUENCE { subHeight, subInterval INTEGER (0) } as
// 04 01 00 01 00.
func buildMCSErectDomainRequest() []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(byte(mcsDomainErectDomainRequest) << 2)
	perWriteInteger(buf, 0)
	perWriteInteger(buf, 0)
	return buf.Bytes()
}

// buildMCSAttachUserRequest emits the T.125 AttachUserRequest choice byte.
func buildMCSAttachUserRequest() []byte {
	return []byte{byte(mcsDomainAttachUserRequest) << 2}
}

// buildMCSChannelJoinRequest emits T.125 ChannelJoinRequest
// { initiator UserId(1001..), channelId ChannelId }.
func buildMCSChannelJoinRequest(userID, channelID uint16) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(byte(mcsDomainChannelJoinRequest) << 2)
	perWriteInteger16(buf, userID, mcsBaseChannelID)
	perWriteInteger16(buf, channelID, 0)
	return buf.Bytes()
}

// buildMCSSendDataRequest emits T.125 SendDataRequest
// { initiator, channelId, dataPriority|segmentation = 0x70, userData }.
func buildMCSSendDataRequest(userID, channelID uint16, data []byte) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(byte(mcsDomainSendDataRequest) << 2)
	perWriteInteger16(buf, userID, mcsBaseChannelID)
	perWriteInteger16(buf, channelID, 0)
	buf.WriteByte(0x70)
	perWriteLength(buf, len(data))
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
	// Check MCS Connect-Response result code (first field after BER header)
	gccData := data[len(data)-length:]
	if len(gccData) >= 3 && gccData[0] == 0x0a { // ENUMERATED = result
		resultVal := gccData[2]
		if resultVal != 0 {
			return nil, fmt.Errorf("MCS Connect-Response rejected: result=%d", resultVal)
		}
	}
	return parseGCCConferenceCreateResponse(gccData)
}

// Server data block type IDs per [MS-RDPBCGR] §2.2.1.4.
const (
	scCore     uint16 = 0x0C01
	scSecurity uint16 = 0x0C02
)

// parseGCCConferenceCreateResponse walks the server-side GCC user-data blocks
// produced in the MCS Connect-Response. We're only interested in SC_SECURITY,
// which carries the EncryptionMethod / EncryptionLevel and (for standard RDP
// security) the ServerRandom + ServerCertificate.
func parseGCCConferenceCreateResponse(data []byte) (*SecurityData, error) {
	blocks, err := findServerDataBlocks(data)
	if err != nil {
		return nil, err
	}
	out := &SecurityData{}
	for _, blk := range blocks {
		if blk.headerType == scSecurity {
			parseServerSecurityBlock(blk.data, out)
		}
	}
	return out, nil
}

type serverDataBlock struct {
	headerType uint16
	data       []byte
}

// findServerDataBlocks walks the SC_* blocks starting at the first SC_CORE
// header found in data. Returns the parsed block list (each with header
// stripped). Truncated tail blocks are dropped silently to match the
// best-effort parsing the rest of this file uses.
func findServerDataBlocks(data []byte) ([]serverDataBlock, error) {
	offset := -1
	for i := 0; i < len(data)-4; i++ {
		if binary.LittleEndian.Uint16(data[i:]) == scCore {
			offset = i
			break
		}
	}
	if offset == -1 {
		return nil, fmt.Errorf("could not find server core data block in GCC response")
	}

	var out []serverDataBlock
	r := bytes.NewReader(data[offset:])
	for r.Len() >= 4 {
		var headerType, length uint16
		binary.Read(r, binary.LittleEndian, &headerType)
		binary.Read(r, binary.LittleEndian, &length)
		if r.Len() < int(length-4) {
			break
		}
		body := make([]byte, length-4)
		r.Read(body)
		out = append(out, serverDataBlock{headerType: headerType, data: body})
	}
	return out, nil
}

// parseServerSecurityBlock extracts the SC_SECURITY fields per [MS-RDPBCGR]
// §2.2.1.4.3. The block layout is:
//
//	encryptionMethod(4) encryptionLevel(4)
//	[ serverRandomLen(4) serverCertLen(4) serverRandom(serverRandomLen)
//	  serverCertificate(serverCertLen) ]   (only when EncryptionMethod != NONE)
func parseServerSecurityBlock(blockData []byte, out *SecurityData) {
	if len(blockData) < 8 {
		return
	}
	out.EncryptionMethod = binary.LittleEndian.Uint32(blockData[0:])
	out.EncryptionLevel = binary.LittleEndian.Uint32(blockData[4:])
	if len(blockData) <= 16 {
		return
	}
	serverRandomLen := binary.LittleEndian.Uint32(blockData[8:])
	serverCertLen := binary.LittleEndian.Uint32(blockData[12:])
	if serverRandomLen > 0 && 16+serverRandomLen <= uint32(len(blockData)) {
		out.ServerRandom = blockData[16 : 16+serverRandomLen]
	}
	if serverCertLen > 0 && 16+serverRandomLen+serverCertLen <= uint32(len(blockData)) {
		certData := blockData[16+serverRandomLen : 16+serverRandomLen+serverCertLen]
		if key, err := parseServerCertificate(certData); err != nil {
			head := certData
			if len(head) > 32 {
				head = head[:32]
			}
			Logger.Warn().Err(err).Hex("head", head).Msg("parse server certificate failed")
		} else {
			out.ServerPublicKey = key
		}
	}
}

// parseServerCertificate decodes a TS_SERVER_CERTIFICATE per MS-RDPBCGR
// 2.2.1.4.3. dwVersion picks one of two layouts:
//
//	0x00000001 -> Proprietary Server Certificate (2.2.1.4.3.1)
//	0x00000002 -> Server X.509 Certificate Chain (2.2.1.4.3.2)
//
// The high bit of dwVersion (TS_CERTIFICATE_PERMANENTLY_ISSUED, 0x80000000)
// is informational and is masked off before dispatching.
func parseServerCertificate(data []byte) (*rsa.PublicKey, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("server certificate too short: %d bytes", len(data))
	}
	dwVersion := binary.LittleEndian.Uint32(data[0:4]) & 0x7FFFFFFF
	switch dwVersion {
	case 0x00000001:
		return parseProprietaryServerCertificate(data[4:])
	case 0x00000002:
		return parseX509CertificateChain(data[4:])
	default:
		return nil, fmt.Errorf("unsupported server certificate dwVersion=0x%08x", dwVersion)
	}
}

// parseX509CertificateChain decodes TS_X509_CERTIFICATE_CHAIN
// { NumCertBlobs(4), { cbCert(4), abCert }... } per [MS-RDPBCGR] §2.2.1.4.3.2.
// The last cert is the server's exchange/license cert.
func parseX509CertificateChain(data []byte) (*rsa.PublicKey, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("x509 chain header truncated")
	}
	numCerts := binary.LittleEndian.Uint32(data[0:4])
	if numCerts == 0 || numCerts > 16 {
		return nil, fmt.Errorf("x509 chain implausible NumCertBlobs=%d", numCerts)
	}
	blobs := make([][]byte, 0, numCerts)
	off := uint32(4)
	for i := range numCerts {
		if uint32(len(data)) < off+4 {
			return nil, fmt.Errorf("x509 chain: truncated cbCert[%d]", i)
		}
		cbCert := binary.LittleEndian.Uint32(data[off : off+4])
		off += 4
		if uint32(len(data)) < off+cbCert {
			return nil, fmt.Errorf("x509 chain: truncated abCert[%d] (cbCert=%d)", i, cbCert)
		}
		blobs = append(blobs, data[off:off+cbCert])
		off += cbCert
	}
	leaf := blobs[len(blobs)-1]
	key, err := rsaPublicKeyFromCertDER(leaf)
	if err != nil {
		return nil, fmt.Errorf("x509 chain: extract leaf cert public key: %w", err)
	}
	return key, nil
}

// rsaPublicKeyFromCertDER extracts the RSA public key from an X.509 DER cert
// without trusting the AlgorithmIdentifier OID. Some RDP servers wrap the
// modulus/exponent under a Microsoft-specific OID (e.g. 1.3.6.1.4.1.311.31.1)
// that zcrypto refuses to parse; we walk the DER tags down to the
// SubjectPublicKeyInfo BIT STRING and unmarshal it as PKCS#1 RSAPublicKey.
func rsaPublicKeyFromCertDER(der []byte) (*rsa.PublicKey, error) {
	if cert, err := x509.ParseCertificate(der); err == nil && cert.PublicKey != nil {
		if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return rsaKey, nil
		}
	}
	tbs, err := derInner(der, 0x30)
	if err != nil {
		return nil, fmt.Errorf("der: outer SEQUENCE: %w", err)
	}
	tbsContent, err := derInner(tbs, 0x30)
	if err != nil {
		return nil, fmt.Errorf("der: TBSCertificate SEQUENCE: %w", err)
	}
	rest := tbsContent
	if len(rest) > 0 && rest[0] == 0xA0 {
		_, _, after, err := derSplit(rest)
		if err != nil {
			return nil, fmt.Errorf("der: skip [0] Version: %w", err)
		}
		rest = after
	}
	for _, name := range []string{"serialNumber", "signature", "issuer", "validity", "subject"} {
		_, _, after, err := derSplit(rest)
		if err != nil {
			return nil, fmt.Errorf("der: skip %s: %w", name, err)
		}
		rest = after
	}
	tag, spkiContent, _, err := derSplit(rest)
	if err != nil || tag != 0x30 {
		return nil, fmt.Errorf("der: expected SubjectPublicKeyInfo SEQUENCE (tag=0x%02x): %w", tag, err)
	}
	algRest := spkiContent
	_, _, afterAlg, err := derSplit(algRest)
	if err != nil {
		return nil, fmt.Errorf("der: skip SPKI algorithm: %w", err)
	}
	bsTag, bsContent, _, err := derSplit(afterAlg)
	if err != nil || bsTag != 0x03 {
		return nil, fmt.Errorf("der: expected BIT STRING for subjectPublicKey (tag=0x%02x)", bsTag)
	}
	if len(bsContent) < 1 {
		return nil, fmt.Errorf("der: empty BIT STRING")
	}
	bits := bsContent[1:]
	var pkcs1 struct {
		N *big.Int
		E int
	}
	if _, err := asn1.Unmarshal(bits, &pkcs1); err != nil {
		return nil, fmt.Errorf("pkcs1 unmarshal: %w", err)
	}
	if pkcs1.N == nil || pkcs1.N.Sign() <= 0 || pkcs1.E <= 0 {
		return nil, fmt.Errorf("invalid pkcs1 modulus/exponent")
	}
	return &rsa.PublicKey{N: pkcs1.N, E: pkcs1.E}, nil
}

// derSplit reads one ASN.1 DER TLV from data and returns
// (tag, content, restAfterThisTLV, err).
func derSplit(data []byte) (byte, []byte, []byte, error) {
	if len(data) < 2 {
		return 0, nil, nil, fmt.Errorf("der: header truncated")
	}
	tag := data[0]
	lenByte := data[1]
	var contentLen int
	var headerLen int
	if lenByte&0x80 == 0 {
		contentLen = int(lenByte)
		headerLen = 2
	} else {
		nLen := int(lenByte & 0x7F)
		if nLen == 0 || nLen > 4 || len(data) < 2+nLen {
			return 0, nil, nil, fmt.Errorf("der: bad long-form length nLen=%d", nLen)
		}
		for i := range nLen {
			contentLen = (contentLen << 8) | int(data[2+i])
		}
		headerLen = 2 + nLen
	}
	if len(data) < headerLen+contentLen {
		return 0, nil, nil, fmt.Errorf("der: content truncated (need %d, have %d)", contentLen, len(data)-headerLen)
	}
	return tag, data[headerLen : headerLen+contentLen], data[headerLen+contentLen:], nil
}

// derInner returns the content bytes of the outermost TLV in data, asserting
// its tag matches expected.
func derInner(data []byte, expected byte) ([]byte, error) {
	tag, content, _, err := derSplit(data)
	if err != nil {
		return nil, err
	}
	if tag != expected {
		return nil, fmt.Errorf("der: expected tag 0x%02x, got 0x%02x", expected, tag)
	}
	return content, nil
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

	slices.Reverse(modulusBytes)
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

// parseMCSAttachUserConfirm per T.125 AttachUserConfirm:
//
//	[APPLICATION 11] SEQUENCE {
//	    result    Result,
//	    initiator UserId OPTIONAL
//	}
//
// First byte: (choice<<2)|options where options bit 1 indicates initiator
// is present. result is an ENUMERATED (single byte). Initiator is a UserId
// (16-bit BE with offset MCS_BASE_CHANNEL_ID).
func parseMCSAttachUserConfirm(data []byte) (uint16, error) {
	if len(data) < 2 {
		return 0, fmt.Errorf("MCS Attach User Confirm PDU too short")
	}
	choice := data[0] >> 2
	if choice != mcsDomainAttachUserConfirm {
		return 0, fmt.Errorf("expected AttachUserConfirm, got choice=%d", choice)
	}
	hasInitiator := data[0]&0x02 != 0
	result := data[1]
	if result != 0 {
		return 0, fmt.Errorf("attach user rejected with result=%d", result)
	}
	if !hasInitiator {
		return 0, fmt.Errorf("AttachUserConfirm missing initiator")
	}
	if len(data) < 4 {
		return 0, fmt.Errorf("AttachUserConfirm truncated; need 4 bytes, got %d", len(data))
	}
	offset := binary.BigEndian.Uint16(data[2:4])
	return offset + mcsBaseChannelID, nil
}

// parseMCSChannelJoinConfirm per T.125 ChannelJoinConfirm:
//
//	[APPLICATION 15] SEQUENCE {
//	    result      Result,
//	    initiator   UserId,
//	    requested   ChannelId,
//	    channelId   ChannelId OPTIONAL
//	}
//
// Layout: 1 byte choice|opts, 1 byte result, 2 bytes initiator, 2 bytes
// requested, 2 bytes channelId (optional). We only check the result.
func parseMCSChannelJoinConfirm(data []byte) error {
	if len(data) < 6 {
		return fmt.Errorf("channel join confirm PDU too short: %d bytes", len(data))
	}
	choice := data[0] >> 2
	if choice != mcsDomainChannelJoinConfirm {
		return fmt.Errorf("expected ChannelJoinConfirm, got choice=%d", choice)
	}
	if result := data[1]; result != 0 {
		return fmt.Errorf("channel join rejected with result=%d", result)
	}
	return nil
}

// mcsSendDataIndication is a parsed T.125 SendDataIndication header.
type mcsSendDataIndication struct {
	Initiator uint16
	ChannelID uint16
	UserData  []byte
}

// parseMCSSendDataIndication parses an inbound SendDataIndication PDU.
// Layout per T.125: choice byte | (initiator BE u16 + 1001) | (channel BE u16)
// | dataPriority+segmentation byte | PER length | user data.
func parseMCSSendDataIndication(data []byte) (*mcsSendDataIndication, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("SendDataIndication too short: %d bytes", len(data))
	}
	choice := data[0] >> 2
	if choice != mcsDomainSendDataIndication {
		return nil, fmt.Errorf("expected SendDataIndication, got choice=%d", choice)
	}
	initiator := binary.BigEndian.Uint16(data[1:3]) + mcsBaseChannelID
	channel := binary.BigEndian.Uint16(data[3:5])
	// data[5] is dataPriority + segmentation
	r := bytes.NewReader(data[6:])
	ln, err := readPERLength(r)
	if err != nil {
		return nil, fmt.Errorf("SendDataIndication user data length: %w", err)
	}
	remaining := make([]byte, r.Len())
	r.Read(remaining)
	if len(remaining) < ln {
		// Some servers pad; trust the remaining bytes.
		ln = len(remaining)
	}
	return &mcsSendDataIndication{
		Initiator: initiator,
		ChannelID: channel,
		UserData:  remaining[:ln],
	}, nil
}

// readPERLength reads a PER aligned length determinant.
func readPERLength(r *bytes.Reader) (int, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	if b&0x80 == 0 {
		return int(b), nil
	}
	b2, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	return int(b&0x7F)<<8 | int(b2), nil
}
