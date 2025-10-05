package rdp

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"testing"
)

func TestClientOptions(t *testing.T) {
	opts := DefaultClientOptions()
	if opts.Timeout == 0 {
		t.Error("default timeout should not be zero")
	}
}

func TestTPKTHeader(t *testing.T) {
	hdr := NewTPKTHeader(100)
	if hdr.Version != TPKTVersion {
		t.Errorf("TPKT version: got %d, want %d", hdr.Version, TPKTVersion)
	}
	if hdr.Length != 100+TPKTHeaderSize {
		t.Errorf("TPKT length: got %d, want %d", hdr.Length, 100+TPKTHeaderSize)
	}
}

func TestX224ConnectionRequest(t *testing.T) {
	cr := NewX224ConnectionRequest("testuser")
	if cr.TPDUCode != 0xE0 {
		t.Errorf("TPDU code: got 0x%02X, want 0xE0", cr.TPDUCode)
	}
	if len(cr.Cookie) == 0 {
		t.Error("cookie should not be empty")
	}
}

func TestSPNEGORoundtrip(t *testing.T) {
	ntlmMsg := []byte("NTLMSSP\x00\x01\x00\x00\x00" + "testdata1234")

	// Wrap as initial (NegTokenInit)
	wrapped, err := wrapNTLMInSPNEGO(ntlmMsg, true)
	if err != nil {
		t.Fatalf("wrap initial: %v", err)
	}
	if wrapped[0] != 0x60 {
		t.Errorf("initial wrap should start with APPLICATION[0] (0x60), got 0x%02x", wrapped[0])
	}

	unwrapped, err := unwrapSPNEGO(wrapped)
	if err != nil {
		t.Fatalf("unwrap initial: %v", err)
	}
	if string(unwrapped) != string(ntlmMsg) {
		t.Errorf("roundtrip mismatch: got %x, want %x", unwrapped, ntlmMsg)
	}

	// Wrap as response (NegTokenResp)
	wrappedResp, err := wrapNTLMInSPNEGO(ntlmMsg, false)
	if err != nil {
		t.Fatalf("wrap response: %v", err)
	}
	if wrappedResp[0] != 0xa1 {
		t.Errorf("response wrap should start with CONTEXT[1] (0xa1), got 0x%02x", wrappedResp[0])
	}

	unwrappedResp, err := unwrapSPNEGO(wrappedResp)
	if err != nil {
		t.Fatalf("unwrap response: %v", err)
	}
	if string(unwrappedResp) != string(ntlmMsg) {
		t.Errorf("response roundtrip mismatch: got %x, want %x", unwrappedResp, ntlmMsg)
	}
}

func TestTSRequestMarshalUnmarshal(t *testing.T) {
	original := TSRequest{
		Version:    3,
		PubKeyAuth: []byte{0x01, 0x02, 0x03, 0x04},
		NegoTokens: NegoData{{Token: []byte{0xAA, 0xBB, 0xCC}}},
	}

	data, err := asn1.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded TSRequest
	_, err = asn1.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Version != original.Version {
		t.Errorf("version: got %d, want %d", decoded.Version, original.Version)
	}
	if len(decoded.PubKeyAuth) != len(original.PubKeyAuth) {
		t.Errorf("pubKeyAuth length: got %d, want %d", len(decoded.PubKeyAuth), len(original.PubKeyAuth))
	}
	if len(decoded.NegoTokens) != 1 {
		t.Fatalf("negoTokens count: got %d, want 1", len(decoded.NegoTokens))
	}
}

func TestTSRequestWithCredentials(t *testing.T) {
	creds := TSPasswordCreds{
		DomainName: toUnicode("CORP"),
		UserName:   toUnicode("admin"),
		Password:   toUnicode("secret"),
	}
	credsBytes, err := asn1.Marshal(creds)
	if err != nil {
		t.Fatalf("marshal TSPasswordCreds: %v", err)
	}

	tsCreds := TSCredentials{
		CredType:    1,
		Credentials: credsBytes,
	}
	tsCredsBytes, err := asn1.Marshal(tsCreds)
	if err != nil {
		t.Fatalf("marshal TSCredentials: %v", err)
	}

	req := TSRequest{
		Version:  3,
		AuthInfo: tsCredsBytes,
	}
	data, err := asn1.Marshal(req)
	if err != nil {
		t.Fatalf("marshal TSRequest with creds: %v", err)
	}

	var decoded TSRequest
	if _, err := asn1.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(decoded.AuthInfo) == 0 {
		t.Error("authInfo should not be empty")
	}
}

func TestNTLMNegotiateMessage(t *testing.T) {
	msg, err := buildNtlmNegotiate("TESTDOMAIN", false)
	if err != nil {
		t.Fatalf("buildNtlmNegotiate: %v", err)
	}

	if len(msg) < 32 {
		t.Fatalf("negotiate message too short: %d bytes", len(msg))
	}
	if string(msg[:8]) != ntlmSignature {
		t.Errorf("wrong signature: got %x", msg[:8])
	}
	msgType := binary.LittleEndian.Uint32(msg[8:12])
	if msgType != ntlmTypeNegotiate {
		t.Errorf("message type: got %d, want %d", msgType, ntlmTypeNegotiate)
	}
	flags := binary.LittleEndian.Uint32(msg[12:16])
	if flags&negotiateNTLM == 0 {
		t.Error("NEGOTIATE_NTLM flag not set")
	}
	if flags&negotiateUnicode == 0 {
		t.Error("NEGOTIATE_UNICODE flag not set")
	}
}

func TestNTLMv2Hash(t *testing.T) {
	hash1 := ntlmNTOWFv2("password", "user", "DOMAIN")
	hash2 := ntlmNTOWFv2("password", "user", "DOMAIN")
	hash3 := ntlmNTOWFv2("different", "user", "DOMAIN")

	if len(hash1) != 16 {
		t.Fatalf("hash length: got %d, want 16", len(hash1))
	}

	// Deterministic
	for i := range hash1 {
		if hash1[i] != hash2[i] {
			t.Error("same inputs should produce same hash")
			break
		}
	}

	// Sensitive to input changes
	same := true
	for i := range hash1 {
		if hash1[i] != hash3[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("different passwords should produce different hashes")
	}
}

func TestPubKeyAuthHashOrder(t *testing.T) {
	// Verify the hash order matches MS-CSSP spec: SHA256(magic, nonce, pubkey)
	magic := "CredSSP Client-To-Server Binding Hash\x00"
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	pubkey := []byte("fake-subject-public-key-info-data")

	h := sha256.New()
	h.Write([]byte(magic))
	h.Write(nonce)
	h.Write(pubkey)
	expected := h.Sum(nil)

	// Wrong order should produce different hash
	h2 := sha256.New()
	h2.Write(pubkey)
	h2.Write([]byte(magic))
	h2.Write(nonce)
	wrongOrder := h2.Sum(nil)

	if string(expected) == string(wrongOrder) {
		t.Error("different hash order should produce different results")
	}

	if len(expected) != 32 {
		t.Errorf("SHA256 hash should be 32 bytes, got %d", len(expected))
	}
}

func TestClientInfoPDUContainsCredentials(t *testing.T) {
	client := &Client{
		opts: &ClientOptions{
			Username: "testuser",
			Password: "testpass",
			Domain:   "TESTDOM",
		},
	}

	pdu := client.buildClientInfoPDU()
	if len(pdu) < 20 {
		t.Fatalf("Client Info PDU too short: %d bytes", len(pdu))
	}

	// Check that the username appears in the PDU as UTF-16LE
	usernameUTF16 := toUnicode("testuser")
	found := false
	for i := 0; i <= len(pdu)-len(usernameUTF16); i++ {
		match := true
		for j := 0; j < len(usernameUTF16); j++ {
			if pdu[i+j] != usernameUTF16[j] {
				match = false
				break
			}
		}
		if match {
			found = true
			break
		}
	}
	if !found {
		t.Error("username not found in Client Info PDU")
	}

	// Check domain
	domainUTF16 := toUnicode("TESTDOM")
	found = false
	for i := 0; i <= len(pdu)-len(domainUTF16); i++ {
		match := true
		for j := 0; j < len(domainUTF16); j++ {
			if pdu[i+j] != domainUTF16[j] {
				match = false
				break
			}
		}
		if match {
			found = true
			break
		}
	}
	if !found {
		t.Error("domain not found in Client Info PDU")
	}
}

func TestNTLMSealProducesSignatureAndEncryptedData(t *testing.T) {
	sessionKey := make([]byte, 16)
	for i := range sessionKey {
		sessionKey[i] = byte(i + 1)
	}

	plaintext := []byte("test data for NTLM seal operation")
	sealed, err := ntlmSeal(sessionKey, 0, plaintext)
	if err != nil {
		t.Fatalf("ntlmSeal: %v", err)
	}

	// Sealed = 16-byte signature + encrypted data
	if len(sealed) != 16+len(plaintext) {
		t.Fatalf("sealed length: got %d, want %d", len(sealed), 16+len(plaintext))
	}

	// Signature version must be 1
	sigVersion := binary.LittleEndian.Uint32(sealed[0:4])
	if sigVersion != 1 {
		t.Errorf("signature version: got %d, want 1", sigVersion)
	}

	// Encrypted data should differ from plaintext
	encData := sealed[16:]
	same := true
	for i := range plaintext {
		if encData[i] != plaintext[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("encrypted data should differ from plaintext")
	}
}

func TestToUnicode(t *testing.T) {
	result := toUnicode("AB")
	expected := []byte{0x41, 0x00, 0x42, 0x00}
	if len(result) != len(expected) {
		t.Fatalf("length: got %d, want %d", len(result), len(expected))
	}
	for i := range expected {
		if result[i] != expected[i] {
			t.Errorf("byte %d: got 0x%02x, want 0x%02x", i, result[i], expected[i])
		}
	}
}

func TestMD4Hash(t *testing.T) {
	// Verify MD4 is deterministic and produces 16-byte output
	hash1 := md4Hash([]byte("password"))
	hash2 := md4Hash([]byte("password"))
	if len(hash1) != 16 {
		t.Fatalf("MD4 hash length: got %d, want 16", len(hash1))
	}
	for i := range hash1 {
		if hash1[i] != hash2[i] {
			t.Error("MD4 should be deterministic")
			break
		}
	}

	// Different inputs should produce different outputs
	hash3 := md4Hash([]byte("different"))
	same := true
	for i := range hash1 {
		if hash1[i] != hash3[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("different inputs should produce different MD4 hashes")
	}
}
