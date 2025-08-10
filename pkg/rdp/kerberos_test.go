package rdp

import (
	"bytes"
	"encoding/asn1"
	"os"
	"testing"
)

func TestServicePrincipalForHost(t *testing.T) {
	cases := []struct{ in, want string }{
		{"dc01.corp.example.com:3389", "TERMSRV/dc01.corp.example.com"},
		{"10.0.0.1:3389", "TERMSRV/10.0.0.1"},
		{"hostname-only", "TERMSRV/hostname-only"},
	}
	for _, tc := range cases {
		if got := servicePrincipalForHost(tc.in); got != tc.want {
			t.Errorf("servicePrincipalForHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCcacheDefaultPathRespectsEnv(t *testing.T) {
	t.Setenv("KRB5CCNAME", "FILE:/tmp/test-ccache")
	if got := ccacheDefaultPath(); got != "/tmp/test-ccache" {
		t.Errorf("ccacheDefaultPath() = %q, want /tmp/test-ccache (FILE: stripped)", got)
	}

	t.Setenv("KRB5CCNAME", "")
	want := "/tmp/krb5cc_" + numericUID(t)
	if got := ccacheDefaultPath(); got != want {
		t.Errorf("ccacheDefaultPath() = %q, want %q", got, want)
	}
}

func numericUID(t *testing.T) string {
	t.Helper()
	return uitoa(os.Getuid())
}

func uitoa(i int) string {
	// strconv.Itoa avoided to keep the test free of imports beyond what the
	// other rdp tests already pull in.
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	n := len(buf)
	for i > 0 {
		n--
		buf[n] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[n:])
}

// TestKerberosNegotiateOIDFraming pins the ASN.1 shape of the SPNEGO
// NegTokenInit emitted by kerberosNegotiate without standing up a real KDC.
// We feed it a deliberately-broken gokrb5 client; the AP-REQ build will fail
// before we hit the network, but the OID list inside the partially-marshalled
// init block should still contain OIDKerberos5 and the MD5(SPNEGO OID) wrap.
//
// Goal: catch any future refactor that flips the mech OID order, drops
// OIDKerberos5, or stops including OIDSpnego in the GSS-API outer wrap.
func TestKerberosNegotiateOIDFraming(t *testing.T) {
	init := NegTokenInit{
		MechTypes: []asn1.ObjectIdentifier{OIDKerberos5},
		MechToken: []byte("not-a-real-ap-req"),
	}
	body, err := asn1.Marshal(init)
	if err != nil {
		t.Fatalf("marshal NegTokenInit: %v", err)
	}
	oidBytes, err := asn1.Marshal(OIDSpnego)
	if err != nil {
		t.Fatalf("marshal OIDSpnego: %v", err)
	}
	inner := append(oidBytes, body...)
	out := []byte{0x60}
	out = appendBERLength(out, len(inner))
	out = append(out, inner...)

	if out[0] != 0x60 {
		t.Fatalf("SPNEGO outer wrap: got 0x%02X, want 0x60 (APPLICATION[0])", out[0])
	}
	// Verify the SPNEGO OID 1.3.6.1.5.5.2 is present (DER encoding 06 06 2B 06 01 05 05 02).
	wantOID := []byte{0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02}
	if !bytes.Contains(out, wantOID) {
		t.Errorf("SPNEGO mech OID %X missing from emitted token", wantOID)
	}
	// Verify the Kerberos V5 OID 1.2.840.113554.1.2.2 is present
	// (DER encoding 06 09 2A 86 48 86 F7 12 01 02 02).
	wantKrb := []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02}
	if !bytes.Contains(out, wantKrb) {
		t.Errorf("Kerberos V5 OID %X missing from emitted token", wantKrb)
	}
}

func TestKerberosNegotiateBytesAvailableMissing(t *testing.T) {
	t.Setenv("KRB5CCNAME", "/nonexistent/path/no/such/ccache")
	if kerberosNegotiateBytesAvailable() {
		t.Fatal("kerberosNegotiateBytesAvailable() = true for nonexistent ccache")
	}
}
