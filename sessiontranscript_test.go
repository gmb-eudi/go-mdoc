package mdoc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Fixed inputs for reproducible golden vectors.
const (
	tClientID  = "x509_san_dns:verifier.example.com"
	tNonce     = "e1f2c3b4a596877869"
	tMdocNonce = "mdoc-generated-nonce-01"
	tRespURI   = "https://verifier.example.com/response"
	tOrigin    = "https://verifier.example.com"
)

func TestOID4VPHandover_Structure(t *testing.T) {
	st := OID4VPHandover(tClientID, tNonce, tMdocNonce, tRespURI)
	var arr []cbor.RawMessage
	if err := decode(st.Bytes(), &arr); err != nil {
		t.Fatal(err)
	}
	if len(arr) != 3 {
		t.Fatalf("SessionTranscript has %d elements, want 3", len(arr))
	}
	// first two elements are null
	for i := 0; i < 2; i++ {
		var n any
		if err := decode(arr[i], &n); err != nil || n != nil {
			t.Errorf("element %d = %#v, want null", i, n)
		}
	}
	var handover []cbor.RawMessage
	if err := decode(arr[2], &handover); err != nil {
		t.Fatal(err)
	}
	if len(handover) != 3 {
		t.Fatalf("OID4VPHandover has %d elements, want 3", len(handover))
	}
	var cidHash, uriHash []byte
	var nonce string
	if err := decode(handover[0], &cidHash); err != nil || len(cidHash) != sha256.Size {
		t.Errorf("clientIdHash len = %d (%v), want 32", len(cidHash), err)
	}
	if err := decode(handover[1], &uriHash); err != nil || len(uriHash) != sha256.Size {
		t.Errorf("responseUriHash len = %d (%v), want 32", len(uriHash), err)
	}
	if err := decode(handover[2], &nonce); err != nil || nonce != tNonce {
		t.Errorf("nonce = %q (%v), want %q", nonce, err, tNonce)
	}
	// hashes must equal SHA-256 over the documented tuples
	wantCID, _ := encode([]any{tClientID, tMdocNonce})
	sum := sha256.Sum256(wantCID)
	if hex.EncodeToString(cidHash) != hex.EncodeToString(sum[:]) {
		t.Errorf("clientIdHash mismatch")
	}
}

func TestOID4VPDCAPIHandover_Structure(t *testing.T) {
	st := OID4VPDCAPIHandover(tOrigin, tClientID, tNonce)
	var arr []cbor.RawMessage
	if err := decode(st.Bytes(), &arr); err != nil {
		t.Fatal(err)
	}
	var handover []cbor.RawMessage
	if err := decode(arr[2], &handover); err != nil {
		t.Fatal(err)
	}
	if len(handover) != 2 {
		t.Fatalf("OID4VPDCAPIHandover has %d elements, want 2", len(handover))
	}
	var id string
	if err := decode(handover[0], &id); err != nil || id != "OpenID4VPDCAPIHandover" {
		t.Errorf("identifier = %q (%v)", id, err)
	}
	var infoHash []byte
	if err := decode(handover[1], &infoHash); err != nil || len(infoHash) != sha256.Size {
		t.Errorf("handoverInfoHash len = %d (%v), want 32", len(infoHash), err)
	}
}

func TestSessionTranscript_Deterministic(t *testing.T) {
	a := OID4VPHandover(tClientID, tNonce, tMdocNonce, tRespURI)
	b := OID4VPHandover(tClientID, tNonce, tMdocNonce, tRespURI)
	if hex.EncodeToString(a.Bytes()) != hex.EncodeToString(b.Bytes()) {
		t.Fatal("constructor is not deterministic")
	}
}

// Byte-exact vs committed golden vectors (regenerate with MDOC_GEN=1).
func TestSessionTranscript_Golden(t *testing.T) {
	for file, got := range map[string][]byte{
		"oid4vp-handover.hex":       OID4VPHandover(tClientID, tNonce, tMdocNonce, tRespURI).Bytes(),
		"oid4vp-dcapi-handover.hex": OID4VPDCAPIHandover(tOrigin, tClientID, tNonce).Bytes(),
	} {
		t.Run(file, func(t *testing.T) {
			p := filepath.Join("testdata", "sessiontranscript", file)
			want, err := os.ReadFile(p) //nolint:gosec // G304: path is a fixed local testdata literal, not external input
			if err != nil {
				t.Skipf("golden not generated yet: %v", err)
			}
			if hex.EncodeToString(got) != string(trimSpace(want)) {
				t.Errorf("golden mismatch for %s:\n got=%s\nwant=%s", file, hex.EncodeToString(got), string(trimSpace(want)))
			}
		})
	}
}

// The constructor produces a transcript usable by device authentication
// (round-trips with T-03.5): sign a device response over it and verify.
func TestSessionTranscript_UsableForDeviceAuth(t *testing.T) {
	is, issuerPub, deviceKey := buildValidIssuerSigned(t, "org.iso.18013.5.1.mDL", "SHA-256", now2026().Add(-time.Hour), now2026().Add(time.Hour))
	st := OID4VPHandover(tClientID, tNonce, tMdocNonce, tRespURI)
	raw := wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, deviceKey, st)
	if _, err := NewVerifier(WithClock(now2026)).Verify(context.Background(), VerifyInput{
		DeviceResponse: raw, SessionTranscript: st, IssuerChainResolver: fixedResolver(issuerPub),
	}); err != nil {
		t.Fatalf("Verify with OID4VPHandover transcript: %v", err)
	}
}

// TestGenerateSessionTranscriptGoldens regenerates testdata/sessiontranscript
// golden vectors. Run with MDOC_GEN=1 to (re)generate; committed output is
// checked byte-exact by TestSessionTranscript_Golden.
func TestGenerateSessionTranscriptGoldens(t *testing.T) {
	if os.Getenv("MDOC_GEN") == "" {
		t.Skip("set MDOC_GEN=1 to regenerate the golden vectors")
	}
	dir := filepath.Join("testdata", "sessiontranscript")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	goldens := map[string][]byte{
		"oid4vp-handover.hex":       OID4VPHandover(tClientID, tNonce, tMdocNonce, tRespURI).Bytes(),
		"oid4vp-dcapi-handover.hex": OID4VPDCAPIHandover(tOrigin, tClientID, tNonce).Bytes(),
	}
	for file, b := range goldens {
		if err := os.WriteFile(filepath.Join(dir, file), []byte(hex.EncodeToString(b)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
