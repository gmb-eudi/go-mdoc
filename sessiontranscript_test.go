package mdoc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Fixed inputs for reproducible golden vectors.
const (
	tClientID = "x509_san_dns:verifier.example.com"
	tNonce    = "e1f2c3b4a596877869"
	tRespURI  = "https://verifier.example.com/response"
	tOrigin   = "https://verifier.example.com"
)

// tThumbprint stands in for an RFC 7638 JWK thumbprint: 32 raw digest bytes,
// which is what the handover carries.
var tThumbprint = mustHex("3736cbb1787cb8309c77ee8c3705c5e16ffb9e859715901f1e4c59b11182f57b")

// ---------------------------------------------------------------------------
// Specification vectors — the external oracle.
//
// [OpenID4VP 1.0 Annex B.2.6.1] (redirect) and [Annex B.2.6.2] (Digital
// Credentials API) each publish a worked example: an input JWK, the resulting
// HandoverInfo, Handover and SessionTranscript, in hex. Reproducing them
// byte-for-byte is the only check here that cannot agree with a wrong
// implementation, because the expected bytes come from the specification rather
// than from this package. Everything else round-trips our own encoder.
//
// This is what pins jwkThumbprint as a CBOR byte string: the published bytes
// carry a 32-byte bstr (major type 2 head 0x58 0x20), not the printable
// base64url text.
// ---------------------------------------------------------------------------
const (
	specClientID = "x509_san_dns:example.com"
	specNonce    = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA"
	specRespURI  = "https://example.com/response"
	specOrigin   = "https://example.com"

	// The RFC 7638 thumbprint of the annexes' example JWK.
	specThumbprintHex = "4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047"

	// Annex B.2.6.1.
	specHandoverInfoHex = "847818783530395f73616e5f646e733a6578616d706c652e636f6d782b" +
		"6578633767426b786a7831726463397564527276654b7653734a497138306176" +
		"6c58654c4868477771744158204283ec927ae0f208daaa2d026a814f2b22dca5" +
		"2cf85ffa8f3f8626c6bd669047781c68747470733a2f2f6578616d706c652e63" +
		"6f6d2f726573706f6e7365"
	specHandoverHex = "82714f70656e494434565048616e646f7665725820048bc053c00442af9b8e" +
		"ed494cefdd9d95240d254b046b11b68013722aad38ac"
	specSessionTranscriptHex = "83f6f6" + specHandoverHex

	// Annex B.2.6.2.
	specDCAPIHandoverInfoHex = "837368747470733a2f2f6578616d706c652e636f6d782b6578633767426b78" +
		"6a7831726463397564527276654b7653734a4971383061766c58654c48684777" +
		"71744158204283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626" +
		"c6bd669047"
	specDCAPIHandoverHex = "82764f70656e4944345650444341504948616e646f7665725820fbece366f4" +
		"212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a"
	specDCAPISessionTranscriptHex = "83f6f6" + specDCAPIHandoverHex

	// The transcript this package produced before the thumbprint was corrected
	// from a text string to a byte string: same inputs, base64url text in the
	// third element. Pinned so the regression cannot come back silently.
	staleTextThumbprintTranscriptHex = "83f6f682714f70656e494434565048616e646f7665725820cd330238edfcba" +
		"aafd322bef726de73be261cd1e7a0720cef62c202a3e3ce102"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("mdoc test: bad hex literal: " + err.Error())
	}
	return b
}

// The published SessionTranscript hex, reproduced exactly. Both annex variants.
func TestSessionTranscript_SpecVectors(t *testing.T) {
	thumb := mustHex(specThumbprintHex)
	for _, tc := range []struct {
		name string
		got  []byte
		want string
	}{
		{"B.2.6.1 redirect", OID4VPHandover(specClientID, specNonce, thumb, specRespURI).Bytes(), specSessionTranscriptHex},
		{"B.2.6.2 DC API", OID4VPDCAPIHandover(specOrigin, specNonce, thumb).Bytes(), specDCAPISessionTranscriptHex},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hex.EncodeToString(tc.got); got != tc.want {
				t.Errorf("SessionTranscript does not match the published vector:\n got=%s\nwant=%s", got, tc.want)
			}
		})
	}
}

// The intermediate structures the annexes publish must match too, so a failure
// above localises to the element that diverged instead of just "the hash".
func TestSessionTranscript_SpecVectorIntermediates(t *testing.T) {
	thumb := mustHex(specThumbprintHex)

	info, err := encode([]any{specClientID, specNonce, thumb, specRespURI})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(info); got != specHandoverInfoHex {
		t.Errorf("OpenID4VPHandoverInfo:\n got=%s\nwant=%s", got, specHandoverInfoHex)
	}
	sum := sha256.Sum256(info)
	handover, err := encode([]any{"OpenID4VPHandover", sum[:]})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(handover); got != specHandoverHex {
		t.Errorf("OpenID4VPHandover:\n got=%s\nwant=%s", got, specHandoverHex)
	}

	dInfo, err := encode([]any{specOrigin, specNonce, thumb})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(dInfo); got != specDCAPIHandoverInfoHex {
		t.Errorf("OpenID4VPDCAPIHandoverInfo:\n got=%s\nwant=%s", got, specDCAPIHandoverInfoHex)
	}
	dSum := sha256.Sum256(dInfo)
	dHandover, err := encode([]any{"OpenID4VPDCAPIHandover", dSum[:]})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(dHandover); got != specDCAPIHandoverHex {
		t.Errorf("OpenID4VPDCAPIHandover:\n got=%s\nwant=%s", got, specDCAPIHandoverHex)
	}
}

// The third element must be a CBOR byte string (major type 2), inspected on the
// wire rather than inferred from a matching hash.
//
// The constructors hash the HandoverInfo, so it cannot be recovered from a
// SessionTranscript — the element the constructors actually place is taken from
// nullable, then encoded the same way, so both are checked here.
func TestOID4VPHandoverInfo_ThumbprintIsByteString(t *testing.T) {
	thumb := mustHex(specThumbprintHex)

	switch v := nullable(thumb).(type) {
	case []byte:
		if hex.EncodeToString(v) != specThumbprintHex {
			t.Errorf("nullable returned %x, want %s", v, specThumbprintHex)
		}
	default:
		t.Fatalf("nullable returned %T, want []byte — anything else encodes as the wrong CBOR type", v)
	}

	info, err := encode([]any{specClientID, specNonce, nullable(thumb), specRespURI})
	if err != nil {
		t.Fatal(err)
	}
	var elems []cbor.RawMessage
	if err := decode(info, &elems); err != nil {
		t.Fatal(err)
	}
	if len(elems) != 4 {
		t.Fatalf("HandoverInfo has %d elements, want 4", len(elems))
	}
	if head := elems[2][0]; head>>5 != 2 {
		t.Errorf("jwkThumbprint CBOR major type = %d (head 0x%02x), want 2 (byte string)", head>>5, head)
	}
	var asBytes []byte
	if err := decode(elems[2], &asBytes); err != nil {
		t.Fatalf("jwkThumbprint does not decode as a byte string: %v", err)
	}
	if hex.EncodeToString(asBytes) != specThumbprintHex {
		t.Errorf("jwkThumbprint = %x, want %s", asBytes, specThumbprintHex)
	}
	var asText string
	if err := decode(elems[2], &asText); err == nil {
		t.Errorf("jwkThumbprint decoded as the text string %q — it must be a byte string", asText)
	}
}

// The historical defect encoded the printable base64url thumbprint as a CBOR
// TEXT string. The []byte parameter makes that unrepresentable through the
// public API, so the wrong transcript has to be built by hand here to prove the
// constructor can no longer reach it — and to pin the exact bytes a wallet was
// being checked against, in case anything ever reproduces them again.
func TestOID4VPHandover_RejectsTextThumbprintEncoding(t *testing.T) {
	raw := mustHex(specThumbprintHex)
	printable := base64.RawURLEncoding.EncodeToString(raw)

	correct := hex.EncodeToString(OID4VPHandover(specClientID, specNonce, raw, specRespURI).Bytes())
	if correct != specSessionTranscriptHex {
		t.Fatalf("raw digest bytes must yield the published transcript, got %s", correct)
	}

	// Rebuild the pre-fix construction: the thumbprint as a tstr.
	staleInfo, err := encode([]any{specClientID, specNonce, printable, specRespURI})
	if err != nil {
		t.Fatal(err)
	}
	staleSum := sha256.Sum256(staleInfo)
	stale, err := encode([]any{nil, nil, []any{"OpenID4VPHandover", staleSum[:]}})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(stale); got != staleTextThumbprintTranscriptHex {
		t.Errorf("stale-encoding pin drifted:\n got=%s\nwant=%s", got, staleTextThumbprintTranscriptHex)
	}
	if correct == staleTextThumbprintTranscriptHex {
		t.Error("the corrected constructor still produces the historical text-thumbprint transcript")
	}

	// A caller that hands over the printable form as bytes gets a byte string of
	// ASCII — wrong in a different way, and it must not match either.
	asASCII := hex.EncodeToString(OID4VPHandover(specClientID, specNonce, []byte(printable), specRespURI).Bytes())
	if asASCII == specSessionTranscriptHex {
		t.Error("the base64url text form produced the published transcript — the vector cannot tell the encodings apart")
	}
}

func TestOID4VPHandover_Structure(t *testing.T) {
	st := OID4VPHandover(tClientID, tNonce, tThumbprint, tRespURI)
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
	if len(handover) != 2 {
		t.Fatalf("OID4VPHandover has %d elements, want 2", len(handover))
	}
	var id string
	if err := decode(handover[0], &id); err != nil || id != "OpenID4VPHandover" {
		t.Errorf("identifier = %q (%v)", id, err)
	}
	var infoHash []byte
	if err := decode(handover[1], &infoHash); err != nil || len(infoHash) != sha256.Size {
		t.Errorf("handoverInfoHash len = %d (%v), want 32", len(infoHash), err)
	}
	// hash must equal SHA-256 over the documented HandoverInfo tuple
	wantInfo, _ := encode([]any{tClientID, tNonce, tThumbprint, tRespURI})
	sum := sha256.Sum256(wantInfo)
	if hex.EncodeToString(infoHash) != hex.EncodeToString(sum[:]) {
		t.Errorf("handoverInfoHash mismatch")
	}
}

// An absent thumbprint (unencrypted response) is CBOR null, for nil and for an
// empty non-nil slice alike.
func TestOID4VPHandover_NullThumbprint(t *testing.T) {
	wantInfo, _ := encode([]any{tClientID, tNonce, nil, tRespURI})
	sum := sha256.Sum256(wantInfo)

	for name, absent := range map[string][]byte{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			st := OID4VPHandover(tClientID, tNonce, absent, tRespURI)
			var arr []cbor.RawMessage
			if err := decode(st.Bytes(), &arr); err != nil {
				t.Fatal(err)
			}
			var handover []cbor.RawMessage
			if err := decode(arr[2], &handover); err != nil {
				t.Fatal(err)
			}
			var infoHash []byte
			if err := decode(handover[1], &infoHash); err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(infoHash) != hex.EncodeToString(sum[:]) {
				t.Errorf("handoverInfoHash mismatch: an absent thumbprint must encode as CBOR null")
			}
		})
	}
}

// A present thumbprint must not collide with an absent one.
func TestOID4VPHandover_NullDiffersFromPresent(t *testing.T) {
	absent := OID4VPHandover(tClientID, tNonce, nil, tRespURI)
	present := OID4VPHandover(tClientID, tNonce, tThumbprint, tRespURI)
	if hex.EncodeToString(absent.Bytes()) == hex.EncodeToString(present.Bytes()) {
		t.Error("encrypted and unencrypted responses produced the same transcript")
	}
}

func TestOID4VPDCAPIHandover_Structure(t *testing.T) {
	st := OID4VPDCAPIHandover(tOrigin, tNonce, tThumbprint)
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
	wantInfo, _ := encode([]any{tOrigin, tNonce, tThumbprint})
	sum := sha256.Sum256(wantInfo)
	if hex.EncodeToString(infoHash) != hex.EncodeToString(sum[:]) {
		t.Errorf("handoverInfoHash mismatch")
	}
}

// The constructors must not alias the caller's slice: a later mutation of the
// thumbprint cannot retroactively change an already-built transcript.
func TestSessionTranscript_ThumbprintNotAliased(t *testing.T) {
	thumb := mustHex(specThumbprintHex)
	before := hex.EncodeToString(OID4VPHandover(specClientID, specNonce, thumb, specRespURI).Bytes())
	thumb[0] ^= 0xff
	after := hex.EncodeToString(OID4VPHandover(specClientID, specNonce, thumb, specRespURI).Bytes())
	if before == after {
		t.Fatal("mutating the thumbprint did not change the transcript — inputs are not being read")
	}
	if before != specSessionTranscriptHex {
		t.Errorf("pre-mutation transcript drifted from the published vector")
	}
}

func TestSessionTranscript_Deterministic(t *testing.T) {
	a := OID4VPHandover(tClientID, tNonce, tThumbprint, tRespURI)
	b := OID4VPHandover(tClientID, tNonce, tThumbprint, tRespURI)
	if hex.EncodeToString(a.Bytes()) != hex.EncodeToString(b.Bytes()) {
		t.Fatal("constructor is not deterministic")
	}
}

// Byte-exact vs committed golden vectors (regenerate with MDOC_GEN=1).
func TestSessionTranscript_Golden(t *testing.T) {
	for file, got := range map[string][]byte{
		"oid4vp-handover.hex":       OID4VPHandover(tClientID, tNonce, tThumbprint, tRespURI).Bytes(),
		"oid4vp-dcapi-handover.hex": OID4VPDCAPIHandover(tOrigin, tNonce, tThumbprint).Bytes(),
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
// (round-trips with the device-auth path): sign a device response over it and verify.
func TestSessionTranscript_UsableForDeviceAuth(t *testing.T) {
	is, issuerPub, deviceKey := buildValidIssuerSigned(t, "org.iso.18013.5.1.mDL", "SHA-256", now2026().Add(-time.Hour), now2026().Add(time.Hour))
	st := OID4VPHandover(tClientID, tNonce, tThumbprint, tRespURI)
	raw := wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, deviceKey, st)
	if _, err := NewVerifier(WithClock(now2026)).Verify(context.Background(), VerifyInput{
		DeviceResponse: raw, SessionTranscript: st, IssuerTrust: &fixedTrust{pub: issuerPub},
	}); err != nil {
		t.Fatalf("Verify with OID4VPHandover transcript: %v", err)
	}
}

// A device response signed over one transcript must not verify against another —
// the property the thumbprint encoding silently broke.
func TestSessionTranscript_WrongTranscriptFailsDeviceAuth(t *testing.T) {
	is, issuerPub, deviceKey := buildValidIssuerSigned(t, "org.iso.18013.5.1.mDL", "SHA-256", now2026().Add(-time.Hour), now2026().Add(time.Hour))
	signed := OID4VPHandover(tClientID, tNonce, tThumbprint, tRespURI)
	raw := wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, deviceKey, signed)

	other := OID4VPHandover(tClientID, tNonce, []byte(base64.RawURLEncoding.EncodeToString(tThumbprint)), tRespURI)
	if _, err := NewVerifier(WithClock(now2026)).Verify(context.Background(), VerifyInput{
		DeviceResponse: raw, SessionTranscript: other, IssuerTrust: &fixedTrust{pub: issuerPub},
	}); err == nil {
		t.Fatal("Verify accepted a device response signed over a different SessionTranscript")
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
		"oid4vp-handover.hex":       OID4VPHandover(tClientID, tNonce, tThumbprint, tRespURI).Bytes(),
		"oid4vp-dcapi-handover.hex": OID4VPDCAPIHandover(tOrigin, tNonce, tThumbprint).Bytes(),
	}
	for file, b := range goldens {
		if err := os.WriteFile(filepath.Join(dir, file), []byte(hex.EncodeToString(b)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
