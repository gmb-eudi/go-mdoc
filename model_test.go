package mdoc

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// buildMinimalDeviceResponse assembles a structurally complete (but NOT
// cryptographically valid) DeviceResponse purely from the wire structs, so the
// model can be exercised before the Issue façade (T-03.9) exists. It uses the
// package encode()/encodeTagged24() helpers directly.
func buildMinimalDeviceResponse(t *testing.T) []byte {
	t.Helper()
	// One IssuerSignedItem, wrapped as #6.24(bstr .cbor IssuerSignedItem).
	item := IssuerSignedItem{
		DigestID:          0,
		Random:            []byte("0123456789abcdef0123456789abcdef"),
		ElementIdentifier: "family_name",
		ElementValue:      mustRawCBOR(t, "Dent"),
	}
	itemBytes, err := encodeTagged24(item)
	if err != nil {
		t.Fatal(err)
	}
	// A placeholder issuerAuth: a 4-element COSE_Sign1 array (untagged) with an
	// empty protected header, empty unprotected map, nil payload, empty sig.
	issuerAuth := mustRawCBOR(t, []any{[]byte{}, map[int]any{}, nil, []byte{}})
	// DeviceNameSpacesBytes for an empty DeviceNameSpaces map, tag-24-wrapped.
	devNS, err := encodeTagged24(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	deviceSig := mustRawCBOR(t, []any{[]byte{}, map[int]any{}, nil, []byte{}})

	resp := DeviceResponse{
		Version: "1.0",
		Documents: []Document{{
			DocType: "org.iso.18013.5.1.mDL",
			IssuerSigned: IssuerSigned{
				NameSpaces: IssuerNameSpaces{
					"org.iso.18013.5.1": []cbor.RawMessage{itemBytes},
				},
				IssuerAuth: issuerAuth,
			},
			DeviceSigned: DeviceSigned{
				NameSpaces: devNS,
				DeviceAuth: DeviceAuth{DeviceSignature: deviceSig},
			},
		}},
		Status: 0,
	}
	raw, err := encode(resp)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustRawCBOR(t *testing.T, v any) cbor.RawMessage {
	t.Helper()
	b, err := encode(v)
	if err != nil {
		t.Fatal(err)
	}
	return cbor.RawMessage(b)
}

func TestDecodeDeviceResponseRoundtrip(t *testing.T) {
	raw := buildMinimalDeviceResponse(t)
	d, err := DecodeDeviceResponse(raw)
	if err != nil {
		t.Fatalf("DecodeDeviceResponse: %v", err)
	}
	if d.Version != "1.0" || len(d.Documents) != 1 {
		t.Fatalf("decoded = %+v", d)
	}
	doc := d.Documents[0]
	if doc.DocType != "org.iso.18013.5.1.mDL" {
		t.Errorf("docType = %q", doc.DocType)
	}
	items := doc.IssuerSigned.NameSpaces["org.iso.18013.5.1"]
	if len(items) != 1 {
		t.Fatalf("items = %d, want 1", len(items))
	}
	// The raw item must still be a tag-24 wrapper (byte-exact preservation).
	if items[0][0] != 0xd8 || items[0][1] != 0x18 {
		t.Errorf("item not tag-24-wrapped: %x", items[0][:2])
	}
	var isi IssuerSignedItem
	if err := decodeTagged24(items[0], &isi); err != nil {
		t.Fatal(err)
	}
	if isi.ElementIdentifier != "family_name" {
		t.Errorf("elementIdentifier = %q", isi.ElementIdentifier)
	}
	// re-encode and re-decode must be stable
	raw2, err := encode(*d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeDeviceResponse(raw2); err != nil {
		t.Fatalf("re-decode: %v", err)
	}
}

// T-03.2 acceptance: unknown-field tolerance per CDDL — a forward-compatible
// producer may add map members we do not model; decoding must ignore them.
func TestDecodeToleratesUnknownFields(t *testing.T) {
	// Encode a map with the DeviceResponse members plus an extra "futureField".
	m := map[string]any{
		"version":     "1.0",
		"status":      uint(0),
		"futureField": "ignore me",
	}
	raw, err := encode(m)
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecodeDeviceResponse(raw)
	if err != nil {
		t.Fatalf("unknown field must be tolerated: %v", err)
	}
	if d.Version != "1.0" {
		t.Errorf("version = %q", d.Version)
	}
}

// A non-OK top-level status is the wallet's own signal that something went
// wrong; the whole response is rejected, not just the affected document(s).
func TestDecodeDeviceResponseRejectsNonZeroStatus(t *testing.T) {
	m := map[string]any{"version": "1.0", "status": uint(11)} // 11 = cbor_decoding_error
	raw, err := encode(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeDeviceResponse(raw); !errors.Is(err, ErrDeviceResponseStatus) {
		t.Fatalf("err = %v, want ErrDeviceResponseStatus", err)
	}
}

// A non-empty documentErrors is rejected even if status happens to read 0 —
// either signal alone means the wallet flagged a problem.
func TestDecodeDeviceResponseRejectsDocumentErrors(t *testing.T) {
	m := map[string]any{
		"version":        "1.0",
		"status":         uint(0),
		"documentErrors": []map[string]int{{"org.iso.18013.5.1.mDL": 0}},
	}
	raw, err := encode(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeDeviceResponse(raw); !errors.Is(err, ErrDeviceResponseStatus) {
		t.Fatalf("err = %v, want ErrDeviceResponseStatus", err)
	}
}

func TestDecodeDeviceResponseRejectsGarbage(t *testing.T) {
	for name, raw := range map[string][]byte{
		"nil":       nil,
		"empty":     {},
		"not-a-map": {0x01},
		"truncated": {0xa1, 0x67, 'v', 'e', 'r'},
		"array-top": {0x80},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeDeviceResponse(raw); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

// The generated vector is committed so other modules (WP-08/WP-09) can decode a
// known-shape DeviceResponse without regenerating it.
func TestDecodeCommittedVector(t *testing.T) {
	p := filepath.Join("testdata", "mdoc", "minimal-deviceresponse.hex")
	h, err := os.ReadFile(p) //nolint:gosec // G304: path is a fixed local testdata literal, not external input
	if err != nil {
		t.Skipf("vector not generated yet: %v", err) // written in Step 5
	}
	raw, err := hex.DecodeString(string(trimSpace(h)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeDeviceResponse(raw); err != nil {
		t.Fatalf("committed vector must decode: %v", err)
	}
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}

// TestGenerateMinimalVector regenerates testdata/mdoc/minimal-deviceresponse.hex.
// Run with -run TestGenerateMinimalVector to (re)generate; committed output is
// the reproducible artifact (testdata/README.md: synthetic vectors come from a
// generator).
func TestGenerateMinimalVector(t *testing.T) {
	if os.Getenv("MDOC_GEN") == "" {
		t.Skip("set MDOC_GEN=1 to regenerate the committed vector")
	}
	raw := buildMinimalDeviceResponse(t)
	out := filepath.Join("testdata", "mdoc", "minimal-deviceresponse.hex")
	if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte(hex.EncodeToString(raw)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}
