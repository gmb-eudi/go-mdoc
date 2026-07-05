package mdoc

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

func genKey(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// cosePointXY splits an EC public key's SEC1 uncompressed-point encoding
// (0x04 || X || Y, both fixed-width per curve) into its X/Y coordinate bytes.
// Uses PublicKey.Bytes() rather than the deprecated PublicKey.X/Y big.Int
// fields (Go 1.26).
func cosePointXY(pub *ecdsa.PublicKey) (x, y []byte, err error) {
	b, err := pub.Bytes()
	if err != nil {
		return nil, nil, err
	}
	if len(b) < 1 || b[0] != 0x04 { // sanity: uncompressed point marker
		return nil, nil, errors.New("cosePointXY: unexpected point encoding")
	}
	half := (len(b) - 1) / 2
	return b[1 : 1+half], b[1+half:], nil
}

// coseCurveLabel maps a stdlib curve to its COSE EC2 curve label (RFC 9053
// §7.1), or ok=false for curves this test package doesn't build fixtures for.
func coseCurveLabel(c elliptic.Curve) (label int64, ok bool) {
	switch c {
	case elliptic.P256():
		return 1, true
	case elliptic.P384():
		return 2, true
	case elliptic.P521():
		return 3, true
	default:
		return 0, false
	}
}

// deviceKeyToCOSE encodes an EC public key as a COSE_Key (RFC 9052 §7): kty EC2,
// crv label, x, y. Matches parseCOSEKey.
func deviceKeyToCOSE(t *testing.T, pub *ecdsa.PublicKey) cbor.RawMessage {
	t.Helper()
	crv, ok := coseCurveLabel(pub.Curve)
	if !ok {
		t.Fatalf("unsupported test curve %s", pub.Curve.Params().Name)
	}
	x, y, err := cosePointXY(pub)
	if err != nil {
		t.Fatal(err)
	}
	b, err := encode(map[int64]any{1: int64(2), -1: crv, -2: x, -3: y})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// deviceKeyToCOSEBytes mirrors deviceKeyToCOSE without a *testing.T, so fuzz
// seeds (which can't take a *testing.T) can build a valid COSE_Key.
func deviceKeyToCOSEBytes(pub *ecdsa.PublicKey) []byte {
	crv, ok := coseCurveLabel(pub.Curve)
	if !ok {
		return nil
	}
	x, y, err := cosePointXY(pub)
	if err != nil {
		return nil
	}
	b, err := encode(map[int64]any{1: int64(2), -1: crv, -2: x, -3: y})
	if err != nil {
		return nil
	}
	return b
}

// deviceKeyToCOSEUnchecked encodes with an explicit crv label so negative
// tests can inject a disallowed/bogus curve label.
func deviceKeyToCOSEUnchecked(t *testing.T, pub *ecdsa.PublicKey, crv int64) cbor.RawMessage {
	t.Helper()
	x, y, err := cosePointXY(pub)
	if err != nil {
		t.Fatal(err)
	}
	b, err := encode(map[int64]any{1: int64(2), -1: crv, -2: x, -3: y})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// buildValidIssuerSigned returns a DeviceResponse-ready IssuerSigned with one
// cryptographically valid MSO, plus the issuer public key (for a matching or
// mismatching resolver) and the device PRIVATE key so callers can sign the
// device side (device auth is mandatory from T-03.5 onward).
func buildValidIssuerSigned(t *testing.T, docType, digestAlg string, from, until time.Time) (issuerSigned IssuerSigned, issuerPub *ecdsa.PublicKey, deviceKey *ecdsa.PrivateKey) {
	t.Helper()
	issuerKey := genKey(t, elliptic.P256())
	dev := genKey(t, elliptic.P256())
	fn := itemBytes(t, 0, "org.iso.18013.5.1", "family_name", "Dent")
	gn := itemBytes(t, 1, "org.iso.18013.5.1", "given_name", "Arthur")
	msoBytes := buildMSOBytes(t, msoFixture{
		docType: docType, digestAlg: digestAlg, deviceKey: &dev.PublicKey,
		validFrom: from, validUntil: until,
		items: map[string]map[uint]cbor.RawMessage{"org.iso.18013.5.1": {0: fn, 1: gn}},
	})
	issuerAuth := signIssuerAuth(t, issuerKey, [][]byte{{0x01, 0x02}}, msoBytes)
	return IssuerSigned{NameSpaces: IssuerNameSpaces{"org.iso.18013.5.1": {fn, gn}}, IssuerAuth: issuerAuth}, &issuerKey.PublicKey, dev
}

// wrapDeviceResponse wraps is into a single-document DeviceResponse, signing a
// real detached deviceSignature bound to st with deviceKey (ISO 18013-5
// §9.1.3.4; device auth is mandatory from T-03.5 onward).
func wrapDeviceResponse(t *testing.T, docType string, is IssuerSigned, deviceKey *ecdsa.PrivateKey, st SessionTranscript) []byte {
	t.Helper()
	resp := DeviceResponse{Version: "1.0", Documents: []Document{{
		DocType: docType, IssuerSigned: is, DeviceSigned: signDeviceSigned(t, deviceKey, docType, st),
	}}}
	raw, err := encode(resp)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// signDeviceSigned builds a DeviceSigned with an empty DeviceNameSpaces and a
// valid detached deviceSignature over DeviceAuthenticationBytes for st (ISO
// 18013-5 §9.1.3.4).
func signDeviceSigned(t *testing.T, deviceKey *ecdsa.PrivateKey, docType string, st SessionTranscript) DeviceSigned {
	t.Helper()
	devNS, err := encodeTagged24(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	deviceAuthBytes, err := encodeTagged24([]any{"DeviceAuthentication", cbor.RawMessage(st.Bytes()), docType, cbor.RawMessage(devNS)})
	if err != nil {
		t.Fatal(err)
	}
	kp := eudicrypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"dev": deviceKey})
	attached, err := eudicrypto.SignCOSESign1(context.Background(), kp, "dev", nil, deviceAuthBytes)
	if err != nil {
		t.Fatal(err)
	}
	detached, err := detachCOSEPayload(cbor.RawMessage(attached))
	if err != nil {
		t.Fatal(err)
	}
	return DeviceSigned{NameSpaces: devNS, DeviceAuth: DeviceAuth{DeviceSignature: detached}}
}

// defaultTranscript is a fixed non-empty transcript for fixtures that don't
// exercise transcript binding.
func defaultTranscript(t *testing.T) SessionTranscript {
	t.Helper()
	raw, err := encode([]any{nil, nil, []any{[]byte("cidhash"), []byte("urihash"), "nonce"}})
	if err != nil {
		t.Fatal(err)
	}
	return sessionTranscriptFromRaw(raw)
}

// msoFixture describes a Mobile Security Object to build for a test.
type msoFixture struct {
	docType    string
	digestAlg  string
	deviceKey  *ecdsa.PublicKey
	validFrom  time.Time
	validUntil time.Time
	// namespace => (digestID => IssuerSignedItemBytes) so tests can tamper.
	items map[string]map[uint]cbor.RawMessage
	// optional status extension raw CBOR (T-03.8)
	status cbor.RawMessage
}

// buildMSOBytes computes ValueDigests over the given IssuerSignedItemBytes and
// returns MobileSecurityObjectBytes (#6.24(bstr .cbor MSO)).
//
// f.digestAlg is written into the MSO verbatim even when it is not
// ECCG-allowed (e.g. "SHA-1" fixtures exercising Verify's fail-closed digest
// allow-list, WP-03 README T-03.3 acceptance criteria): ValueDigests still
// need SOME well-formed hash so the MSO decodes structurally, so this falls
// back to SHA-256 to compute them. The fallback is test-only plumbing, not a
// second production allow-list (hard rule 4) — Verify rejects the disallowed
// digestAlg before per-item digests are ever consulted (T-03.4).
func buildMSOBytes(t *testing.T, f msoFixture) []byte {
	t.Helper()
	h, err := hashForMSODigestAlg(f.digestAlg)
	if err != nil {
		h = stdcrypto.SHA256
	}
	vd := ValueDigests{}
	for ns, byID := range f.items {
		ids := DigestIDs{}
		for id, itemBytes := range byID {
			hh := h.New()
			hh.Write(itemBytes)
			ids[id] = hh.Sum(nil)
		}
		vd[ns] = ids
	}
	mso := MobileSecurityObject{
		Version:         "1.0",
		DigestAlgorithm: f.digestAlg,
		ValueDigests:    vd,
		DeviceKeyInfo:   DeviceKeyInfo{DeviceKey: deviceKeyToCOSE(t, f.deviceKey)},
		DocType:         f.docType,
		ValidityInfo:    ValidityInfo{Signed: f.validFrom, ValidFrom: f.validFrom, ValidUntil: f.validUntil},
		Status:          f.status,
	}
	b, err := encodeTagged24(mso)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// signIssuerAuth signs MobileSecurityObjectBytes with the issuer key and injects
// the x5chain into the unprotected header (ISO 18013-5 §9.1.2.4 location).
func signIssuerAuth(t *testing.T, issuerKey *ecdsa.PrivateKey, x5chain [][]byte, msoBytes []byte) cbor.RawMessage {
	t.Helper()
	kp := eudicrypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"ds": issuerKey})
	raw, err := signCOSEWithX5Chain(context.Background(), kp, "ds", x5chain, msoBytes)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// cryptoPub aliases the stdlib crypto.PublicKey the resolver returns.
type cryptoPub = stdcrypto.PublicKey

// fixedResolver returns an IssuerChainResolver that always yields pub.
func fixedResolver(pub *ecdsa.PublicKey) IssuerChainResolver {
	return func(_ [][]byte) (cryptoPub, error) { return pub, nil }
}

// itemBytes builds one IssuerSignedItemBytes for family_name-style elements.
func itemBytes(t *testing.T, digestID uint, _, id string, value any) cbor.RawMessage {
	t.Helper()
	ev, err := encode(value)
	if err != nil {
		t.Fatal(err)
	}
	b, err := encodeTagged24(IssuerSignedItem{
		DigestID:          digestID,
		Random:            bytesRepeat(byte((digestID+1)&0xff), 32), //nolint:gosec // test fixture filler byte; digestID is a small test-local constant, not attacker-controlled
		ElementIdentifier: id,
		ElementValue:      ev,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// itemBytesRaw builds an IssuerSignedItemBytes with a fixed salt so the same
// (digestID,id,value) reproduces identical bytes; used to craft tampered items.
func itemBytesRaw(t *testing.T, digestID uint, id string, value any) cbor.RawMessage {
	t.Helper()
	b, err := encodeTagged24(IssuerSignedItem{DigestID: digestID, Random: bytesRepeat(byte((digestID+1)&0xff), 32), ElementIdentifier: id, ElementValue: mustEnc(t, value)}) //nolint:gosec // test fixture filler byte; digestID is a small test-local constant, not attacker-controlled
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustEnc(t *testing.T, v any) cbor.RawMessage {
	t.Helper()
	b, err := encode(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
