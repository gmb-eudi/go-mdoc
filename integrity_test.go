package mdoc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// buildForIntegrity returns a valid MSO + the item map so tests can present
// subsets, tampered items, or cross-namespace items. items[ns][id] = bytes.
func buildForIntegrity(t *testing.T) (mso *MobileSecurityObject, items map[string]map[uint]cbor.RawMessage, deviceKey *ecdsa.PublicKey) {
	t.Helper()
	dev := genKey(t, elliptic.P256())
	fn := itemBytes(t, 0, "org.iso.18013.5.1", "family_name", "Dent")
	gn := itemBytes(t, 1, "org.iso.18013.5.1", "given_name", "Arthur")
	addr := itemBytes(t, 0, "org.iso.18013.5.1.aamva", "resident_city", "Milliways")
	items = map[string]map[uint]cbor.RawMessage{
		"org.iso.18013.5.1":       {0: fn, 1: gn},
		"org.iso.18013.5.1.aamva": {0: addr},
	}
	msoBytes := buildMSOBytes(t, msoFixture{
		docType:    "org.iso.18013.5.1.mDL",
		digestAlg:  "SHA-256",
		deviceKey:  &dev.PublicKey,
		validFrom:  now2026().Add(-time.Hour),
		validUntil: now2026().Add(time.Hour),
		items:      items,
	})
	var m MobileSecurityObject
	if err := decodeTagged24(msoBytes, &m); err != nil {
		t.Fatal(err)
	}
	return &m, items, &dev.PublicKey
}

func TestIntegrity_DisclosedSubsetPasses(t *testing.T) {
	mso, items, _ := buildForIntegrity(t)
	v := NewVerifier(WithClock(now2026))
	// present only family_name from the primary namespace
	ns := IssuerNameSpaces{"org.iso.18013.5.1": {items["org.iso.18013.5.1"][0]}}
	got, err := v.verifyIssuerIntegrity(mso, ns)
	if err != nil {
		t.Fatalf("verifyIssuerIntegrity: %v", err)
	}
	if got["org.iso.18013.5.1"]["family_name"] != "Dent" {
		t.Errorf("disclosed value = %#v", got["org.iso.18013.5.1"]["family_name"])
	}
	if _, present := got["org.iso.18013.5.1"]["given_name"]; present {
		t.Errorf("undisclosed given_name leaked into output")
	}
}

func TestIntegrity_Failures(t *testing.T) {
	v := NewVerifier(WithClock(now2026))
	tests := []struct {
		name string
		ns   func(t *testing.T, items map[string]map[uint]cbor.RawMessage) IssuerNameSpaces
	}{
		{
			name: "tampered element value",
			ns: func(t *testing.T, _ map[string]map[uint]cbor.RawMessage) IssuerNameSpaces {
				// same digestID 0 but a different value → different wire bytes.
				tampered := itemBytesRaw(t, 0, "family_name", "Prefect")
				return IssuerNameSpaces{"org.iso.18013.5.1": {tampered}}
			},
		},
		{
			name: "tampered element identifier",
			ns: func(t *testing.T, _ map[string]map[uint]cbor.RawMessage) IssuerNameSpaces {
				tampered := itemBytesRaw(t, 0, "surname", "Dent") // id renamed
				return IssuerNameSpaces{"org.iso.18013.5.1": {tampered}}
			},
		},
		{
			name: "tampered random salt",
			ns: func(t *testing.T, _ map[string]map[uint]cbor.RawMessage) IssuerNameSpaces {
				b, err := encodeTagged24(IssuerSignedItem{DigestID: 0, Random: bytesRepeat(0xAA, 32), ElementIdentifier: "family_name", ElementValue: mustEnc(t, "Dent")})
				if err != nil {
					t.Fatal(err)
				}
				return IssuerNameSpaces{"org.iso.18013.5.1": {b}}
			},
		},
		{
			name: "item missing from ValueDigests (unknown digestID)",
			ns: func(t *testing.T, _ map[string]map[uint]cbor.RawMessage) IssuerNameSpaces {
				b := itemBytes(t, 99, "org.iso.18013.5.1", "age_over_18", true) // digestID 99 not in MSO
				return IssuerNameSpaces{"org.iso.18013.5.1": {b}}
			},
		},
		{
			name: "digest from other namespace",
			ns: func(_ *testing.T, items map[string]map[uint]cbor.RawMessage) IssuerNameSpaces {
				// primary-namespace item (digestID 0) presented under the aamva
				// namespace, whose DigestIDs[0] hashes a different item.
				return IssuerNameSpaces{"org.iso.18013.5.1.aamva": {items["org.iso.18013.5.1"][0]}}
			},
		},
		{
			name: "namespace absent from ValueDigests",
			ns: func(_ *testing.T, items map[string]map[uint]cbor.RawMessage) IssuerNameSpaces {
				return IssuerNameSpaces{"org.evil.ns": {items["org.iso.18013.5.1"][0]}}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mso, items, _ := buildForIntegrity(t)
			err := func() error {
				_, e := v.verifyIssuerIntegrity(mso, tt.ns(t, items))
				return e
			}()
			if !errors.Is(err, ErrIntegrity) {
				t.Fatalf("err = %v, want ErrIntegrity", err)
			}
		})
	}
}

// End-to-end: a full Verify populates VerifiedDocument.Namespaces with the
// digest-checked disclosed items.
func TestVerify_PopulatesNamespaces(t *testing.T) {
	is, pub, deviceKey := buildValidIssuerSigned(t, "org.iso.18013.5.1.mDL", "SHA-256", now2026().Add(-time.Hour), now2026().Add(time.Hour))
	st := defaultTranscript(t)
	raw := wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, deviceKey, st)
	docs, err := NewVerifier(WithClock(now2026)).Verify(context.Background(), VerifyInput{DeviceResponse: raw, SessionTranscript: st, IssuerChainResolver: fixedResolver(pub)})
	if err != nil {
		t.Fatal(err)
	}
	got := docs[0].Namespaces["org.iso.18013.5.1"]
	if got["family_name"] != "Dent" || got["given_name"] != "Arthur" {
		t.Errorf("namespaces = %#v", got)
	}
}
