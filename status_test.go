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

func statusListCBOR(t *testing.T, uri string, idx uint) cbor.RawMessage {
	t.Helper()
	b, err := encode(map[string]any{"status_list": map[string]any{"uri": uri, "idx": idx}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseMSOStatus(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		ref, err := parseMSOStatus(nil)
		if err != nil || ref != nil {
			t.Fatalf("got %+v, %v; want nil, nil", ref, err)
		}
	})
	t.Run("present valid", func(t *testing.T) {
		ref, err := parseMSOStatus(statusListCBOR(t, "https://issuer.example/statuslists/1", 42))
		if err != nil {
			t.Fatal(err)
		}
		if ref == nil || ref.URI != "https://issuer.example/statuslists/1" || ref.Index != 42 {
			t.Fatalf("ref = %+v", ref)
		}
	})
	t.Run("malformed: not a map", func(t *testing.T) {
		bad, _ := encode("just a string")
		if _, err := parseMSOStatus(bad); !errors.Is(err, ErrStatus) {
			t.Fatalf("err = %v, want ErrStatus", err)
		}
	})
	t.Run("malformed: status_list missing uri", func(t *testing.T) {
		bad, _ := encode(map[string]any{"status_list": map[string]any{"idx": uint(1)}})
		if _, err := parseMSOStatus(bad); !errors.Is(err, ErrStatus) {
			t.Fatalf("err = %v, want ErrStatus", err)
		}
	})
}

// End-to-end: a valid MSO status surfaces on VerifiedDocument.Status; a
// malformed one fails the whole verification (fail closed, hard rule 7).
func TestVerify_StatusSurfaced(t *testing.T) {
	build := func(t *testing.T, status cbor.RawMessage) ([]byte, *ecdsa.PublicKey, SessionTranscript) {
		issuerKey := genKey(t, elliptic.P256())
		dev := genKey(t, elliptic.P256())
		fn := itemBytes(t, 0, "org.iso.18013.5.1", "family_name", "Dent")
		msoBytes := buildMSOBytes(t, msoFixture{
			docType: "org.iso.18013.5.1.mDL", digestAlg: "SHA-256", deviceKey: &dev.PublicKey,
			validFrom: now2026().Add(-time.Hour), validUntil: now2026().Add(time.Hour),
			items:  map[string]map[uint]cbor.RawMessage{"org.iso.18013.5.1": {0: fn}},
			status: status,
		})
		issuerAuth := signIssuerAuth(t, issuerKey, [][]byte{{0x01}}, msoBytes)
		is := IssuerSigned{NameSpaces: IssuerNameSpaces{"org.iso.18013.5.1": {fn}}, IssuerAuth: issuerAuth}
		st := defaultTranscript(t)
		return wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, dev, st), &issuerKey.PublicKey, st
	}

	t.Run("valid status surfaced", func(t *testing.T) {
		raw, pub, st := build(t, statusListCBOR(t, "https://issuer.example/sl/7", 5))
		docs, err := NewVerifier(WithClock(now2026)).Verify(context.Background(), VerifyInput{DeviceResponse: raw, SessionTranscript: st, IssuerChainResolver: fixedResolver(pub)})
		if err != nil {
			t.Fatal(err)
		}
		if docs[0].Status == nil || docs[0].Status.URI != "https://issuer.example/sl/7" || docs[0].Status.Index != 5 {
			t.Fatalf("Status = %+v", docs[0].Status)
		}
	})

	t.Run("absent status → nil", func(t *testing.T) {
		raw, pub, st := build(t, nil)
		docs, err := NewVerifier(WithClock(now2026)).Verify(context.Background(), VerifyInput{DeviceResponse: raw, SessionTranscript: st, IssuerChainResolver: fixedResolver(pub)})
		if err != nil {
			t.Fatal(err)
		}
		if docs[0].Status != nil {
			t.Fatalf("Status = %+v, want nil", docs[0].Status)
		}
	})

	t.Run("malformed status fails verification", func(t *testing.T) {
		bad, _ := encode("not a status map")
		raw, pub, st := build(t, cbor.RawMessage(bad))
		_, err := NewVerifier(WithClock(now2026)).Verify(context.Background(), VerifyInput{DeviceResponse: raw, SessionTranscript: st, IssuerChainResolver: fixedResolver(pub)})
		if !errors.Is(err, ErrStatus) {
			t.Fatalf("err = %v, want ErrStatus", err)
		}
	})
}
