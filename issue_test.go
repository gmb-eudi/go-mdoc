package mdoc

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

func newTestIssuer(t *testing.T) (*Issuer, *ecdsa.PublicKey) {
	t.Helper()
	dsKey := genKey(t, elliptic.P256())
	kp := eudicrypto.NewStaticProvider(map[string]*ecdsa.PrivateKey{"ds": dsKey})
	return NewIssuer(kp, "ds", [][]byte{{0xDE, 0xAD}}), &dsKey.PublicKey
}

func pidTemplate() DocumentTemplate {
	return DocumentTemplate{
		DocType: "eu.europa.ec.eudi.pid.1",
		Namespaces: map[string]map[string]any{
			"eu.europa.ec.eudi.pid.1": {
				"family_name": "Dent",
				"given_name":  "Arthur",
				"age_over_18": true,
			},
		},
		ValidityInfo: ValidityInfo{Signed: now2026().Add(-time.Hour), ValidFrom: now2026().Add(-time.Hour), ValidUntil: now2026().Add(24 * time.Hour)},
		DigestAlg:    "SHA-256",
	}
}

// Full roundtrip: Issue → DevicePresent (subset) → Verify. Selective disclosure
// means only requested elements appear in the verified output.
func TestIssueDevicePresentVerify_SelectiveDisclosure(t *testing.T) {
	issuer, dsPub := newTestIssuer(t)
	deviceKey := genKey(t, elliptic.P256())
	issuerSigned, err := issuer.Issue(context.Background(), pidTemplate(), &deviceKey.PublicKey)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	st := OID4VPHandover(tClientID, tNonce, tMdocNonce, tRespURI)
	deviceResp, err := DevicePresent(context.Background(), deviceKey, issuerSigned, map[string][]string{
		"eu.europa.ec.eudi.pid.1": {"family_name", "age_over_18"}, // disclose subset; withhold given_name
	}, st)
	if err != nil {
		t.Fatalf("DevicePresent: %v", err)
	}
	docs, err := NewVerifier(WithClock(now2026)).Verify(context.Background(), VerifyInput{
		DeviceResponse: deviceResp, SessionTranscript: st, IssuerChainResolver: fixedResolver(dsPub),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	got := docs[0].Namespaces["eu.europa.ec.eudi.pid.1"]
	if got["family_name"] != "Dent" || got["age_over_18"] != true {
		t.Errorf("disclosed = %#v", got)
	}
	if _, leaked := got["given_name"]; leaked {
		t.Error("given_name was disclosed despite not being requested")
	}
	if docs[0].DocType != "eu.europa.ec.eudi.pid.1" || docs[0].MSODigestAlg != "SHA-256" {
		t.Errorf("doc = %+v", docs[0])
	}
	// device key round-trips
	if !docs[0].DeviceKey.(*ecdsa.PublicKey).Equal(&deviceKey.PublicKey) {
		t.Error("device key mismatch after roundtrip")
	}
}

// Full disclosure and a status reference round-trip.
func TestIssueDevicePresentVerify_FullWithStatus(t *testing.T) {
	issuer, dsPub := newTestIssuer(t)
	deviceKey := genKey(t, elliptic.P256())
	tmpl := pidTemplate()
	tmpl.Status = &StatusRef{URI: "https://issuer.example/sl/3", Index: 17}
	issuerSigned, err := issuer.Issue(context.Background(), tmpl, &deviceKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	st := OID4VPDCAPIHandover(tOrigin, tClientID, tNonce)
	deviceResp, err := DevicePresent(context.Background(), deviceKey, issuerSigned, map[string][]string{
		"eu.europa.ec.eudi.pid.1": {"family_name", "given_name", "age_over_18"},
	}, st)
	if err != nil {
		t.Fatal(err)
	}
	docs, err := NewVerifier(WithClock(now2026)).Verify(context.Background(), VerifyInput{
		DeviceResponse: deviceResp, SessionTranscript: st, IssuerChainResolver: fixedResolver(dsPub),
	})
	if err != nil {
		t.Fatal(err)
	}
	if docs[0].Status == nil || docs[0].Status.URI != "https://issuer.example/sl/3" || docs[0].Status.Index != 17 {
		t.Fatalf("Status = %+v", docs[0].Status)
	}
}

// Every pipeline check must be fail-able from the Issue façade (conventions.md):
// a device response presented under the WRONG transcript fails device auth.
func TestIssueDevicePresent_WrongTranscriptFailsVerify(t *testing.T) {
	issuer, dsPub := newTestIssuer(t)
	deviceKey := genKey(t, elliptic.P256())
	issuerSigned, _ := issuer.Issue(context.Background(), pidTemplate(), &deviceKey.PublicKey)
	deviceResp, err := DevicePresent(context.Background(), deviceKey, issuerSigned, map[string][]string{"eu.europa.ec.eudi.pid.1": {"family_name"}}, OID4VPHandover(tClientID, tNonce, tMdocNonce, tRespURI))
	if err != nil {
		t.Fatal(err)
	}
	wrong := OID4VPHandover(tClientID, "OTHER-nonce", tMdocNonce, tRespURI)
	_, err = NewVerifier(WithClock(now2026)).Verify(context.Background(), VerifyInput{DeviceResponse: deviceResp, SessionTranscript: wrong, IssuerChainResolver: fixedResolver(dsPub)})
	if !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("err = %v, want ErrDeviceAuth", err)
	}
}

func TestDevicePresent_UnknownElementRejected(t *testing.T) {
	issuer, _ := newTestIssuer(t)
	deviceKey := genKey(t, elliptic.P256())
	issuerSigned, _ := issuer.Issue(context.Background(), pidTemplate(), &deviceKey.PublicKey)
	_, err := DevicePresent(context.Background(), deviceKey, issuerSigned, map[string][]string{"eu.europa.ec.eudi.pid.1": {"no_such_element"}}, defaultTranscript(t))
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
}

// --- Issue edge cases (fail closed; hard rule 7) ---

func TestIssue_EmptyDocTypeFails(t *testing.T) {
	issuer, _ := newTestIssuer(t)
	deviceKey := genKey(t, elliptic.P256())
	tmpl := pidTemplate()
	tmpl.DocType = ""
	_, err := issuer.Issue(context.Background(), tmpl, &deviceKey.PublicKey)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
}

// DigestAlg left empty defaults to SHA-256 (documented DocumentTemplate behavior).
func TestIssue_DefaultDigestAlg(t *testing.T) {
	issuer, dsPub := newTestIssuer(t)
	deviceKey := genKey(t, elliptic.P256())
	tmpl := pidTemplate()
	tmpl.DigestAlg = ""
	issuerSigned, err := issuer.Issue(context.Background(), tmpl, &deviceKey.PublicKey)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	st := defaultTranscript(t)
	deviceResp, err := DevicePresent(context.Background(), deviceKey, issuerSigned, map[string][]string{"eu.europa.ec.eudi.pid.1": {"family_name"}}, st)
	if err != nil {
		t.Fatalf("DevicePresent: %v", err)
	}
	docs, err := NewVerifier(WithClock(now2026)).Verify(context.Background(), VerifyInput{
		DeviceResponse: deviceResp, SessionTranscript: st, IssuerChainResolver: fixedResolver(dsPub),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if docs[0].MSODigestAlg != "SHA-256" {
		t.Errorf("MSODigestAlg = %q, want default SHA-256", docs[0].MSODigestAlg)
	}
}

// A digestAlg outside the ECCG allow-list (hard rule 4) must reject at Issue
// time, not just at Verify time.
func TestIssue_DisallowedDigestAlgFails(t *testing.T) {
	issuer, _ := newTestIssuer(t)
	deviceKey := genKey(t, elliptic.P256())
	tmpl := pidTemplate()
	tmpl.DigestAlg = "SHA-1"
	if _, err := issuer.Issue(context.Background(), tmpl, &deviceKey.PublicKey); err == nil {
		t.Fatal("want error for disallowed digest algorithm")
	}
}

// A non-EC device key cannot be sealed into the MSO (COSE_Key EC2 only).
func TestIssue_NonECDeviceKeyFails(t *testing.T) {
	issuer, _ := newTestIssuer(t)
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Issue(context.Background(), pidTemplate(), edPub); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
}

// An EC device key on a curve outside the ECCG allow-list (hard rule 4) fails
// at encodeCOSEKey.
func TestIssue_UnsupportedDeviceCurveFails(t *testing.T) {
	issuer, _ := newTestIssuer(t)
	deviceKey := genKey(t, elliptic.P224())
	if _, err := issuer.Issue(context.Background(), pidTemplate(), &deviceKey.PublicKey); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
}

// The full roundtrip must work for every ECCG-allowed device-key curve, not
// just P-256 (encodeCOSEKey / parseCOSEKey both branch per curve).
func TestIssueDevicePresentVerify_DeviceKeyCurves(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			issuer, dsPub := newTestIssuer(t)
			deviceKey := genKey(t, curve)
			issuerSigned, err := issuer.Issue(context.Background(), pidTemplate(), &deviceKey.PublicKey)
			if err != nil {
				t.Fatalf("Issue: %v", err)
			}
			st := defaultTranscript(t)
			deviceResp, err := DevicePresent(context.Background(), deviceKey, issuerSigned, map[string][]string{"eu.europa.ec.eudi.pid.1": {"family_name"}}, st)
			if err != nil {
				t.Fatalf("DevicePresent: %v", err)
			}
			docs, err := NewVerifier(WithClock(now2026)).Verify(context.Background(), VerifyInput{
				DeviceResponse: deviceResp, SessionTranscript: st, IssuerChainResolver: fixedResolver(dsPub),
			})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !docs[0].DeviceKey.(*ecdsa.PublicKey).Equal(&deviceKey.PublicKey) {
				t.Error("device key mismatch after roundtrip")
			}
		})
	}
}

// --- DevicePresent edge cases (fail closed; hard rule 7) ---

func TestDevicePresent_MalformedIssuerSignedFails(t *testing.T) {
	deviceKey := genKey(t, elliptic.P256())
	if _, err := DevicePresent(context.Background(), deviceKey, []byte{0xff}, map[string][]string{"ns": {"x"}}, defaultTranscript(t)); err == nil {
		t.Fatal("want error for malformed issuerSigned bytes")
	}
}

// A non-EC device signer cannot produce a valid deviceSignature (ECDSA only).
func TestDevicePresent_NonECDeviceKeyFails(t *testing.T) {
	issuer, _ := newTestIssuer(t)
	deviceKey := genKey(t, elliptic.P256())
	issuerSigned, err := issuer.Issue(context.Background(), pidTemplate(), &deviceKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DevicePresent(context.Background(), edPriv, issuerSigned, map[string][]string{"eu.europa.ec.eudi.pid.1": {"family_name"}}, defaultTranscript(t))
	if err == nil {
		t.Fatal("want error for non-EC device signer")
	}
}

// A requested namespace absent from the credential (not just an absent
// element within a known namespace) fails closed.
func TestDevicePresent_NamespaceNotInCredentialFails(t *testing.T) {
	issuer, _ := newTestIssuer(t)
	deviceKey := genKey(t, elliptic.P256())
	issuerSigned, err := issuer.Issue(context.Background(), pidTemplate(), &deviceKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DevicePresent(context.Background(), deviceKey, issuerSigned, map[string][]string{"com.example.other": {"foo"}}, defaultTranscript(t))
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
}

// --- Internal helper edge cases (white-box; malformed-input robustness, hard rule 5) ---

func TestSelectDisclosed_MalformedItemFails(t *testing.T) {
	if _, err := selectDisclosed(IssuerNameSpaces{"ns": {cbor.RawMessage{0xff}}}, map[string][]string{"ns": {"x"}}); err == nil {
		t.Fatal("want error for malformed IssuerSignedItem bytes")
	}
}

func TestDocTypeFromIssuerAuth_MalformedCOSEFails(t *testing.T) {
	bad, err := encode([]any{1, 2, 3}) // not a 4-element COSE_Sign1
	if err != nil {
		t.Fatal(err)
	}
	if _, err := docTypeFromIssuerAuth(cbor.RawMessage(bad)); err == nil {
		t.Fatal("want error for malformed COSE structure")
	}
}

func TestDocTypeFromIssuerAuth_MalformedPayloadFails(t *testing.T) {
	bad, err := encode([]any{[]byte{}, map[int]any{}, true, []byte{}}) // payload not a bstr
	if err != nil {
		t.Fatal(err)
	}
	if _, err := docTypeFromIssuerAuth(cbor.RawMessage(bad)); err == nil {
		t.Fatal("want error for non-bstr payload")
	}
}

func TestDocTypeFromIssuerAuth_MalformedMSOFails(t *testing.T) {
	garbage := []byte{0x01, 0x02} // not tag-24 wrapped
	bad, err := encode([]any{[]byte{}, map[int]any{}, garbage, []byte{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := docTypeFromIssuerAuth(cbor.RawMessage(bad)); err == nil {
		t.Fatal("want error for non-tag24 MSO payload")
	}
}

func TestSignerProvider_PublicAndDecrypter(t *testing.T) {
	key := genKey(t, elliptic.P256())
	sp := signerProvider{key}
	pub, err := sp.Public(context.Background(), "x")
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	if !pub.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Error("Public returned a different key")
	}
	if _, err := sp.Decrypter(context.Background(), "x"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Decrypter err = %v, want ErrUnsupported", err)
	}
}
