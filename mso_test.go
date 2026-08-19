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

func now2026() time.Time { return time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC) }

func TestVerifyMSO_Valid(t *testing.T) {
	is, issuerPub, deviceKey := buildValidIssuerSigned(t, "org.iso.18013.5.1.mDL", "SHA-256", now2026().Add(-time.Hour), now2026().Add(time.Hour))
	st := defaultTranscript(t)
	raw := wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, deviceKey, st)
	v := NewVerifier(WithClock(now2026))
	docs, err := v.Verify(context.Background(), VerifyInput{
		DeviceResponse:    raw,
		SessionTranscript: st,
		IssuerTrust:       &fixedTrust{pub: issuerPub},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(docs) != 1 {
		t.Fatalf("docs = %d", len(docs))
	}
	if docs[0].DocType != "org.iso.18013.5.1.mDL" {
		t.Errorf("docType = %q", docs[0].DocType)
	}
	if docs[0].MSODigestAlg != "SHA-256" {
		t.Errorf("digestAlg = %q", docs[0].MSODigestAlg)
	}
	// DeviceKey must equal the key sealed in the MSO.
	got, ok := docs[0].DeviceKey.(*ecdsa.PublicKey)
	if !ok || !got.Equal(&deviceKey.PublicKey) {
		t.Errorf("DeviceKey mismatch")
	}
}

func TestVerifyMSO_Failures(t *testing.T) {
	from, until := now2026().Add(-time.Hour), now2026().Add(time.Hour)
	tests := []struct {
		name    string
		mutate  func(t *testing.T) (raw []byte, trust IssuerTrust)
		wantErr error
	}{
		{
			name: "wrong DS key",
			mutate: func(t *testing.T) ([]byte, IssuerTrust) {
				is, _, deviceKey := buildValidIssuerSigned(t, "org.iso.18013.5.1.mDL", "SHA-256", from, until)
				other := genKey(t, elliptic.P256())
				return wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, deviceKey, defaultTranscript(t)), &fixedTrust{pub: &other.PublicKey}
			},
			wantErr: ErrIssuerAuth,
		},
		{
			name: "expired MSO",
			mutate: func(t *testing.T) ([]byte, IssuerTrust) {
				is, pub, deviceKey := buildValidIssuerSigned(t, "org.iso.18013.5.1.mDL", "SHA-256", now2026().Add(-48*time.Hour), now2026().Add(-24*time.Hour))
				return wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, deviceKey, defaultTranscript(t)), &fixedTrust{pub: pub}
			},
			wantErr: ErrValidity,
		},
		{
			name: "validFrom equals validUntil",
			mutate: func(t *testing.T) ([]byte, IssuerTrust) {
				is, pub, deviceKey := buildValidIssuerSigned(t, "org.iso.18013.5.1.mDL", "SHA-256", now2026(), now2026())
				return wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, deviceKey, defaultTranscript(t)), &fixedTrust{pub: pub}
			},
			wantErr: ErrMalformed,
		},
		{
			name: "digestAlg SHA-1",
			mutate: func(t *testing.T) ([]byte, IssuerTrust) {
				is, pub, deviceKey := buildValidIssuerSigned(t, "org.iso.18013.5.1.mDL", "SHA-1", from, until)
				return wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, deviceKey, defaultTranscript(t)), &fixedTrust{pub: pub}
			},
			wantErr: ErrDigestAlg,
		},
		{
			name: "docType mismatch MSO vs Document",
			mutate: func(t *testing.T) ([]byte, IssuerTrust) {
				is, pub, deviceKey := buildValidIssuerSigned(t, "eu.europa.ec.eudi.pid.1", "SHA-256", from, until)
				// Document says mDL, MSO says PID.
				return wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, deviceKey, defaultTranscript(t)), &fixedTrust{pub: pub}
			},
			wantErr: ErrDocTypeMismatch,
		},
		{
			name: "resolver rejects chain",
			mutate: func(t *testing.T) ([]byte, IssuerTrust) {
				is, _, deviceKey := buildValidIssuerSigned(t, "org.iso.18013.5.1.mDL", "SHA-256", from, until)
				return wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, deviceKey, defaultTranscript(t)), &refusingTrust{}
			},
			wantErr: ErrIssuerAuth,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, resolver := tt.mutate(t)
			v := NewVerifier(WithClock(now2026))
			_, err := v.Verify(context.Background(), VerifyInput{DeviceResponse: raw, SessionTranscript: defaultTranscript(t), IssuerTrust: resolver})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyMSO_ExpectedDocTypeNarrowing(t *testing.T) {
	is, pub, deviceKey := buildValidIssuerSigned(t, "org.iso.18013.5.1.mDL", "SHA-256", now2026().Add(-time.Hour), now2026().Add(time.Hour))
	st := defaultTranscript(t)
	raw := wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, deviceKey, st)
	v := NewVerifier(WithClock(now2026))
	_, err := v.Verify(context.Background(), VerifyInput{DeviceResponse: raw, SessionTranscript: st, IssuerTrust: &fixedTrust{pub: pub}, ExpectedDocType: "eu.europa.ec.eudi.pid.1"})
	if !errors.Is(err, ErrDocTypeMismatch) {
		t.Fatalf("err = %v, want ErrDocTypeMismatch", err)
	}
}

func TestParseCOSEKey_CurvePolicy(t *testing.T) {
	// P-224 is a real curve but not ECCG-allowed → rejected.
	bad := genKey(t, elliptic.P224())
	raw := deviceKeyToCOSEUnchecked(t, &bad.PublicKey, 99) // bogus crv label
	if _, err := parseCOSEKey(raw); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
}

// buildIssuerSignedCertWindow is buildValidIssuerSigned with the document
// signer certificate's own window under the test's control, so the signing time
// and the signer's validity period can be moved independently.
func buildIssuerSignedCertWindow(t *testing.T, from, until, certFrom, certUntil time.Time) (IssuerSigned, *ecdsa.PublicKey, *ecdsa.PrivateKey) {
	t.Helper()
	issuerKey := genKey(t, elliptic.P256())
	dev := genKey(t, elliptic.P256())
	fn := itemBytes(t, 0, "org.iso.18013.5.1", "family_name", "Dent")
	msoBytes := buildMSOBytes(t, msoFixture{
		docType: "org.iso.18013.5.1.mDL", digestAlg: "SHA-256", deviceKey: &dev.PublicKey,
		validFrom: from, validUntil: until,
		items: map[string]map[uint]cbor.RawMessage{"org.iso.18013.5.1": {0: fn}},
	})
	dsCert := issuerCertDER(t, issuerKey, certFrom, certUntil)
	issuerAuth := signIssuerAuth(t, issuerKey, [][]byte{dsCert}, msoBytes)
	return IssuerSigned{NameSpaces: IssuerNameSpaces{"org.iso.18013.5.1": {fn}}, IssuerAuth: issuerAuth}, &issuerKey.PublicKey, dev
}

// The signing time must fall inside the signer certificate's own validity
// window. This is what stops a signer whose window never covered the moment it
// claims to have signed at, and it holds no matter which instant the trust
// boundary judges the path at.
func TestVerifyRejectsSigningTimeOutsideSignerWindow(t *testing.T) {
	signedAt := now2026().Add(-time.Hour) // == validFrom, which the fixture uses as `signed`
	// A signer certificate whose window begins AFTER the credential was signed.
	is, pub, dev := buildIssuerSignedCertWindow(t,
		signedAt, now2026().Add(time.Hour),
		signedAt.Add(24*time.Hour), signedAt.Add(48*time.Hour))
	st := defaultTranscript(t)
	raw := wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, dev, st)

	_, err := NewVerifier(WithClock(now2026)).Verify(context.Background(), VerifyInput{
		DeviceResponse: raw, SessionTranscript: st, IssuerTrust: &fixedTrust{pub: pub},
	})
	if !errors.Is(err, ErrIssuerCertValidity) {
		t.Fatalf("want ErrIssuerCertValidity, got %v", err)
	}
}

// The claimed signing time reaches the trust boundary, and it is the value the
// signed structure carries. Without it the boundary has no instant to judge the
// certificate path at other than the current clock — which is what failed every
// credential signed before its issuer's last rotation.
func TestVerifyPassesSigningTimeToTrustBoundary(t *testing.T) {
	signedAt := now2026().Add(-30 * 24 * time.Hour)
	is, pub, dev := buildIssuerSignedCertWindow(t,
		signedAt, now2026().Add(time.Hour),
		signedAt.Add(-time.Hour), signedAt.Add(time.Hour))
	st := defaultTranscript(t)
	raw := wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, dev, st)

	tr := &fixedTrust{pub: pub}
	docs, err := NewVerifier(WithClock(now2026)).Verify(context.Background(), VerifyInput{
		DeviceResponse: raw, SessionTranscript: st, IssuerTrust: tr,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !tr.askedFor.Equal(signedAt) {
		t.Fatalf("trust boundary asked for %s, want the signing time %s", tr.askedFor, signedAt)
	}
	if !docs[0].ValidityInfo.Signed.Equal(signedAt) {
		t.Fatalf("verified signing time %s, want %s", docs[0].ValidityInfo.Signed, signedAt)
	}
}

// A document signer that has since expired is no longer this library's decision:
// it hands the signing time to the trust boundary and accepts that answer. The
// credential's own window is still judged against the current clock.
func TestVerifyLeavesExpiredSignerToTheTrustBoundary(t *testing.T) {
	signedAt := now2026().Add(-200 * 24 * time.Hour)
	is, pub, dev := buildIssuerSignedCertWindow(t,
		signedAt, now2026().Add(24*time.Hour), // credential still valid now
		signedAt.Add(-time.Hour), signedAt.Add(time.Hour)) // signer long expired
	st := defaultTranscript(t)
	raw := wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, dev, st)

	if _, err := NewVerifier(WithClock(now2026)).Verify(context.Background(), VerifyInput{
		DeviceResponse: raw, SessionTranscript: st, IssuerTrust: &fixedTrust{pub: pub},
	}); err != nil {
		t.Fatalf("an expired signer must not be refused by this library: %v", err)
	}

	// And when the boundary refuses, the credential is refused.
	_, err := NewVerifier(WithClock(now2026)).Verify(context.Background(), VerifyInput{
		DeviceResponse: raw, SessionTranscript: st, IssuerTrust: &refusingTrust{},
	})
	if !errors.Is(err, ErrIssuerAuth) {
		t.Fatalf("want ErrIssuerAuth when the trust boundary refuses, got %v", err)
	}
}
