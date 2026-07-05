package mdoc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"testing"
	"time"
)

func now2026() time.Time { return time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC) }

func TestVerifyMSO_Valid(t *testing.T) {
	is, issuerPub, deviceKey := buildValidIssuerSigned(t, "org.iso.18013.5.1.mDL", "SHA-256", now2026().Add(-time.Hour), now2026().Add(time.Hour))
	st := defaultTranscript(t)
	raw := wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, deviceKey, st)
	v := NewVerifier(WithClock(now2026))
	docs, err := v.Verify(context.Background(), VerifyInput{
		DeviceResponse:      raw,
		SessionTranscript:   st,
		IssuerChainResolver: fixedResolver(issuerPub),
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
		mutate  func(t *testing.T) (raw []byte, resolver IssuerChainResolver)
		wantErr error
	}{
		{
			name: "wrong DS key",
			mutate: func(t *testing.T) ([]byte, IssuerChainResolver) {
				is, _, deviceKey := buildValidIssuerSigned(t, "org.iso.18013.5.1.mDL", "SHA-256", from, until)
				other := genKey(t, elliptic.P256())
				return wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, deviceKey, defaultTranscript(t)), fixedResolver(&other.PublicKey)
			},
			wantErr: ErrIssuerAuth,
		},
		{
			name: "expired MSO",
			mutate: func(t *testing.T) ([]byte, IssuerChainResolver) {
				is, pub, deviceKey := buildValidIssuerSigned(t, "org.iso.18013.5.1.mDL", "SHA-256", now2026().Add(-48*time.Hour), now2026().Add(-24*time.Hour))
				return wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, deviceKey, defaultTranscript(t)), fixedResolver(pub)
			},
			wantErr: ErrValidity,
		},
		{
			name: "digestAlg SHA-1",
			mutate: func(t *testing.T) ([]byte, IssuerChainResolver) {
				is, pub, deviceKey := buildValidIssuerSigned(t, "org.iso.18013.5.1.mDL", "SHA-1", from, until)
				return wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, deviceKey, defaultTranscript(t)), fixedResolver(pub)
			},
			wantErr: ErrDigestAlg,
		},
		{
			name: "docType mismatch MSO vs Document",
			mutate: func(t *testing.T) ([]byte, IssuerChainResolver) {
				is, pub, deviceKey := buildValidIssuerSigned(t, "eu.europa.ec.eudi.pid.1", "SHA-256", from, until)
				// Document says mDL, MSO says PID.
				return wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, deviceKey, defaultTranscript(t)), fixedResolver(pub)
			},
			wantErr: ErrDocTypeMismatch,
		},
		{
			name: "resolver rejects chain",
			mutate: func(t *testing.T) ([]byte, IssuerChainResolver) {
				is, _, deviceKey := buildValidIssuerSigned(t, "org.iso.18013.5.1.mDL", "SHA-256", from, until)
				return wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, deviceKey, defaultTranscript(t)), func(_ [][]byte) (cryptoPub, error) { return nil, errors.New("untrusted") }
			},
			wantErr: ErrIssuerAuth,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, resolver := tt.mutate(t)
			v := NewVerifier(WithClock(now2026))
			_, err := v.Verify(context.Background(), VerifyInput{DeviceResponse: raw, SessionTranscript: defaultTranscript(t), IssuerChainResolver: resolver})
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
	_, err := v.Verify(context.Background(), VerifyInput{DeviceResponse: raw, SessionTranscript: st, IssuerChainResolver: fixedResolver(pub), ExpectedDocType: "eu.europa.ec.eudi.pid.1"})
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
