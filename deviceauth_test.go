package mdoc

import (
	"context"
	"crypto/elliptic"
	"errors"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func TestDeviceAuth_Valid(t *testing.T) {
	is, issuerPub, deviceKey := buildValidIssuerSigned(t, "org.iso.18013.5.1.mDL", "SHA-256", now2026().Add(-time.Hour), now2026().Add(time.Hour))
	st := defaultTranscript(t)
	raw := wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, deviceKey, st)
	_, err := NewVerifier(WithClock(now2026)).Verify(context.Background(), VerifyInput{
		DeviceResponse: raw, SessionTranscript: st, IssuerChainResolver: fixedResolver(issuerPub),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// Transcript binding: verify with a DIFFERENT transcript than the one signed →
// device auth fails (swap nonce ⇒ fail).
func TestDeviceAuth_TranscriptSwapFails(t *testing.T) {
	is, issuerPub, deviceKey := buildValidIssuerSigned(t, "org.iso.18013.5.1.mDL", "SHA-256", now2026().Add(-time.Hour), now2026().Add(time.Hour))
	signedST := defaultTranscript(t)
	raw := wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, deviceKey, signedST)
	otherRaw, err := encode([]any{nil, nil, []any{[]byte("cidhash"), []byte("urihash"), "DIFFERENT-nonce"}})
	if err != nil {
		t.Fatal(err)
	}
	swapped := sessionTranscriptFromRaw(otherRaw)
	_, err = NewVerifier(WithClock(now2026)).Verify(context.Background(), VerifyInput{
		DeviceResponse: raw, SessionTranscript: swapped, IssuerChainResolver: fixedResolver(issuerPub),
	})
	if !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("err = %v, want ErrDeviceAuth", err)
	}
}

// deviceMac is unsupported for remote flows → distinct typed error.
func TestDeviceAuth_DeviceMacUnsupported(t *testing.T) {
	is, issuerPub, deviceKey := buildValidIssuerSigned(t, "org.iso.18013.5.1.mDL", "SHA-256", now2026().Add(-time.Hour), now2026().Add(time.Hour))
	st := defaultTranscript(t)
	devNS, _ := encodeTagged24(map[string]any{})
	mac, _ := encode([]any{[]byte{}, map[int]any{}, nil, []byte("mac-tag")}) // COSE_Mac0-shaped placeholder
	resp := DeviceResponse{Version: "1.0", Documents: []Document{{
		DocType:      "org.iso.18013.5.1.mDL",
		IssuerSigned: is,
		DeviceSigned: DeviceSigned{NameSpaces: devNS, DeviceAuth: DeviceAuth{DeviceMac: cbor.RawMessage(mac)}},
	}}}
	raw, err := encode(resp)
	if err != nil {
		t.Fatal(err)
	}
	_ = deviceKey
	_, err = NewVerifier(WithClock(now2026)).Verify(context.Background(), VerifyInput{
		DeviceResponse: raw, SessionTranscript: st, IssuerChainResolver: fixedResolver(issuerPub),
	})
	if !errors.Is(err, ErrDeviceMacUnsupported) {
		t.Fatalf("err = %v, want ErrDeviceMacUnsupported", err)
	}
}

// Wrong device key: sign with a key not sealed in the MSO → fails.
func TestDeviceAuth_WrongDeviceKeyFails(t *testing.T) {
	is, issuerPub, _ := buildValidIssuerSigned(t, "org.iso.18013.5.1.mDL", "SHA-256", now2026().Add(-time.Hour), now2026().Add(time.Hour))
	st := defaultTranscript(t)
	rogue := genKey(t, elliptic.P256()) // not the MSO deviceKey
	raw := wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, rogue, st)
	_, err := NewVerifier(WithClock(now2026)).Verify(context.Background(), VerifyInput{
		DeviceResponse: raw, SessionTranscript: st, IssuerChainResolver: fixedResolver(issuerPub),
	})
	if !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("err = %v, want ErrDeviceAuth", err)
	}
}

// Missing transcript for a remote flow fails closed.
func TestDeviceAuth_MissingTranscriptFails(t *testing.T) {
	is, issuerPub, deviceKey := buildValidIssuerSigned(t, "org.iso.18013.5.1.mDL", "SHA-256", now2026().Add(-time.Hour), now2026().Add(time.Hour))
	raw := wrapDeviceResponse(t, "org.iso.18013.5.1.mDL", is, deviceKey, defaultTranscript(t))
	_, err := NewVerifier(WithClock(now2026)).Verify(context.Background(), VerifyInput{
		DeviceResponse: raw, IssuerChainResolver: fixedResolver(issuerPub), // no SessionTranscript
	})
	if !errors.Is(err, ErrDeviceAuth) {
		t.Fatalf("err = %v, want ErrDeviceAuth", err)
	}
}
