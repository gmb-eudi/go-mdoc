package mdoc

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

// verifyIssuerAuth performs [ISO/IEC 18013-5 §9.1.2] issuer data authentication:
// extract x5chain → read the claimed signing time → assert it lies inside the
// document signer certificate's window ([ISO/IEC 18013-5 §9.3.1] step 5) →
// resolve the DS key at that time (trust boundary) → verify the IssuerAuth
// COSE_Sign1 (go-eudi-crypto) → decode the MSO → re-assert the signing time
// against the authenticated copy → enforce the digest-alg allow-list and the
// ValidityInfo window, and return the sealed device key.
func (v *Verifier) verifyIssuerAuth(issuerAuth cbor.RawMessage, trust IssuerTrust, at time.Time) (*MobileSecurityObject, crypto.PublicKey, error) {
	parts, err := coseParts(issuerAuth)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: IssuerAuth: %w", ErrIssuerAuth, err)
	}
	x5chain, err := x5chainFrom(parts)
	if err != nil {
		return nil, nil, err
	}
	// The signing time the credential claims, read before its signature is
	// verified. The certificate path has to be judged at some instant, and the
	// only instant on offer is inside the structure being verified — so it is
	// read here, treated as untrusted, and used to select a validation time and
	// nothing else. Two assertions make that safe: the window check immediately
	// below, and the re-assertion against the authenticated value once the
	// signature holds. A forged time buys an attacker a chain judged at an
	// instant inside the signer's own window, against the same anchors, and
	// still requires the signer's private key to get past the signature.
	claimed, err := claimedSigningTime(parts[2])
	if err != nil {
		return nil, nil, err
	}
	if err := checkSignerWindow(x5chain, claimed); err != nil {
		return nil, nil, err
	}
	dsKey, err := trust.ResolveIssuerKey(x5chain, claimed)
	if err != nil {
		// Wrap the cause, not only its text: a certificate outside its window
		// and a chain that reaches no anchor arrive here as different errors and
		// must stay tellable apart by the caller.
		return nil, nil, fmt.Errorf("%w: chain resolution: %w", ErrIssuerAuth, err)
	}
	if dsKey == nil {
		return nil, nil, fmt.Errorf("%w: trust boundary returned nil key", ErrIssuerAuth)
	}
	tagged, err := coseAssemble(parts)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrIssuerAuth, err)
	}
	payload, _, err := eudicrypto.VerifyCOSESign1([]byte(tagged), dsKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrIssuerAuth, err) // wraps ErrVerificationFailed/ErrAlg*
	}
	// payload = MobileSecurityObjectBytes = #6.24(bstr .cbor MSO)
	var mso MobileSecurityObject
	if err := decodeTagged24(payload, &mso); err != nil {
		return nil, nil, fmt.Errorf("%w: MSO: %w", ErrMalformed, err)
	}
	// The signing time is issuer-attested from here on. The certificate window
	// and the validation time were decided on the unverified copy, so require
	// the authenticated value to be the same one: otherwise the bytes that were
	// judged are not the bytes that were signed.
	if !mso.ValidityInfo.Signed.Equal(claimed) {
		return nil, nil, fmt.Errorf("%w: signing time differs between the signed and the presented structure", ErrIssuerAuth)
	}
	if _, err := hashForMSODigestAlg(mso.DigestAlgorithm); err != nil {
		return nil, nil, err
	}
	if err := checkValidity(mso.ValidityInfo, at); err != nil {
		return nil, nil, err
	}
	deviceKey, err := parseCOSEKey(mso.DeviceKeyInfo.DeviceKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: deviceKey: %w", ErrMalformed, err)
	}
	return &mso, deviceKey, nil
}

// claimedSigningTime reads validityInfo.signed out of an unverified
// MobileSecurityObjectBytes payload element. The value is a claim, not a fact,
// until the enclosing signature verifies — the caller treats it as such.
func claimedSigningTime(payloadElement cbor.RawMessage) (time.Time, error) {
	var payload []byte
	if err := decode([]byte(payloadElement), &payload); err != nil {
		return time.Time{}, fmt.Errorf("%w: IssuerAuth payload: %w", ErrMalformed, err)
	}
	var mso MobileSecurityObject
	if err := decodeTagged24(payload, &mso); err != nil {
		return time.Time{}, fmt.Errorf("%w: MSO: %w", ErrMalformed, err)
	}
	if mso.ValidityInfo.Signed.IsZero() {
		return time.Time{}, fmt.Errorf("%w: ValidityInfo missing signed", ErrMalformed)
	}
	return mso.ValidityInfo.Signed, nil
}

// checkSignerWindow enforces the first assertion of [ISO/IEC 18013-5 §9.3.1]
// step 5: the signing time must lie within the validity period of the
// certificate in the MSO header. It is independent of any expiry policy — what
// it stops is a signer whose window never covered the moment it claims to have
// signed at — so it runs for every credential and is not configurable.
// Certificate dates and the signing time are provenance, not attribute values,
// so they are safe to name in the error.
func checkSignerWindow(x5chain [][]byte, signed time.Time) error {
	if len(x5chain) == 0 {
		return fmt.Errorf("%w: empty x5chain", ErrIssuerAuth)
	}
	leaf, err := x509.ParseCertificate(x5chain[0])
	if err != nil {
		return fmt.Errorf("%w: document signer certificate does not parse", ErrIssuerAuth)
	}
	if signed.Before(leaf.NotBefore) || signed.After(leaf.NotAfter) {
		return fmt.Errorf("%w: signed=%s signer certificate window=[%s,%s]", ErrIssuerCertValidity,
			signed.UTC().Format(time.RFC3339),
			leaf.NotBefore.UTC().Format(time.RFC3339),
			leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

// checkValidity enforces [ISO/IEC 18013-5 §9.1.2.4] ValidityInfo. Times are safe to
// include in errors (not attribute values). validFrom must be strictly before
// validUntil (EU cross-check): an issuer that sets
// them equal (or reversed) has produced an incoherent window, not a
// zero-length-but-valid one.
func checkValidity(vi ValidityInfo, at time.Time) error {
	if vi.ValidFrom.IsZero() || vi.ValidUntil.IsZero() {
		return fmt.Errorf("%w: ValidityInfo missing validFrom/validUntil", ErrMalformed)
	}
	if !vi.ValidFrom.Before(vi.ValidUntil) {
		return fmt.Errorf("%w: validFrom not strictly before validUntil", ErrMalformed)
	}
	if at.Before(vi.ValidFrom) || at.After(vi.ValidUntil) {
		return fmt.Errorf("%w: at=%s window=[%s,%s]", ErrValidity, at.UTC().Format(time.RFC3339), vi.ValidFrom.UTC().Format(time.RFC3339), vi.ValidUntil.UTC().Format(time.RFC3339))
	}
	return nil
}
