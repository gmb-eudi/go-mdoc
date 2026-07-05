package mdoc

import (
	"crypto"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

// verifyIssuerAuth performs ISO 18013-5 §9.1.2 issuer data authentication:
// extract x5chain → resolve DS key (trust callback) → verify the IssuerAuth
// COSE_Sign1 (go-eudi-crypto) → decode the MSO → enforce the digest-alg
// allow-list, the ValidityInfo window, and return the sealed device key.
func (v *Verifier) verifyIssuerAuth(issuerAuth cbor.RawMessage, resolver IssuerChainResolver, at time.Time) (*MobileSecurityObject, crypto.PublicKey, error) {
	parts, err := coseParts(issuerAuth)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: IssuerAuth: %v", ErrIssuerAuth, err)
	}
	x5chain, err := x5chainFrom(parts)
	if err != nil {
		return nil, nil, err
	}
	dsKey, err := resolver(x5chain)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: chain resolution: %v", ErrIssuerAuth, err)
	}
	if dsKey == nil {
		return nil, nil, fmt.Errorf("%w: resolver returned nil key", ErrIssuerAuth)
	}
	tagged, err := coseAssemble(parts)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrIssuerAuth, err)
	}
	payload, _, err := eudicrypto.VerifyCOSESign1([]byte(tagged), dsKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrIssuerAuth, err) // wraps ErrVerificationFailed/ErrAlg*
	}
	// payload = MobileSecurityObjectBytes = #6.24(bstr .cbor MSO)
	var mso MobileSecurityObject
	if err := decodeTagged24(payload, &mso); err != nil {
		return nil, nil, fmt.Errorf("%w: MSO: %v", ErrMalformed, err)
	}
	if _, err := hashForMSODigestAlg(mso.DigestAlgorithm); err != nil {
		return nil, nil, err
	}
	if err := checkValidity(mso.ValidityInfo, at); err != nil {
		return nil, nil, err
	}
	deviceKey, err := parseCOSEKey(mso.DeviceKeyInfo.DeviceKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: deviceKey: %v", ErrMalformed, err)
	}
	return &mso, deviceKey, nil
}

// checkValidity enforces ISO 18013-5 §9.1.2.4 ValidityInfo. Times are safe to
// include in errors (not attribute values).
func checkValidity(vi ValidityInfo, at time.Time) error {
	if vi.ValidFrom.IsZero() || vi.ValidUntil.IsZero() {
		return fmt.Errorf("%w: ValidityInfo missing validFrom/validUntil", ErrMalformed)
	}
	if at.Before(vi.ValidFrom) || at.After(vi.ValidUntil) {
		return fmt.Errorf("%w: at=%s window=[%s,%s]", ErrValidity, at.UTC().Format(time.RFC3339), vi.ValidFrom.UTC().Format(time.RFC3339), vi.ValidUntil.UTC().Format(time.RFC3339))
	}
	return nil
}
