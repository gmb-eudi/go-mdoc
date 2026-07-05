package mdoc

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

// parseCOSEKey parses a COSE_Key (RFC 9052 §7) into an EC public key. EC2 keys
// only. The curve is validated against the ECCG allow-list via go-eudi-crypto
// (hard rule 4); the point is checked on-curve via crypto/ecdh.
//
// FLAG (README corrections, finding #5): go-eudi-crypto exposes no COSE_Key
// parser; propose eudicrypto.ParseCOSEKey. This implementation threads the
// curve allow-list through eudicrypto.ECCG().AllowedCurve.
func parseCOSEKey(raw cbor.RawMessage) (*ecdsa.PublicKey, error) {
	var m map[int64]cbor.RawMessage
	if err := decode([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("%w: COSE_Key: %v", ErrMalformed, err)
	}
	var kty int64
	if err := decode(m[1], &kty); err != nil || kty != 2 { // RFC 9053 §7.1: EC2 = 2
		return nil, fmt.Errorf("%w: COSE_Key kty not EC2", ErrUnsupported)
	}
	var crvLabel int64
	if err := decode(m[-1], &crvLabel); err != nil {
		return nil, fmt.Errorf("%w: COSE_Key crv: %v", ErrMalformed, err)
	}
	curve, ecdhCurve, crvName, err := curveForCOSELabel(crvLabel)
	if err != nil {
		return nil, err
	}
	if !eudicrypto.ECCG().AllowedCurve(crvName) {
		return nil, fmt.Errorf("%w: curve %s not ECCG-allowed", ErrUnsupported, crvName)
	}
	var x, y []byte
	if err := decode(m[-2], &x); err != nil {
		return nil, fmt.Errorf("%w: COSE_Key x: %v", ErrMalformed, err)
	}
	if err := decode(m[-3], &y); err != nil {
		return nil, fmt.Errorf("%w: COSE_Key y: %v", ErrMalformed, err)
	}
	size := (curve.Params().BitSize + 7) / 8
	if len(x) > size || len(y) > size {
		return nil, fmt.Errorf("%w: COSE_Key coordinate too large", ErrMalformed)
	}
	pt := make([]byte, 1+2*size)
	pt[0] = 0x04
	copy(pt[1+size-len(x):1+size], x)
	copy(pt[1+2*size-len(y):], y)
	if _, err := ecdhCurve.NewPublicKey(pt); err != nil { // validates on-curve
		return nil, fmt.Errorf("%w: COSE_Key point invalid: %v", ErrMalformed, err)
	}
	return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
}

// curveForCOSELabel maps a COSE EC2 curve label (RFC 9053 §7.1) to the stdlib
// curve, its ecdh counterpart, and the ECCG policy name.
func curveForCOSELabel(label int64) (elliptic.Curve, ecdh.Curve, string, error) {
	switch label {
	case 1: // P-256
		return elliptic.P256(), ecdh.P256(), "P-256", nil
	case 2: // P-384
		return elliptic.P384(), ecdh.P384(), "P-384", nil
	case 3: // P-521
		return elliptic.P521(), ecdh.P521(), "P-521", nil
	default:
		return nil, nil, "", fmt.Errorf("%w: COSE curve label %d", ErrUnsupported, label)
	}
}

// encodeCOSEKey encodes an EC public key as a COSE_Key (RFC 9052 §7): kty EC2,
// crv, x, y. The curve is validated via the ECCG allow-list (hard rule 4) and
// coordinates are read via ecdsa.PublicKey.Bytes() (Go 1.26; the deprecated
// X/Y big.Int fields are not used). Used by Issue (T-03.9) to seal the device
// key into the MSO DeviceKeyInfo — the inverse of parseCOSEKey.
func encodeCOSEKey(pub *ecdsa.PublicKey) ([]byte, error) {
	var crv int64
	var name string
	switch pub.Curve {
	case elliptic.P256():
		crv, name = 1, "P-256"
	case elliptic.P384():
		crv, name = 2, "P-384"
	case elliptic.P521():
		crv, name = 3, "P-521"
	default:
		return nil, fmt.Errorf("%w: curve %s", ErrUnsupported, pub.Curve.Params().Name)
	}
	if !eudicrypto.ECCG().AllowedCurve(name) {
		return nil, fmt.Errorf("%w: curve %s not ECCG-allowed", ErrUnsupported, name)
	}
	x, y, err := ecPointCoordinates(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	return encode(map[int64]any{1: int64(2), -1: crv, -2: x, -3: y})
}

// errPointEncoding is returned by ecPointCoordinates for an unexpected SEC1
// point encoding; wrapped with ErrUnsupported by the caller.
var errPointEncoding = errors.New("unexpected point encoding")

// ecPointCoordinates splits an EC public key's SEC1 uncompressed-point
// encoding (0x04 || X || Y, both fixed-width per curve) into its X/Y
// coordinate bytes via ecdsa.PublicKey.Bytes() (Go 1.26; avoids the deprecated
// X/Y big.Int fields). Mirrors the test helper cosePointXY but lives in
// production code for encodeCOSEKey.
func ecPointCoordinates(pub *ecdsa.PublicKey) (x, y []byte, err error) {
	b, err := pub.Bytes()
	if err != nil {
		return nil, nil, err
	}
	if len(b) < 1 || b[0] != 0x04 {
		return nil, nil, errPointEncoding
	}
	half := (len(b) - 1) / 2
	return b[1 : 1+half], b[1+half:], nil
}
