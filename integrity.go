package mdoc

import (
	"crypto/subtle"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// verifyIssuerIntegrity performs ISO 18013-5 §9.1.2.5 issuer-data integrity:
// for every disclosed IssuerSignedItem, recompute the digest over its exact
// IssuerSignedItemBytes (wire bytes) and match it against MSO ValueDigests for
// the SAME namespace and digestID. Any item whose namespace/digestID is absent
// from ValueDigests, or whose digest differs, fails closed (hard rule 7). A
// disclosed subset is allowed: only presented items are checked. Returns the
// disclosed, digest-checked values (forwarded to the caller, never persisted).
func (v *Verifier) verifyIssuerIntegrity(mso *MobileSecurityObject, ns IssuerNameSpaces) (map[string]map[string]any, error) {
	h, err := hashForMSODigestAlg(mso.DigestAlgorithm)
	if err != nil {
		return nil, err // already allow-listed during MSO verification; defensive
	}
	out := make(map[string]map[string]any, len(ns))
	for namespace, items := range ns {
		digestIDs, ok := mso.ValueDigests[namespace]
		if !ok {
			return nil, fmt.Errorf("%w: namespace %q absent from MSO ValueDigests", ErrIntegrity, namespace)
		}
		nsOut := make(map[string]any, len(items))
		for _, itemBytes := range items {
			var isi IssuerSignedItem
			if err := decodeTagged24(itemBytes, &isi); err != nil {
				return nil, fmt.Errorf("%w: IssuerSignedItem: %v", ErrMalformed, err)
			}
			want, ok := digestIDs[isi.DigestID]
			if !ok {
				return nil, fmt.Errorf("%w: namespace %q digestID %d not in ValueDigests", ErrIntegrity, namespace, isi.DigestID)
			}
			hh := h.New()
			hh.Write([]byte(itemBytes)) // digest over exact wire bytes (ISO §9.1.2.5)
			got := hh.Sum(nil)
			if subtle.ConstantTimeCompare(got, want) != 1 {
				return nil, fmt.Errorf("%w: namespace %q element %q digest mismatch", ErrIntegrity, namespace, isi.ElementIdentifier)
			}
			val, err := decodeElementValue(isi.ElementValue)
			if err != nil {
				return nil, err
			}
			nsOut[isi.ElementIdentifier] = val
		}
		out[namespace] = nsOut
	}
	return out, nil
}

// decodeElementValue decodes a DataElementValue into a Go value (map keys are
// strings via DefaultMapType). Never leaks the value into an error (hard rule
// 3): some fxamacker/cbor decode errors (e.g. duplicate-map-key) embed the
// offending key from inside the value, so the wrapped error is a STATIC
// message with no formatted underlying error text.
func decodeElementValue(raw cbor.RawMessage) (any, error) {
	var val any
	if err := decode([]byte(raw), &val); err != nil {
		return nil, fmt.Errorf("%w: element value decode failed", ErrMalformed)
	}
	return val, nil
}
