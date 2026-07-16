package mdoc

import (
	"context"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

// coseParts strips an optional COSE_Sign1 tag (18) and returns the four
// structural elements [protected, unprotected, payload, signature] as raw CBOR
// (ISO mdoc COSE structures are commonly untagged; finding #3).
func coseParts(raw cbor.RawMessage) ([4]cbor.RawMessage, error) {
	var parts [4]cbor.RawMessage
	body := []byte(raw)
	if len(body) > 0 && body[0] == 0xd2 { // 0xd2 == tag(18)
		var tagged cbor.RawTag
		if err := decode(body, &tagged); err != nil {
			return parts, err
		}
		if tagged.Number != 18 {
			return parts, fmt.Errorf("%w: COSE tag %d, want 18", ErrMalformed, tagged.Number)
		}
		body = []byte(tagged.Content)
	}
	var arr []cbor.RawMessage
	if err := decode(body, &arr); err != nil {
		return parts, err
	}
	if len(arr) != 4 {
		return parts, fmt.Errorf("%w: COSE_Sign1 has %d elements, want 4", ErrMalformed, len(arr))
	}
	copy(parts[:], arr)
	return parts, nil
}

// coseAssemble re-wraps four COSE_Sign1 elements as a tag-18 message — the form
// go-eudi-crypto's VerifyCOSESign1 consumes. Elements are emitted verbatim, so
// the protected header + payload (the signed content) are byte-preserved.
func coseAssemble(parts [4]cbor.RawMessage) (cbor.RawMessage, error) {
	body, err := encode([]cbor.RawMessage{parts[0], parts[1], parts[2], parts[3]})
	if err != nil {
		return nil, err
	}
	return encode(cbor.RawTag{Number: 18, Content: cbor.RawMessage(body)})
}

// x5chainFrom extracts the certificate chain (RFC 9360 label 33) from the
// COSE_Sign1 unprotected header ([ISO/IEC 18013-5 §9.1.2.4] location); it also checks
// the protected header, which RFC 9360 permits.
func x5chainFrom(parts [4]cbor.RawMessage) ([][]byte, error) {
	if chain, ok, err := x5chainFromMap([]byte(parts[1])); err != nil {
		return nil, err
	} else if ok {
		return chain, nil
	}
	protBytes, err := headerBytes(parts[0])
	if err != nil {
		return nil, err
	}
	if len(protBytes) > 0 {
		if chain, ok, err := x5chainFromMap(protBytes); err != nil {
			return nil, err
		} else if ok {
			return chain, nil
		}
	}
	return nil, fmt.Errorf("%w: no x5chain (label 33) in COSE headers", ErrIssuerAuth)
}

func headerBytes(raw cbor.RawMessage) ([]byte, error) {
	var b []byte
	if err := decode(raw, &b); err != nil {
		return nil, fmt.Errorf("%w: protected header not a byte string: %v", ErrMalformed, err)
	}
	return b, nil
}

func x5chainFromMap(mapCBOR []byte) ([][]byte, bool, error) {
	var m map[int64]cbor.RawMessage
	if err := decode(mapCBOR, &m); err != nil {
		return nil, false, nil // not a header map / empty → treat as absent
	}
	v, ok := m[33]
	if !ok {
		return nil, false, nil
	}
	chain, err := parseX5Chain(v)
	if err != nil {
		return nil, false, err
	}
	return chain, true, nil
}

// parseX5Chain accepts either a single bstr (one cert) or an array of bstr
// ([RFC 9360 §2]). DER parsing/validation is the resolver's job (go-eudi-crypto).
func parseX5Chain(raw cbor.RawMessage) ([][]byte, error) {
	var single []byte
	if err := decode(raw, &single); err == nil {
		return [][]byte{single}, nil
	}
	var many [][]byte
	if err := decode(raw, &many); err != nil {
		return nil, fmt.Errorf("%w: x5chain not bstr or [bstr]: %v", ErrMalformed, err)
	}
	if len(many) == 0 {
		return nil, fmt.Errorf("%w: empty x5chain", ErrIssuerAuth)
	}
	return many, nil
}

// spliceCOSEPayload replaces the (detached) payload of a COSE_Sign1 with
// payload and returns a tag-18 message ready for VerifyCOSESign1. Used for
// DeviceSignature verification ([ISO/IEC 18013-5 §9.1.3.4] detached payload;
// finding #2) via verifyDeviceAuth.
func spliceCOSEPayload(raw cbor.RawMessage, payload []byte) (cbor.RawMessage, error) {
	parts, err := coseParts(raw)
	if err != nil {
		return nil, err
	}
	pb, err := encode(payload) // encodes []byte as a bstr
	if err != nil {
		return nil, err
	}
	parts[2] = cbor.RawMessage(pb)
	return coseAssemble(parts)
}

// detachCOSEPayload replaces the payload of a COSE_Sign1 with CBOR null,
// producing the [ISO/IEC 18013-5 §9.1.3.4] detached-payload form of a device
// signature. The signature is unaffected (it never covers the payload slot
// literally; it covers the Sig_structure). Used by DevicePresent.
func detachCOSEPayload(raw cbor.RawMessage) (cbor.RawMessage, error) {
	parts, err := coseParts(raw)
	if err != nil {
		return nil, err
	}
	nullByte, err := encode(nil) // CBOR null (0xf6)
	if err != nil {
		return nil, err
	}
	parts[2] = cbor.RawMessage(nullByte)
	return coseAssemble(parts)
}

// signCOSEWithX5Chain signs payload with go-eudi-crypto and injects the x5chain
// into the unprotected header ([ISO/IEC 18013-5 §9.1.2.4]). The signature covers the
// protected header + payload only, so unprotected injection is safe.
//
// NOTE (README corrections, finding #1): go-eudi-crypto's SignCOSESign1 cannot
// set unprotected headers, so go-mdoc performs the injection via CBOR surgery.
func signCOSEWithX5Chain(ctx context.Context, kp eudicrypto.KeyProvider, keyID string, x5chain [][]byte, payload []byte) (cbor.RawMessage, error) {
	raw, err := eudicrypto.SignCOSESign1(ctx, kp, keyID, nil, payload)
	if err != nil {
		return nil, err
	}
	parts, err := coseParts(cbor.RawMessage(raw))
	if err != nil {
		return nil, err
	}
	unprot, err := encode(map[int64]any{33: x5chain})
	if err != nil {
		return nil, err
	}
	parts[1] = cbor.RawMessage(unprot)
	return coseAssemble(parts)
}
