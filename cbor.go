package mdoc

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"

	"github.com/fxamacker/cbor/v2"
)

// Hardened decode limits (conventions.md: max nesting, max array/map size,
// duplicate-key reject). Bounds are generous for legitimate mdoc responses yet
// bounded against resource-exhaustion / ambiguity attacks on untrusted input.
const (
	maxNestedLevels  = 16    // ISO mdoc nests ~6 deep; 16 is ample headroom
	maxArrayElements = 65536 // e.g. many IssuerSignedItems; hard ceiling
	maxMapPairs      = 65536 // e.g. valueDigests entries; hard ceiling
)

// decMode is the ONE decoder for all untrusted input. fxamacker/cbor is wrapped
// here and never exposed in the public API (ADR-0004). go-eudi-crypto exposes
// no CBOR options, and conventions.md permits format libs to own their DecMode.
var decMode = mustDecMode()

// encMode is the ONE deterministic encoder. Canonical map-key sort + tag-0
// (RFC 3339) times make Issue output and SessionTranscript hashes reproducible.
var encMode = mustEncMode()

func mustDecMode() cbor.DecMode {
	m, err := cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF, // RFC 8949 §5.6: reject duplicates
		IndefLength:      cbor.IndefLengthForbidden, // ISO mdoc uses definite lengths
		MaxNestedLevels:  maxNestedLevels,
		MaxArrayElements: maxArrayElements,
		MaxMapPairs:      maxMapPairs,
		TagsMd:           cbor.TagsAllowed,                    // need tag 0 (time) and tag 24 (embedded)
		DefaultMapType:   reflect.TypeOf(map[string]any(nil)), // element values → map[string]any (go-dcql, WP-05)
		// ExtraReturnErrors intentionally does NOT include ExtraDecErrorUnknownField:
		// the CDDL wire model (T-03.2) requires unknown-map-field tolerance so a
		// forward-compatible producer can add members we don't model yet
		// (TestDecodeToleratesUnknownFields). T-03.1's guard tests decode into
		// concrete types and do not depend on this option.
		UTF8: cbor.UTF8RejectInvalid,
	}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("mdoc: bad DecOptions: %v", err))
	}
	return m
}

func mustEncMode() cbor.EncMode {
	m, err := cbor.EncOptions{
		Sort:        cbor.SortCanonical, // deterministic map-key order
		Time:        cbor.TimeRFC3339,   // tdate as RFC 3339 string
		TimeTag:     cbor.EncTagRequired,
		IndefLength: cbor.IndefLengthForbidden,
	}.EncMode()
	if err != nil {
		panic(fmt.Sprintf("mdoc: bad EncOptions: %v", err))
	}
	return m
}

// decode decodes exactly one top-level CBOR item into v using the hardened
// DecMode and rejects trailing data. Every fxamacker error becomes ErrMalformed
// so parsers never leak third-party error types (ADR-0004) and never panic
// (hard rule 5).
func decode(raw []byte, v any) error {
	dec := decMode.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	// Reject trailing bytes: anything after the top-level item must decode to
	// exactly nothing (io.EOF). A second valid item, a partial/truncated head,
	// or garbage bytes are all trailing data and must fail closed (hard rule 7)
	// rather than being silently accepted because they didn't parse cleanly.
	var scratch cbor.RawMessage
	if err := dec.Decode(&scratch); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing data after top-level item", ErrMalformed)
	}
	return nil
}

// encode marshals v with the deterministic EncMode.
func encode(v any) ([]byte, error) {
	out, err := encMode.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return out, nil
}

// encodeTagged24 encodes v then wraps the encoding as #6.24(bstr .cbor v) —
// the ISO wrapping for IssuerSignedItemBytes, MobileSecurityObjectBytes,
// DeviceNameSpacesBytes and DeviceAuthenticationBytes. Content is a []byte, so
// it marshals as a byte string carrying the nested CBOR (RFC 8949 tag 24).
func encodeTagged24(v any) ([]byte, error) {
	inner, err := encode(v)
	if err != nil {
		return nil, err
	}
	return encode(cbor.Tag{Number: 24, Content: inner})
}

// decodeTagged24 reverses encodeTagged24: decode the tag-24 byte string, then
// decode its content into v.
func decodeTagged24(raw []byte, v any) error {
	inner, err := untag24(raw)
	if err != nil {
		return err
	}
	return decode(inner, v)
}

// untag24 returns the inner CBOR bytes of a #6.24(bstr .cbor ...) item without
// decoding them, preserving the exact wire bytes (needed for digesting).
func untag24(raw []byte) ([]byte, error) {
	var t cbor.Tag
	if err := decode(raw, &t); err != nil {
		return nil, err
	}
	if t.Number != 24 {
		return nil, fmt.Errorf("%w: expected tag 24, got %d", ErrMalformed, t.Number)
	}
	inner, ok := t.Content.([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: tag 24 content is %T, want byte string", ErrMalformed, t.Content)
	}
	return inner, nil
}
