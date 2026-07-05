package mdoc

import (
	"errors"
	"testing"
)

// T-03.1: the hardened DecMode must reject duplicate map keys (RFC 8949 §5.6
// ambiguity is an injection vector), over-deep nesting, and over-large
// arrays/maps, and must reject indefinite-length items. These are decoded via
// the same decode() every untrusted-input path uses.

func TestDecodeRejectsDuplicateMapKeys(t *testing.T) {
	// {1: 1, 1: 2} — duplicate integer key 1.
	raw := []byte{0xa2, 0x01, 0x01, 0x01, 0x02}
	var v map[int]int
	if err := decode(raw, &v); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed (duplicate key)", err)
	}
}

func TestDecodeRejectsDeepNesting(t *testing.T) {
	// Build maxNestedLevels+1 nested single-element arrays: 0x81 repeated then a 0.
	depth := maxNestedLevels + 1
	raw := make([]byte, 0, depth+1)
	for i := 0; i < depth; i++ {
		raw = append(raw, 0x81) // array(1)
	}
	raw = append(raw, 0x00) // final element: 0
	var v any
	if err := decode(raw, &v); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed (nesting > %d)", err, maxNestedLevels)
	}
}

func TestDecodeRejectsIndefiniteLength(t *testing.T) {
	// 0x9f ... 0xff is an indefinite-length array; ISO mdoc uses definite lengths.
	raw := []byte{0x9f, 0x01, 0x02, 0xff}
	var v []int
	if err := decode(raw, &v); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed (indefinite length)", err)
	}
}

func TestDecodeRejectsTrailingData(t *testing.T) {
	// The trailing-data check must fail closed regardless of whether the
	// trailing bytes happen to parse as a complete item, a truncated head, or
	// a stray break byte — anything other than a clean io.EOF is malformed
	// (hard rule 7: fail closed).
	cases := []struct {
		name string
		raw  []byte
	}{
		{"two valid items", []byte{0x01, 0x02}},  // int(1), int(2)
		{"stray break byte", []byte{0x01, 0xff}}, // int(1), then lone 0xff break
		{"truncated head", []byte{0x01, 0x18}},   // int(1), then partial uint8 head with no payload
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v int
			if err := decode(tc.raw, &v); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed (trailing data)", err)
			}
		})
	}
}

func TestDecodeRejectsInvalidUTF8(t *testing.T) {
	// A CBOR text string (major type 3) of length 1 whose single byte (0xff)
	// is not valid UTF-8. mustDecMode sets UTF8: cbor.UTF8RejectInvalid, so
	// this must fail closed rather than silently accepting invalid text.
	raw := []byte{0x61, 0xff}
	var s string
	if err := decode(raw, &s); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed (invalid UTF-8)", err)
	}

	var v any
	if err := decode(raw, &v); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed (invalid UTF-8 into any)", err)
	}
}

func TestDecodeEncodeRoundtrip(t *testing.T) {
	type sample struct {
		A string `cbor:"a"`
		B int    `cbor:"b"`
	}
	in := sample{A: "x", B: 7}
	raw, err := encode(in)
	if err != nil {
		t.Fatal(err)
	}
	var out sample
	if err := decode(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("roundtrip = %+v, want %+v", out, in)
	}
}

// tag 24 (#6.24(bstr .cbor X)) is the ISO wrapping used for every *Bytes item;
// the helper roundtrip must be exact so digests computed over wire bytes match.
func TestTagged24Roundtrip(t *testing.T) {
	type inner struct {
		N int `cbor:"n"`
	}
	wrapped, err := encodeTagged24(inner{N: 42})
	if err != nil {
		t.Fatal(err)
	}
	if wrapped[0] != 0xd8 || wrapped[1] != 0x18 { // tag(24) head
		t.Fatalf("tag head = %x %x, want d8 18", wrapped[0], wrapped[1])
	}
	var got inner
	if err := decodeTagged24(wrapped, &got); err != nil {
		t.Fatal(err)
	}
	if got.N != 42 {
		t.Fatalf("inner = %+v, want {42}", got)
	}
}
