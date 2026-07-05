package mdoc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

// FuzzDecodeDeviceResponse: the DeviceResponse decoder must never panic on
// malformed input (hard rule 5). Run ≥ 30 s locally before completing T-03.2.
func FuzzDecodeDeviceResponse(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0xa0})       // empty map
	f.Add([]byte{0x80})       // empty array
	f.Add([]byte{0xd8, 0x18}) // dangling tag 24
	// seed with the structurally valid minimal vector
	f.Add(buildFuzzSeed())
	f.Fuzz(func(_ *testing.T, data []byte) {
		if d, err := DecodeDeviceResponse(data); err == nil {
			// exercise downstream raw accessors without panicking
			for i := range d.Documents {
				for _, items := range d.Documents[i].IssuerSigned.NameSpaces {
					for _, it := range items {
						var isi IssuerSignedItem
						_ = decodeTagged24(it, &isi)
					}
				}
			}
		}
	})
}

// FuzzVerify: Verify must never panic on malformed DeviceResponse bytes, even
// with a resolver that returns a key. Run ≥ 30 s (hard rule 5).
func FuzzVerify(f *testing.F) {
	f.Add(buildFuzzSeed())
	f.Add([]byte{0xa0})
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	resolver := func(_ [][]byte) (cryptoPub, error) { return &key.PublicKey, nil }
	v := NewVerifier(WithClock(func() time.Time { return time.Unix(1_800_000_000, 0) }))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = v.Verify(context.Background(), VerifyInput{DeviceResponse: data, IssuerChainResolver: resolver})
	})
}

// FuzzParseCOSEKey: the COSE_Key parser must never panic (hard rule 5).
func FuzzParseCOSEKey(f *testing.F) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.Add(deviceKeyToCOSEBytes(&key.PublicKey))
	f.Add([]byte{0xa0})
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = parseCOSEKey(data)
	})
}

// FuzzParseMSOStatus: the MSO status extension parser must never panic (hard
// rule 5). FuzzVerify cannot reach this path because it is gated behind
// eudicrypto.VerifyCOSESign1 (a real ECDSA signature check the mutation
// fuzzer cannot satisfy from an unsigned seed), so parseMSOStatus needs its
// own direct-call fuzz target — same rationale as FuzzParseCOSEKey above.
func FuzzParseMSOStatus(f *testing.F) {
	valid, _ := encode(map[string]any{"status_list": map[string]any{"uri": "https://x/1", "idx": uint(1)}})
	missingURI, _ := encode(map[string]any{"status_list": map[string]any{"idx": uint(1)}})
	notAMap, _ := encode("x")
	f.Add(valid)
	f.Add([]byte(nil))
	f.Add([]byte{0xa0}) // empty map
	f.Add(notAMap)
	f.Add(missingURI)
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = parseMSOStatus(data)
	})
}

// buildFuzzSeed mirrors buildMinimalDeviceResponse without a *testing.T.
func buildFuzzSeed() []byte {
	item := IssuerSignedItem{DigestID: 0, Random: make([]byte, 32), ElementIdentifier: "family_name"}
	item.ElementValue, _ = encode("Dent")
	itemBytes, _ := encodeTagged24(item)
	issuerAuth, _ := encode([]any{[]byte{}, map[int]any{}, nil, []byte{}})
	devNS, _ := encodeTagged24(map[string]any{})
	deviceSig, _ := encode([]any{[]byte{}, map[int]any{}, nil, []byte{}})
	resp := DeviceResponse{
		Version: "1.0",
		Documents: []Document{{
			DocType:      "org.iso.18013.5.1.mDL",
			IssuerSigned: IssuerSigned{NameSpaces: IssuerNameSpaces{"org.iso.18013.5.1": {itemBytes}}, IssuerAuth: issuerAuth},
			DeviceSigned: DeviceSigned{NameSpaces: devNS, DeviceAuth: DeviceAuth{DeviceSignature: deviceSig}},
		}},
	}
	raw, _ := encode(resp)
	return raw
}
