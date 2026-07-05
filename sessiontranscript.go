package mdoc

import (
	"crypto/sha256"
)

// SessionTranscript is the ISO 18013-5 §9.1.5.1 / ISO/IEC TS 18013-7 Annex B
// SessionTranscript = [DeviceEngagementBytes, EReaderKeyBytes, Handover],
// carried as its exact CBOR encoding. It is opaque to callers of Verify: built
// by go-oid4vp via the OID4VPHandover / OID4VPDCAPIHandover constructors
// (T-03.6) and consumed by device-authentication transcript binding (T-03.5).
type SessionTranscript struct {
	cbor []byte
}

// Bytes returns the exact CBOR encoding of the SessionTranscript array. Used
// for golden-vector byte-exactness (T-03.6) and by go-oid4vp when it needs the
// on-the-wire transcript.
func (s SessionTranscript) Bytes() []byte {
	out := make([]byte, len(s.cbor))
	copy(out, s.cbor)
	return out
}

// sessionTranscriptFromRaw wraps pre-encoded SessionTranscript CBOR. Internal:
// the public constructors (T-03.6) call it after building the handover.
func sessionTranscriptFromRaw(raw []byte) SessionTranscript {
	cp := make([]byte, len(raw))
	copy(cp, raw)
	return SessionTranscript{cbor: cp}
}

// OID4VPHandover builds the SessionTranscript for the redirect (non-DC-API)
// OpenID4VP flow: SessionTranscript = [null, null, OID4VPHandover], where
// OID4VPHandover = [clientIdHash, responseUriHash, nonce] and each hash is
// SHA-256 over the CBOR array of its inputs (OpenID4VP 1.0 Annex B.2.6.1;
// ISO/IEC TS 18013-7 Annex B). SHA-256 is fixed by the profile — a spec
// constant, not an ECCG-negotiable choice, so it is not routed through the
// algorithm allow-list.
func OID4VPHandover(clientID, nonce, mdocGeneratedNonce, responseURI string) SessionTranscript {
	clientIDHash := sha256Sum(mustEncode([]any{clientID, mdocGeneratedNonce}))
	responseURIHash := sha256Sum(mustEncode([]any{responseURI, mdocGeneratedNonce}))
	handover := []any{clientIDHash, responseURIHash, nonce}
	return sessionTranscriptFromRaw(mustEncode([]any{nil, nil, handover}))
}

// OID4VPDCAPIHandover builds the SessionTranscript for the W3C Digital
// Credentials API flow: SessionTranscript = [null, null, OID4VPDCAPIHandover],
// OID4VPDCAPIHandover = ["OpenID4VPDCAPIHandover", SHA-256(CBOR([origin,
// client_id, nonce]))] (OpenID4VP 1.0 Annex B.2.6.2).
func OID4VPDCAPIHandover(origin, clientID, nonce string) SessionTranscript {
	infoHash := sha256Sum(mustEncode([]any{origin, clientID, nonce}))
	handover := []any{"OpenID4VPDCAPIHandover", infoHash}
	return sessionTranscriptFromRaw(mustEncode([]any{nil, nil, handover}))
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// mustEncode encodes deterministically. The constructors marshal only strings
// and byte slices, so encoding cannot fail; a failure would be a programming
// error, not untrusted input (hard rule 5 concerns parsers, not builders).
func mustEncode(v any) []byte {
	b, err := encode(v)
	if err != nil {
		panic("mdoc: SessionTranscript encode: " + err.Error())
	}
	return b
}
