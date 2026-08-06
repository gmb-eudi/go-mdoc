package mdoc

import (
	"crypto/sha256"
)

// SessionTranscript is the [ISO/IEC 18013-5 §9.1.5.1] / ISO/IEC TS 18013-7 Annex B
// SessionTranscript = [DeviceEngagementBytes, EReaderKeyBytes, Handover],
// carried as its exact CBOR encoding. It is opaque to callers of Verify: built
// by go-oid4vp via the OID4VPHandover / OID4VPDCAPIHandover constructors
// and consumed by device-authentication transcript binding.
type SessionTranscript struct {
	cbor []byte
}

// Bytes returns the exact CBOR encoding of the SessionTranscript array. Used
// for golden-vector byte-exactness and by go-oid4vp when it needs the
// on-the-wire transcript.
func (s SessionTranscript) Bytes() []byte {
	out := make([]byte, len(s.cbor))
	copy(out, s.cbor)
	return out
}

// sessionTranscriptFromRaw wraps pre-encoded SessionTranscript CBOR. Internal:
// the public constructors call it after building the handover.
func sessionTranscriptFromRaw(raw []byte) SessionTranscript {
	cp := make([]byte, len(raw))
	copy(cp, raw)
	return SessionTranscript{cbor: cp}
}

// OID4VPHandover builds the SessionTranscript for the redirect (non-DC-API)
// OpenID4VP flow: SessionTranscript = [null, null, OID4VPHandover], where
// OID4VPHandover = ["OpenID4VPHandover", SHA-256(CBOR(OpenID4VPHandoverInfo))]
// and OpenID4VPHandoverInfo = [clientId, nonce, jwkThumbprint, responseUri]
// ([OpenID4VP 1.0 Annex B.2.6.1]). SHA-256 is fixed by the profile — a spec
// constant, not an ECCG-negotiable choice, so it is not routed through the
// algorithm allow-list.
//
// clientID is the client_id request parameter INCLUDING its Client Identifier
// Prefix (e.g. "x509_san_dns:verifier.example.com"); responseURI is whichever
// of response_uri / redirect_uri the response mode used.
//
// jwkThumbprint is the RFC 7638 JWK SHA-256 thumbprint of the RP's ephemeral
// response-encryption public key as RAW DIGEST BYTES, encoded on the wire as a
// CBOR byte string — never the printable base64url form, which hashes to a
// different transcript and would fail device authentication against every
// conformant wallet. Pass nil when the response is not encrypted; that encodes
// as CBOR null, as the spec requires.
func OID4VPHandover(clientID, nonce string, jwkThumbprint []byte, responseURI string) SessionTranscript {
	info := []any{clientID, nonce, nullable(jwkThumbprint), responseURI}
	infoHash := sha256Sum(mustEncode(info))
	handover := []any{"OpenID4VPHandover", infoHash}
	return sessionTranscriptFromRaw(mustEncode([]any{nil, nil, handover}))
}

// OID4VPDCAPIHandover builds the SessionTranscript for the W3C Digital
// Credentials API flow: SessionTranscript = [null, null, OID4VPDCAPIHandover],
// OID4VPDCAPIHandover = ["OpenID4VPDCAPIHandover",
// SHA-256(CBOR(OpenID4VPDCAPIHandoverInfo))], OpenID4VPDCAPIHandoverInfo =
// [origin, nonce, jwkThumbprint] ([OpenID4VP 1.0 Annex B.2.6.2]; no clientId or
// responseUri in this variant — origin carries the RP identity signal instead,
// and must not carry an "origin:" prefix).
//
// jwkThumbprint: raw digest bytes or nil, exactly as for OID4VPHandover. It is
// present for response mode dc_api.jwt and null for plain dc_api.
func OID4VPDCAPIHandover(origin, nonce string, jwkThumbprint []byte) SessionTranscript {
	info := []any{origin, nonce, nullable(jwkThumbprint)}
	infoHash := sha256Sum(mustEncode(info))
	handover := []any{"OpenID4VPDCAPIHandover", infoHash}
	return sessionTranscriptFromRaw(mustEncode([]any{nil, nil, handover}))
}

// nullable maps an absent (nil or empty) thumbprint to CBOR null, matching the
// spec's "otherwise the third element MUST be null" phrasing. A non-empty value
// is returned as []byte so the encoder emits a byte string, not a text string.
func nullable(thumbprint []byte) any {
	if len(thumbprint) == 0 {
		return nil
	}
	return thumbprint
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// mustEncode encodes deterministically. The constructors marshal only strings
// and byte slices, so encoding cannot fail; a failure would be a programming
// error, not untrusted input (the never-panic rule concerns parsers, not builders).
func mustEncode(v any) []byte {
	b, err := encode(v)
	if err != nil {
		panic("mdoc: SessionTranscript encode: " + err.Error())
	}
	return b
}
