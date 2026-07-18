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
// and OpenID4VPHandoverInfo = [client_id, nonce, jwkThumbprint, response_uri]
// (OpenID4VP 1.0 Annex B.2.6.1). jwkThumbprint is the RFC 7638 thumbprint of
// the RP's ephemeral encryption key when the response is JWE-encrypted
// (response_mode=direct_post.jwt); pass "" (encoded as CBOR null) when it is
// not. SHA-256 is fixed by the profile — a spec constant, not an
// ECCG-negotiable choice, so it is not routed through the algorithm allow-list.
//
// FLAG (2026-07-06 EU cross-check): this replaces
// an earlier, unverified 3-hash-tuple construction that never matched any
// known implementation. Corrected to match the EU reference verifier
// (eudi-srv-verifier-endpoint-main, DocumentValidator.kt buildOpenId4VpHandover)
// after the OpenID4VP 1.0 Annex B text could not be fetched this session
// (WebFetch truncates before Annex B; no vendored copy in references/). The
// outer shape (identifier + single HandoverInfo hash) and inner element
// order/membership are well-corroborated against that production reference;
// jwkThumbprint's exact CBOR type (tstr assumed here) is NOT yet confirmed
// against primary spec text — re-verify before wiring in an encrypted-response
// production deployment.
func OID4VPHandover(clientID, nonce, jwkThumbprint, responseURI string) SessionTranscript {
	info := []any{clientID, nonce, nullable(jwkThumbprint), responseURI}
	infoHash := sha256Sum(mustEncode(info))
	handover := []any{"OpenID4VPHandover", infoHash}
	return sessionTranscriptFromRaw(mustEncode([]any{nil, nil, handover}))
}

// OID4VPDCAPIHandover builds the SessionTranscript for the W3C Digital
// Credentials API flow: SessionTranscript = [null, null, OID4VPDCAPIHandover],
// OID4VPDCAPIHandover = ["OpenID4VPDCAPIHandover",
// SHA-256(CBOR(OpenID4VPDCAPIHandoverInfo))], OpenID4VPDCAPIHandoverInfo =
// [origin, nonce, jwkThumbprint] (OpenID4VP 1.0 Annex B.2.6.2; no client_id or
// response_uri in this variant — origin carries the RP identity signal
// instead). jwkThumbprint: see OID4VPHandover's doc comment (same FLAG applies).
func OID4VPDCAPIHandover(origin, nonce, jwkThumbprint string) SessionTranscript {
	info := []any{origin, nonce, nullable(jwkThumbprint)}
	infoHash := sha256Sum(mustEncode(info))
	handover := []any{"OpenID4VPDCAPIHandover", infoHash}
	return sessionTranscriptFromRaw(mustEncode([]any{nil, nil, handover}))
}

// nullable maps an absent (empty) optional string to CBOR null, matching the
// spec's "or null" phrasing for the ephemeral-key thumbprint elements.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
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
