// Package mdoc implements ISO/IEC 18013-5 mdoc structures (CBOR/COSE) and the
// verification of a DeviceResponse for remote flows (ISO/IEC TS 18013-7 /
// OpenID4VP Annex B): MSO / issuer-data authentication, issuer-data integrity,
// and device authentication bound to a SessionTranscript. A minimal Issue /
// DevicePresent façade supports test wallets and a future issuer.
//
// The package is framework-free: it does no logging, takes a
// context.Context and an IssuerChainResolver callback for trust, and delegates
// every COSE/X.509 operation to go-eudi-crypto (ECCG-pinned policy, hard rule
// 4). It never names a COSE/JWS algorithm; the sole MSO digest-algorithm
// allow-list (digest.go) is flagged for migration into go-eudi-crypto.
//
// deviceMac (session-encryption MAC) is out of scope for remote presentment.
package mdoc
