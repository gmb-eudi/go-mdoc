package mdoc

import "errors"

// Sentinel errors. All are wrapped with %w and carry only safe context
// (namespaces, element identifiers, digest IDs, doctypes) — never element
// values (hard rule 3). Services map these to conventions.md reason codes.
var (
	// ErrMalformed: CBOR structurally invalid or violates the hardened decode
	// options. Maps to err:credential:parse.
	ErrMalformed = errors.New("mdoc: malformed")
	// ErrUnsupported: a well-formed but unsupported construct (e.g. version).
	ErrUnsupported = errors.New("mdoc: unsupported")
	// ErrIssuerAuth: IssuerAuth (MSO) signature or chain resolution failed.
	// Maps to err:credential:issuer-untrusted.
	ErrIssuerAuth = errors.New("mdoc: issuer authentication failed")
	// ErrIntegrity: an IssuerSignedItem digest does not match MSO ValueDigests,
	// or an item is absent from ValueDigests. Maps to err:credential:integrity.
	ErrIntegrity = errors.New("mdoc: issuer-data integrity check failed")
	// ErrDeviceAuth: DeviceAuth signature invalid / not bound to the transcript.
	// Maps to err:credential:binding-failed.
	ErrDeviceAuth = errors.New("mdoc: device authentication failed")
	// ErrValidity: current time outside the MSO ValidityInfo window.
	// Maps to err:credential:expired.
	ErrValidity = errors.New("mdoc: outside validity window")
	// ErrDocTypeMismatch: MSO docType != Document docType, or != ExpectedDocType.
	ErrDocTypeMismatch = errors.New("mdoc: docType mismatch")
	// ErrDeviceMacUnsupported: deviceMac present; remote flows require a
	// signature (WP-03 Decisions). Maps to err:credential:binding-failed.
	ErrDeviceMacUnsupported = errors.New("mdoc: deviceMac not supported (use deviceSignature)")
	// ErrDigestAlg: MSO digestAlgorithm not in the SHA-2 allow-list.
	ErrDigestAlg = errors.New("mdoc: MSO digest algorithm not allowed")
	// ErrStatus: MSO status extension present but malformed.
	ErrStatus = errors.New("mdoc: malformed status extension")
	// ErrDeviceResponseStatus: DeviceResponse.status is non-zero, or
	// documentErrors is non-empty (ISO 18013-5 §8.3.2.1.2.3 Table: 0 = OK).
	// The wallet itself signaled a problem producing the response; treated as
	// untrustworthy as a whole rather than partially trusted (hard rule 7).
	ErrDeviceResponseStatus = errors.New("mdoc: DeviceResponse reports a non-OK status")
)
