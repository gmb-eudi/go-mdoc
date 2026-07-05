package mdoc

import (
	"time"

	"github.com/fxamacker/cbor/v2"
)

// DeviceResponse — ISO 18013-5 §8.3.2.1.2.2. Text-keyed CBOR map.
type DeviceResponse struct {
	Version        string          `cbor:"version"`
	Documents      []Document      `cbor:"documents,omitempty"`
	DocumentErrors []DocumentError `cbor:"documentErrors,omitempty"`
	Status         uint            `cbor:"status"`
}

// DocumentError — ISO 18013-5 §8.3.2.1.2.2: DocType => ErrorCode(int).
type DocumentError map[string]int

// Document — ISO 18013-5 §8.3.2.1.2.2.
type Document struct {
	DocType      string       `cbor:"docType"`
	IssuerSigned IssuerSigned `cbor:"issuerSigned"`
	DeviceSigned DeviceSigned `cbor:"deviceSigned"`
	Errors       Errors       `cbor:"errors,omitempty"`
}

// Errors — ISO 18013-5 §8.3.2.1.2.2: NameSpace => (DataElementIdentifier => ErrorCode).
type Errors map[string]map[string]int

// IssuerSigned — ISO 18013-5 §9.1.2.4. issuerAuth is a COSE_Sign1 kept raw and
// delegated to go-eudi-crypto (hard rule 4).
type IssuerSigned struct {
	NameSpaces IssuerNameSpaces `cbor:"nameSpaces,omitempty"`
	IssuerAuth cbor.RawMessage  `cbor:"issuerAuth"`
}

// IssuerNameSpaces — NameSpace => [+ IssuerSignedItemBytes]. Each element is a
// #6.24(bstr .cbor IssuerSignedItem); kept raw so digests hash wire bytes.
type IssuerNameSpaces map[string][]cbor.RawMessage

// IssuerSignedItem — ISO 18013-5 §9.1.2.4.
type IssuerSignedItem struct {
	DigestID          uint            `cbor:"digestID"`
	Random            []byte          `cbor:"random"`
	ElementIdentifier string          `cbor:"elementIdentifier"`
	ElementValue      cbor.RawMessage `cbor:"elementValue"` // any DataElementValue, kept raw
}

// MobileSecurityObject — ISO 18013-5 §9.1.2.4. status is the IETF Token
// Status List extension (draft-ietf-oauth-status-list, T-03.8); kept raw,
// parsed lazily.
type MobileSecurityObject struct {
	Version         string          `cbor:"version"`
	DigestAlgorithm string          `cbor:"digestAlgorithm"` // "SHA-256"|"SHA-384"|"SHA-512"
	ValueDigests    ValueDigests    `cbor:"valueDigests"`
	DeviceKeyInfo   DeviceKeyInfo   `cbor:"deviceKeyInfo"`
	DocType         string          `cbor:"docType"`
	ValidityInfo    ValidityInfo    `cbor:"validityInfo"`
	Status          cbor.RawMessage `cbor:"status,omitempty"`
}

// ValueDigests — NameSpace => DigestIDs.
type ValueDigests map[string]DigestIDs

// DigestIDs — DigestID(uint) => Digest(bstr).
type DigestIDs map[uint][]byte

// DeviceKeyInfo — ISO 18013-5 §9.1.2.4. deviceKey is a COSE_Key, kept raw and
// parsed by parseCOSEKey (T-03.3); curve is validated via ECCG policy.
type DeviceKeyInfo struct {
	DeviceKey         cbor.RawMessage         `cbor:"deviceKey"`
	KeyAuthorizations cbor.RawMessage         `cbor:"keyAuthorizations,omitempty"`
	KeyInfo           map[int]cbor.RawMessage `cbor:"keyInfo,omitempty"`
}

// ValidityInfo — ISO 18013-5 §9.1.2.4. tdate (#6.0 tstr) fields; also the
// public output type embedded in VerifiedDocument (README target).
type ValidityInfo struct {
	Signed         time.Time  `cbor:"signed"`
	ValidFrom      time.Time  `cbor:"validFrom"`
	ValidUntil     time.Time  `cbor:"validUntil"`
	ExpectedUpdate *time.Time `cbor:"expectedUpdate,omitempty"`
}

// DeviceSigned — ISO 18013-5 §8.3.2.1.2.2. nameSpaces is DeviceNameSpacesBytes
// (#6.24(bstr .cbor DeviceNameSpaces)); kept raw for the DeviceAuthentication.
type DeviceSigned struct {
	NameSpaces cbor.RawMessage `cbor:"nameSpaces"`
	DeviceAuth DeviceAuth      `cbor:"deviceAuth"`
}

// DeviceAuth — ISO 18013-5 §9.1.3.4. Exactly one of deviceSignature (supported)
// or deviceMac (unsupported for remote flows, WP-03 Decisions) is present.
type DeviceAuth struct {
	DeviceSignature cbor.RawMessage `cbor:"deviceSignature,omitempty"`
	DeviceMac       cbor.RawMessage `cbor:"deviceMac,omitempty"`
}
