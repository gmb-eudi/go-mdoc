package mdoc

import (
	"context"
	"crypto"
	"fmt"
	"time"
)

// IssuerChainResolver resolves the issuer certificate chain (x5chain, DER) to
// the document-signer public key. It is the trust boundary: go-mdoc stays
// trust-agnostic and eudi-verifier-core wires this to go-eudi-trust.
type IssuerChainResolver func(x5chain [][]byte) (dsKey crypto.PublicKey, err error)

// VerifyInput bundles one DeviceResponse with the session binding and the trust
// callback. SessionTranscript is opaque here (built by go-oid4vp via the
// constructors) and is enforced by device-auth transcript binding
// (verifyDeviceAuth): an empty/mismatched transcript fails closed.
type VerifyInput struct {
	DeviceResponse      []byte
	SessionTranscript   SessionTranscript
	IssuerChainResolver IssuerChainResolver
	ExpectedDocType     string
}

// VerifiedDocument is the result for one Document: disclosed + digest-checked
// namespaces, the validity window, the device key, an optional status ref, and
// the MSO digest algorithm. Namespaces carry disclosed values forwarded to the
// caller and are never persisted.
type VerifiedDocument struct {
	DocType      string
	Namespaces   map[string]map[string]any
	ValidityInfo ValidityInfo
	DeviceKey    crypto.PublicKey
	Status       *StatusRef
	MSODigestAlg string
}

// Verifier holds the injected clock and hardened codec (package-level decMode).
type Verifier struct {
	now func() time.Time
}

// Option configures a Verifier.
type Option func(*Verifier)

// WithClock injects the time source for ValidityInfo checks (no wall clock:
// inject func() time.Time into anything validating validity windows).
func WithClock(now func() time.Time) Option {
	return func(v *Verifier) {
		if now != nil {
			v.now = now
		}
	}
}

// NewVerifier returns a Verifier defaulting to time.Now.
func NewVerifier(opts ...Option) *Verifier {
	v := &Verifier{now: time.Now}
	for _, o := range opts {
		o(v)
	}
	return v
}

// Verify parses and verifies a DeviceResponse for remote flows. Fail closed:
// any failing check aborts with a precise sentinel (fail closed). verifyDocument
// performs MSO (issuer) authentication, issuer-data integrity, device
// authentication, and status-reference extraction, in that order.
//
// [ISO/IEC 18013-5 §8.3 / §9.1]; ISO/IEC TS 18013-7 Annex B.
func (v *Verifier) Verify(ctx context.Context, in VerifyInput) ([]VerifiedDocument, error) {
	_ = ctx // resolver carries no context (README signature); reserved for future use
	if in.IssuerChainResolver == nil {
		return nil, fmt.Errorf("%w: nil IssuerChainResolver", ErrUnsupported)
	}
	resp, err := DecodeDeviceResponse(in.DeviceResponse)
	if err != nil {
		return nil, err
	}
	at := v.now()
	out := make([]VerifiedDocument, 0, len(resp.Documents))
	for i := range resp.Documents {
		doc := &resp.Documents[i]
		if in.ExpectedDocType != "" && doc.DocType != in.ExpectedDocType {
			return nil, fmt.Errorf("%w: document %q, expected %q", ErrDocTypeMismatch, doc.DocType, in.ExpectedDocType)
		}
		vd, err := v.verifyDocument(doc, in, at)
		if err != nil {
			return nil, err
		}
		out = append(out, vd)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: DeviceResponse has no documents", ErrMalformed)
	}
	return out, nil
}

// verifyDocument runs the per-document checks: issuer auth, issuer-data
// integrity, device auth, then status-reference extraction (the
// reference is only extracted here, not evaluated — see parseMSOStatus).
func (v *Verifier) verifyDocument(doc *Document, in VerifyInput, at time.Time) (VerifiedDocument, error) {
	mso, deviceKey, err := v.verifyIssuerAuth(doc.IssuerSigned.IssuerAuth, in.IssuerChainResolver, at)
	if err != nil {
		return VerifiedDocument{}, err
	}
	// [ISO/IEC 18013-5 §8.3.2.1.2.2 / §9.1.2]: docType is carried independently on
	// Document and inside the signed MSO; a reader MUST reject a mismatch
	// (an attacker could otherwise splice a validly-signed MSO for one
	// doctype under a Document claiming another).
	if mso.DocType != doc.DocType {
		return VerifiedDocument{}, fmt.Errorf("%w: MSO docType %q, Document docType %q", ErrDocTypeMismatch, mso.DocType, doc.DocType)
	}
	namespaces, err := v.verifyIssuerIntegrity(mso, doc.IssuerSigned.NameSpaces)
	if err != nil {
		return VerifiedDocument{}, err
	}
	if err := v.verifyDeviceAuth(doc, deviceKey, in.SessionTranscript); err != nil {
		return VerifiedDocument{}, err
	}
	statusRef, err := parseMSOStatus(mso.Status)
	if err != nil {
		return VerifiedDocument{}, err
	}
	return VerifiedDocument{
		DocType:      doc.DocType,
		Namespaces:   namespaces,
		ValidityInfo: mso.ValidityInfo,
		DeviceKey:    deviceKey,
		Status:       statusRef,
		MSODigestAlg: mso.DigestAlgorithm,
	}, nil
}
