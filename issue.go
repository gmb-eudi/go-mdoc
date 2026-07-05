package mdoc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

// DocumentTemplate describes an mdoc to issue. Minimal by design (test wallet +
// future issuer); the verifier never uses it.
type DocumentTemplate struct {
	DocType      string
	Namespaces   map[string]map[string]any
	ValidityInfo ValidityInfo
	DigestAlg    string // "SHA-256" (default) | "SHA-384" | "SHA-512"
	Status       *StatusRef
}

// Issuer signs MobileSecurityObjects with a document-signer key via
// go-eudi-crypto and stamps the issuer certificate chain (x5chain).
type Issuer struct {
	kp      eudicrypto.KeyProvider
	keyID   string
	x5chain [][]byte
}

// NewIssuer returns an Issuer using kp[keyID] as the document-signer key and
// x5chain (DER) as the issuer chain placed in the IssuerAuth unprotected header.
func NewIssuer(kp eudicrypto.KeyProvider, keyID string, x5chain [][]byte) *Issuer {
	return &Issuer{kp: kp, keyID: keyID, x5chain: x5chain}
}

// Issue builds an IssuerSigned (ISO 18013-5 §9.1.2): one IssuerSignedItem per
// element (fresh 32-byte random salt), the ValueDigests over the exact
// IssuerSignedItemBytes, an MSO sealing the device key, and the COSE_Sign1
// IssuerAuth. deviceKey must be an ECCG-allowed EC public key.
func (i *Issuer) Issue(ctx context.Context, doc DocumentTemplate, deviceKey crypto.PublicKey) ([]byte, error) {
	if doc.DocType == "" {
		return nil, fmt.Errorf("%w: empty DocType", ErrUnsupported)
	}
	digestAlg := doc.DigestAlg
	if digestAlg == "" {
		digestAlg = "SHA-256"
	}
	h, err := hashForMSODigestAlg(digestAlg)
	if err != nil {
		return nil, err
	}
	devPub, ok := deviceKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: device key is %T, EC required", ErrUnsupported, deviceKey)
	}
	deviceKeyCOSE, err := encodeCOSEKey(devPub)
	if err != nil {
		return nil, err
	}

	nameSpaces := IssuerNameSpaces{}
	valueDigests := ValueDigests{}
	for ns, elems := range doc.Namespaces {
		var digestID uint
		ids := DigestIDs{}
		var items []cbor.RawMessage
		for id, value := range elems {
			ev, err := encode(value)
			if err != nil {
				return nil, err
			}
			salt := make([]byte, 32)
			if _, err := rand.Read(salt); err != nil {
				return nil, fmt.Errorf("%w: salt: %v", ErrUnsupported, err)
			}
			itemBytes, err := encodeTagged24(IssuerSignedItem{
				DigestID: digestID, Random: salt, ElementIdentifier: id, ElementValue: ev,
			})
			if err != nil {
				return nil, err
			}
			hh := h.New()
			hh.Write(itemBytes)
			ids[digestID] = hh.Sum(nil)
			items = append(items, itemBytes)
			digestID++
		}
		nameSpaces[ns] = items
		valueDigests[ns] = ids
	}

	mso := MobileSecurityObject{
		Version:         "1.0",
		DigestAlgorithm: digestAlg,
		ValueDigests:    valueDigests,
		DeviceKeyInfo:   DeviceKeyInfo{DeviceKey: deviceKeyCOSE},
		DocType:         doc.DocType,
		ValidityInfo:    doc.ValidityInfo,
	}
	if doc.Status != nil {
		statusBytes, err := encode(map[string]any{"status_list": map[string]any{"uri": doc.Status.URI, "idx": doc.Status.Index}})
		if err != nil {
			return nil, err
		}
		mso.Status = statusBytes
	}
	msoBytes, err := encodeTagged24(mso)
	if err != nil {
		return nil, err
	}
	issuerAuth, err := signCOSEWithX5Chain(ctx, i.kp, i.keyID, i.x5chain, msoBytes)
	if err != nil {
		return nil, err
	}
	return encode(IssuerSigned{NameSpaces: nameSpaces, IssuerAuth: issuerAuth})
}

// DevicePresent produces a DeviceResponse from an issued IssuerSigned by
// disclosing only the requested elements and signing the DeviceAuthentication
// with the holder's device key, bound to st (ISO 18013-5 §9.1.3). This is the
// test-wallet counterpart to Verify.
func DevicePresent(ctx context.Context, deviceKey crypto.Signer, issuerSigned []byte, disclose map[string][]string, st SessionTranscript) ([]byte, error) {
	var is IssuerSigned
	if err := decode(issuerSigned, &is); err != nil {
		return nil, err
	}
	docType, err := docTypeFromIssuerAuth(is.IssuerAuth)
	if err != nil {
		return nil, err
	}
	disclosed, err := selectDisclosed(is.NameSpaces, disclose)
	if err != nil {
		return nil, err
	}

	devNS, err := encodeTagged24(map[string]any{}) // empty DeviceNameSpaces
	if err != nil {
		return nil, err
	}
	deviceAuthBytes, err := encodeTagged24([]any{"DeviceAuthentication", cbor.RawMessage(st.Bytes()), docType, cbor.RawMessage(devNS)})
	if err != nil {
		return nil, err
	}
	attached, err := eudicrypto.SignCOSESign1(ctx, signerProvider{deviceKey}, "device", nil, deviceAuthBytes)
	if err != nil {
		return nil, err
	}
	detached, err := detachCOSEPayload(cbor.RawMessage(attached))
	if err != nil {
		return nil, err
	}

	resp := DeviceResponse{
		Version: "1.0",
		Documents: []Document{{
			DocType:      docType,
			IssuerSigned: IssuerSigned{NameSpaces: disclosed, IssuerAuth: is.IssuerAuth},
			DeviceSigned: DeviceSigned{NameSpaces: devNS, DeviceAuth: DeviceAuth{DeviceSignature: detached}},
		}},
		Status: 0,
	}
	return encode(resp)
}

// selectDisclosed keeps only the requested elements per namespace; a requested
// element absent from the credential is an error (fail closed).
func selectDisclosed(ns IssuerNameSpaces, disclose map[string][]string) (IssuerNameSpaces, error) {
	out := IssuerNameSpaces{}
	for namespace, ids := range disclose {
		items, ok := ns[namespace]
		if !ok {
			return nil, fmt.Errorf("%w: namespace %q not in credential", ErrUnsupported, namespace)
		}
		want := make(map[string]bool, len(ids))
		for _, id := range ids {
			want[id] = true
		}
		var kept []cbor.RawMessage
		for _, itemBytes := range items {
			var isi IssuerSignedItem
			if err := decodeTagged24(itemBytes, &isi); err != nil {
				return nil, err
			}
			if want[isi.ElementIdentifier] {
				kept = append(kept, itemBytes)
				delete(want, isi.ElementIdentifier)
			}
		}
		if len(want) > 0 {
			return nil, fmt.Errorf("%w: requested elements not in credential: %d missing in %q", ErrUnsupported, len(want), namespace)
		}
		out[namespace] = kept
	}
	return out, nil
}

// docTypeFromIssuerAuth reads the docType from the MSO carried in IssuerAuth's
// (unverified) payload — the wallet trusts its own credential.
func docTypeFromIssuerAuth(issuerAuth cbor.RawMessage) (string, error) {
	parts, err := coseParts(issuerAuth)
	if err != nil {
		return "", err
	}
	var payload []byte
	if err := decode([]byte(parts[2]), &payload); err != nil {
		return "", fmt.Errorf("%w: IssuerAuth payload: %v", ErrMalformed, err)
	}
	var mso MobileSecurityObject
	if err := decodeTagged24(payload, &mso); err != nil {
		return "", fmt.Errorf("%w: MSO: %v", ErrMalformed, err)
	}
	return mso.DocType, nil
}

// signerProvider adapts a crypto.Signer to the go-eudi-crypto KeyProvider that
// SignCOSESign1 requires. Only Signer/Public are used.
type signerProvider struct{ s crypto.Signer }

func (p signerProvider) Signer(context.Context, string) (crypto.Signer, error) { return p.s, nil }
func (p signerProvider) Public(context.Context, string) (crypto.PublicKey, error) {
	return p.s.Public(), nil
}
func (p signerProvider) Decrypter(context.Context, string) (eudicrypto.Decrypter, error) {
	return nil, fmt.Errorf("%w: signerProvider has no decrypter", ErrUnsupported)
}
