package mdoc

import (
	"crypto"
	_ "crypto/sha256" // register SHA-256/384 so crypto.Hash.New() works
	_ "crypto/sha512" // register SHA-512
	"fmt"

	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

// hashForMSODigestAlg maps an ISO/IEC 18013-5 §9.1.2.5 MSO digestAlgorithm to
// its hash by delegating to the centralized ECCG policy (hard rule 4: no digest
// allow-list outside go-eudi-crypto). SHA-256/384/512 only; SHA-1/unknown fail
// closed. Policy error normalized to the mdoc sentinel ErrDigestAlg.
func hashForMSODigestAlg(alg string) (crypto.Hash, error) {
	h, err := eudicrypto.ECCG().HashForMSODigestAlg(alg)
	if err != nil {
		return 0, fmt.Errorf("%w: %q", ErrDigestAlg, alg)
	}
	return h, nil
}
