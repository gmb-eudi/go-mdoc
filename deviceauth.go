package mdoc

import (
	"crypto"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	eudicrypto "github.com/gmb-eudi/go-eudi-crypto"
)

// verifyDeviceAuth performs [ISO/IEC 18013-5 §9.1.3] mdoc (device) authentication.
// deviceMac is rejected (remote flows use a signature). The
// deviceSignature is a COSE_Sign1 with a detached payload equal to
// DeviceAuthenticationBytes; go-mdoc recomputes those bytes from the transcript
// it was given and splices them in before delegating verification to
// go-eudi-crypto — binding the signature to this exact session (finding #2).
//
// DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, DocType,
// DeviceNameSpacesBytes] ([ISO/IEC 18013-5 §9.1.3.4]).
func (v *Verifier) verifyDeviceAuth(doc *Document, deviceKey crypto.PublicKey, st SessionTranscript) error {
	da := doc.DeviceSigned.DeviceAuth
	if len(da.DeviceMac) > 0 {
		return fmt.Errorf("%w", ErrDeviceMacUnsupported)
	}
	if len(da.DeviceSignature) == 0 {
		return fmt.Errorf("%w: no deviceSignature", ErrDeviceAuth)
	}
	if len(st.cbor) == 0 {
		return fmt.Errorf("%w: no SessionTranscript for remote device authentication", ErrDeviceAuth)
	}
	deviceAuthBytes, err := encodeTagged24([]any{
		"DeviceAuthentication",
		cbor.RawMessage(st.cbor),
		doc.DocType,
		cbor.RawMessage(doc.DeviceSigned.NameSpaces),
	})
	if err != nil {
		return fmt.Errorf("%w: build DeviceAuthentication: %v", ErrDeviceAuth, err)
	}
	spliced, err := spliceCOSEPayload(da.DeviceSignature, deviceAuthBytes)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDeviceAuth, err)
	}
	if _, _, err := eudicrypto.VerifyCOSESign1([]byte(spliced), deviceKey); err != nil {
		return fmt.Errorf("%w: %v", ErrDeviceAuth, err)
	}
	return nil
}
