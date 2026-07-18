package mdoc

import "fmt"

// DecodeDeviceResponse parses an ISO 18013-5 DeviceResponse from untrusted CBOR
// using the hardened decoder. Tolerant of unknown map members (CDDL
// forward-compatibility) but strict on the documented shape. Never panics on
// malformed input (fuzzed by FuzzDecodeDeviceResponse).
//
// A non-zero top-level status or a non-empty documentErrors is the wallet's
// own signal that something went wrong producing the response
// ([ISO/IEC 18013-5 §8.3.2.1.2.3] Table: 0 = OK); go-mdoc rejects the whole response rather than
// verifying whatever documents did decode (no partial trust of
// a response the wallet itself flagged as broken).
//
// [ISO/IEC 18013-5 §8.3.2.1.2.2] DeviceResponse.
func DecodeDeviceResponse(raw []byte) (*DeviceResponse, error) {
	var d DeviceResponse
	if err := decode(raw, &d); err != nil {
		return nil, err
	}
	if d.Version == "" {
		return nil, fmt.Errorf("%w: DeviceResponse.version empty", ErrMalformed)
	}
	if d.Status != 0 {
		return nil, fmt.Errorf("%w: status=%d", ErrDeviceResponseStatus, d.Status)
	}
	if len(d.DocumentErrors) > 0 {
		return nil, fmt.Errorf("%w: %d documentErrors present", ErrDeviceResponseStatus, len(d.DocumentErrors))
	}
	return &d, nil
}
