package mdoc

import "fmt"

// DecodeDeviceResponse parses an ISO 18013-5 DeviceResponse from untrusted CBOR
// using the hardened decoder. Tolerant of unknown map members (CDDL
// forward-compatibility) but strict on the documented shape. Never panics on
// malformed input (hard rule 5; fuzzed by FuzzDecodeDeviceResponse).
//
// ISO 18013-5 §8.3.2.1.2.2 DeviceResponse.
func DecodeDeviceResponse(raw []byte) (*DeviceResponse, error) {
	var d DeviceResponse
	if err := decode(raw, &d); err != nil {
		return nil, err
	}
	if d.Version == "" {
		return nil, fmt.Errorf("%w: DeviceResponse.version empty", ErrMalformed)
	}
	return &d, nil
}
