package mdoc

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// StatusRef is the MSO status extension reference (IETF Token Status List,
// draft-ietf-oauth-status-list) surfaced to the caller. go-mdoc only extracts
// it; fetching and evaluating the status list is go-statuslist. Raw
// preserves the full status map for forward-compatibility (e.g. identifier_list).
//
// Note: only the type existed here originally so VerifiedDocument.Status
// type-checked against the locked public interface; parseMSOStatus below now
// populates it and verify.go wires VerifiedDocument.Status.
type StatusRef struct {
	URI   string
	Index uint
	Raw   map[string]any
}

// parseMSOStatus extracts the status reference from an MSO status field.
// Absent (nil/empty) → (nil, nil). Present but not a valid status structure →
// ErrStatus (fail closed: unknown status format is a hard failure).
//
// ISO 18013-5 MSO status extension carrying an IETF Token Status List
// (draft-ietf-oauth-status-list) reference:
// status = { "status_list": { "idx": uint, "uri": tstr } }.
func parseMSOStatus(raw cbor.RawMessage) (*StatusRef, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var full map[string]any
	if err := decode([]byte(raw), &full); err != nil {
		return nil, fmt.Errorf("%w: not a map: %v", ErrStatus, err)
	}
	var typed struct {
		StatusList *struct {
			Index uint   `cbor:"idx"`
			URI   string `cbor:"uri"`
		} `cbor:"status_list"`
	}
	if err := decode([]byte(raw), &typed); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStatus, err)
	}
	if typed.StatusList == nil {
		// A status map without a recognized status_list is an unknown format.
		return nil, fmt.Errorf("%w: no status_list member", ErrStatus)
	}
	if typed.StatusList.URI == "" {
		return nil, fmt.Errorf("%w: status_list.uri empty", ErrStatus)
	}
	return &StatusRef{URI: typed.StatusList.URI, Index: typed.StatusList.Index, Raw: full}, nil
}
