package mdoc

import (
	"fmt"
	"strings"
	"testing"
)

func TestKnownDocType(t *testing.T) {
	for _, dt := range []string{"org.iso.18013.5.1.mDL", "eu.europa.ec.eudi.pid.1"} {
		if !KnownDocType(dt) {
			t.Errorf("KnownDocType(%q) = false, want true", dt)
		}
	}
	if KnownDocType("com.example.loyalty.1") {
		t.Error("KnownDocType(unknown) = true")
	}
}

func TestReport_KnownMDL(t *testing.T) {
	vd := VerifiedDocument{
		DocType: "org.iso.18013.5.1.mDL",
		Namespaces: map[string]map[string]any{
			"org.iso.18013.5.1": {
				"family_name":        "Dent",
				"portrait":           []byte{0xff, 0xd8, 0xff}, // JPEG SOI
				"age_over_21":        true,
				"driving_privileges": []any{map[string]any{"vehicle_category_code": "B"}},
				"unmapped_element":   "x",
			},
		},
	}
	rep := Report(vd)
	if !rep.KnownDocType {
		t.Fatal("KnownDocType = false")
	}
	byID := map[string]ElementReport{}
	for _, e := range rep.Elements {
		byID[e.Identifier] = e
	}
	if !byID["family_name"].Known || !byID["family_name"].TypeValid {
		t.Errorf("family_name = %+v", byID["family_name"])
	}
	if !byID["portrait"].PII || !byID["portrait"].TypeValid {
		t.Errorf("portrait = %+v, want PII+TypeValid", byID["portrait"])
	}
	if !byID["age_over_21"].Known || !byID["age_over_21"].TypeValid {
		t.Errorf("age_over_21 (pattern) = %+v", byID["age_over_21"])
	}
	if byID["unmapped_element"].Known {
		t.Errorf("unmapped_element wrongly Known")
	}
	if !byID["unmapped_element"].TypeValid { // no hook → valid
		t.Errorf("unmapped_element TypeValid = false")
	}
}

func TestReport_TypeHookFailures(t *testing.T) {
	vd := VerifiedDocument{
		DocType: "eu.europa.ec.eudi.pid.1",
		Namespaces: map[string]map[string]any{
			"eu.europa.ec.eudi.pid.1": {
				"age_over_18": "yes",       // must be bool
				"portrait":    "not-bytes", // must be bytes
			},
		},
	}
	rep := Report(vd)
	byID := map[string]ElementReport{}
	for _, e := range rep.Elements {
		byID[e.Identifier] = e
	}
	if byID["age_over_18"].TypeValid {
		t.Error("age_over_18=string must be TypeValid=false")
	}
	if byID["portrait"].TypeValid {
		t.Error("portrait=string must be TypeValid=false")
	}
	if !byID["portrait"].PII {
		t.Error("portrait must remain PII even when type-invalid")
	}
}

func TestReport_UnknownDocTypePassThrough(t *testing.T) {
	vd := VerifiedDocument{
		DocType: "com.example.loyalty.1",
		Namespaces: map[string]map[string]any{
			"com.example.loyalty": {"points": int64(9000)},
		},
	}
	rep := Report(vd)
	if rep.KnownDocType {
		t.Error("unknown doctype reported as known")
	}
	if len(rep.Elements) != 1 || rep.Elements[0].Known {
		t.Errorf("elements = %+v, want one unknown element listed", rep.Elements)
	}
	if !rep.Elements[0].TypeValid {
		t.Error("unknown element with no hook must be TypeValid=true")
	}
}

// The report type carries no place for a value. TestReport_NoValues
// proves this operationally (not just by type-shape inspection): it plants a
// distinctive sentinel as a disclosed value, runs it through Report, and then
// asserts the sentinel string is absent from every representation of the
// resulting DocumentReport — both a full-struct dump (%+v, which would print
// any hidden/future field, exported or not, including inside nested structs)
// and each ElementReport's individual string fields. If a future change adds
// so much as a debug/value field to ElementReport or DocumentReport and any
// code path ever copies the disclosed value into it, this test fails.
func TestReport_NoValues(t *testing.T) {
	const sentinel = "SECRET-SENTINEL-VALUE"
	vd := VerifiedDocument{
		DocType: "org.iso.18013.5.1.mDL",
		Namespaces: map[string]map[string]any{
			"org.iso.18013.5.1": {"family_name": sentinel},
		},
	}
	rep := Report(vd)

	if dump := fmt.Sprintf("%+v", rep); strings.Contains(dump, sentinel) {
		t.Fatalf("DocumentReport dump contains the disclosed value: %s", dump)
	}
	found := false
	for _, e := range rep.Elements {
		if e.Namespace == "org.iso.18013.5.1" && e.Identifier == "family_name" {
			found = true
		}
		// ElementReport carries only string identifiers and bool flags — no
		// "any" field a value could hide in. Walk them explicitly so this
		// assertion breaks (not silently passes) if a value-typed field is
		// ever added to the struct.
		if e.Namespace == sentinel || e.Identifier == sentinel {
			t.Fatalf("ElementReport leaked the disclosed value: %+v", e)
		}
	}
	if !found {
		t.Fatal("expected family_name element report to be present")
	}
}
