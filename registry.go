package mdoc

import (
	"sort"
	"strings"
)

// ElementReport annotates one disclosed element for the verification report.
// It carries identifiers and flags only — never a value (hard rule 3).
type ElementReport struct {
	Namespace  string
	Identifier string
	Known      bool // element registered for this doctype's namespace
	PII        bool // portrait/biometric — redact in logs/report (conventions.md)
	TypeValid  bool // value passed the registered type hook (true if no hook)
}

// DocumentReport annotates a VerifiedDocument for the verification report.
type DocumentReport struct {
	DocType      string
	KnownDocType bool
	Elements     []ElementReport // sorted by namespace, then identifier
}

// KnownDocType reports whether docType is in the registry (ARF 2.9 PID / ISO
// 18013-5 mDL). Unknown doctypes still verify; they are annotated, not rejected.
func KnownDocType(docType string) bool {
	_, ok := registry[docType]
	return ok
}

// Report annotates the disclosed namespaces of a verified document using the
// doctype/namespace registry and its value-type hooks. Pure and value-free:
// Verify (T-03.3–5) never consults this registry, so an unknown doctype still
// verifies cryptographically — Report is descriptive metadata only, consumed
// by eudi-verifier-core (WP-09) for its client report + redaction hints.
func Report(vd VerifiedDocument) DocumentReport {
	spec, known := registry[vd.DocType]
	rep := DocumentReport{DocType: vd.DocType, KnownDocType: known}
	for _, ns := range sortedStringKeys(vd.Namespaces) {
		nsSpec, nsKnown := namespaceSpec{}, false
		if known {
			nsSpec, nsKnown = spec.namespaces[ns]
		}
		for _, id := range sortedAnyKeys(vd.Namespaces[ns]) {
			er := ElementReport{Namespace: ns, Identifier: id}
			pii, validate, elKnown := resolveElement(nsSpec, nsKnown, id)
			er.Known = known && nsKnown && elKnown
			er.PII = pii
			er.TypeValid = validate == nil || validate(vd.Namespaces[ns][id])
			rep.Elements = append(rep.Elements, er)
		}
	}
	return rep
}

// resolveElement finds an element's PII flag and type hook, first by exact name
// then by pattern (e.g. age_over_NN). elKnown is true only for an exact or
// pattern match in a known namespace.
func resolveElement(ns namespaceSpec, nsKnown bool, id string) (pii bool, validate validator, elKnown bool) {
	if !nsKnown {
		return false, nil, false
	}
	if es, ok := ns.elements[id]; ok {
		return es.pii, es.validate, true
	}
	for _, p := range ns.patterns {
		if p.match(id) {
			return p.pii, p.validate, true
		}
	}
	return false, nil, false
}

// --- registry data ---

type validator func(any) bool

type elementSpec struct {
	pii      bool
	validate validator
}

type patternSpec struct {
	match    func(id string) bool
	pii      bool
	validate validator
}

type namespaceSpec struct {
	elements map[string]elementSpec
	patterns []patternSpec
}

type docTypeSpec struct {
	namespaces map[string]namespaceSpec
}

func isBool(v any) bool   { _, ok := v.(bool); return ok }
func isBytes(v any) bool  { _, ok := v.([]byte); return ok }
func isString(v any) bool { _, ok := v.(string); return ok }

// ageOverPattern matches age_over_NN (NN one or more digits), ISO 18013-5 /
// PID Rulebook boolean age-attestation elements.
func ageOverPattern(id string) bool {
	const p = "age_over_"
	if !strings.HasPrefix(id, p) || len(id) == len(p) {
		return false
	}
	for _, r := range id[len(p):] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// commonIdentityElements are shared name/date/portrait elements; PII flags per
// conventions.md redaction list (portrait, biometric_template, document numbers).
func commonIdentityElements() map[string]elementSpec {
	return map[string]elementSpec{
		"family_name":        {validate: isString},
		"given_name":         {validate: isString},
		"birth_date":         {}, // tdate/full-date — accept any
		"issue_date":         {},
		"expiry_date":        {},
		"issuing_country":    {validate: isString},
		"issuing_authority":  {validate: isString},
		"document_number":    {pii: true, validate: isString},
		"portrait":           {pii: true, validate: isBytes},
		"biometric_template": {pii: true, validate: isBytes},
		"age_in_years":       {},
		"age_birth_year":     {},
	}
}

// mdlNamespace: ISO/IEC 18013-5:2021 §7.2.1 (org.iso.18013.5.1 namespace).
func mdlNamespace() namespaceSpec {
	el := commonIdentityElements()
	el["driving_privileges"] = elementSpec{} // array of maps
	el["un_distinguishing_sign"] = elementSpec{validate: isString}
	el["age_over_18"] = elementSpec{validate: isBool}
	return namespaceSpec{
		elements: el,
		patterns: []patternSpec{{match: ageOverPattern, validate: isBool}},
	}
}

// pidNamespace: ARF 2.9 / PID Rulebook (eu.europa.ec.eudi.pid.1 namespace).
func pidNamespace() namespaceSpec {
	el := commonIdentityElements()
	el["age_over_18"] = elementSpec{validate: isBool}
	el["nationality"] = elementSpec{}
	el["birth_place"] = elementSpec{validate: isString}
	el["resident_address"] = elementSpec{pii: true, validate: isString}
	el["resident_country"] = elementSpec{validate: isString}
	el["resident_city"] = elementSpec{validate: isString}
	el["resident_postal_code"] = elementSpec{validate: isString}
	el["personal_administrative_number"] = elementSpec{pii: true, validate: isString}
	return namespaceSpec{
		elements: el,
		patterns: []patternSpec{{match: ageOverPattern, validate: isBool}},
	}
}

// registry: ARF 2.9 identifiers. Verified against
// references/eudi-doc-architecture-and-reference-framework-main (PID Rulebook,
// mDL). Element sets are representative, not exhaustive — unknown elements pass
// through (Known=false) and unknown doctypes verify without registry support.
var registry = map[string]docTypeSpec{
	"org.iso.18013.5.1.mDL": {namespaces: map[string]namespaceSpec{
		"org.iso.18013.5.1": mdlNamespace(),
	}},
	"eu.europa.ec.eudi.pid.1": {namespaces: map[string]namespaceSpec{
		"eu.europa.ec.eudi.pid.1": pidNamespace(),
	}},
}

func sortedStringKeys(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedAnyKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
