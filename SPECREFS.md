# Pinned specification versions

| Spec | Version pinned | In `references/`? |
|---|---|---|
| ISO/IEC 18013-5 (mdoc data model, MSO, device auth) | :2021 | NO — paywalled |
| ISO/IEC TS 18013-7 (SessionTranscript for OpenID4VP) | :2024 | NO — paywalled |
| OpenID4VP (Annex B.2 mso_mdoc profile, OpenID4VPHandover / OpenID4VPDCAPIHandover) | 1.0 (final) | via references/links.md |
| OpenID4VC High Assurance Interoperability Profile | 1.0 (final) | via references/links.md |
| COSE (delegated to go-eudi-crypto) | RFC 9052 / 9053 | n/a |
| CBOR | RFC 8949 | n/a |
| ARF (PID Rulebook / mDL identifiers; §6.6.3.6–6.6.3.8) | 2.9 | references/eudi-doc-architecture-and-reference-framework-main |

## Not-vendored source risk
ISO 18013-5/-7 and the OpenID4VP Annex B CDDL are not in-repo. CBOR structures
here are cross-checked against ARF §6.6.3.6–6.6.3.8 where it cites them and
against the well-known EUDI reference-wallet layouts. Identifiers verified
against ARF 2.9: PID doctype/namespace `eu.europa.ec.eudi.pid.1`, PID SD-JWT VCT
`urn:eudi:pid:1`, mDL doctype `org.iso.18013.5.1.mDL` / namespace
`org.iso.18013.5.1`.

## SessionTranscript / `OID4VPHandover` / `OID4VPDCAPIHandover` — confirmed
Verified against the primary OpenID4VP 1.0 Annex B.2.6.1 / B.2.6.2 text and the
worked examples published there. `TestSessionTranscript_SpecVectors` reproduces
those examples byte-for-byte for both handover types, so the shape, the element
order and each element's CBOR type are pinned by the specification rather than
by inference. See `testdata/sessiontranscript/SOURCE.md` for the CDDL this
package implements and for the two encodings it previously got wrong.
