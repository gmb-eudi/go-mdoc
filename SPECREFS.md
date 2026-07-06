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

**SessionTranscript / `OID4VPHandover` / `OID4VPDCAPIHandover` — CORRECTED
2026-07-06** (see `../../docs/mdoc-eu-gap-report.md` §3, and
`testdata/sessiontranscript/SOURCE.md`): the original 3-hash-tuple construction
never matched any known implementation (it was PENDING cross-check from the
start). Corrected against `references/eudi-srv-verifier-endpoint-main` (the EU
reference RP verifier — same role as us) to the `["<identifier>",
SHA-256(CBOR(HandoverInfo))]` shape. **Primary-source confirmation is still
outstanding**: OpenID4VP 1.0 (and ISO/IEC TS 18013-7 Annex B, which mirrors it)
could not be fetched this session — the official spec HTML is too large for the
available fetch tooling and truncates before reaching Annex B; no vendored copy
exists under `references/`. Vendor it and re-verify byte-for-byte — especially
the exact CBOR type of the ephemeral-key JWK thumbprint element (`tstr`
assumed) — before wiring an encrypted-response (`direct_post.jwt`) deployment
against these constructors in WP-08.
