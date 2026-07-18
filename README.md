# go-mdoc

ISO/IEC 18013-5 mdoc (CBOR/COSE) for EUDI Wallet relying parties:

- Parse and verify a `DeviceResponse` for remote flows (ISO/IEC TS 18013-7 /
  OpenID4VP Annex B): MSO / issuer-data authentication, issuer-data integrity,
  and mdoc (device) authentication bound to a session transcript.
- SessionTranscript constructors for the OpenID4VP and DC-API handovers.
- A minimal Issue / DevicePresent façade for test wallets and a future issuer.
- Framework-free (no Azugo/platform-kit); all COSE/X.509 crypto is delegated to
  go-eudi-crypto (ECCG-pinned policy). Trust-agnostic: the issuer certificate
  chain is resolved through a caller-supplied `IssuerChainResolver` callback.
- `deviceMac` (session-encryption MAC) is out of scope; remote flows use the
  device signature.

Implemented specs: ISO/IEC 18013-5:2021 §8.3/§9.1, ISO/IEC TS 18013-7:2024
Annex B, OpenID4VP 1.0 Annex B.2, ARF 2.9. See SPECREFS.md.

Status: pre-v1. API frozen no earlier than an OIDF/ISO conformance pass.
