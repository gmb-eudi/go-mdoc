# Changelog

Notable changes to this library, newest first. Versions are git tags; this file is written
for whoever bumps the dependency.

## v0.1.1

Compatible: no signature changes, no message-text changes, nothing that passed before now
fails.

### Changed

- **Errors now wrap their cause as well as their sentinel — 27 sites** across `cbor.go`,
  `cose.go`, `deviceauth.go`, `integrity.go`, `issue.go`, `key.go`, `mso.go` and `status.go`.
  Each was built as `fmt.Errorf("%w: …: %v", ErrSentinel, err)`: the sentinel wrapped, the
  cause printed into the string and then unreachable. Both are now `%w`.

  For a document parser this is the difference between "malformed" and *what was malformed* —
  a CBOR type error, a truncated payload, a bad certificate — without matching on text:

  ```go
  var typeErr *cbor.UnmarshalTypeError
  if errors.Is(err, ErrMalformed) && errors.As(err, &typeErr) { /* CBOR shape is wrong */ }
  ```

  `errors.Is(err, ErrMalformed)` / `ErrUnsupported` / `ErrDeviceAuth` / `ErrIssuerAuth` still
  hold and every rendered message is byte-identical (`%v` and `%w` print an error the same
  way), so no existing caller needs to change.

- `parseCOSEKey` builds the returned `*ecdsa.PublicKey` by parsing the uncompressed point
  instead of assigning the deprecated `X`/`Y` coordinate fields. **No behavioural change:** the
  same bytes were already validated on-curve a few lines earlier, so this rejects and accepts
  exactly what it did before. It clears a deprecation, nothing more.

### Dependencies

- `github.com/lestrrat-go/dsig` v1.3.0 → v1.4.0 (indirect).

### Notes

- The `go` directive is now `1.26.6`, which is the minimum Go version a consumer needs. The
  previous `1.26` resolved to whatever patch the toolchain happened to have; the exact patch
  is pinned because earlier 1.26 releases carry standard-library security fixes this library's
  callers should not silently miss.

## v0.1.0

Breaking, and deliberately so: a security check that silently does nothing is worse than a
compile error. There is one construction site per consumer, and the fix is mechanical.

### Changed — BREAKING

- **`VerifyInput.IssuerChainResolver` (a func) is replaced by `VerifyInput.IssuerTrust`
  (an interface):**

  ```go
  type IssuerTrust interface {
      ResolveIssuerKey(x5chain [][]byte, signed time.Time) (dsKey crypto.PublicKey, err error)
  }
  ```

  The signing time the credential claims is now passed to the trust boundary, so the
  implementation — not this library — decides which instant the certificate path is judged
  at. A document signer is short-lived while the credentials it signed stay in wallets far
  longer, so only the caller knows whether the question is "was this issuer trusted when it
  signed" or "is it trusted now". A nil `IssuerTrust` fails with `ErrUnsupported`, exactly   as a nil resolver did.

  **Migration.** Move your closure onto a type with that one method:

  ```go
  // before
  in.IssuerChainResolver = func(x5chain [][]byte) (crypto.PublicKey, error) { … }

  // after
  type myTrust struct{ … }
  func (t myTrust) ResolveIssuerKey(x5chain [][]byte, signed time.Time) (crypto.PublicKey, error) { … }
  in.IssuerTrust = myTrust{…}
  ```

  Ignore the `signed` argument to keep validating at the current time; pass it as the
  validation time to honour a signer that has since expired for credentials it signed while
  it was valid.

- **Verification order.** The claimed signing time is read from the *unverified* payload
  before the chain is resolved. It selects a validation time and authorizes nothing: the
  window check below and the re-assertion after the signature verifies are what make it
  safe. No consumer-visible effect beyond the interface change.

- A trust-boundary error is now wrapped with `%w` rather than only its text, so a caller can
  inspect the cause it returned.

### Added

- **The signing time is asserted to lie inside the document signer certificate's own
  validity window** ([ISO/IEC 18013-5 §9.3.1] step 5). This check did not exist before. It
  is unconditional and not configurable — it is what stops a signer whose window never
  covered the moment it claims to have signed at. New sentinel `ErrIssuerCertValidity`,
  distinct from `ErrIssuerAuth` so a certificate-window problem is never reported as an
  unknown issuer.
- After the signature verifies, the authenticated signing time is re-checked against the
  value the trust boundary was given, so the bytes that were judged are the bytes that were
  signed.

### Notes

- Dependency update.
- Test fixtures now carry a real document signer certificate, because the window assertion
  parses `x5chain[0]`.
