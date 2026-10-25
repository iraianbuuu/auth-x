# Changelog

This project follows [Semantic Versioning](https://semver.org). Until 1.0.0, a minor version bump (0.1 to 0.2) can contain breaking changes.

## 0.2.0 - 2026-10-25

### Changed (breaking)

- `encryptSecret` and `decryptSecret` take a `Keyring` (`{ current, keys }`) instead of a single key. Payloads now record the key ID: `v1:<keyId>:<iv>:<tag>:<ciphertext>`. The version and key ID are authenticated, so editing either makes decryption fail. Payloads from 0.1.0 do not decrypt.
- `createEnrollment` returns `{ secret, uri }` and is synchronous. Render the URI as a QR code in the app.
- `verifyTotp` rejects a `window` above 10.

### Added

- `needsReencryption` tells whether a payload was encrypted with a key other than the keyring's current one, for key rotation.

### Removed

- `toQrDataUrl` and the `qrcode` dependency. The package has no runtime dependencies.

### Fixed

- The package ships `src`, so the source maps in `dist` resolve.
- `npm run build` clears `dist` first, so deleted modules are not packed.

## 0.1.0 - 2026-10-25

First release.

### Added

- `createEnrollment` returns a new secret, its `otpauth://` URI and a QR code as a PNG data URL.
- `verifyTotp` checks a code against a drift window (default: one step either side), compares in constant time, and rejects steps at or before `afterStep` to block replay.
- `generateTotp` with configurable algorithm (SHA-1, SHA-256, SHA-512), digits (6 or 8) and period, verified against RFC 6238 Appendix B.
- `createOtpAuthUri` and `parseOtpAuthUri`, which carry non-default options in the URI.
- `encryptSecret` and `decryptSecret` with AES-256-GCM, a random IV per call, a `v1:` version prefix and an optional context bound to the payload.
- `generateRecoveryCodes` and `verifyRecoveryCode`, with SHA-256 hashes for storage and one-time use through the returned index.
- `generateSecret`, `encodeBase32`, `decodeBase32` and `toQrDataUrl`.
- `OtpError` with the codes `INVALID_OPTIONS`, `INVALID_SECRET`, `INVALID_URI`, `INVALID_KEY` and `DECRYPTION_FAILED`.
