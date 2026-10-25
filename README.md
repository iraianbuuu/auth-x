# auth-x

A TypeScript library for time-based one-time passwords (TOTP, RFC 6238), the six-digit codes shown by Google Authenticator and similar apps. It is being built as the two-factor authentication core for a Node.js backend.

## Status

Enrollment, code verification, secret encryption and recovery codes work, and the TOTP code is tested against the RFC test vectors. The package installs from a tarball or git; it is not on npm. See [Roadmap](#roadmap) for what is left.

## Requirements

- Node.js 22 or later
- npm

## Setup

```bash
git clone git@github.com:iraianbuuu/auth-x.git
cd auth-x
npm install
npm test
```

## Scripts

| Command | What it does |
|---|---|
| `npm test` | Runs the tests with Node's built-in test runner |
| `npm run coverage` | Runs the tests with a coverage report for `src`; fails below 95% lines, branches or functions |
| `npm run typecheck` | Type-checks `src`, `tests` and `examples` without emitting files |
| `npm run lint` | Checks linting and formatting with Biome |
| `npm run format` | Fixes formatting and safe lint issues |
| `npm run build` | Compiles `src` to `dist` |
| `npm run dev` | Runs the demo in `examples/demo.ts` |

## Install

```bash
npm install auth-x
```

Everything is imported from the package root; internal modules are not reachable. The package has no runtime dependencies. Releases are listed in [CHANGELOG.md](CHANGELOG.md).

## Usage

### Enroll a user

```ts
import { createEnrollment, encryptSecret, generateRecoveryCodes } from "auth-x";

const keyring = {
  current: "2026-10",
  keys: { "2026-10": Buffer.from(process.env.TOTP_KEY_2026_10, "base64") },
};

const { secret, uri } = createEnrollment({
  account: "alice@example.com",
  issuer: "Acme Co",
});
const { codes, hashes } = generateRecoveryCodes(); // 10 codes like "K7QM-9XRT"

user.totpSecret = encryptSecret(secret, keyring, `user:${user.id}`);
user.recoveryHashes = hashes;
```

Render `uri` as a QR code for the user to scan, with any QR library (for example `qrcode` on the server or a QR component in the browser). Show `codes` once; store neither. Turn 2FA on only after the user enters one correct code.

Each key in the keyring is a 32-byte `Buffer` from a secrets manager or environment variable, never from the database. `current` names the key that encrypts new secrets; key IDs are 1 to 32 letters, digits, `-` or `_`. The third argument binds the payload to the user, so a payload copied into another user's row fails to decrypt.

### Verify a code at login

```ts
import { decodeBase32, decryptSecret, verifyTotp } from "auth-x";

const key = decodeBase32(
  decryptSecret(user.totpSecret, keyring, `user:${user.id}`),
);
const step = verifyTotp(key, typedCode, {
  afterStep: user.lastUsedStep, // omit on the first login
});

if (step === null) {
  // wrong, expired, reused or malformed code
} else {
  user.lastUsedStep = step; // blocks the same code from being used again
}
```

`verifyTotp` accepts the previous, current and next 30-second step by default (`window: 1`), which allows for clock drift and typing time. `window` can be at most 10. It returns the matched step, or `null`.

### Use a recovery code

```ts
import { verifyRecoveryCode } from "auth-x";

const index = verifyRecoveryCode(typedCode, user.recoveryHashes);
if (index !== -1) {
  user.recoveryHashes.splice(index, 1); // each code works once
}
```

Case, spaces and dashes are ignored, so `k7qm 9xrt` matches `K7QM-9XRT`.

### Rotate the encryption key

Every payload records the ID of the key that encrypted it (`v1:2026-10:...`), so old and new keys can be used side by side:

1. Add the new key and make it `current`. Keep the old key in `keys`.
2. At login, re-encrypt secrets that still use an old key:
   ```ts
   if (needsReencryption(user.totpSecret, keyring)) {
     const plain = decryptSecret(user.totpSecret, keyring, `user:${user.id}`);
     user.totpSecret = encryptSecret(plain, keyring, `user:${user.id}`);
   }
   ```
3. Count the rows left on the old key, for example `WHERE totp_secret LIKE 'v1:2026-10:%'`, and re-encrypt them in a batch if needed.
4. When the count is 0, remove the old key from `keys`.

### Lower-level functions

`generateSecret`, `createOtpAuthUri`, `parseOtpAuthUri`, `generateTotp`, `encodeBase32` and `decodeBase32` are also exported, for apps that build their own enrollment flow:

```ts
import { createOtpAuthUri, decodeBase32, generateSecret, generateTotp } from "auth-x";

const secret = generateSecret(); // 160-bit key as 32 base32 characters
const uri = createOtpAuthUri({ secret, issuer: "Acme Co", account: "alice" });

generateTotp(decodeBase32(secret), {
  algorithm: "SHA256",
  digits: 8,
  period: 60,
  timestamp: 1234567890, // Unix seconds; defaults to now
});
```

### Options

| Option | Values | Default |
|---|---|---|
| `algorithm` | `"SHA1"`, `"SHA256"`, `"SHA512"` | `"SHA1"` |
| `digits` | `6` or `8` | `6` |
| `period` | positive whole number of seconds | `30` |
| `timestamp` | Unix time in whole seconds, not milliseconds | current time |

Most authenticator apps only support the defaults. `createOtpAuthUri` writes any non-default option into the URI, so the app and the server use the same settings.

### Errors

Invalid input throws an `OtpError` with a `code`:

| Code | Thrown when |
|---|---|
| `INVALID_OPTIONS` | An option is outside the values above, or a timestamp or counter is negative, fractional or not a number |
| `INVALID_SECRET` | A base32 secret has invalid characters, an impossible length or non-zero padding bits, or the key is shorter than 16 bytes |
| `INVALID_URI` | An `otpauth://` URI is malformed, the account is empty, or the issuer or account contains `:` |
| `INVALID_KEY` | The keyring's `current` key is missing, a key is not 32 bytes, or a key ID is invalid |
| `DECRYPTION_FAILED` | An encrypted secret was changed, is malformed, names a key ID that is not in the keyring, or is decrypted with the wrong key or context |

```ts
import { OtpError } from "auth-x";

try {
  generateTotp(decodeBase32(userInput));
} catch (error) {
  if (error instanceof OtpError && error.code === "INVALID_SECRET") {
    // ask the user to re-enter the secret
  }
}
```

## Project layout

```
src/
  index.ts        public API (the package entry point)
  auth/
    types.ts      TotpOptions, DEFAULTS, option validation
    errors.ts     OtpError
    hotp.ts       HOTP (RFC 4226)
    totp.ts       TOTP (RFC 6238) generation and verification
    base32.ts     base32 encode and decode (RFC 4648)
    secret.ts     random secret generation
    otpauth.ts    otpauth:// URI build and parse
    enrollment.ts secret and URI in one call
    encryption.ts AES-256-GCM secret encryption with key IDs
    recovery.ts   one-time recovery codes
examples/
  demo.ts         enrollment, encryption, verification and recovery
tests/            one test file per module; imports use the @/ alias for src/
```

## Testing

Expected values in the tests come from the RFCs, not from running this code:

- RFC 4226 Appendix D: HOTP codes for counters 0 to 9
- RFC 6238 Appendix B: TOTP codes for SHA-1, SHA-256 and SHA-512 at six timestamps
- RFC 4648 Section 10: base32 encodings of `f` through `foobar`

## Security notes

- Never compare a user's code with `===`; it leaks timing information. `verifyTotp` compares in constant time.
- Store the step `verifyTotp` returns and pass it back as `afterStep`. Without it, a code can be used again until it expires.
- TOTP secrets cannot be hashed like passwords because the server needs the original to compute codes, which is why they are encrypted instead.
- Store TOTP secrets only through `encryptSecret`, and keep the keys outside the database. Rotate keys with a new key ID rather than replacing a key in place. Store recovery codes only as the hashes `generateRecoveryCodes` returns.
- Pass `timestamp` in seconds. Passing `Date.now()` (milliseconds) produces codes no authenticator app will accept.

## Releasing

1. Add the changes to `CHANGELOG.md` and bump `version` in `package.json`.
2. Commit, then tag and push: `git tag -a v0.3.0 -m "auth-x 0.3.0" && git push origin v0.3.0`.
3. The Publish workflow checks the tag matches `package.json`, runs the checks, and publishes to npm with provenance.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not open a public issue.

## Roadmap

- [x] Configurable algorithm, digits and period
- [x] `OtpError` codes and input validation
- [x] `verifyTotp` with a clock-drift window and replay protection
- [x] Non-default options in `otpauth://` URIs and an enrollment helper
- [x] Secret encryption (AES-256-GCM) with key rotation, and recovery codes
- [x] Public entry point and packaging
- [x] CI for typecheck, lint, tests, build and `npm audit`
- [x] Test coverage report, enforced in CI
- [x] Semver tags and a changelog

## License

ISC
