# auth-x

A TypeScript library for time-based one-time passwords (TOTP, RFC 6238), the six-digit codes shown by Google Authenticator and similar apps. It is being built as the two-factor authentication core for a Node.js backend.

## Status

Work in progress. Enrollment (secret, `otpauth://` URI and QR code), code generation and code verification work, and are tested against the RFC test vectors. Secret encryption, recovery codes and npm packaging are not built yet; see [Roadmap](#roadmap).

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
| `npm run typecheck` | Type-checks `src` and `tests` without emitting files |
| `npm run lint` | Checks linting and formatting with Biome |
| `npm run format` | Fixes formatting and safe lint issues |
| `npm run build` | Compiles `src` to `dist` |
| `npm run dev` | Runs the demo in `src/index.ts` |

## Usage

The library is not published as a package yet, so the examples import from `src/auth/` directly.

### Create a secret and a provisioning URI

```ts
import { generateSecret } from "./src/auth/secret.ts";
import { createOtpAuthUri } from "./src/auth/otpauth.ts";

const secret = generateSecret(); // 160-bit key as 32 base32 characters

const uri = createOtpAuthUri({
  secret,
  issuer: "Acme Co",
  account: "alice@example.com",
});
// otpauth://totp/Acme%20Co%3Aalice%40example.com?secret=...&issuer=Acme%20Co
```

Turn `uri` into a QR code and the user scans it with an authenticator app.

### Enroll a user

```ts
import { createEnrollment } from "./src/auth/enrollment.ts";

const { secret, uri, qrDataUrl } = await createEnrollment({
  account: "alice@example.com",
  issuer: "Acme Co",
});
```

Show `qrDataUrl` in an `<img>` tag for the user to scan, and store `secret` with the user. Turn 2FA on only after the user enters one correct code.

### Verify a code

```ts
import { decodeBase32 } from "./src/auth/base32.ts";
import { verifyTotp } from "./src/auth/totp.ts";

const step = verifyTotp(decodeBase32(secret), typedCode, {
  afterStep: user.lastUsedStep, // omit on the first login
});

if (step === null) {
  // wrong, expired, reused or malformed code
} else {
  user.lastUsedStep = step; // blocks the same code from being used again
}
```

`verifyTotp` accepts the previous, current and next 30-second step by default (`window: 1`), which allows for clock drift and typing time. It returns the matched step, or `null`.

### Generate a code

```ts
import { decodeBase32 } from "./src/auth/base32.ts";
import { generateTotp } from "./src/auth/totp.ts";

const key = decodeBase32(secret);

generateTotp(key); // current 6-digit code, SHA-1, 30-second period

generateTotp(key, {
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

```ts
import { OtpError } from "./src/auth/errors.ts";

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
  index.ts        demo script
  auth/
    types.ts      TotpOptions, DEFAULTS, option validation
    errors.ts     OtpError
    hotp.ts       HOTP (RFC 4226)
    totp.ts       TOTP (RFC 6238) generation and verification
    base32.ts     base32 encode and decode (RFC 4648)
    secret.ts     random secret generation
    otpauth.ts    otpauth:// URI build and parse
    qrcode.ts     URI to PNG data URL
    enrollment.ts secret, URI and QR code in one call
tests/            one test file per module
```

## Testing

Expected values in the tests come from the RFCs, not from running this code:

- RFC 4226 Appendix D: HOTP codes for counters 0 to 9
- RFC 6238 Appendix B: TOTP codes for SHA-1, SHA-256 and SHA-512 at six timestamps
- RFC 4648 Section 10: base32 encodings of `f` through `foobar`

## Security notes

- Never compare a user's code with `===`; it leaks timing information. `verifyTotp` compares in constant time.
- Store the step `verifyTotp` returns and pass it back as `afterStep`. Without it, a code can be used again until it expires.
- TOTP secrets cannot be hashed like passwords because the server needs the original to compute codes. Store them encrypted.
- Pass `timestamp` in seconds. Passing `Date.now()` (milliseconds) produces codes no authenticator app will accept.

## Roadmap

- [x] Configurable algorithm, digits and period
- [x] `OtpError` codes and input validation
- [x] `verifyTotp` with a clock-drift window and replay protection
- [x] Non-default options in `otpauth://` URIs, QR codes as data URLs, enrollment helper
- [ ] Secret encryption (AES-256-GCM) and recovery codes
- [ ] Public entry point and npm packaging
- [ ] CI for typecheck, lint and tests

## License

ISC
