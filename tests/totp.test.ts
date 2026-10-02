import assert from "node:assert/strict";
import { test } from "node:test";
import { generateTotp } from "../src/auth/totp.ts";
import type { HashAlgorithm, TotpOptions } from "../src/auth/types.ts";
import { otpError } from "./helpers.ts";

// RFC 6238 Appendix B keys: the ASCII digits "1234567890" repeated to
// 20 bytes for SHA-1, 32 bytes for SHA-256 and 64 bytes for SHA-512.
function rfcKey(algorithm: HashAlgorithm): Buffer {
  const length = algorithm === "SHA1" ? 20 : algorithm === "SHA256" ? 32 : 64;
  return Buffer.from("1234567890".repeat(7).slice(0, length));
}

const RFC_6238: [number, HashAlgorithm, string][] = [
  [59, "SHA1", "94287082"],
  [59, "SHA256", "46119246"],
  [59, "SHA512", "90693936"],
  [1111111109, "SHA1", "07081804"],
  [1111111109, "SHA256", "68084774"],
  [1111111109, "SHA512", "25091201"],
  [1111111111, "SHA1", "14050471"],
  [1111111111, "SHA256", "67062674"],
  [1111111111, "SHA512", "99943326"],
  [1234567890, "SHA1", "89005924"],
  [1234567890, "SHA256", "91819424"],
  [1234567890, "SHA512", "93441116"],
  [2000000000, "SHA1", "69279037"],
  [2000000000, "SHA256", "90698825"],
  [2000000000, "SHA512", "38618901"],
  [20000000000, "SHA1", "65353130"],
  [20000000000, "SHA256", "77737706"],
  [20000000000, "SHA512", "47863826"],
];

test("generateTotp matches the RFC 6238 test vectors (8 digits)", () => {
  for (const [timestamp, algorithm, expected] of RFC_6238) {
    assert.equal(
      generateTotp(rfcKey(algorithm), { timestamp, algorithm, digits: 8 }),
      expected,
    );
  }
});

// RFC 6238 Appendix B (SHA-1), last 6 digits of each 8-digit code
const SIX_DIGIT_VECTORS: [number, string][] = [
  [59, "287082"],
  [1111111109, "081804"],
  [1111111111, "050471"],
  [1234567890, "005924"],
  [2000000000, "279037"],
  [20000000000, "353130"],
];

test("generateTotp matches RFC 6238 test vectors with the defaults", () => {
  for (const [timestamp, expected] of SIX_DIGIT_VECTORS) {
    assert.equal(generateTotp(rfcKey("SHA1"), { timestamp }), expected);
  }
});

test("generateTotp returns the same code within one time step", () => {
  const key = rfcKey("SHA1");
  assert.equal(
    generateTotp(key, { timestamp: 30 }),
    generateTotp(key, { timestamp: 59 }),
  );
  assert.notEqual(
    generateTotp(key, { timestamp: 59 }),
    generateTotp(key, { timestamp: 60 }),
  );
});

test("generateTotp uses the configured period", () => {
  const key = rfcKey("SHA1");
  assert.equal(
    generateTotp(key, { timestamp: 0, period: 60 }),
    generateTotp(key, { timestamp: 59, period: 60 }),
  );
  assert.notEqual(
    generateTotp(key, { timestamp: 59, period: 60 }),
    generateTotp(key, { timestamp: 60, period: 60 }),
  );
});

test("generateTotp rejects invalid options", () => {
  const invalid = [
    { digits: 7 },
    { digits: "6" },
    { period: 0 },
    { period: -30 },
    { period: 1.5 },
    { algorithm: "MD5" },
    { algorithm: "sha1" },
    { timestamp: -1 },
    { timestamp: 1.5 },
    { timestamp: Number.NaN },
    { timestamp: Number.POSITIVE_INFINITY },
  ] as unknown as Partial<TotpOptions>[];
  for (const options of invalid) {
    assert.throws(
      () => generateTotp(rfcKey("SHA1"), options),
      otpError("INVALID_OPTIONS"),
    );
  }
});
