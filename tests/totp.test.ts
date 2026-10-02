import assert from "node:assert/strict";
import { test } from "node:test";
import { generateTotp } from "../src/auth/totp.ts";

// RFC 6238 Appendix B (SHA-1), last 6 digits of each 8-digit code
const KEY = Buffer.from("12345678901234567890");
const VECTORS: [number, string][] = [
  [59, "287082"],
  [1111111109, "081804"],
  [1111111111, "050471"],
  [1234567890, "005924"],
  [2000000000, "279037"],
  [20000000000, "353130"],
];

test("generateTotp matches RFC 6238 test vectors", () => {
  for (const [unixSeconds, expected] of VECTORS) {
    assert.equal(generateTotp(KEY, unixSeconds), expected);
  }
});

test("generateTotp returns the same code within one 30-second step", () => {
  assert.equal(generateTotp(KEY, 30), generateTotp(KEY, 59));
  assert.notEqual(generateTotp(KEY, 59), generateTotp(KEY, 60));
});
