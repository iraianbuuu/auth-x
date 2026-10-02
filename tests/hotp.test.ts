import assert from "node:assert/strict";
import { test } from "node:test";
import { generateHotp } from "../src/auth/hotp.ts";
import { otpError } from "./helpers.ts";

// RFC 4226 Appendix D
const KEY = Buffer.from("12345678901234567890");
const EXPECTED = [
  "755224",
  "287082",
  "359152",
  "969429",
  "338314",
  "254676",
  "287922",
  "162583",
  "399871",
  "520489",
];

test("generateHotp matches RFC 4226 test vectors", () => {
  EXPECTED.forEach((expected, counter) => {
    assert.equal(generateHotp(KEY, counter), expected);
  });
});

test("generateHotp rejects a negative or fractional counter", () => {
  for (const counter of [-1, 1.5]) {
    assert.throws(
      () => generateHotp(KEY, counter),
      otpError("INVALID_OPTIONS"),
    );
  }
});

test("generateHotp rejects an empty key", () => {
  assert.throws(
    () => generateHotp(Buffer.alloc(0), 0),
    otpError("INVALID_SECRET"),
  );
});
