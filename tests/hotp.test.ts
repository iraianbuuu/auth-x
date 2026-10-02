import assert from "node:assert/strict";
import { test } from "node:test";
import { generateHotp } from "../src/auth/hotp.ts";

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
  EXPECTED.forEach((expected, count) => {
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(BigInt(count));
    assert.equal(generateHotp(KEY, counter), expected);
  });
});
