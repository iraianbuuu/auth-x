import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBase32, encodeBase32 } from "../src/auth/base32.ts";
import { otpError } from "./helpers.ts";

// RFC 4648 Section 10, without padding
const VECTORS: [string, string][] = [
  ["f", "MY"],
  ["fo", "MZXQ"],
  ["foo", "MZXW6"],
  ["foob", "MZXW6YQ"],
  ["fooba", "MZXW6YTB"],
  ["foobar", "MZXW6YTBOI"],
];

test("encodeBase32 matches RFC 4648 test vectors", () => {
  for (const [input, expected] of VECTORS) {
    assert.equal(encodeBase32(Buffer.from(input)), expected);
  }
});

test("decodeBase32 matches RFC 4648 test vectors", () => {
  for (const [expected, input] of VECTORS) {
    assert.equal(decodeBase32(input).toString(), expected);
  }
});

test("decodeBase32 accepts lowercase, padding and spaces", () => {
  assert.equal(decodeBase32("mzxw6===").toString(), "foo");
  assert.equal(decodeBase32("MZXW 6YTB OI").toString(), "foobar");
});

test("decodeBase32 rejects invalid characters", () => {
  assert.throws(() => decodeBase32("MZ1W"), /Invalid Base32 character: 1/);
  assert.throws(() => decodeBase32("MZ1W"), otpError("INVALID_SECRET"));
});

test("decodeBase32 rejects padding in the middle", () => {
  assert.throws(() => decodeBase32("MY=MZXQ"), otpError("INVALID_SECRET"));
});

// 5 bits per character: lengths 1, 3 and 6 (mod 8) leave 5 or more unused
// bits, which can never come from encoding whole bytes (RFC 4648 Section 6).
test("decodeBase32 rejects impossible lengths", () => {
  for (const input of ["M", "MZX", "MZXW6Y"]) {
    assert.throws(() => decodeBase32(input), otpError("INVALID_SECRET"));
  }
});

// "f" encodes to "MY": 01100 11000, and the last two bits are zero padding.
// "MZ" (01100 11001) sets a padding bit, so no byte string encodes to it.
test("decodeBase32 rejects non-zero padding bits", () => {
  assert.throws(() => decodeBase32("MZ"), otpError("INVALID_SECRET"));
});
