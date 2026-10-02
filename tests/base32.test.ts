import assert from "node:assert/strict";
import { test } from "node:test";
import {
  decodeBase32,
  encodeBase32,
  generateSecret,
} from "../src/auth/base32.ts";

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

test("decodeBase32 accepts lowercase and padding", () => {
  assert.equal(decodeBase32("mzxw6===").toString(), "foo");
});

test("decodeBase32 rejects invalid characters", () => {
  assert.throws(() => decodeBase32("MZ1W"), /Invalid Base32 character: 1/);
});

test("generateSecret returns a 20-byte key encoded as base32", () => {
  const secret = generateSecret();
  assert.equal(secret.length, 32);
  assert.equal(decodeBase32(secret).length, 20);
  assert.notEqual(generateSecret(), secret);
});
