import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBase32 } from "@/auth/base32.ts";
import { generateSecret } from "@/auth/secret.ts";

test("generateSecret returns a 20-byte key encoded as base32", () => {
  const secret = generateSecret();
  assert.equal(secret.length, 32);
  assert.equal(decodeBase32(secret).length, 20);
  assert.notEqual(generateSecret(), secret);
});
