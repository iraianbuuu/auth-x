import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import {
  generateRecoveryCodes,
  verifyRecoveryCode,
} from "../src/auth/recovery.ts";
import { otpError } from "./helpers.ts";

const FORMAT = /^[A-Z2-7]{4}-[A-Z2-7]{4}$/;

test("generateRecoveryCodes returns 10 formatted codes by default", () => {
  const { codes, hashes } = generateRecoveryCodes();
  assert.equal(codes.length, 10);
  assert.equal(hashes.length, 10);
  for (const code of codes) assert.match(code, FORMAT);
});

test("generateRecoveryCodes returns the requested count of unique codes", () => {
  const { codes } = generateRecoveryCodes(50);
  assert.equal(codes.length, 50);
  assert.equal(new Set(codes).size, 50);
});

test("each hash is the SHA-256 of the code without its dash", () => {
  const { codes, hashes } = generateRecoveryCodes(3);
  codes.forEach((code, i) => {
    const expected = createHash("sha256")
      .update(code.replace("-", ""))
      .digest("hex");
    assert.equal(hashes[i], expected);
  });
});

test("generateRecoveryCodes rejects an invalid count", () => {
  for (const count of [0, -1, 1.5, Number.NaN, 101]) {
    assert.throws(
      () => generateRecoveryCodes(count),
      otpError("INVALID_OPTIONS"),
      String(count),
    );
  }
});

test("verifyRecoveryCode returns the index of the matching hash", () => {
  const { codes, hashes } = generateRecoveryCodes(5);
  codes.forEach((code, i) => {
    assert.equal(verifyRecoveryCode(code, hashes), i);
  });
});

test("verifyRecoveryCode ignores case, spaces and dashes", () => {
  const { codes, hashes } = generateRecoveryCodes(1);
  const [code = ""] = codes;
  const compact = code.replace("-", "");
  for (const typed of [
    code.toLowerCase(),
    compact,
    `${compact.slice(0, 4)} ${compact.slice(4)}`,
    `  ${code}  `,
  ]) {
    assert.equal(verifyRecoveryCode(typed, hashes), 0, typed);
  }
});

test("verifyRecoveryCode returns -1 for wrong or malformed codes", () => {
  const { codes, hashes } = generateRecoveryCodes(3);
  const [first = ""] = codes;
  const [other = ""] = generateRecoveryCodes(1).codes;
  for (const code of [other, "", "ABCD", "ABCD-EFG1", `${first}X`]) {
    assert.equal(verifyRecoveryCode(code, hashes), -1, code);
  }
  assert.equal(verifyRecoveryCode(first, []), -1);
});

test("a code stops working once the app removes its hash", () => {
  const { codes, hashes } = generateRecoveryCodes(3);
  const [, used = "", unused = ""] = codes;
  const index = verifyRecoveryCode(used, hashes);
  const remaining = hashes.filter((_, i) => i !== index);
  assert.equal(verifyRecoveryCode(used, remaining), -1);
  assert.equal(verifyRecoveryCode(unused, remaining), 1);
});
