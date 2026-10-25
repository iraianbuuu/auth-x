import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import { decryptSecret, encryptSecret } from "@/auth/encryption.ts";
import { otpError } from "./helpers.ts";

const KEY = randomBytes(32);
const SECRET = "JBSWY3DPEHPK3PXP";

// Replaces the first character of one ":"-separated part with a different
// base64 character. The first character holds the top 6 bits of the first
// byte, so the decoded bytes always change.
function tamper(payload: string, part: number): string {
  const parts = payload.split(":");
  const value = parts[part] ?? "";
  parts[part] = (value.startsWith("A") ? "B" : "A") + value.slice(1);
  return parts.join(":");
}

test("decryptSecret reverses encryptSecret", () => {
  assert.equal(decryptSecret(encryptSecret(SECRET, KEY), KEY), SECRET);
});

test("encryptSecret returns v1:<iv>:<tag>:<ciphertext> in base64", () => {
  const [version, iv = "", tag = "", ciphertext = "", ...rest] = encryptSecret(
    SECRET,
    KEY,
  ).split(":");
  assert.equal(version, "v1");
  assert.equal(Buffer.from(iv, "base64").length, 12);
  assert.equal(Buffer.from(tag, "base64").length, 16);
  assert.ok(ciphertext.length > 0);
  assert.deepEqual(rest, []);
});

test("encryptSecret rejects an empty secret", () => {
  assert.throws(() => encryptSecret("", KEY), otpError("INVALID_SECRET"));
});

test("encrypting the same secret twice gives different output", () => {
  assert.notEqual(encryptSecret(SECRET, KEY), encryptSecret(SECRET, KEY));
});

test("decryptSecret rejects a tampered IV, tag or ciphertext", () => {
  const payload = encryptSecret(SECRET, KEY);
  for (const part of [1, 2, 3]) {
    assert.throws(
      () => decryptSecret(tamper(payload, part), KEY),
      otpError("DECRYPTION_FAILED"),
      `part ${part}`,
    );
  }
});

test("decryptSecret rejects the wrong key", () => {
  const payload = encryptSecret(SECRET, KEY);
  assert.throws(
    () => decryptSecret(payload, randomBytes(32)),
    otpError("DECRYPTION_FAILED"),
  );
});

test("decryptSecret rejects malformed payloads", () => {
  const [, iv = "", tag = "", ciphertext = ""] = encryptSecret(
    SECRET,
    KEY,
  ).split(":");
  const malformed = [
    "",
    "v1",
    `v1:${iv}:${tag}`,
    `v2:${iv}:${tag}:${ciphertext}`,
    `v1:${iv}:${tag}:${ciphertext}:extra`,
    `v1:${iv.slice(4)}:${tag}:${ciphertext}`,
    `v1:${iv}:${tag.slice(4)}:${ciphertext}`,
    `v1:${iv}:${tag}:`,
  ];
  for (const payload of malformed) {
    assert.throws(
      () => decryptSecret(payload, KEY),
      otpError("DECRYPTION_FAILED"),
      payload,
    );
  }
});

test("both functions require a 32-byte key", () => {
  const payload = encryptSecret(SECRET, KEY);
  for (const key of [Buffer.alloc(0), Buffer.alloc(16), Buffer.alloc(33)]) {
    assert.throws(() => encryptSecret(SECRET, key), otpError("INVALID_KEY"));
    assert.throws(() => decryptSecret(payload, key), otpError("INVALID_KEY"));
  }
});

test("a payload only decrypts with the context it was encrypted with", () => {
  const alice = encryptSecret(SECRET, KEY, "user:alice");
  assert.equal(decryptSecret(alice, KEY, "user:alice"), SECRET);
  assert.throws(
    () => decryptSecret(alice, KEY, "user:mallory"),
    otpError("DECRYPTION_FAILED"),
  );
  assert.throws(() => decryptSecret(alice, KEY), otpError("DECRYPTION_FAILED"));
});
