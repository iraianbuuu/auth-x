import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { test } from "node:test";
import {
  decryptSecret,
  encryptSecret,
  type Keyring,
  needsReencryption,
} from "@/auth/encryption.ts";
import { otpError } from "./helpers.ts";

const OLD_KEY = randomBytes(32);
const NEW_KEY = randomBytes(32);
const OLD: Keyring = { current: "2026-10", keys: { "2026-10": OLD_KEY } };
const ROTATING: Keyring = {
  current: "2027-01",
  keys: { "2026-10": OLD_KEY, "2027-01": NEW_KEY },
};
const SECRET = "JBSWY3DPEHPK3PXP";

// Payload parts: 0 version, 1 key ID, 2 IV, 3 tag, 4 ciphertext.
function withPart(payload: string, part: number, value: string): string {
  const parts = payload.split(":");
  parts[part] = value;
  return parts.join(":");
}

// Replaces the first character of a base64 part with a different one. The
// first character holds the top 6 bits of the first byte, so the decoded
// bytes always change.
function tamper(payload: string, part: number): string {
  const value = payload.split(":")[part] ?? "";
  return withPart(
    payload,
    part,
    (value.startsWith("A") ? "B" : "A") + value.slice(1),
  );
}

test("decryptSecret reverses encryptSecret", () => {
  assert.equal(decryptSecret(encryptSecret(SECRET, OLD), OLD), SECRET);
});

test("encryptSecret returns v1:<keyId>:<iv>:<tag>:<ciphertext>", () => {
  const [version, keyId, iv = "", tag = "", ciphertext = "", ...rest] =
    encryptSecret(SECRET, ROTATING).split(":");
  assert.equal(version, "v1");
  assert.equal(keyId, "2027-01");
  assert.equal(Buffer.from(iv, "base64").length, 12);
  assert.equal(Buffer.from(tag, "base64").length, 16);
  assert.ok(ciphertext.length > 0);
  assert.deepEqual(rest, []);
});

test("encryptSecret rejects an empty secret", () => {
  assert.throws(() => encryptSecret("", OLD), otpError("INVALID_SECRET"));
});

test("encrypting the same secret twice gives different output", () => {
  assert.notEqual(encryptSecret(SECRET, OLD), encryptSecret(SECRET, OLD));
});

test("decryptSecret picks the key named in the payload", () => {
  const oldPayload = encryptSecret(SECRET, OLD);
  const newPayload = encryptSecret(SECRET, ROTATING);
  assert.equal(decryptSecret(oldPayload, ROTATING), SECRET);
  assert.equal(decryptSecret(newPayload, ROTATING), SECRET);
});

test("a full key rotation keeps every secret readable", () => {
  const before = encryptSecret(SECRET, OLD, "user:alice");
  assert.equal(needsReencryption(before, OLD), false);
  assert.equal(needsReencryption(before, ROTATING), true);

  const after = encryptSecret(
    decryptSecret(before, ROTATING, "user:alice"),
    ROTATING,
    "user:alice",
  );
  assert.equal(needsReencryption(after, ROTATING), false);

  const newOnly: Keyring = {
    current: "2027-01",
    keys: { "2027-01": NEW_KEY },
  };
  assert.equal(decryptSecret(after, newOnly, "user:alice"), SECRET);
  assert.throws(
    () => decryptSecret(before, newOnly, "user:alice"),
    otpError("DECRYPTION_FAILED"),
  );
});

test("decryptSecret rejects a tampered key ID, IV, tag or ciphertext", () => {
  const payload = encryptSecret(SECRET, ROTATING);
  assert.throws(
    () => decryptSecret(withPart(payload, 1, "2026-10"), ROTATING),
    otpError("DECRYPTION_FAILED"),
    "key ID",
  );
  for (const part of [2, 3, 4]) {
    assert.throws(
      () => decryptSecret(tamper(payload, part), ROTATING),
      otpError("DECRYPTION_FAILED"),
      `part ${part}`,
    );
  }
});

test("decryptSecret rejects a wrong key under the same key ID", () => {
  const payload = encryptSecret(SECRET, OLD);
  const wrong: Keyring = {
    current: "2026-10",
    keys: { "2026-10": randomBytes(32) },
  };
  assert.throws(
    () => decryptSecret(payload, wrong),
    otpError("DECRYPTION_FAILED"),
  );
});

test("decryptSecret names a key ID missing from the keyring", () => {
  const payload = encryptSecret(SECRET, ROTATING);
  assert.throws(
    () => decryptSecret(payload, OLD),
    (error: unknown) =>
      otpError("DECRYPTION_FAILED")(error) &&
      (error as Error).message.includes("2027-01"),
  );
});

test("decryptSecret rejects malformed payloads", () => {
  const payload = encryptSecret(SECRET, OLD);
  const [, , iv = "", tag = ""] = payload.split(":");
  const malformed = [
    "",
    "v1",
    "v1:2026-10",
    withPart(payload, 0, "v2"),
    `${payload}:extra`,
    withPart(payload, 1, ""),
    withPart(payload, 2, iv.slice(4)),
    withPart(payload, 3, tag.slice(4)),
    withPart(payload, 4, ""),
  ];
  for (const bad of malformed) {
    assert.throws(
      () => decryptSecret(bad, OLD),
      otpError("DECRYPTION_FAILED"),
      bad,
    );
  }
});

test("both functions reject an invalid keyring", () => {
  const payload = encryptSecret(SECRET, OLD);
  const shortKey: Keyring = {
    current: "2026-10",
    keys: { "2026-10": Buffer.alloc(16) },
  };
  const invalid: Keyring[] = [
    { current: "missing", keys: { "2026-10": OLD_KEY } },
    shortKey,
    { current: "2026-10", keys: { "2026-10": Buffer.alloc(33) } },
  ];
  for (const keyring of invalid) {
    assert.throws(
      () => encryptSecret(SECRET, keyring),
      otpError("INVALID_KEY"),
    );
  }
  assert.throws(
    () => decryptSecret(payload, shortKey),
    otpError("INVALID_KEY"),
  );
});

test("key IDs must be 1 to 32 letters, digits, dashes or underscores", () => {
  for (const id of ["", "a:b", "a b", "x".repeat(33)]) {
    assert.throws(
      () => encryptSecret(SECRET, { current: id, keys: { [id]: OLD_KEY } }),
      otpError("INVALID_KEY"),
      JSON.stringify(id),
    );
  }
  const ok = "Key_2026-10";
  assert.doesNotThrow(() =>
    encryptSecret(SECRET, { current: ok, keys: { [ok]: OLD_KEY } }),
  );
});

test("a payload only decrypts with the context it was encrypted with", () => {
  const alice = encryptSecret(SECRET, OLD, "user:alice");
  assert.equal(decryptSecret(alice, OLD, "user:alice"), SECRET);
  assert.throws(
    () => decryptSecret(alice, OLD, "user:mallory"),
    otpError("DECRYPTION_FAILED"),
  );
  assert.throws(() => decryptSecret(alice, OLD), otpError("DECRYPTION_FAILED"));
});
