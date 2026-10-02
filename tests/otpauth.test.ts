import assert from "node:assert/strict";
import { test } from "node:test";
import { createOtpAuthUri, parseOtpAuthUri } from "../src/auth/otpauth.ts";

const PARAMS = {
  secret: "JBSWY3DPEHPK3PXP",
  issuer: "Acme Co",
  account: "alice@example.com",
};

test("createOtpAuthUri encodes the label and issuer", () => {
  assert.equal(
    createOtpAuthUri(PARAMS),
    "otpauth://totp/Acme%20Co%3Aalice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Acme%20Co",
  );
});

test("parseOtpAuthUri reverses createOtpAuthUri", () => {
  assert.deepEqual(parseOtpAuthUri(createOtpAuthUri(PARAMS)), PARAMS);
});

test("parseOtpAuthUri rejects other schemes and OTP types", () => {
  for (const uri of [
    "https://totp/Acme:alice?secret=A&issuer=Acme",
    "otpauth://hotp/Acme:alice?secret=A&issuer=Acme",
  ]) {
    assert.throws(() => parseOtpAuthUri(uri), /Invalid otpauth URI/);
  }
});

test("parseOtpAuthUri rejects missing or mismatched fields", () => {
  const cases: [string, RegExp][] = [
    ["otpauth://totp/Acme:alice?issuer=Acme", /Missing secret/],
    ["otpauth://totp/Acme:alice?secret=A", /Missing issuer/],
    ["otpauth://totp/alice?secret=A&issuer=Acme", /Invalid label/],
    ["otpauth://totp/Acme:?secret=A&issuer=Acme", /Missing account/],
    ["otpauth://totp/Other:alice?secret=A&issuer=Acme", /Issuer mismatch/],
  ];
  for (const [uri, error] of cases) {
    assert.throws(() => parseOtpAuthUri(uri), error);
  }
});
