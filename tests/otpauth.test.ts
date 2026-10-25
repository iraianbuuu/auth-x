import assert from "node:assert/strict";
import { test } from "node:test";
import { createOtpAuthUri, parseOtpAuthUri } from "@/auth/otpauth.ts";
import { DEFAULTS, type TotpOptions } from "@/auth/types.ts";
import { otpError } from "./helpers.ts";

const SECRET = "JBSWY3DPEHPK3PXP";

const PARAMS = {
  secret: SECRET,
  issuer: "Acme Co",
  account: "alice@example.com",
};

const BASE = "otpauth://totp/Acme%20Co%3Aalice%40example.com";

test("createOtpAuthUri encodes the label and issuer", () => {
  assert.equal(
    createOtpAuthUri(PARAMS),
    `${BASE}?secret=${SECRET}&issuer=Acme%20Co`,
  );
});

test("createOtpAuthUri leaves out options that equal the defaults", () => {
  assert.equal(
    createOtpAuthUri({ ...PARAMS, options: { ...DEFAULTS } }),
    `${BASE}?secret=${SECRET}&issuer=Acme%20Co`,
  );
});

test("createOtpAuthUri adds options that differ from the defaults", () => {
  assert.equal(
    createOtpAuthUri({
      ...PARAMS,
      options: { algorithm: "SHA256", digits: 8, period: 60 },
    }),
    `${BASE}?secret=${SECRET}&issuer=Acme%20Co&algorithm=SHA256&digits=8&period=60`,
  );
  assert.equal(
    createOtpAuthUri({ ...PARAMS, options: { digits: 8 } }),
    `${BASE}?secret=${SECRET}&issuer=Acme%20Co&digits=8`,
  );
});

test("createOtpAuthUri works without an issuer", () => {
  assert.equal(
    createOtpAuthUri({ secret: SECRET, account: "alice@example.com" }),
    `otpauth://totp/alice%40example.com?secret=${SECRET}`,
  );
});

test("createOtpAuthUri rejects bad input", () => {
  assert.throws(
    () => createOtpAuthUri({ ...PARAMS, issuer: "Acme:Corp" }),
    otpError("INVALID_URI"),
  );
  assert.throws(
    () => createOtpAuthUri({ secret: SECRET, account: "Acme:alice" }),
    otpError("INVALID_URI"),
  );
  assert.throws(
    () => createOtpAuthUri({ ...PARAMS, account: "" }),
    otpError("INVALID_URI"),
  );
  assert.throws(
    () => createOtpAuthUri({ ...PARAMS, secret: "not base32!" }),
    otpError("INVALID_SECRET"),
  );
  assert.throws(
    () =>
      createOtpAuthUri({
        ...PARAMS,
        options: { digits: 7 } as unknown as Partial<TotpOptions>,
      }),
    otpError("INVALID_OPTIONS"),
  );
});

test("parseOtpAuthUri reverses createOtpAuthUri with resolved options", () => {
  assert.deepEqual(parseOtpAuthUri(createOtpAuthUri(PARAMS)), {
    ...PARAMS,
    options: DEFAULTS,
  });

  const options: TotpOptions = { algorithm: "SHA512", digits: 8, period: 60 };
  assert.deepEqual(parseOtpAuthUri(createOtpAuthUri({ ...PARAMS, options })), {
    ...PARAMS,
    options,
  });
});

test("parseOtpAuthUri treats the issuer as optional", () => {
  assert.deepEqual(parseOtpAuthUri(`otpauth://totp/alice?secret=${SECRET}`), {
    secret: SECRET,
    account: "alice",
    options: DEFAULTS,
  });
});

test("parseOtpAuthUri takes the issuer from the label prefix", () => {
  assert.deepEqual(
    parseOtpAuthUri(`otpauth://totp/Acme:alice?secret=${SECRET}`),
    { secret: SECRET, issuer: "Acme", account: "alice", options: DEFAULTS },
  );
});

test("parseOtpAuthUri rejects malformed URIs with INVALID_URI", () => {
  const invalid = [
    "not a uri",
    `https://totp/Acme:alice?secret=${SECRET}`,
    `otpauth://hotp/Acme:alice?secret=${SECRET}`,
    "otpauth://totp/Acme:alice?issuer=Acme",
    `otpauth://totp/Acme:?secret=${SECRET}`,
    `otpauth://totp/?secret=${SECRET}`,
    `otpauth://totp/Other:alice?secret=${SECRET}&issuer=Acme`,
    `otpauth://totp/Acme%ZZ:alice?secret=${SECRET}`,
  ];
  for (const uri of invalid) {
    assert.throws(() => parseOtpAuthUri(uri), otpError("INVALID_URI"), uri);
  }
});

test("parseOtpAuthUri rejects an invalid secret", () => {
  assert.throws(
    () => parseOtpAuthUri("otpauth://totp/Acme:alice?secret=A"),
    otpError("INVALID_SECRET"),
  );
});

test("parseOtpAuthUri rejects invalid options", () => {
  for (const query of [
    "algorithm=MD5",
    "digits=7",
    "digits=abc",
    "period=0",
    "period=1.5",
  ]) {
    assert.throws(
      () => parseOtpAuthUri(`otpauth://totp/alice?secret=${SECRET}&${query}`),
      otpError("INVALID_OPTIONS"),
      query,
    );
  }
});
