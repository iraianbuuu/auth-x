import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBase32 } from "@/auth/base32.ts";
import { createEnrollment } from "@/auth/enrollment.ts";
import { parseOtpAuthUri } from "@/auth/otpauth.ts";
import { generateTotp, verifyTotp } from "@/auth/totp.ts";
import { DEFAULTS } from "@/auth/types.ts";

test("createEnrollment returns a secret and a matching URI", () => {
  const enrollment = createEnrollment({
    account: "alice@example.com",
    issuer: "Acme Co",
  });

  assert.equal(decodeBase32(enrollment.secret).length, 20);
  assert.deepEqual(parseOtpAuthUri(enrollment.uri), {
    secret: enrollment.secret,
    issuer: "Acme Co",
    account: "alice@example.com",
    options: DEFAULTS,
  });
});

test("createEnrollment carries options into the URI", () => {
  const options = { algorithm: "SHA256", digits: 8, period: 60 } as const;
  const enrollment = createEnrollment({ account: "alice", options });
  assert.deepEqual(parseOtpAuthUri(enrollment.uri).options, options);
});

test("createEnrollment gives a different secret every time", () => {
  const first = createEnrollment({ account: "alice" });
  const second = createEnrollment({ account: "alice" });
  assert.notEqual(first.secret, second.secret);
});

test("a code from the enrolled secret verifies", () => {
  const { secret, uri } = createEnrollment({ account: "alice" });
  const { options } = parseOtpAuthUri(uri);
  const key = decodeBase32(secret);
  const timestamp = 1111111111;

  const code = generateTotp(key, { ...options, timestamp });
  assert.equal(
    verifyTotp(key, code, { ...options, timestamp }),
    Math.floor(timestamp / options.period),
  );
});
