import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBase32 } from "@/auth/base32.ts";
import { createEnrollment } from "@/auth/enrollment.ts";
import { parseOtpAuthUri } from "@/auth/otpauth.ts";
import { toQrDataUrl } from "@/auth/qrcode.ts";
import { generateTotp, verifyTotp } from "@/auth/totp.ts";
import { DEFAULTS } from "@/auth/types.ts";

const PNG_DATA_URL = "data:image/png;base64,";

test("toQrDataUrl returns a PNG data URL", async () => {
  const url = await toQrDataUrl("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP");
  assert.ok(url.startsWith(PNG_DATA_URL));
});

test("toQrDataUrl lets errors reach the caller", async () => {
  await assert.rejects(() => toQrDataUrl(""));
});

test("createEnrollment returns a secret, a matching URI and a QR code", async () => {
  const enrollment = await createEnrollment({
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
  assert.ok(enrollment.qrDataUrl.startsWith(PNG_DATA_URL));
});

test("createEnrollment carries options into the URI", async () => {
  const options = { algorithm: "SHA256", digits: 8, period: 60 } as const;
  const enrollment = await createEnrollment({ account: "alice", options });
  assert.deepEqual(parseOtpAuthUri(enrollment.uri).options, options);
});

test("createEnrollment gives a different secret every time", async () => {
  const first = await createEnrollment({ account: "alice" });
  const second = await createEnrollment({ account: "alice" });
  assert.notEqual(first.secret, second.secret);
});

test("a code from the enrolled secret verifies", async () => {
  const { secret, uri } = await createEnrollment({ account: "alice" });
  const { options } = parseOtpAuthUri(uri);
  const key = decodeBase32(secret);
  const timestamp = 1111111111;

  const code = generateTotp(key, { ...options, timestamp });
  assert.equal(
    verifyTotp(key, code, { ...options, timestamp }),
    Math.floor(timestamp / options.period),
  );
});
