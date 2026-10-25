import assert from "node:assert/strict";
import { test } from "node:test";
import * as authX from "@/index.ts";

test("the entry point exports exactly the public API", () => {
  assert.deepEqual(Object.keys(authX).sort(), [
    "DEFAULTS",
    "OtpError",
    "createEnrollment",
    "createOtpAuthUri",
    "decodeBase32",
    "decryptSecret",
    "encodeBase32",
    "encryptSecret",
    "generateRecoveryCodes",
    "generateSecret",
    "generateTotp",
    "parseOtpAuthUri",
    "toQrDataUrl",
    "verifyRecoveryCode",
    "verifyTotp",
  ]);
});

test("the entry point runs the full enrollment and login flow", async () => {
  const key = Buffer.alloc(32, 7);
  const { secret, uri } = await authX.createEnrollment({
    account: "alice",
    issuer: "Acme",
  });
  const stored = authX.encryptSecret(secret, key, "user:alice");

  const totpKey = authX.decodeBase32(
    authX.decryptSecret(stored, key, "user:alice"),
  );
  const { options } = authX.parseOtpAuthUri(uri);
  const timestamp = 1111111111;
  const code = authX.generateTotp(totpKey, { ...options, timestamp });

  assert.equal(
    authX.verifyTotp(totpKey, code, { ...options, timestamp }),
    Math.floor(timestamp / options.period),
  );
});
