import assert from "node:assert/strict";
import { test } from "node:test";
import { verifyTotp } from "@/auth/totp.ts";
import { otpError, rfcKey } from "./helpers.ts";

// RFC 6238 Appendix B (SHA-1, 6 digits). These two vectors sit in
// neighboring 30-second steps: floor(1111111109 / 30) = 37037036 and
// floor(1111111111 / 30) = 37037037.
const STEP_A = 37037036;
const CODE_A = "081804";
const TIME_A = 1111111109;
const STEP_B = 37037037;
const CODE_B = "050471";
const TIME_B = 1111111111;

const key = rfcKey("SHA1");

test("verifyTotp returns the step of a code from the current step", () => {
  assert.equal(verifyTotp(key, CODE_A, { timestamp: TIME_A }), STEP_A);
  assert.equal(verifyTotp(key, CODE_B, { timestamp: TIME_B }), STEP_B);
});

test("verifyTotp accepts the previous and next step by default", () => {
  assert.equal(verifyTotp(key, CODE_A, { timestamp: TIME_B }), STEP_A);
  assert.equal(verifyTotp(key, CODE_B, { timestamp: TIME_A }), STEP_B);
});

test("verifyTotp rejects a code two steps away", () => {
  const twoStepsLater = TIME_A + 60;
  assert.equal(verifyTotp(key, CODE_A, { timestamp: twoStepsLater }), null);
  assert.equal(
    verifyTotp(key, CODE_A, { timestamp: twoStepsLater, window: 2 }),
    STEP_A,
  );
});

test("verifyTotp with window 0 accepts only the current step", () => {
  assert.equal(
    verifyTotp(key, CODE_A, { timestamp: TIME_A, window: 0 }),
    STEP_A,
  );
  assert.equal(verifyTotp(key, CODE_B, { timestamp: TIME_A, window: 0 }), null);
});

test("verifyTotp rejects a step at or before afterStep", () => {
  assert.equal(
    verifyTotp(key, CODE_A, { timestamp: TIME_A, afterStep: STEP_A }),
    null,
  );
  assert.equal(
    verifyTotp(key, CODE_A, { timestamp: TIME_A, afterStep: STEP_B }),
    null,
  );
  assert.equal(
    verifyTotp(key, CODE_A, { timestamp: TIME_A, afterStep: STEP_A - 1 }),
    STEP_A,
  );
});

test("verifyTotp returns null for malformed codes without throwing", () => {
  const malformed = [
    "",
    "08180",
    "0818040",
    "08180a",
    " 081804",
    "081804 ",
    "-81804",
    "81804.",
  ];
  for (const code of malformed) {
    assert.equal(verifyTotp(key, code, { timestamp: TIME_A }), null, code);
  }
});

test("verifyTotp handles the window near step 0", () => {
  // RFC 6238 Appendix B: "287082" is the code for step 1 (timestamp 59).
  // At timestamp 0 the window reaches step -1, which must not throw.
  assert.equal(verifyTotp(key, "287082", { timestamp: 0 }), 1);
});

test("verifyTotp honors algorithm and digits", () => {
  // RFC 6238 Appendix B: SHA-256, 8 digits, timestamp 59 (step 1).
  const options = { timestamp: 59, algorithm: "SHA256", digits: 8 } as const;
  assert.equal(verifyTotp(rfcKey("SHA256"), "46119246", options), 1);
  assert.equal(verifyTotp(rfcKey("SHA256"), "461192", options), null);
});

test("verifyTotp rejects an invalid window", () => {
  for (const window of [-1, 1.5, Number.NaN]) {
    assert.throws(
      () => verifyTotp(key, CODE_A, { timestamp: TIME_A, window }),
      otpError("INVALID_OPTIONS"),
    );
  }
});

test("verifyTotp rejects an invalid afterStep", () => {
  // NaN would make every `step <= afterStep` check false and disable
  // replay protection, so it must throw instead.
  for (const afterStep of [Number.NaN, 1.5]) {
    assert.throws(
      () => verifyTotp(key, CODE_A, { timestamp: TIME_A, afterStep }),
      otpError("INVALID_OPTIONS"),
    );
  }
});

test("verifyTotp rejects keys shorter than 16 bytes", () => {
  assert.throws(
    () => verifyTotp(Buffer.alloc(15, 1), CODE_A, { timestamp: TIME_A }),
    otpError("INVALID_SECRET"),
  );
});
