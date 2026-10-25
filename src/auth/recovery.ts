import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { encodeBase32 } from "./base32.ts";
import { OtpError } from "./errors.ts";

// 5 random bytes are 40 bits, which encode to exactly 8 base32 characters.
const CODE_BYTES = 5;
const CODE_PATTERN = /^[A-Z2-7]{8}$/;
const MAX_CODES = 100;

export interface RecoveryCodes {
  /** Codes to show the user once. Never store them. */
  codes: string[];
  /** SHA-256 hashes to store, in the same order as `codes`. */
  hashes: string[];
}

function hashCode(normalized: string): string {
  return createHash("sha256").update(normalized).digest("hex");
}

/**
 * Generates one-time recovery codes formatted as `XXXX-XXXX`, each with 40
 * random bits.
 *
 * @param count From 1 to 100.
 * @throws {OtpError} `INVALID_OPTIONS` for an invalid count.
 */
export function generateRecoveryCodes(count = 10): RecoveryCodes {
  if (!Number.isSafeInteger(count) || count < 1 || count > MAX_CODES) {
    throw new OtpError(
      "INVALID_OPTIONS",
      `Count must be an integer from 1 to ${MAX_CODES}`,
    );
  }

  const codes = Array.from({ length: count }, () => {
    const raw = encodeBase32(randomBytes(CODE_BYTES));
    return `${raw.slice(0, 4)}-${raw.slice(4)}`;
  });
  return {
    codes,
    hashes: codes.map((code) => hashCode(code.replace("-", ""))),
  };
}

/**
 * Checks a typed recovery code against stored hashes, ignoring case, spaces
 * and dashes. Returns the index of the matching hash, which the caller must
 * delete so the code works only once, or `-1`.
 */
export function verifyRecoveryCode(code: string, hashes: string[]): number {
  const normalized = code.toUpperCase().replace(/[\s-]/g, "");
  if (!CODE_PATTERN.test(normalized)) return -1;

  const given = Buffer.from(hashCode(normalized), "hex");
  return hashes.findIndex((hash) => {
    const stored = Buffer.from(hash, "hex");
    return stored.length === given.length && timingSafeEqual(stored, given);
  });
}
