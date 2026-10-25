import { randomBytes } from "node:crypto";
import { encodeBase32 } from "./base32.ts";

const SECRET_BYTES = 20;

/** Generates a random 160-bit TOTP secret as 32 base32 characters. */
export function generateSecret(): string {
  return encodeBase32(randomBytes(SECRET_BYTES));
}
