import { randomBytes } from "node:crypto";
import { encodeBase32 } from "./base32.ts";

const SECRET_BYTES = 20;

export function generateSecret(): string {
  return encodeBase32(randomBytes(SECRET_BYTES));
}
