import { createHmac } from "node:crypto";

const DIGITS = 6;

export function generateHmac(key: Buffer, counter: Buffer): Buffer {
  return createHmac("sha1", key).update(counter).digest();
}

export function generateHotp(key: Buffer, counter: Buffer): string {
  const hmac = generateHmac(key, counter);

  const lastByte = hmac[hmac.length - 1] as number;
  const offset = lastByte & 0x0f;

  const truncated = hmac.readUInt32BE(offset) & 0x7fffffff;

  return String(truncated % 10 ** DIGITS).padStart(DIGITS, "0");
}
