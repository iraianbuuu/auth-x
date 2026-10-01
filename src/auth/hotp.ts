import { createHmac } from "node:crypto";

function generateHmac(secret: Buffer, counter: Buffer): Buffer {
  return createHmac("sha1", secret)
    .update(counter)
    .digest();
}

function generateHotp(secret: Buffer, counter: Buffer): string {
  const hmac = generateHmac(secret, counter);

  const lastByte = hmac[hmac.length - 1] as number;
  const offset = lastByte & 0x0f;

  const binary = hmac.readUInt32BE(offset);

  const masked = binary & 0x7fffffff;

  return String(masked % 1_000_000).padStart(6, "0");
}

export { generateHmac, generateHotp };