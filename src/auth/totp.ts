import { generateHotp } from "./hotp.ts";

function getCounter(unixSeconds: number): Buffer {
  const counter = Math.floor(unixSeconds / 30);

  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(counter), 0);
  return buffer;
}

function generateTotp(
  secret: Buffer,
  unixSeconds: number
): string {

  const counter = getCounter(unixSeconds);
  return generateHotp(secret, counter);
}

export {
  generateTotp
}
