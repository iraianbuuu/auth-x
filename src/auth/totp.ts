import { generateHotp } from "./hotp.ts";

function getCounter(timestamp: number): Buffer {
  const counter = Math.floor(timestamp / 30);

  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(counter), 0);
  return buffer;
}

function generateTotp(
  secret: Buffer,
  timestamp : number
): string {

  const counter = getCounter(timestamp);
  return generateHotp(secret, counter);
}

export {
  generateTotp
}
