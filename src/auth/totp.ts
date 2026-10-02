import { generateHotp } from "./hotp.ts";

const TIME_STEP_SECONDS = 30;

function timeToCounter(unixSeconds: number): Buffer {
  const step = Math.floor(unixSeconds / TIME_STEP_SECONDS);

  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step), 0);
  return counter;
}

export function generateTotp(key: Buffer, unixSeconds: number): string {
  const counter = timeToCounter(unixSeconds);
  return generateHotp(key, counter);
}
