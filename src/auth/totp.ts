import { timingSafeEqual } from "node:crypto";
import { OtpError } from "./errors.ts";
import { generateHotp } from "./hotp.ts";
import { resolveOptions, type TotpOptions } from "./types.ts";

type TotpInput = Partial<TotpOptions> & { timestamp?: number };

type VerifyInput = TotpInput & { window?: number; afterStep?: number };

function timeStep(timestamp: number, period: number): number {
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
    throw new OtpError(
      "INVALID_OPTIONS",
      "Timestamp must be a non-negative integer of Unix seconds",
    );
  }
  return Math.floor(timestamp / period);
}

export function generateTotp(key: Buffer, input: TotpInput = {}): string {
  const { timestamp = Math.floor(Date.now() / 1000), ...options } = input;
  const resolved = resolveOptions(options);
  return generateHotp(key, timeStep(timestamp, resolved.period), resolved);
}

export function verifyTotp(
  key: Buffer,
  code: string,
  input: VerifyInput = {},
): number | null {
  const {
    timestamp = Math.floor(Date.now() / 1000),
    window = 1,
    afterStep = -1,
    ...options
  } = input;
  const resolved = resolveOptions(options);

  if (!Number.isSafeInteger(window) || window < 0) {
    throw new OtpError(
      "INVALID_OPTIONS",
      "Window must be a non-negative integer",
    );
  }
  if (!Number.isSafeInteger(afterStep)) {
    throw new OtpError("INVALID_OPTIONS", "afterStep must be an integer");
  }

  const current = timeStep(timestamp, resolved.period);

  if (!new RegExp(`^\\d{${resolved.digits}}$`).test(code)) {
    return null;
  }

  const given = Buffer.from(code);

  for (let step = current - window; step <= current + window; step++) {
    if (step < 0 || step <= afterStep) continue;
    const expected = Buffer.from(generateHotp(key, step, resolved));
    if (timingSafeEqual(expected, given)) return step;
  }
  return null;
}
