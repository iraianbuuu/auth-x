import { OtpError } from "./errors.ts";
import { generateHotp } from "./hotp.ts";
import { resolveOptions, type TotpOptions } from "./types.ts";

type TotpInput = Partial<TotpOptions> & { timestamp?: number };

export function generateTotp(key: Buffer, input: TotpInput = {}): string {
  const { timestamp = Math.floor(Date.now() / 1000), ...options } = input;
  const resolved = resolveOptions(options);

  if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
    throw new OtpError(
      "INVALID_OPTIONS",
      "Timestamp must be a non-negative integer of Unix seconds",
    );
  }

  const counter = Math.floor(timestamp / resolved.period);
  return generateHotp(key, counter, resolved);
}
