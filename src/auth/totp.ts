import { timingSafeEqual } from "node:crypto";
import { OtpError } from "./errors.ts";
import { generateHotp } from "./hotp.ts";
import { resolveOptions, type TotpOptions } from "./types.ts";

type TotpInput = Partial<TotpOptions> & {
  /** Unix time in whole seconds, not milliseconds. Defaults to now. */
  timestamp?: number;
};

type VerifyInput = TotpInput & {
  /** Steps accepted on each side of the current one, from 0 to 10. Defaults to 1. */
  window?: number;
  /** The step returned by the last successful verification. Steps at or before it are rejected. */
  afterStep?: number;
};

// Each extra step is two more HMACs and widens the replay window.
const MAX_WINDOW = 10;

function timeStep(timestamp: number, period: number): number {
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
    throw new OtpError(
      "INVALID_OPTIONS",
      "Timestamp must be a non-negative integer of Unix seconds",
    );
  }
  return Math.floor(timestamp / period);
}

/**
 * Generates the TOTP code for a key at a point in time (RFC 6238).
 *
 * @param key The decoded secret, for example `decodeBase32(secret)`.
 * @throws {OtpError} `INVALID_OPTIONS` for bad options or timestamp;
 * `INVALID_SECRET` for a key shorter than 16 bytes.
 */
export function generateTotp(key: Buffer, input: TotpInput = {}): string {
  const { timestamp = Math.floor(Date.now() / 1000), ...options } = input;
  const resolved = resolveOptions(options);
  return generateHotp(key, timeStep(timestamp, resolved.period), resolved);
}

/**
 * Checks a code typed by the user. Compares in constant time and returns the
 * matched time step, or `null` for a wrong, expired, reused or malformed code.
 * Store the returned step and pass it back as `afterStep` next time so the
 * same code cannot be used twice.
 *
 * @param key The decoded secret, for example `decodeBase32(secret)`.
 * @throws {OtpError} `INVALID_OPTIONS` for bad options; `INVALID_SECRET` for a
 * key shorter than 16 bytes.
 */
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

  if (!Number.isSafeInteger(window) || window < 0 || window > MAX_WINDOW) {
    throw new OtpError(
      "INVALID_OPTIONS",
      `Window must be an integer from 0 to ${MAX_WINDOW}`,
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
