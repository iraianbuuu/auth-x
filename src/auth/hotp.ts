import { createHmac } from "node:crypto";
import { OtpError } from "./errors.ts";
import { resolveOptions, type TotpOptions } from "./types.ts";

const MIN_KEY_BYTES = 16;

export function generateHotp(
  key: Buffer,
  counter: number,
  options: Partial<TotpOptions> = {},
): string {
  const { algorithm, digits } = resolveOptions(options);

  // RFC 4226 section 4 requires a shared secret of at least 128 bits.
  if (key.length < MIN_KEY_BYTES) {
    throw new OtpError(
      "INVALID_SECRET",
      `Key must be at least ${MIN_KEY_BYTES} bytes`,
    );
  }
  if (!Number.isSafeInteger(counter) || counter < 0) {
    throw new OtpError(
      "INVALID_OPTIONS",
      "Counter must be a non-negative integer",
    );
  }

  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac(algorithm.toLowerCase(), key)
    .update(message)
    .digest();

  const offset = hmac.readUInt8(hmac.length - 1) & 0x0f;

  const truncated = hmac.readUInt32BE(offset) & 0x7fffffff;

  return String(truncated % 10 ** digits).padStart(digits, "0");
}
