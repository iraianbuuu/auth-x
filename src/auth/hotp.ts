import { createHmac } from "node:crypto";
import { OtpError } from "./errors.ts";
import { resolveOptions, type TotpOptions } from "./types.ts";

export function generateHotp(
  key: Buffer,
  counter: number,
  options: Partial<TotpOptions> = {},
): string {
  const { algorithm, digits } = resolveOptions(options);

  if (key.length === 0) {
    throw new OtpError("INVALID_SECRET", "Key must not be empty");
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
