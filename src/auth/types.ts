import { OtpError } from "./errors.ts";

const ALGORITHMS = ["SHA1", "SHA256", "SHA512"] as const;

export type HashAlgorithm = (typeof ALGORITHMS)[number];

export type TotpOptions = {
  algorithm: HashAlgorithm;
  digits: 6 | 8;
  period: number;
};

export const DEFAULTS: TotpOptions = {
  algorithm: "SHA1",
  digits: 6,
  period: 30,
};

export function resolveOptions(
  options: Partial<TotpOptions> = {},
): TotpOptions {
  const resolved = { ...DEFAULTS, ...options };

  if (!ALGORITHMS.includes(resolved.algorithm)) {
    throw new OtpError(
      "INVALID_OPTIONS",
      `Unsupported algorithm: ${resolved.algorithm}`,
    );
  }
  if (resolved.digits !== 6 && resolved.digits !== 8) {
    throw new OtpError("INVALID_OPTIONS", "Digits must be 6 or 8");
  }
  if (!Number.isSafeInteger(resolved.period) || resolved.period <= 0) {
    throw new OtpError("INVALID_OPTIONS", "Period must be a positive integer");
  }

  return resolved;
}
