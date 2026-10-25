import { OtpError, type OtpErrorCode } from "../src/auth/errors.ts";
import type { HashAlgorithm } from "../src/auth/types.ts";

export function otpError(code: OtpErrorCode) {
  return (error: unknown): boolean =>
    error instanceof OtpError && error.code === code;
}

// RFC 6238 Appendix B keys: the ASCII digits "1234567890" repeated to
// 20 bytes for SHA-1, 32 bytes for SHA-256 and 64 bytes for SHA-512.
export function rfcKey(algorithm: HashAlgorithm): Buffer {
  const length = algorithm === "SHA1" ? 20 : algorithm === "SHA256" ? 32 : 64;
  return Buffer.from("1234567890".repeat(7).slice(0, length));
}
