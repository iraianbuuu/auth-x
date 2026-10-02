import { OtpError, type OtpErrorCode } from "../src/auth/errors.ts";

export function otpError(code: OtpErrorCode) {
  return (error: unknown): boolean =>
    error instanceof OtpError && error.code === code;
}
