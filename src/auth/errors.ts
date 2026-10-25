export type OtpErrorCode = "INVALID_OPTIONS" | "INVALID_SECRET" | "INVALID_URI";

export class OtpError extends Error {
  readonly code: OtpErrorCode;

  constructor(code: OtpErrorCode, message: string) {
    super(message);
    this.name = "OtpError";
    this.code = code;
  }
}
