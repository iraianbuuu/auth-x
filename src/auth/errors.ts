export type OtpErrorCode =
  | "INVALID_OPTIONS"
  | "INVALID_SECRET"
  | "INVALID_URI"
  | "INVALID_KEY"
  | "DECRYPTION_FAILED";

/** Thrown for invalid input. Check `code` rather than the message. */
export class OtpError extends Error {
  readonly code: OtpErrorCode;

  constructor(code: OtpErrorCode, message: string) {
    super(message);
    this.name = "OtpError";
    this.code = code;
  }
}
