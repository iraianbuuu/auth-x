import { createOtpAuthUri, type OtpAuthParams } from "./otpauth.ts";
import { generateSecret } from "./secret.ts";

export interface Enrollment {
  secret: string;
  uri: string;
}

/**
 * Creates a new random secret and its `otpauth://` URI. Render `uri` as a QR
 * code for the user to scan, and store `secret` encrypted with
 * `encryptSecret`.
 *
 * @throws {OtpError} The same errors as {@link createOtpAuthUri}.
 */
export function createEnrollment(
  params: Omit<OtpAuthParams, "secret">,
): Enrollment {
  const secret = generateSecret();
  return { secret, uri: createOtpAuthUri({ ...params, secret }) };
}
