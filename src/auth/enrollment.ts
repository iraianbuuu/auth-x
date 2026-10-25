import { createOtpAuthUri, type OtpAuthParams } from "./otpauth.ts";
import { generateSecret } from "./secret.ts";

export interface Enrollment {
  secret: string;
  uri: string;
}

// Render `uri` as a QR code in the app for the user to scan.
export function createEnrollment(
  params: Omit<OtpAuthParams, "secret">,
): Enrollment {
  const secret = generateSecret();
  return { secret, uri: createOtpAuthUri({ ...params, secret }) };
}
