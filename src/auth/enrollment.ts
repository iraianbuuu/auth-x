import { createOtpAuthUri, type OtpAuthParams } from "./otpauth.ts";
import { toQrDataUrl } from "./qrcode.ts";
import { generateSecret } from "./secret.ts";

export interface Enrollment {
  secret: string;
  uri: string;
  qrDataUrl: string;
}

export async function createEnrollment(
  params: Omit<OtpAuthParams, "secret">,
): Promise<Enrollment> {
  const secret = generateSecret();
  const uri = createOtpAuthUri({ ...params, secret });
  return { secret, uri, qrDataUrl: await toQrDataUrl(uri) };
}
