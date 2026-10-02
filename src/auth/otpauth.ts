export interface OtpAuthParams {
  secret: string;
  issuer: string;
  account: string;
}

export function createOtpAuthUri({
  secret,
  issuer,
  account,
}: OtpAuthParams): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  const encodedIssuer = encodeURIComponent(issuer);
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodedIssuer}`;
}

export function parseOtpAuthUri(uri: string): OtpAuthParams {
  const url = new URL(uri);
  if (url.protocol !== "otpauth:" || url.hostname !== "totp") {
    throw new Error("Invalid otpauth URI");
  }

  const secret = url.searchParams.get("secret");
  if (!secret) throw new Error("Missing secret");

  const issuer = url.searchParams.get("issuer");
  if (!issuer) throw new Error("Missing issuer");

  const label = decodeURIComponent(url.pathname.slice(1));
  const separatorIndex = label.indexOf(":");
  if (separatorIndex === -1) throw new Error("Invalid label");

  const labelIssuer = label.slice(0, separatorIndex);
  const account = label.slice(separatorIndex + 1);

  if (!account) throw new Error("Missing account");
  if (labelIssuer !== issuer) throw new Error("Issuer mismatch");

  return { secret, issuer, account };
}
