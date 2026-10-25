import qrcode from "qrcode";

export function toQrDataUrl(uri: string): Promise<string> {
  return qrcode.toDataURL(uri);
}
