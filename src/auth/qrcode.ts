import qrcode from "qrcode";

export async function saveQrCode(uri: string): Promise<void> {
  try {
    await qrcode.toFile("totp-qr.png", uri);
  } catch (error) {
    console.error("Error generating QR code:", error);
  }
}
