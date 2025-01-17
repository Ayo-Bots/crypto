import * as crypto from "crypto";

export default class Crypto {
  private readonly token: string;
  private readonly ALGORITHM: string;
  private readonly KEY: string;
  private readonly IV_LENGTH: number;
  public constructor(token: string) {
    this.token = token;
    this.ALGORITHM = "aes-256-ctr";
    this.KEY = crypto
      .createHash("sha256")
      .update(String(this.token))
      .digest("base64")
      .substr(0, 32);

    this.IV_LENGTH = 16;
  }

  public encrypt(plaintext: string): string {
    const iv = crypto.randomBytes(this.IV_LENGTH);
    const cipher = crypto.createCipheriv(this.ALGORITHM, this.KEY, iv);
    const encrypted = Buffer.concat([
      cipher.update(plaintext, "utf8"),
      cipher.final(),
    ]);
    return `${iv.toString("hex")}:${encrypted.toString("hex")}`;
  }

  public decrypt(encryptedText: string): string {
    const [ivHex, encryptedHex] = encryptedText.split(":");
    if (!ivHex || !encryptedHex)
      throw new Error("Invalid encrypted text format");

    const iv = Buffer.from(ivHex, "hex");
    const encrypted = Buffer.from(encryptedHex, "hex");
    const decipher = crypto.createDecipheriv(this.ALGORITHM, this.KEY, iv);
    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final(),
    ]);

    return decrypted.toString("utf8");
  }
}
