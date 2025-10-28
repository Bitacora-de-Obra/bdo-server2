import crypto from "crypto";

export const sha256 = (data: Buffer | string): string => {
  const buffer = typeof data === "string" ? Buffer.from(data, "utf-8") : data;
  return crypto.createHash("sha256").update(buffer).digest("hex");
};
