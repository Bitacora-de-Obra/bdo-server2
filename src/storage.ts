import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import path from "path";
import fs from "fs/promises";

export interface StorageInterface {
  save(params: { path: string; content: Buffer }): Promise<void>;
  load(path: string): Promise<Buffer>;
  read(path: string): Promise<Buffer>; // Alias para load - compatibilidad
  delete(path: string): Promise<void>;
  remove(path: string): Promise<void>; // Alias para delete - compatibilidad
  getPublicUrl(path: string): string;
  getSignedUrl(path: string, expiresIn?: number): Promise<string>;
}

class LocalStorage implements StorageInterface {
  private uploadsDir: string;

  constructor(uploadsDir: string) {
    this.uploadsDir = uploadsDir;
  }

  async save(params: { path: string; content: Buffer }): Promise<void> {
    const fullPath = path.join(this.uploadsDir, params.path);
    const dir = path.dirname(fullPath);

    // Crear directorio si no existe
    await fs.mkdir(dir, { recursive: true });
    await fs.writeFile(fullPath, params.content);
  }

  async load(filePath: string): Promise<Buffer> {
    const fullPath = path.join(this.uploadsDir, filePath);
    return await fs.readFile(fullPath);
  }

  async read(filePath: string): Promise<Buffer> {
    // Alias para load - compatibilidad
    return this.load(filePath);
  }

  async delete(filePath: string): Promise<void> {
    const fullPath = path.join(this.uploadsDir, filePath);
    await fs.unlink(fullPath);
  }

  async remove(filePath: string): Promise<void> {
    // Alias para delete - compatibilidad
    return this.delete(filePath);
  }

  getPublicUrl(filePath: string): string {
    const baseUrl =
      process.env.STORAGE_PUBLIC_URL ||
      process.env.SERVER_PUBLIC_URL ||
      process.env.APP_BASE_URL ||
      process.env.BASE_URL ||
      `http://localhost:${process.env.PORT || 4001}`;
    return `${baseUrl.replace(/\/$/, "")}/uploads/${filePath}`;
  }

  async getSignedUrl(
    filePath: string,
    expiresIn: number = 3600
  ): Promise<string> {
    // Para storage local, retornamos la URL pública
    return this.getPublicUrl(filePath);
  }
}

class CloudflareR2Storage implements StorageInterface {
  private client: S3Client;
  private bucket: string;
  private publicUrl: string;

  constructor() {
    const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
    const accessKeyId = process.env.CLOUDFLARE_R2_ACCESS_KEY_ID;
    const secretAccessKey = process.env.CLOUDFLARE_R2_SECRET_ACCESS_KEY;
    this.bucket = process.env.CLOUDFLARE_R2_BUCKET || "";
    this.publicUrl = process.env.CLOUDFLARE_R2_PUBLIC_URL || "";

    if (!accountId || !accessKeyId || !secretAccessKey || !this.bucket) {
      throw new Error("Faltan variables de entorno para Cloudflare R2");
    }

    this.client = new S3Client({
      region: "auto", // Cloudflare R2 usa "auto"
      endpoint: `https://${accountId}.r2.cloudflarestorage.com`,
      credentials: {
        accessKeyId,
        secretAccessKey,
      },
      forcePathStyle: true,
    });
  }

  async save(params: { path: string; content: Buffer }): Promise<void> {
    const command = new PutObjectCommand({
      Bucket: this.bucket,
      Key: params.path,
      Body: params.content,
      ContentType: this.getContentType(params.path),
    });

    await this.client.send(command);
  }

  async load(filePath: string): Promise<Buffer> {
    const command = new GetObjectCommand({
      Bucket: this.bucket,
      Key: filePath,
    });

    const response = await this.client.send(command);

    if (!response.Body) {
      throw new Error(`No se pudo cargar el archivo: ${filePath}`);
    }

    // Convertir el stream a buffer
    const chunks: Uint8Array[] = [];
    const reader = response.Body.transformToByteArray();
    return Buffer.from(await reader);
  }

  async read(filePath: string): Promise<Buffer> {
    // Alias para load - compatibilidad
    return this.load(filePath);
  }

  async delete(filePath: string): Promise<void> {
    const command = new DeleteObjectCommand({
      Bucket: this.bucket,
      Key: filePath,
    });

    await this.client.send(command);
  }

  async remove(filePath: string): Promise<void> {
    // Alias para delete - compatibilidad
    return this.delete(filePath);
  }

  getPublicUrl(filePath: string): string {
    if (this.publicUrl) {
      return `${this.publicUrl.replace(/\/$/, "")}/${filePath}`;
    }
    // URL pública estándar de R2 (si el bucket está configurado como público)
    const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
    return `https://${this.bucket}.${accountId}.r2.cloudflarestorage.com/${filePath}`;
  }

  async getSignedUrl(
    filePath: string,
    expiresIn: number = 3600
  ): Promise<string> {
    const command = new GetObjectCommand({
      Bucket: this.bucket,
      Key: filePath,
    });

    return await getSignedUrl(this.client, command, { expiresIn });
  }

  private getContentType(filePath: string): string {
    const ext = path.extname(filePath).toLowerCase();
    const contentTypes: { [key: string]: string } = {
      ".jpg": "image/jpeg",
      ".jpeg": "image/jpeg",
      ".png": "image/png",
      ".gif": "image/gif",
      ".pdf": "application/pdf",
      ".doc": "application/msword",
      ".docx":
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      ".xls": "application/vnd.ms-excel",
      ".xlsx":
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      ".txt": "text/plain",
      ".zip": "application/zip",
    };

    return contentTypes[ext] || "application/octet-stream";
  }
}

// Instancia singleton del storage
let storageInstance: StorageInterface | null = null;

export const getStorage = (): StorageInterface => {
  if (!storageInstance) {
    const defaultDriver =
      process.env.CLOUDFLARE_ACCOUNT_ID &&
      process.env.CLOUDFLARE_R2_ACCESS_KEY_ID &&
      process.env.CLOUDFLARE_R2_SECRET_ACCESS_KEY
        ? "r2"
        : "local";
    const driver = (process.env.STORAGE_DRIVER || defaultDriver).toLowerCase();

    switch (driver) {
      case "cloudflare":
      case "r2":
        storageInstance = new CloudflareR2Storage();
        break;
      case "local":
      default:
        const uploadsDir = process.env.UPLOADS_DIR || "uploads";
        storageInstance = new LocalStorage(uploadsDir);
        break;
    }
  }

  return storageInstance;
};

// Función para resetear la instancia (útil para testing)
export const resetStorage = () => {
  storageInstance = null;
};
