import path from 'path';
import type { StorageProvider } from './index';

const streamToBuffer = async (stream: any): Promise<Buffer> => {
  if (!stream) {
    return Buffer.alloc(0);
  }
  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    stream.on('data', (chunk: Buffer) => chunks.push(chunk));
    stream.on('error', (err: Error) => reject(err));
    stream.on('end', () => resolve(Buffer.concat(chunks)));
  });
};

const bucket = process.env.S3_BUCKET || '';
const region = process.env.S3_REGION || 'us-east-1';
const endpoint = process.env.S3_ENDPOINT;
const customPublicUrl = process.env.STORAGE_PUBLIC_URL;

const normalizeKey = (value: string) => {
  const key = path.posix.normalize(value).replace(/^\/+/g, '');
  if (!key || key.startsWith('..')) {
    throw new Error('Clave inválida para almacenamiento S3.');
  }
  return key;
};

const getClient = () => {
  if (!bucket) {
    throw new Error('S3_BUCKET no está configurado.');
  }

  let s3Module: any;
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires,global-require
    s3Module = require('@aws-sdk/client-s3');
  } catch (error) {
    throw new Error('El driver S3 no está instalado. Ejecuta npm install @aws-sdk/client-s3');
  }

  const { S3Client, PutObjectCommand, DeleteObjectCommand, GetObjectCommand } =
    s3Module;

  const client = new S3Client({
    region,
    credentials: process.env.S3_ACCESS_KEY_ID
      ? {
          accessKeyId: process.env.S3_ACCESS_KEY_ID,
          secretAccessKey: process.env.S3_SECRET_ACCESS_KEY || '',
        }
      : undefined,
    endpoint: endpoint || undefined,
    forcePathStyle: process.env.S3_FORCE_PATH_STYLE === 'true',
  });

  return { client, PutObjectCommand, DeleteObjectCommand, GetObjectCommand };
};

export const s3StorageProvider: StorageProvider = {
  async save({ content, path: filePath }: { content: Buffer; path: string }) {
    const key = normalizeKey(filePath);
    const { client, PutObjectCommand } = getClient();

    await client.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: key,
        Body: content,
      })
    );

    return key;
  },
  async read(filePath: string) {
    const key = normalizeKey(filePath);
    const { client, GetObjectCommand } = getClient();
    const response = await client.send(
      new GetObjectCommand({
        Bucket: bucket,
        Key: key,
      })
    );

    const bodyStream = (response as any).Body;
    if (Buffer.isBuffer(bodyStream)) {
      return bodyStream;
    }
    return streamToBuffer(bodyStream);
  },

  async remove(filePath: string) {
    const key = normalizeKey(filePath);
    const { client, DeleteObjectCommand } = getClient();

    await client.send(
      new DeleteObjectCommand({
        Bucket: bucket,
        Key: key,
      })
    );
  },
  getPublicUrl(filePath: string) {
    const key = normalizeKey(filePath);

    if (customPublicUrl) {
      return `${customPublicUrl.replace(/\/$/, '')}/${key}`;
    }
    if (endpoint) {
      return `${endpoint.replace(/\/$/, '')}/${bucket}/${key}`;
    }
    return `https://${bucket}.s3.${region}.amazonaws.com/${key}`;
  },
};
