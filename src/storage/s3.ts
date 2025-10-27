const bucket = process.env.S3_BUCKET || '';
const region = process.env.S3_REGION || 'us-east-1';
const endpoint = process.env.S3_ENDPOINT;
const customPublicUrl = process.env.STORAGE_PUBLIC_URL;

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

  const { S3Client, PutObjectCommand, DeleteObjectCommand } = s3Module;

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

  return { client, PutObjectCommand, DeleteObjectCommand };
};

export const s3StorageProvider = {
  async save({ content, path: filePath }: { content: Buffer; path: string }) {
    const { client, PutObjectCommand } = getClient();

    await client.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: filePath,
        Body: content,
      })
    );

    return filePath;
  },

  async remove(filePath: string) {
    const { client, DeleteObjectCommand } = getClient();

    const key = filePath.startsWith(`${bucket}/`)
      ? filePath.slice(bucket.length + 1)
      : filePath;

    await client.send(
      new DeleteObjectCommand({
        Bucket: bucket,
        Key: key,
      })
    );
  },
  getPublicUrl(filePath: string) {
    const key = filePath.startsWith(`${bucket}/`)
      ? filePath.slice(bucket.length + 1)
      : filePath;

    if (customPublicUrl) {
      return `${customPublicUrl.replace(/\/$/, '')}/${key}`;
    }
    if (endpoint) {
      return `${endpoint.replace(/\/$/, '')}/${bucket}/${key}`;
    }
    return `https://${bucket}.s3.${region}.amazonaws.com/${key}`;
  },
};
