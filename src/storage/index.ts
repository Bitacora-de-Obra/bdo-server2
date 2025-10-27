import { logger } from '../logger';
import { localStorageProvider } from './local';
import { s3StorageProvider } from './s3';

type StorageDriver = 'local' | 's3';

export interface StorageProvider {
  save: (options: { path: string; content: Buffer }) => Promise<string>; // returns storage key
  remove: (path: string) => Promise<void>;
  getPublicUrl: (path: string) => string;
}

const ALLOWED_DRIVERS: StorageDriver[] = ['local', 's3'];

let cachedProvider: StorageProvider | null = null;
let resolvedDriver: StorageDriver | null = null;

const resolveDriver = (): StorageDriver => {
  if (resolvedDriver) {
    return resolvedDriver;
  }

  const raw = (process.env.STORAGE_DRIVER || 'local').toString().toLowerCase();

  if (!ALLOWED_DRIVERS.includes(raw as StorageDriver)) {
    logger.warn('STORAGE_DRIVER no válido, se usará "local" por defecto.', {
      requestedDriver: raw,
    });
    resolvedDriver = 'local';
    return resolvedDriver;
  }

  if (raw === 's3' && !process.env.S3_BUCKET) {
    logger.warn(
      'STORAGE_DRIVER=s3 pero falta S3_BUCKET. Se vuelve al almacenamiento local.'
    );
    resolvedDriver = 'local';
    return resolvedDriver;
  }

  resolvedDriver = raw as StorageDriver;
  return resolvedDriver;
};

export const getStorage = (): StorageProvider => {
  if (!cachedProvider) {
    const driver = resolveDriver();
    cachedProvider = driver === 's3' ? s3StorageProvider : localStorageProvider;
    logger.info('Storage driver configurado', { driver });
  }
  return cachedProvider;
};

export const getStorageDriver = (): StorageDriver => resolveDriver();
