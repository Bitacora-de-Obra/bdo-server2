import { localStorageProvider } from './local';
import { s3StorageProvider } from './s3';

type StorageDriver = 'local' | 's3';

export interface StorageProvider {
  save: (options: { path: string; content: Buffer }) => Promise<string>; // returns storage key
  remove: (path: string) => Promise<void>;
  getPublicUrl: (path: string) => string;
}

export const getStorage = (): StorageProvider => {
  const driver = (process.env.STORAGE_DRIVER || 'local') as StorageDriver;
  if (driver === 's3') {
    return s3StorageProvider;
  }
  return localStorageProvider;
};
