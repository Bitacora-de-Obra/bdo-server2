import fs from 'fs/promises';
import path from 'path';
import type { StorageProvider } from './index';

const baseDir = path.resolve(process.env.UPLOADS_DIR || path.join(__dirname, '../../uploads'));
const publicBase = (process.env.STORAGE_PUBLIC_URL || `${process.env.SERVER_PUBLIC_URL || `http://localhost:${process.env.PORT || 4001}`}/uploads`).replace(/\/$/, '');

const normalizeKey = (key: string) => key.replace(/^\/+/g, '');
const toAbsolutePath = (key: string) => path.join(baseDir, ...normalizeKey(key).split('/'));

export const localStorageProvider: StorageProvider = {
  async save({ content, path: filePath }: { content: Buffer; path: string }) {
    const key = normalizeKey(filePath);
    const absolutePath = toAbsolutePath(key);
    await fs.mkdir(path.dirname(absolutePath), { recursive: true });
    await fs.writeFile(absolutePath, content);
    return key;
  },
  async remove(filePath: string) {
    const absolutePath = toAbsolutePath(filePath);
    await fs.rm(absolutePath, { force: true });
  },
  getPublicUrl(filePath: string) {
    return `${publicBase}/${normalizeKey(filePath)}`;
  },
};
