import fs from 'fs/promises';
import fsSync from 'fs';
import path from 'path';
import { logger } from '../logger';
import type { StorageProvider } from './index';

const baseDir = path.resolve(
  process.env.UPLOADS_DIR || path.join(__dirname, '../../uploads')
);

try {
  fsSync.mkdirSync(baseDir, { recursive: true });
} catch (error) {
  logger.error('No se pudo crear el directorio base de uploads.', { error });
}

const publicBase = (
  process.env.STORAGE_PUBLIC_URL ||
  `${process.env.SERVER_PUBLIC_URL || `http://localhost:${process.env.PORT || 4001}`}/uploads`
).replace(/\/$/, '');

const normalizeKey = (key: string) => {
  const normalized = path.posix.normalize(key).replace(/^\/+/g, '');
  if (normalized.startsWith('..')) {
    throw new Error('Ruta inválida para almacenamiento local.');
  }
  return normalized;
};

const toAbsolutePath = (key: string) => {
  const absolutePath = path.resolve(baseDir, ...key.split('/'));
  const relative = path.relative(baseDir, absolutePath);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error('Intento de escribir fuera del directorio de uploads.');
  }
  return absolutePath;
};

export const localStorageProvider: StorageProvider = {
  async save({ content, path: filePath }: { content: Buffer; path: string }) {
    const key = normalizeKey(filePath);
    const absolutePath = toAbsolutePath(key);
    await fs.mkdir(path.dirname(absolutePath), { recursive: true });
    await fs.writeFile(absolutePath, content);
    return key;
  },
  async remove(filePath: string) {
    const key = normalizeKey(filePath);
    const absolutePath = toAbsolutePath(key);
    await fs.rm(absolutePath, { force: true });
  },
  getPublicUrl(filePath: string) {
    const key = normalizeKey(filePath);
    return `${publicBase}/${key}`;
  },
};
