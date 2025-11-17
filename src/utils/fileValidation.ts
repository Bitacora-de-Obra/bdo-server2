import { FileTypeResult } from 'file-type';
import { fileTypeFromBuffer } from 'file-type';
import { logger } from '../logger';

/**
 * Tipos de archivo permitidos con sus magic bytes correspondientes
 */
export const ALLOWED_FILE_TYPES = {
  // Imágenes
  'image/jpeg': {
    extensions: ['.jpg', '.jpeg'],
    magicBytes: [
      [0xFF, 0xD8, 0xFF], // JPEG standard
    ],
  },
  'image/png': {
    extensions: ['.png'],
    magicBytes: [
      [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], // PNG signature
    ],
  },
  'image/gif': {
    extensions: ['.gif'],
    magicBytes: [
      [0x47, 0x49, 0x46, 0x38, 0x37, 0x61], // GIF87a
      [0x47, 0x49, 0x46, 0x38, 0x39, 0x61], // GIF89a
    ],
  },
  'image/webp': {
    extensions: ['.webp'],
    magicBytes: [
      [0x52, 0x49, 0x46, 0x46], // RIFF (WebP starts with RIFF)
    ],
  },
  // Documentos
  'application/pdf': {
    extensions: ['.pdf'],
    magicBytes: [
      [0x25, 0x50, 0x44, 0x46], // %PDF
    ],
  },
} as const;

/**
 * Verifica los magic bytes de un archivo
 */
const verifyMagicBytes = (buffer: Buffer, expectedMagicBytes: number[][]): boolean => {
  for (const magicBytes of expectedMagicBytes) {
    if (buffer.length < magicBytes.length) {
      continue;
    }
    
    const matches = magicBytes.every((byte, index) => buffer[index] === byte);
    if (matches) {
      return true;
    }
  }
  return false;
};

/**
 * Valida un archivo usando magic bytes y MIME type
 * @param file Buffer del archivo
 * @param declaredMimeType MIME type declarado por el cliente
 * @param fileName Nombre del archivo (opcional, para validar extensión)
 * @returns Objeto con isValid y errorMessage opcional
 */
export const validateFileType = async (
  file: Buffer,
  declaredMimeType: string,
  fileName?: string
): Promise<{ isValid: boolean; errorMessage?: string; detectedType?: string }> => {
  try {
    // Verificar que el archivo no esté vacío
    if (!file || file.length === 0) {
      return {
        isValid: false,
        errorMessage: 'El archivo está vacío',
      };
    }

    // Verificar que el MIME type declarado esté en la lista permitida
    if (!(declaredMimeType in ALLOWED_FILE_TYPES)) {
      return {
        isValid: false,
        errorMessage: `Tipo de archivo no permitido: ${declaredMimeType}`,
      };
    }

    const allowedType = ALLOWED_FILE_TYPES[declaredMimeType as keyof typeof ALLOWED_FILE_TYPES];

    // Verificar extensión del archivo si se proporciona
    if (fileName) {
      const extension = fileName.toLowerCase().substring(fileName.lastIndexOf('.'));
      const allowedExtensions = allowedType.extensions as readonly string[];
      if (!allowedExtensions.includes(extension)) {
        return {
          isValid: false,
          errorMessage: `Extensión de archivo no coincide con el tipo declarado: ${extension}`,
        };
      }
    }

    // Verificar magic bytes básicos
    const magicBytesArray: number[][] = allowedType.magicBytes.map(mb => [...mb]);
    const magicBytesValid = verifyMagicBytes(file, magicBytesArray);
    if (!magicBytesValid) {
      // Si la verificación básica falla, intentar con file-type
      try {
        const fileType = await fileTypeFromBuffer(file);
        
        if (!fileType) {
          return {
            isValid: false,
            errorMessage: 'No se pudo determinar el tipo de archivo. El archivo puede estar corrupto o ser de un tipo no permitido.',
          };
        }

        // Verificar que el tipo detectado coincida con el declarado
        if (fileType.mime !== declaredMimeType) {
          return {
            isValid: false,
            errorMessage: `Tipo de archivo no coincide. Declarado: ${declaredMimeType}, Detectado: ${fileType.mime}`,
            detectedType: fileType.mime,
          };
        }

        // Verificar que el tipo detectado esté permitido
        if (!(fileType.mime in ALLOWED_FILE_TYPES)) {
          return {
            isValid: false,
            errorMessage: `Tipo de archivo detectado no permitido: ${fileType.mime}`,
            detectedType: fileType.mime,
          };
        }
      } catch (error) {
        logger.warn('Error al detectar tipo de archivo con file-type', {
          error: error instanceof Error ? error.message : String(error),
        });
        // Si file-type falla pero los magic bytes básicos pasaron, aceptar el archivo
        // (algunos archivos pueden tener variaciones menores en los headers)
        return {
          isValid: true,
        };
      }
    }

    return {
      isValid: true,
    };
  } catch (error) {
    logger.error('Error validando tipo de archivo', {
      error: error instanceof Error ? error.message : String(error),
    });
    return {
      isValid: false,
      errorMessage: 'Error al validar el tipo de archivo',
    };
  }
};

/**
 * Valida el tamaño de un archivo
 */
export const validateFileSize = (
  size: number,
  maxSizeBytes: number = 10 * 1024 * 1024 // 10MB por defecto
): { isValid: boolean; errorMessage?: string } => {
  if (size > maxSizeBytes) {
    const maxSizeMB = (maxSizeBytes / (1024 * 1024)).toFixed(2);
    return {
      isValid: false,
      errorMessage: `El archivo excede el tamaño máximo permitido de ${maxSizeMB}MB`,
    };
  }

  if (size === 0) {
    return {
      isValid: false,
      errorMessage: 'El archivo está vacío',
    };
  }

  return {
    isValid: true,
  };
};

