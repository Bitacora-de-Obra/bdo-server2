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
  // Planos CAD
  'application/acad': {
    extensions: ['.dwg'],
    magicBytes: [
      [0x41, 0x43, 0x31, 0x30], // AC10 (AutoCAD R10)
      [0x41, 0x43, 0x31, 0x31], // AC11 (AutoCAD R11/R12)
      [0x41, 0x43, 0x31, 0x32], // AC12 (AutoCAD R13)
      [0x41, 0x43, 0x31, 0x33], // AC13 (AutoCAD R14)
      [0x41, 0x43, 0x31, 0x34], // AC14 (AutoCAD 2000)
      [0x41, 0x43, 0x31, 0x35], // AC15 (AutoCAD 2004)
      [0x41, 0x43, 0x31, 0x37], // AC17 (AutoCAD 2007)
      [0x41, 0x43, 0x31, 0x38], // AC18 (AutoCAD 2010)
      [0x41, 0x43, 0x31, 0x39], // AC19 (AutoCAD 2013)
      [0x41, 0x43, 0x32, 0x30], // AC20 (AutoCAD 2018)
    ],
  },
  'image/vnd.dwg': {
    extensions: ['.dwg'],
    magicBytes: [
      [0x41, 0x43, 0x31, 0x30], // AC10
      [0x41, 0x43, 0x31, 0x31], // AC11
      [0x41, 0x43, 0x31, 0x32], // AC12
      [0x41, 0x43, 0x31, 0x33], // AC13
      [0x41, 0x43, 0x31, 0x34], // AC14
      [0x41, 0x43, 0x31, 0x35], // AC15
      [0x41, 0x43, 0x31, 0x37], // AC17
      [0x41, 0x43, 0x31, 0x38], // AC18
      [0x41, 0x43, 0x31, 0x39], // AC19
      [0x41, 0x43, 0x32, 0x30], // AC20
    ],
  },
  'application/x-dwg': {
    extensions: ['.dwg'],
    magicBytes: [
      [0x41, 0x43, 0x31, 0x30], // AC10
      [0x41, 0x43, 0x31, 0x31], // AC11
      [0x41, 0x43, 0x31, 0x32], // AC12
      [0x41, 0x43, 0x31, 0x33], // AC13
      [0x41, 0x43, 0x31, 0x34], // AC14
      [0x41, 0x43, 0x31, 0x35], // AC15
      [0x41, 0x43, 0x31, 0x37], // AC17
      [0x41, 0x43, 0x31, 0x38], // AC18
      [0x41, 0x43, 0x31, 0x39], // AC19
      [0x41, 0x43, 0x32, 0x30], // AC20
    ],
  },
  'image/x-dwg': {
    extensions: ['.dwg'],
    magicBytes: [
      [0x41, 0x43, 0x31, 0x30], // AC10
      [0x41, 0x43, 0x31, 0x31], // AC11
      [0x41, 0x43, 0x31, 0x32], // AC12
      [0x41, 0x43, 0x31, 0x33], // AC13
      [0x41, 0x43, 0x31, 0x34], // AC14
      [0x41, 0x43, 0x31, 0x35], // AC15
      [0x41, 0x43, 0x31, 0x37], // AC17
      [0x41, 0x43, 0x31, 0x38], // AC18
      [0x41, 0x43, 0x31, 0x39], // AC19
      [0x41, 0x43, 0x32, 0x30], // AC20
    ],
  },
  'application/dxf': {
    extensions: ['.dxf'],
    magicBytes: [
      [0x30], // DXF files typically start with "0" (ASCII)
    ],
  },
  'image/vnd.dxf': {
    extensions: ['.dxf'],
    magicBytes: [
      [0x30], // DXF files typically start with "0" (ASCII)
    ],
  },
  // XML para cronogramas
  'text/xml': {
    extensions: ['.xml'],
    magicBytes: [
      [0x3C, 0x3F, 0x78, 0x6D, 0x6C], // <?xml
      [0xEF, 0xBB, 0xBF, 0x3C, 0x3F, 0x78, 0x6D, 0x6C], // BOM + <?xml
    ],
  },
  'application/xml': {
    extensions: ['.xml'],
    magicBytes: [
      [0x3C, 0x3F, 0x78, 0x6D, 0x6C], // <?xml
      [0xEF, 0xBB, 0xBF, 0x3C, 0x3F, 0x78, 0x6D, 0x6C], // BOM + <?xml
    ],
  },
  'text/xml; charset=utf-8': {
    extensions: ['.xml'],
    magicBytes: [
      [0x3C, 0x3F, 0x78, 0x6D, 0x6C], // <?xml
      [0xEF, 0xBB, 0xBF, 0x3C, 0x3F, 0x78, 0x6D, 0x6C], // BOM + <?xml
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
    
    // Para XML y DXF, la validación es más flexible (pueden empezar con espacios o BOM)
    const isXml = declaredMimeType.startsWith('text/xml') || declaredMimeType.startsWith('application/xml');
    const isDxf = declaredMimeType.includes('dxf');
    const isDwg = declaredMimeType.includes('dwg');
    
    if (!magicBytesValid) {
      // Para XML, verificar si contiene <?xml en cualquier posición
      if (isXml) {
        const fileContent = file.toString('utf-8', 0, Math.min(100, file.length));
        if (fileContent.includes('<?xml') || fileContent.includes('<?XML')) {
          // XML válido aunque no empiece exactamente con <?xml
          return { isValid: true };
        }
      }
      
      // Para DXF, verificar si empieza con "0" o "SECTION" (formato ASCII)
      if (isDxf) {
        const fileContent = file.toString('utf-8', 0, Math.min(50, file.length)).trim();
        if (fileContent.startsWith('0') || fileContent.startsWith('SECTION') || fileContent.startsWith('section')) {
          return { isValid: true };
        }
      }
      
      // Para DWG, verificar si empieza con AC (AutoCAD signature)
      if (isDwg) {
        if (file.length >= 4 && file[0] === 0x41 && file[1] === 0x43) {
          // Empieza con "AC" (ASCII)
          return { isValid: true };
        }
      }
      
      // Si la verificación básica falla, intentar con file-type
      try {
        const fileType = await fileTypeFromBuffer(file);
        
        if (!fileType) {
          // Para XML, DXF y DWG, file-type puede no detectarlos, pero si pasaron las validaciones anteriores, aceptar
          if (isXml || isDxf || isDwg) {
            return {
              isValid: false,
              errorMessage: `No se pudo verificar el tipo de archivo ${declaredMimeType}. Verifica que el archivo no esté corrupto.`,
            };
          }
          return {
            isValid: false,
            errorMessage: 'No se pudo determinar el tipo de archivo. El archivo puede estar corrupto o ser de un tipo no permitido.',
          };
        }

        // Verificar que el tipo detectado coincida con el declarado (permitir variaciones para XML)
        if (fileType.mime !== declaredMimeType) {
          // Para XML, permitir variaciones de MIME type
          if (isXml && (fileType.mime.includes('xml') || declaredMimeType.includes('xml'))) {
            return { isValid: true };
          }
          
          return {
            isValid: false,
            errorMessage: `Tipo de archivo no coincide. Declarado: ${declaredMimeType}, Detectado: ${fileType.mime}`,
            detectedType: fileType.mime,
          };
        }

        // Verificar que el tipo detectado esté permitido
        if (!(fileType.mime in ALLOWED_FILE_TYPES)) {
          // Para XML, permitir variaciones
          if (isXml && fileType.mime.includes('xml')) {
            return { isValid: true };
          }
          
          return {
            isValid: false,
            errorMessage: `Tipo de archivo detectado no permitido: ${fileType.mime}`,
            detectedType: fileType.mime,
          };
        }
      } catch (error) {
        logger.warn('Error al detectar tipo de archivo con file-type', {
          error: error instanceof Error ? error.message : String(error),
          declaredMimeType,
        });
        // Para XML, DXF y DWG, si file-type falla pero la extensión es correcta, aceptar
        if (isXml || isDxf || isDwg) {
          return {
            isValid: true,
          };
        }
        // Para otros tipos, rechazar si no se puede verificar
        return {
          isValid: false,
          errorMessage: 'No se pudo verificar el tipo de archivo. El archivo puede estar corrupto.',
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

