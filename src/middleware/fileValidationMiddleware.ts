import { Request, Response, NextFunction } from 'express';
import { validateFileType, validateFileSize } from '../utils/fileValidation';
import { logger } from '../logger';
import { AuthRequest } from './auth';
import { recordSecurityEvent } from '../services/securityMonitoring';

/**
 * Middleware para validar archivos después de que multer los procese
 * Valida magic bytes y tamaño de archivo
 */
export const validateUploadedFiles = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const files = req.files;
    
    if (!files || (Array.isArray(files) && files.length === 0)) {
      // No hay archivos, continuar
      return next();
    }

    const fileArray = Array.isArray(files) ? files : [files];
    const maxFileSize = 10 * 1024 * 1024; // 10MB

    for (const file of fileArray) {
      const multerFile = file as Express.Multer.File;

      // Validar tamaño
      const sizeValidation = validateFileSize(multerFile.size, maxFileSize);
      if (!sizeValidation.isValid) {
        return res.status(400).json({
          error: sizeValidation.errorMessage,
          code: 'FILE_SIZE_INVALID',
        });
      }

      // Validar tipo usando magic bytes
      if (multerFile.buffer) {
        const typeValidation = await validateFileType(
          multerFile.buffer,
          multerFile.mimetype,
          multerFile.originalname
        );

        if (!typeValidation.isValid) {
          logger.warn('Archivo rechazado por validación de tipo', {
            fileName: multerFile.originalname,
            declaredMimeType: multerFile.mimetype,
            detectedType: typeValidation.detectedType,
            error: typeValidation.errorMessage,
            userId: (req as AuthRequest).user?.userId,
          });

          recordSecurityEvent('FILE_UPLOAD_REJECTED', 'medium', req, {
            fileName: multerFile.originalname,
            declaredMimeType: multerFile.mimetype,
            detectedType: typeValidation.detectedType,
            userId: (req as AuthRequest).user?.userId,
          });

          return res.status(400).json({
            error: typeValidation.errorMessage || 'Tipo de archivo no válido',
            code: 'FILE_TYPE_INVALID',
            detectedType: typeValidation.detectedType,
          });
        }
      } else {
        // Si no hay buffer, el archivo puede no haberse cargado correctamente
        logger.warn('Archivo sin buffer recibido', {
          fileName: multerFile.originalname,
        });
        return res.status(400).json({
          error: 'Error al procesar el archivo',
          code: 'FILE_PROCESSING_ERROR',
        });
      }
    }

    // Todos los archivos son válidos
    next();
  } catch (error) {
    logger.error('Error en middleware de validación de archivos', {
      error: error instanceof Error ? error.message : String(error),
    });
    res.status(500).json({
      error: 'Error al validar archivos',
      code: 'FILE_VALIDATION_ERROR',
    });
  }
};

