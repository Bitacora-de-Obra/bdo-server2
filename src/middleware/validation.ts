import { Request, Response, NextFunction } from 'express';
import { z, ZodError, ZodTypeAny } from 'zod';
import { AuthRequest } from './auth';

/**
 * Tipo para el schema de validación
 */
export type ValidationSchema = {
  body?: ZodTypeAny;
  query?: ZodTypeAny;
  params?: ZodTypeAny;
};

/**
 * Middleware de validación usando Zod
 * Valida el body, query params o params según el schema proporcionado
 */
export const validate = (schema: ValidationSchema) => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      // Validar body
      if (schema.body) {
        req.body = schema.body.parse(req.body) as any;
      }

      // Validar query params
      if (schema.query) {
        req.query = schema.query.parse(req.query) as any;
      }

      // Validar route params
      if (schema.params) {
        req.params = schema.params.parse(req.params) as any;
      }

      next();
    } catch (error) {
      if (error instanceof ZodError) {
        const errors = (error as any).errors.map((err: any) => ({
          path: err.path.join('.'),
          message: err.message,
        }));

        return res.status(400).json({
          error: 'Error de validación',
          code: 'VALIDATION_ERROR',
          details: errors,
        });
      }

      // Error inesperado
      return res.status(500).json({
        error: 'Error interno durante la validación',
        code: 'VALIDATION_INTERNAL_ERROR',
      });
    }
  };
};

/**
 * Helper para crear schemas comunes
 */
export const commonSchemas = {
  uuid: z.string().uuid('ID inválido'),
  email: z.string().email('Email inválido'),
  date: z.string().datetime().or(z.date()),
  optionalDate: z.string().datetime().optional().or(z.date().optional()),
  positiveNumber: z.number().positive('Debe ser un número positivo'),
  nonEmptyString: z.string().min(1, 'No puede estar vacío'),
  optionalString: z.string().optional(),
  boolean: z.boolean().or(z.string().transform((val) => val === 'true')),
};

