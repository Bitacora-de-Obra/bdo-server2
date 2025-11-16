import { z } from 'zod';
import { commonSchemas } from '../middleware/validation';

/**
 * Schema para crear/invitar un usuario
 */
export const createUserSchema = z.object({
  body: z.object({
    email: commonSchemas.email,
    fullName: z.string().min(1, 'El nombre completo es obligatorio').max(200, 'El nombre es demasiado largo'),
    projectRole: z.enum(['ADMIN', 'RESIDENT', 'SUPERVISOR', 'CONTRACTOR_REP']),
    appRole: z.enum(['admin', 'editor', 'viewer']),
    entity: z.enum(['IDU', 'INTERVENTORIA', 'CONTRATISTA']).optional(),
    cargo: z.string().max(200).optional(),
    canDownload: z.boolean().optional().default(true),
  }),
});

/**
 * Schema para actualizar un usuario
 */
export const updateUserSchema = z.object({
  params: z.object({
    id: commonSchemas.uuid,
  }),
  body: z.object({
    email: commonSchemas.email.optional(),
    fullName: z.string().min(1).max(200).optional(),
    projectRole: z.enum(['ADMIN', 'RESIDENT', 'SUPERVISOR', 'CONTRACTOR_REP']).optional(),
    appRole: z.enum(['admin', 'editor', 'viewer']).optional(),
    entity: z.enum(['IDU', 'INTERVENTORIA', 'CONTRATISTA']).optional(),
    cargo: z.string().max(200).optional(),
    canDownload: z.boolean().optional(),
    status: z.enum(['active', 'inactive']).optional(),
  }).partial(),
});

/**
 * Schema para cambiar contraseña
 */
export const changePasswordSchema = {
  body: z.object({
    oldPassword: z.string().min(1, 'La contraseña actual es obligatoria'),
    newPassword: z.string().min(8, 'La nueva contraseña debe tener al menos 8 caracteres'),
  }),
};

