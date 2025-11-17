import { Response } from 'express';
import { PrismaClient } from '@prisma/client';
import { AuthRequest } from './auth';
import { logger } from '../logger';
import { recordSecurityEvent } from '../services/securityMonitoring';

const prisma = new PrismaClient();

/**
 * Verifica que el usuario tiene acceso a un log entry
 * Retorna el log entry si tiene acceso, null si no
 */
export const verifyLogEntryAccess = async (
  logEntryId: string,
  userId: string,
  requireWriteAccess = false
): Promise<{ entry: any; hasAccess: boolean; reason?: string }> => {
  try {
    const entry = await prisma.logEntry.findUnique({
      where: { id: logEntryId },
      include: {
        author: {
          select: { id: true, appRole: true, projectRole: true },
        },
        assignees: {
          select: { id: true },
        },
        signatureTasks: {
          select: { signerId: true },
        },
      },
    });

    if (!entry) {
      return { entry: null, hasAccess: false, reason: 'Log entry no encontrado' };
    }

    // Obtener información del usuario
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        appRole: true,
        projectRole: true,
        status: true,
      },
    });

    if (!user || user.status !== 'active') {
      return { entry: null, hasAccess: false, reason: 'Usuario no activo' };
    }

    // Admins siempre tienen acceso
    if (user.appRole === 'admin') {
      return { entry, hasAccess: true };
    }

    // Verificar acceso de lectura (cualquier usuario activo puede leer)
    if (!requireWriteAccess) {
      return { entry, hasAccess: true };
    }

    // Verificar acceso de escritura
    const isAuthor = entry.authorId === userId;
    const isAssignee = entry.assignees.some((a: any) => a.id === userId);
    const isSigner = entry.signatureTasks.some((task: any) => task.signerId === userId);

    // El autor siempre puede editar (dependiendo del estado)
    if (isAuthor) {
      return { entry, hasAccess: true };
    }

    // Los asignados pueden editar según el estado
    if (isAssignee) {
      // Lógica específica según el estado del log entry
      // Por ejemplo, contratistas solo pueden editar en estado SUBMITTED
      if (entry.status === 'SUBMITTED' && user.projectRole === 'CONTRACTOR_REP') {
        return { entry, hasAccess: true };
      }
    }

    // Los firmantes pueden firmar pero no editar
    if (isSigner && !requireWriteAccess) {
      return { entry, hasAccess: true };
    }

    return {
      entry,
      hasAccess: false,
      reason: 'No tienes permisos para modificar este recurso',
    };
  } catch (error) {
    console.error('Error verificando acceso a log entry:', error);
    return { entry: null, hasAccess: false, reason: 'Error verificando permisos' };
  }
};

/**
 * Middleware para verificar acceso a un log entry
 */
export const requireLogEntryAccess = (requireWrite = false) => {
  return async (req: AuthRequest, res: Response, next: any) => {
    try {
      const { id } = req.params;
      const userId = req.user?.userId;

      if (!userId) {
        return res.status(401).json({
          error: 'Usuario no autenticado',
          code: 'UNAUTHORIZED',
        });
      }

      if (!id) {
        return res.status(400).json({
          error: 'ID de log entry requerido',
          code: 'MISSING_ID',
        });
      }

      const { entry, hasAccess, reason } = await verifyLogEntryAccess(
        id,
        userId,
        requireWrite
      );

      if (!hasAccess) {
        recordSecurityEvent('ACCESS_DENIED', 'medium', req, {
          reason: reason || 'Resource access denied',
          resourceType: 'logEntry',
          resourceId: id,
          requireWrite: requireWrite,
        });
        return res.status(403).json({
          error: reason || 'No tienes acceso a este recurso',
          code: 'ACCESS_DENIED',
        });
      }

      // Agregar el entry al request para uso posterior
      (req as any).resource = entry;
      next();
    } catch (error) {
      logger.error('Error en middleware de permisos', {
        error: error instanceof Error ? error.message : String(error),
      });
      res.status(500).json({
        error: 'Error verificando permisos',
        code: 'PERMISSION_CHECK_ERROR',
      });
    }
  };
};

/**
 * Verifica que el usuario tiene acceso a un acta
 */
export const verifyActaAccess = async (
  actaId: string,
  userId: string,
  requireWriteAccess = false
): Promise<{ acta: any; hasAccess: boolean; reason?: string }> => {
  try {
    const acta = await prisma.acta.findUnique({
      where: { id: actaId },
      include: {
        signatures: {
          select: { signerId: true },
        },
      },
    });

    if (!acta) {
      return { acta: null, hasAccess: false, reason: 'Acta no encontrada' };
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { appRole: true, status: true },
    });

    if (!user || user.status !== 'active') {
      return { acta: null, hasAccess: false, reason: 'Usuario no activo' };
    }

    // Admins siempre tienen acceso
    if (user.appRole === 'admin') {
      return { acta, hasAccess: true };
    }

    // Lectura: cualquier usuario activo
    if (!requireWriteAccess) {
      return { acta, hasAccess: true };
    }

    // Escritura: solo admins y editores
    if (user.appRole === 'editor') {
      return { acta, hasAccess: true };
    }

    return {
      acta,
      hasAccess: false,
      reason: 'Solo administradores y editores pueden modificar actas',
    };
  } catch (error) {
    console.error('Error verificando acceso a acta:', error);
    return { acta: null, hasAccess: false, reason: 'Error verificando permisos' };
  }
};

