import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import { recordSecurityEvent } from '../services/securityMonitoring';
import { secrets } from '../config/secrets';

const prisma = new PrismaClient();

const respondUnauthorized = (res: Response, error: string, code: string) => {
  return res.status(401).json({ error, code });
};

const respondForbidden = (res: Response, error: string, code: string) => {
  return res.status(403).json({ error, code });
};

export interface AuthRequest extends Request {
  user?: {
    userId: string;
    tokenVersion: number;
    appRole?: string;
    email?: string;
  };
}

export const createAccessToken = (userId: string, tokenVersion: number): string => {
  const secret = secrets.jwt.access;
  return jwt.sign(
    { userId, tokenVersion },
    secret,
    { expiresIn: '15m' }
  );
};

export const createRefreshToken = (userId: string, tokenVersion: number): string => {
  const secret = secrets.jwt.refresh;
  return jwt.sign(
    { userId, tokenVersion },
    secret,
    { expiresIn: '7d' }
  );
};

export const authMiddleware = async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return respondUnauthorized(res, 'No token provided', 'NO_ACCESS_TOKEN');
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
      return respondUnauthorized(res, 'Invalid token format', 'INVALID_AUTH_HEADER');
    }

    try {
      const payload = jwt.verify(token, secrets.jwt.access) as any;
      
      // Buscar usuario considerando tenant si está disponible
      const tenantId = (req as any).tenant?.id;
      const whereClause: any = tenantId 
        ? { id: payload.userId, tenantId }
        : { id: payload.userId };
      
      const user = await prisma.user.findFirst({
        where: whereClause,
        select: { id: true, status: true, tokenVersion: true, appRole: true, email: true }
      }) as any;

      if (!user) {
        return respondUnauthorized(res, 'User not found', 'USER_NOT_FOUND');
      }

      // Validar que el usuario pertenezca al tenant si hay tenant
      if (tenantId && (user as any).tenantId !== tenantId) {
        return respondForbidden(res, 'User does not belong to this tenant', 'TENANT_MISMATCH');
      }

      if (user.status !== 'active') {
        return respondForbidden(res, 'User account is inactive', 'USER_INACTIVE');
      }

      if (user.tokenVersion !== payload.tokenVersion) {
        return respondUnauthorized(res, 'Token version is invalid', 'TOKEN_VERSION_INVALID');
      }

      req.user = {
        userId: user.id,
        tokenVersion: user.tokenVersion,
        appRole: user.appRole,
        email: user.email
      };

      next();
    } catch (err) {
      if (err instanceof jwt.TokenExpiredError) {
        recordSecurityEvent('TOKEN_EXPIRED', 'medium', req);
        return res.status(401).json({ 
          error: 'Token expired',
          code: 'TOKEN_EXPIRED'
        });
      }
      throw err;
    }
  } catch (error) {
    console.error('Auth middleware error:', error);
    recordSecurityEvent('TOKEN_INVALID', 'medium', req);
    res.status(401).json({ error: 'Invalid token', code: 'INVALID_ACCESS_TOKEN' });
  }
};

export const refreshAuthMiddleware = async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const refreshToken = req.cookies.jid;
    if (!refreshToken) {
      return respondUnauthorized(res, 'No refresh token', 'NO_REFRESH_TOKEN');
    }

    let payload: any;
    try {
      payload = jwt.verify(refreshToken, secrets.jwt.refresh);
    } catch (err) {
      if (err instanceof jwt.TokenExpiredError) {
        return respondUnauthorized(res, 'Refresh token expired', 'REFRESH_TOKEN_EXPIRED');
      }
      return respondUnauthorized(res, 'Invalid refresh token', 'INVALID_REFRESH_TOKEN');
    }

    // Buscar usuario considerando tenant si está disponible
    const tenantId = (req as any).tenant?.id;
    const whereClause: any = tenantId 
      ? { id: payload.userId, tenantId }
      : { id: payload.userId };
    
    const user = await prisma.user.findFirst({
      where: whereClause,
      select: { id: true, status: true, tokenVersion: true, appRole: true, email: true }
    }) as any;

    if (!user) {
      return respondUnauthorized(res, 'User not found', 'USER_NOT_FOUND');
    }

    // Validar que el usuario pertenezca al tenant si hay tenant
    if (tenantId && (user as any).tenantId !== tenantId) {
      return respondForbidden(res, 'User does not belong to this tenant', 'TENANT_MISMATCH');
    }

    if (user.status !== 'active') {
      return respondForbidden(res, 'User account is inactive', 'USER_INACTIVE');
    }

    if (user.tokenVersion !== payload.tokenVersion) {
      return respondUnauthorized(res, 'Token version is invalid', 'TOKEN_VERSION_INVALID');
    }

    req.user = {
      userId: user.id,
      tokenVersion: user.tokenVersion,
      appRole: user.appRole,
      email: user.email
    };

    next();
  } catch (error) {
    console.error('Refresh middleware error:', error);
    res.status(401).json({ error: 'Invalid refresh token', code: 'INVALID_REFRESH_TOKEN' });
  }
};
