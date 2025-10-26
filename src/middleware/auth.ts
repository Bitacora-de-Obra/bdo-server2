import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export interface AuthRequest extends Request {
  user?: {
    userId: string;
    tokenVersion: number;
    appRole?: string;
  };
}

export const createAccessToken = (userId: string, tokenVersion: number): string => {
  return jwt.sign(
    { userId, tokenVersion },
    process.env.JWT_SECRET!,
    { expiresIn: '15m' }
  );
};

export const createRefreshToken = (userId: string, tokenVersion: number): string => {
  return jwt.sign(
    { userId, tokenVersion },
    process.env.JWT_SECRET!, // Usamos el mismo secreto por ahora
    { expiresIn: '7d' }
  );
};

export const authMiddleware = async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'Invalid token format' });
    }

    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET!) as any;
      
      const user = await prisma.user.findUnique({
        where: { id: payload.userId },
        select: { id: true, status: true, tokenVersion: true, appRole: true }
      });

      if (!user) {
        return res.status(401).json({ error: 'User not found' });
      }

      if (user.status !== 'active') {
        return res.status(403).json({ error: 'User account is inactive' });
      }

      if (user.tokenVersion !== payload.tokenVersion) {
        return res.status(401).json({ error: 'Token version is invalid' });
      }

      req.user = {
        userId: user.id,
        tokenVersion: user.tokenVersion,
        appRole: user.appRole
      };

      next();
    } catch (err) {
      if (err instanceof jwt.TokenExpiredError) {
        return res.status(401).json({ 
          error: 'Token expired',
          code: 'TOKEN_EXPIRED'
        });
      }
      throw err;
    }
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(401).json({ error: 'Invalid token' });
  }
};

export const refreshAuthMiddleware = async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const refreshToken = req.cookies.jid;
    if (!refreshToken) {
      return res.status(401).json({ error: 'No refresh token' });
    }

    const payload = jwt.verify(refreshToken, process.env.JWT_SECRET!) as any;
    
    const user = await prisma.user.findUnique({
      where: { id: payload.userId },
      select: { id: true, status: true, tokenVersion: true, appRole: true }
    });

    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    if (user.status !== 'active') {
      return res.status(403).json({ error: 'User account is inactive' });
    }

    if (user.tokenVersion !== payload.tokenVersion) {
      return res.status(401).json({ error: 'Token version is invalid' });
    }

    req.user = {
      userId: user.id,
      tokenVersion: user.tokenVersion,
      appRole: user.appRole
    };

    next();
  } catch (error) {
    console.error('Refresh middleware error:', error);
    res.status(401).json({ error: 'Invalid refresh token' });
  }
};