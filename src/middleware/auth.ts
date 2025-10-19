// En bdo-server/src/middleware/auth.ts

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

export interface AuthRequest extends Request {
  user?: { userId: string };
}

export const authMiddleware = (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];


  if (!token) {
    console.log('Auth Middleware: No token provided.'); // Log si no hay token
    return res.status(401).json({ error: 'Acceso denegado. No se proporcionó token.' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as { userId: string };
    req.user = { userId: decoded.userId };
    next();
  } catch (error: any) { // Captura el error específico
    // --- LOGS DE ERROR DETALLADOS ---
    console.error('Auth Middleware: Token verification FAILED.');
    console.error('Error Name:', error.name); // Ej: TokenExpiredError, JsonWebTokenError
    console.error('Error Message:', error.message); // Ej: jwt expired, invalid signature
    // console.error('Error completo:', error); // Descomenta si necesitas más detalle
    // --------------------------------

    res.status(403).json({ error: 'Token inválido o expirado.' }); // Mantenemos el mensaje genérico al frontend
  }
};