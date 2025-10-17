import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

// Extendemos la interfaz de Request de Express para incluir la propiedad `user`
export interface AuthRequest extends Request {
  user?: { userId: string };
}

/**
 * Middleware para verificar el token JWT en las rutas protegidas.
 */
export const authMiddleware = (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization'];
  
  // El token usualmente viene en el formato "Bearer <token>"
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    // 401 Unauthorized: No se proporcionó token
    return res.status(401).json({ error: 'Acceso denegado. No se proporcionó token.' });
  }

  try {
    // Verificamos el token con nuestra clave secreta
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as { userId: string };
    
    // Adjuntamos el payload decodificado (que contiene el userId) al objeto `req`
    req.user = { userId: decoded.userId };
    
    // Pasamos al siguiente middleware o controlador de la ruta
    next();
  } catch (error) {
    // 403 Forbidden: El token no es válido o ha expirado
    res.status(403).json({ error: 'Token inválido o expirado.' });
  }
};