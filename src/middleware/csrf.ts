import { Request, Response, NextFunction } from 'express';
import { randomBytes, createHash } from 'crypto';
import { logger } from '../logger';
import { AuthRequest } from './auth';
import { recordSecurityEvent } from '../services/securityMonitoring';

const CSRF_COOKIE_NAME = 'XSRF-TOKEN';
const CSRF_HEADER_NAME = 'X-XSRF-TOKEN';
const CSRF_TOKEN_LENGTH = 32; // 32 bytes = 64 hex characters

/**
 * Genera un token CSRF aleatorio
 */
export const generateCsrfToken = (): string => {
  return randomBytes(CSRF_TOKEN_LENGTH).toString('hex');
};

/**
 * Middleware para generar y enviar token CSRF en cookie
 * Solo para rutas GET que no requieren autenticación
 */
export const csrfTokenMiddleware = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  // Solo generar token para métodos GET
  if (req.method === 'GET') {
    const token = generateCsrfToken();
    
    // Configurar cookie CSRF
    const isProduction = process.env.NODE_ENV === 'production';
    const secureCookie = process.env.COOKIE_SECURE === 'true' || isProduction;
    const sameSite = secureCookie ? 'none' : 'lax';
    
    res.cookie(CSRF_COOKIE_NAME, token, {
      httpOnly: false, // Debe ser accesible desde JavaScript para enviarlo en header
      secure: secureCookie,
      sameSite: sameSite as 'strict' | 'lax' | 'none',
      path: '/',
      maxAge: 24 * 60 * 60 * 1000, // 24 horas
    });
    
    // También enviar en header para facilitar acceso desde frontend
    res.setHeader('X-CSRF-Token', token);
  }
  
  next();
};

/**
 * Middleware para verificar token CSRF en requests modificadores
 * Solo aplica a métodos POST, PUT, PATCH, DELETE
 */
export const csrfProtection = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  // Solo verificar en métodos que modifican datos
  const modifyingMethods = ['POST', 'PUT', 'PATCH', 'DELETE'];
  if (!modifyingMethods.includes(req.method)) {
    return next();
  }

  // Excluir rutas que no necesitan CSRF (APIs públicas, webhooks, etc.)
  const excludedPaths = [
    '/api/auth/login',
    '/api/auth/register',
    '/api/auth/refresh',
    '/api/public/',
    '/api/docs',
    '/api/swagger',
  ];

  const isExcluded = excludedPaths.some(path => req.path.startsWith(path));
  if (isExcluded) {
    return next();
  }

  // Para APIs REST que usan JWT en headers (no cookies), CSRF es menos crítico
  // pero aún verificamos si hay cookie CSRF presente
  // Si no hay cookie CSRF, asumimos que es una API pura con JWT y permitimos
  const cookieToken = req.cookies?.[CSRF_COOKIE_NAME];
  
  // Si no hay cookie CSRF, permitir (puede ser una API pura con JWT)
  // Esto permite que APIs REST funcionen sin CSRF mientras protegemos contra CSRF cuando hay cookies
  if (!cookieToken) {
    // Log para monitoreo pero permitir la request
    logger.debug('CSRF cookie not present, allowing request (may be pure JWT API)', {
      path: req.path,
      method: req.method,
    });
    return next();
  }

  // Obtener token de header
  const headerToken = req.headers[CSRF_HEADER_NAME.toLowerCase()] as string;

  // Verificar que el token del header exista
  if (!headerToken) {
    logger.warn('CSRF token missing in header', {
      path: req.path,
      method: req.method,
      hasHeaderToken: !!headerToken,
      userId: (req as AuthRequest).user?.userId,
    });

    return res.status(403).json({
      error: 'Token CSRF faltante o inválido',
      code: 'CSRF_TOKEN_MISSING',
    });
  }

  // Comparar tokens de forma segura (timing-safe comparison)
  const cookieTokenBuffer = Buffer.from(cookieToken, 'hex');
  const headerTokenBuffer = Buffer.from(headerToken, 'hex');

  if (cookieTokenBuffer.length !== headerTokenBuffer.length) {
    logger.warn('CSRF token length mismatch', {
      path: req.path,
      method: req.method,
      userId: (req as AuthRequest).user?.userId,
    });

    return res.status(403).json({
      error: 'Token CSRF inválido',
      code: 'CSRF_TOKEN_INVALID',
    });
  }

  // Timing-safe comparison para prevenir timing attacks
  let isValid = true;
  for (let i = 0; i < cookieTokenBuffer.length; i++) {
    if (cookieTokenBuffer[i] !== headerTokenBuffer[i]) {
      isValid = false;
    }
  }

  if (!isValid) {
    logger.warn('CSRF token mismatch', {
      path: req.path,
      method: req.method,
      userId: (req as AuthRequest).user?.userId,
    });

    recordSecurityEvent('CSRF_TOKEN_INVALID', 'high', req, {
      userId: (req as AuthRequest).user?.userId,
    });

    return res.status(403).json({
      error: 'Token CSRF inválido',
      code: 'CSRF_TOKEN_INVALID',
    });
  }

  // Token válido, continuar
  next();
};

/**
 * Helper para obtener el token CSRF actual (para endpoints que lo necesiten)
 */
export const getCsrfToken = (req: Request): string | null => {
  return req.cookies?.[CSRF_COOKIE_NAME] || null;
};

