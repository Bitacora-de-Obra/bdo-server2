import jwt from 'jsonwebtoken';
import { User } from '@prisma/client';
import { secrets } from '../config/secrets';

interface JWTPayload {
  userId: string;
  email: string;
  appRole: string;
  projectRole: string;
}

export function generateTokens(user: User) {
  // Token de acceso - expira en 15 minutos
  const accessToken = jwt.sign(
    {
      userId: user.id,
      email: user.email,
      appRole: user.appRole,
      projectRole: user.projectRole,
    },
    secrets.jwt.access,
    { expiresIn: '15m' }
  );

  // Token de refresco - expira en 7 días
  const refreshToken = jwt.sign(
    {
      userId: user.id,
      tokenVersion: user.tokenVersion, // Para invalidar todos los tokens si es necesario
    },
    secrets.jwt.refresh,
    { expiresIn: '7d' }
  );

  return { accessToken, refreshToken };
}

export function verifyAccessToken(token: string): JWTPayload {
  try {
    const payload = jwt.verify(token, secrets.jwt.access) as JWTPayload;
    return payload;
  } catch (error) {
    console.error('Error al verificar token:', error);
    throw new Error('Token inválido');
  }
}

export function verifyRefreshToken(token: string): { userId: string; tokenVersion: number } {
  try {
    const payload = jwt.verify(token, secrets.jwt.refresh) as {
      userId: string;
      tokenVersion: number;
    };
    return payload;
  } catch (error) {
    throw new Error('Token de refresco inválido');
  }
}

export function generateEmailVerificationToken(userId: string): string {
  return jwt.sign({ userId }, secrets.jwt.legacy, { expiresIn: '24h' });
}

export function generatePasswordResetToken(userId: string): string {
  return jwt.sign({ userId }, secrets.jwt.legacy, { expiresIn: '1h' });
}

export function verifyEmailToken(token: string): { userId: string } {
  try {
    const payload = jwt.verify(token, secrets.jwt.legacy) as { userId: string };
    return payload;
  } catch (error) {
    throw new Error('Token de verificación de email inválido');
  }
}

export function verifyPasswordResetToken(token: string): { userId: string } {
  try {
    const payload = jwt.verify(token, secrets.jwt.legacy) as { userId: string };
    return payload;
  } catch (error) {
    throw new Error('Token de restablecimiento de contraseña inválido');
  }
}

