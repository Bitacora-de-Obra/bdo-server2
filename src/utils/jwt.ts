import jwt from 'jsonwebtoken';
import { User } from '@prisma/client';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'your-refresh-secret-key';

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
    JWT_SECRET,
    { expiresIn: '15m' }
  );

  // Token de refresco - expira en 7 días
  const refreshToken = jwt.sign(
    {
      userId: user.id,
      tokenVersion: user.tokenVersion, // Para invalidar todos los tokens si es necesario
    },
    JWT_REFRESH_SECRET,
    { expiresIn: '7d' }
  );

  return { accessToken, refreshToken };
}

export function verifyAccessToken(token: string): JWTPayload {
  try {
    console.log('Verificando token:', token);
    console.log('JWT_SECRET:', JWT_SECRET);
    const payload = jwt.verify(token, JWT_SECRET) as JWTPayload;
    console.log('Payload:', payload);
    return payload;
  } catch (error) {
    console.error('Error al verificar token:', error);
    throw new Error('Token inválido');
  }
}

export function verifyRefreshToken(token: string): { userId: string; tokenVersion: number } {
  try {
    const payload = jwt.verify(token, JWT_REFRESH_SECRET) as { userId: string; tokenVersion: number };
    return payload;
  } catch (error) {
    throw new Error('Token de refresco inválido');
  }
}

export function generateEmailVerificationToken(userId: string): string {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '24h' });
}

export function generatePasswordResetToken(userId: string): string {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '1h' });
}

export function verifyEmailToken(token: string): { userId: string } {
  try {
    const payload = jwt.verify(token, JWT_SECRET) as { userId: string };
    return payload;
  } catch (error) {
    throw new Error('Token de verificación de email inválido');
  }
}

export function verifyPasswordResetToken(token: string): { userId: string } {
  try {
    const payload = jwt.verify(token, JWT_SECRET) as { userId: string };
    return payload;
  } catch (error) {
    throw new Error('Token de restablecimiento de contraseña inválido');
  }
}

