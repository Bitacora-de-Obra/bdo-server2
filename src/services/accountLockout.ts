import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

// Configuración de account lockout
const MAX_FAILED_ATTEMPTS = 5; // Intentos fallidos antes de bloquear
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutos
const RESET_WINDOW_MS = 15 * 60 * 1000; // Ventana de tiempo para contar intentos

// Almacenamiento en memoria de intentos fallidos por usuario
// En producción, considerar usar Redis para persistencia entre reinicios
interface FailedAttempt {
  count: number;
  firstAttempt: Date;
  lastAttempt: Date;
  lockedUntil?: Date;
}

const failedAttempts = new Map<string, FailedAttempt>();

/**
 * Verifica si una cuenta está bloqueada
 */
export const isAccountLocked = (userId: string): { locked: boolean; lockedUntil?: Date } => {
  const attempts = failedAttempts.get(userId);
  
  if (!attempts) {
    return { locked: false };
  }

  // Si hay un bloqueo temporal y aún no ha expirado
  if (attempts.lockedUntil && attempts.lockedUntil > new Date()) {
    return { locked: true, lockedUntil: attempts.lockedUntil };
  }

  // Si el bloqueo expiró, limpiar
  if (attempts.lockedUntil && attempts.lockedUntil <= new Date()) {
    failedAttempts.delete(userId);
    return { locked: false };
  }

  return { locked: false };
};

/**
 * Registra un intento fallido de login
 */
export const recordFailedAttempt = (userId: string): { locked: boolean; lockedUntil?: Date; attemptsRemaining: number } => {
  const now = new Date();
  const attempts = failedAttempts.get(userId) || {
    count: 0,
    firstAttempt: now,
    lastAttempt: now,
  };

  // Si la ventana de tiempo expiró, resetear contador
  if (now.getTime() - attempts.firstAttempt.getTime() > RESET_WINDOW_MS) {
    attempts.count = 0;
    attempts.firstAttempt = now;
  }

  attempts.count++;
  attempts.lastAttempt = now;

  // Si se alcanzó el límite, bloquear la cuenta
  if (attempts.count >= MAX_FAILED_ATTEMPTS) {
    attempts.lockedUntil = new Date(now.getTime() + LOCKOUT_DURATION_MS);
    failedAttempts.set(userId, attempts);
    return {
      locked: true,
      lockedUntil: attempts.lockedUntil,
      attemptsRemaining: 0,
    };
  }

  failedAttempts.set(userId, attempts);
  return {
    locked: false,
    attemptsRemaining: MAX_FAILED_ATTEMPTS - attempts.count,
  };
};

/**
 * Limpia los intentos fallidos después de un login exitoso
 */
export const clearFailedAttempts = (userId: string): void => {
  failedAttempts.delete(userId);
};

/**
 * Obtiene el número de intentos fallidos restantes antes del bloqueo
 */
export const getRemainingAttempts = (userId: string): number => {
  const attempts = failedAttempts.get(userId);
  if (!attempts) {
    return MAX_FAILED_ATTEMPTS;
  }
  return Math.max(0, MAX_FAILED_ATTEMPTS - attempts.count);
};



