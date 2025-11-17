import { Request } from 'express';
import { logger } from '../logger';
import { AuthRequest } from '../middleware/auth';

export type SecurityEventType =
  | 'LOGIN_FAILED'
  | 'LOGIN_SUCCESS'
  | 'LOGIN_BLOCKED'
  | 'ACCESS_DENIED'
  | 'RATE_LIMIT_EXCEEDED'
  | 'CSRF_TOKEN_INVALID'
  | 'FILE_UPLOAD_REJECTED'
  | 'UNAUTHORIZED_ACCESS_ATTEMPT'
  | 'SUSPICIOUS_ACTIVITY'
  | 'PASSWORD_CHANGE'
  | 'TOKEN_INVALID'
  | 'TOKEN_EXPIRED';

export interface SecurityEvent {
  type: SecurityEventType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  timestamp: Date;
  ipAddress?: string;
  userAgent?: string;
  userId?: string;
  email?: string;
  path?: string;
  method?: string;
  details?: Record<string, any>;
  metadata?: Record<string, any>;
}

// In-memory store para eventos de seguridad (en producción, usar Redis o DB)
const securityEvents: SecurityEvent[] = [];
const MAX_EVENTS = 10000; // Mantener últimos 10,000 eventos

// Contadores para detección de patrones
const failedLoginAttempts = new Map<string, { count: number; lastAttempt: Date }>();
const suspiciousIPs = new Map<string, { count: number; lastSeen: Date; events: SecurityEventType[] }>();

// Configuración
const BRUTE_FORCE_THRESHOLD = 5; // Intentos fallidos antes de alertar
const BRUTE_FORCE_WINDOW_MS = 15 * 60 * 1000; // 15 minutos
const SUSPICIOUS_ACTIVITY_THRESHOLD = 10; // Eventos sospechosos antes de alertar
const SUSPICIOUS_ACTIVITY_WINDOW_MS = 60 * 60 * 1000; // 1 hora

/**
 * Registra un evento de seguridad
 */
export const recordSecurityEvent = (
  type: SecurityEventType,
  severity: SecurityEvent['severity'],
  req: Request | AuthRequest,
  details?: Record<string, any>
): void => {
  const ipAddress = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
                    req.socket.remoteAddress ||
                    'unknown';
  const userAgent = req.headers['user-agent'] || 'unknown';
  const userId = (req as AuthRequest).user?.userId;
  const email = details?.email;

  const event: SecurityEvent = {
    type,
    severity,
    timestamp: new Date(),
    ipAddress,
    userAgent,
    userId,
    email,
    path: req.path,
    method: req.method,
    details,
    metadata: {
      origin: req.headers.origin,
      referer: req.headers.referer,
    },
  };

  // Agregar evento a la lista (FIFO)
  securityEvents.push(event);
  if (securityEvents.length > MAX_EVENTS) {
    securityEvents.shift(); // Remover el más antiguo
  }

  // Log del evento
  logger.warn('Security event recorded', {
    type,
    severity,
    ipAddress,
    userId,
    email,
    path: req.path,
    method: req.method,
  });

  // Detectar patrones sospechosos
  detectSuspiciousPatterns(event, ipAddress);

  // Alertar si es crítico
  if (severity === 'critical' || severity === 'high') {
    alertSecurityEvent(event);
  }
};

/**
 * Detecta patrones sospechosos de actividad
 */
const detectSuspiciousPatterns = (event: SecurityEvent, ipAddress: string): void => {
  // Detectar brute force attacks
  if (event.type === 'LOGIN_FAILED') {
    const now = new Date();
    const attempts = failedLoginAttempts.get(ipAddress) || { count: 0, lastAttempt: now };
    
    // Resetear contador si pasó la ventana de tiempo
    if (now.getTime() - attempts.lastAttempt.getTime() > BRUTE_FORCE_WINDOW_MS) {
      attempts.count = 0;
    }
    
    attempts.count++;
    attempts.lastAttempt = now;
    failedLoginAttempts.set(ipAddress, attempts);

    // Alertar si excede el umbral
    if (attempts.count >= BRUTE_FORCE_THRESHOLD) {
      recordSecurityEvent(
        'LOGIN_BLOCKED',
        'high',
        event as any,
        {
          reason: 'Brute force attack detected',
          failedAttempts: attempts.count,
          ipAddress,
        }
      );
    }
  }

  // Detectar actividad sospechosa general
  const suspiciousTypes: SecurityEventType[] = [
    'ACCESS_DENIED',
    'CSRF_TOKEN_INVALID',
    'FILE_UPLOAD_REJECTED',
    'UNAUTHORIZED_ACCESS_ATTEMPT',
  ];

  if (suspiciousTypes.includes(event.type)) {
    const now = new Date();
    const suspicious = suspiciousIPs.get(ipAddress) || {
      count: 0,
      lastSeen: now,
      events: [],
    };

    // Resetear contador si pasó la ventana de tiempo
    if (now.getTime() - suspicious.lastSeen.getTime() > SUSPICIOUS_ACTIVITY_WINDOW_MS) {
      suspicious.count = 0;
      suspicious.events = [];
    }

    suspicious.count++;
    suspicious.lastSeen = now;
    suspicious.events.push(event.type);
    suspiciousIPs.set(ipAddress, suspicious);

    // Alertar si excede el umbral
    if (suspicious.count >= SUSPICIOUS_ACTIVITY_THRESHOLD) {
      recordSecurityEvent(
        'SUSPICIOUS_ACTIVITY',
        'high',
        event as any,
        {
          reason: 'Multiple suspicious events from same IP',
          eventCount: suspicious.count,
          eventTypes: suspicious.events,
          ipAddress,
        }
      );
    }
  }
};

/**
 * Alerta sobre eventos de seguridad críticos
 */
const alertSecurityEvent = (event: SecurityEvent): void => {
  logger.error('SECURITY ALERT', {
    type: event.type,
    severity: event.severity,
    ipAddress: event.ipAddress,
    userId: event.userId,
    email: event.email,
    path: event.path,
    details: event.details,
    timestamp: event.timestamp.toISOString(),
  });

  // Aquí se podría integrar con sistemas de alertas externos:
  // - Enviar email a administradores
  // - Enviar notificación a Slack/Discord
  // - Integrar con sistemas de SIEM
  // - Etc.
};

/**
 * Obtiene eventos de seguridad filtrados
 */
export const getSecurityEvents = (filters?: {
  type?: SecurityEventType;
  severity?: SecurityEvent['severity'];
  ipAddress?: string;
  userId?: string;
  startDate?: Date;
  endDate?: Date;
  limit?: number;
}): SecurityEvent[] => {
  let filtered = [...securityEvents];

  if (filters?.type) {
    filtered = filtered.filter(e => e.type === filters.type);
  }

  if (filters?.severity) {
    filtered = filtered.filter(e => e.severity === filters.severity);
  }

  if (filters?.ipAddress) {
    filtered = filtered.filter(e => e.ipAddress === filters.ipAddress);
  }

  if (filters?.userId) {
    filtered = filtered.filter(e => e.userId === filters.userId);
  }

  if (filters?.startDate) {
    filtered = filtered.filter(e => e.timestamp >= filters.startDate!);
  }

  if (filters?.endDate) {
    filtered = filtered.filter(e => e.timestamp <= filters.endDate!);
  }

  // Ordenar por timestamp descendente (más recientes primero)
  filtered.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

  // Limitar resultados
  if (filters?.limit) {
    filtered = filtered.slice(0, filters.limit);
  }

  return filtered;
};

/**
 * Obtiene estadísticas de seguridad
 */
export const getSecurityStats = (): {
  totalEvents: number;
  eventsByType: Record<SecurityEventType, number>;
  eventsBySeverity: Record<SecurityEvent['severity'], number>;
  topIPs: Array<{ ip: string; count: number }>;
  recentCriticalEvents: number;
} => {
  const now = new Date();
  const last24Hours = new Date(now.getTime() - 24 * 60 * 60 * 1000);

  const eventsByType: Record<string, number> = {};
  const eventsBySeverity: Record<string, number> = {};
  const ipCounts: Record<string, number> = {};
  let recentCriticalEvents = 0;

  securityEvents.forEach(event => {
    // Contar por tipo
    eventsByType[event.type] = (eventsByType[event.type] || 0) + 1;

    // Contar por severidad
    eventsBySeverity[event.severity] = (eventsBySeverity[event.severity] || 0) + 1;

    // Contar por IP
    if (event.ipAddress) {
      ipCounts[event.ipAddress] = (ipCounts[event.ipAddress] || 0) + 1;
    }

    // Contar eventos críticos recientes
    if (event.severity === 'critical' && event.timestamp >= last24Hours) {
      recentCriticalEvents++;
    }
  });

  // Top IPs
  const topIPs = Object.entries(ipCounts)
    .map(([ip, count]) => ({ ip, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  return {
    totalEvents: securityEvents.length,
    eventsByType: eventsByType as Record<SecurityEventType, number>,
    eventsBySeverity: eventsBySeverity as Record<SecurityEvent['severity'], number>,
    topIPs,
    recentCriticalEvents,
  };
};

/**
 * Limpia eventos antiguos (ejecutar periódicamente)
 */
export const cleanupOldEvents = (maxAgeDays: number = 30): void => {
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - maxAgeDays);

  const initialLength = securityEvents.length;
  while (securityEvents.length > 0 && securityEvents[0].timestamp < cutoffDate) {
    securityEvents.shift();
  }

  const removed = initialLength - securityEvents.length;
  if (removed > 0) {
    logger.info(`Cleaned up ${removed} old security events`);
  }
};


