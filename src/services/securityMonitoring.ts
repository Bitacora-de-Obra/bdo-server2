import { Request } from 'express';
import { Prisma } from '@prisma/client';
import prisma from '../prisma';
import { logger } from '../logger';
import { AuthRequest } from '../middleware/auth';
import { isEmailServiceConfigured, sendSecurityAlertEmail } from './email';

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
  | 'TOKEN_EXPIRED'
  | 'LOG_ENTRY_DELETED';

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

type RequestLike = Request | AuthRequest | SecurityEvent;

const isExpressRequest = (value: any): value is Request | AuthRequest =>
  Boolean(value && typeof value === 'object' && 'headers' in value && 'method' in value);

const resolveEventContext = (
  req: RequestLike,
  details?: Record<string, any>
): Pick<
  SecurityEvent,
  'ipAddress' | 'userAgent' | 'userId' | 'email' | 'path' | 'method' | 'metadata'
> => {
  if (isExpressRequest(req)) {
    const ipAddress =
      ((req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
        req.socket.remoteAddress ||
        'unknown');

    const userAgent = req.headers['user-agent'] || 'unknown';
    const userId = (req as AuthRequest).user?.userId;
    const email = details?.email;
    const path = req.path;
    const method = req.method;
    const metadata = {
      origin: req.headers.origin,
      referer: req.headers.referer,
    };

    return { ipAddress, userAgent, userId, email, path, method, metadata };
  }

  const fallbackEvent = req as SecurityEvent;
  return {
    ipAddress: fallbackEvent.ipAddress || 'unknown',
    userAgent: fallbackEvent.userAgent || 'unknown',
    userId: fallbackEvent.userId,
    email: fallbackEvent.email || details?.email,
    path: fallbackEvent.path,
    method: fallbackEvent.method,
    metadata: fallbackEvent.metadata,
  };
};

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
const DEFAULT_EVENT_LIMIT = 200;

const securityAlertRecipients =
  process.env.SECURITY_ALERT_EMAILS?.split(',')
    .map((email) => email.trim())
    .filter((email) => email.length > 0) || [];

const hasSecurityAlertRecipients = securityAlertRecipients.length > 0;
let securityAlertEmailWarningLogged = false;

/**
 * Registra un evento de seguridad
 */
export const recordSecurityEvent = (
  type: SecurityEventType,
  severity: SecurityEvent['severity'],
  req: Request | AuthRequest | SecurityEvent,
  details?: Record<string, any>
): void => {
  const context = resolveEventContext(req, details);

  const event: SecurityEvent = {
    type,
    severity,
    timestamp: new Date(),
    ...context,
    details,
  };

  // Agregar evento a la lista (FIFO)
  securityEvents.push(event);
  if (securityEvents.length > MAX_EVENTS) {
    securityEvents.shift(); // Remover el más antiguo
  }

  // Persistir en base de datos de forma asíncrona
  void persistSecurityEvent(event);

  // Log del evento
  logger.warn('Security event recorded', {
    type,
    severity,
    ipAddress: event.ipAddress,
    userId: event.userId,
    email: event.email,
    path: event.path,
    method: event.method,
  });

  // Detectar patrones sospechosos
  detectSuspiciousPatterns(event, event.ipAddress || 'unknown');

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
  dispatchSecurityAlertEmail(event);
};

/**
 * Obtiene eventos de seguridad filtrados
 */
type SecurityEventFilters = {
  type?: SecurityEventType;
  severity?: SecurityEvent['severity'];
  ipAddress?: string;
  userId?: string;
  startDate?: Date;
  endDate?: Date;
  limit?: number;
};

export const getSecurityEvents = async (
  filters?: SecurityEventFilters
): Promise<SecurityEvent[]> => {
  const limit = filters?.limit ?? DEFAULT_EVENT_LIMIT;

  try {
    const where = buildSecurityEventWhere(filters);
    const records = await prisma.securityEventLog.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      take: limit,
    });
    return records.map(mapRecordToEvent);
  } catch (error) {
    logger.error('Failed to fetch security events from database', {
      error: error instanceof Error ? error.message : String(error),
    });

    return filterInMemoryEvents(filters).slice(0, limit);
  }
};

/**
 * Obtiene estadísticas de seguridad
 */
export const getSecurityStats = async (): Promise<{
  totalEvents: number;
  eventsByType: Record<SecurityEventType, number>;
  eventsBySeverity: Record<SecurityEvent['severity'], number>;
  topIPs: Array<{ ip: string; count: number }>;
  recentCriticalEvents: number;
}> => {
  const now = new Date();
  const last24Hours = new Date(now.getTime() - 24 * 60 * 60 * 1000);

  try {
    const [totalEvents, eventsByTypeRows, eventsBySeverityRows, topIPsRows, recentCriticalEvents] =
      await Promise.all([
        prisma.securityEventLog.count(),
        prisma.securityEventLog.groupBy({
          by: ['type'],
          _count: { _all: true },
        }),
        prisma.securityEventLog.groupBy({
          by: ['severity'],
          _count: { _all: true },
        }),
        prisma.securityEventLog.groupBy({
          by: ['ipAddress'],
          where: { ipAddress: { not: null } },
          _count: { id: true },
          orderBy: { _count: { id: 'desc' } },
          take: 10,
        }),
        prisma.securityEventLog.count({
          where: {
            severity: 'critical',
            createdAt: { gte: last24Hours },
          },
        }),
      ]);

    const eventsByType = eventsByTypeRows.reduce<Record<SecurityEventType, number>>(
      (acc: any, row: any) => {
        const count = row._count?._all ?? 0;
        acc[row.type as SecurityEventType] = count;
        return acc;
      },
      {} as Record<SecurityEventType, number>
    );

    const eventsBySeverity = eventsBySeverityRows.reduce<
      Record<SecurityEvent['severity'], number>
    >((acc: any, row: any) => {
      const count = row._count?._all ?? 0;
      acc[row.severity as SecurityEvent['severity']] = count;
      return acc;
    }, {} as Record<SecurityEvent['severity'], number>);

    const topIPs = topIPsRows
      .filter((row: any) => row.ipAddress)
      .map((row: any) => ({
        ip: row.ipAddress as string,
        count: row._count.id ?? 0,
      }));

    return {
      totalEvents,
      eventsByType,
      eventsBySeverity,
      topIPs,
      recentCriticalEvents,
    };
  } catch (error) {
    logger.error('Failed to compute persisted security stats', {
      error: error instanceof Error ? error.message : String(error),
    });

    return calculateInMemoryStats(last24Hours);
  }
};

/**
 * Limpia eventos antiguos (ejecutar periódicamente)
 */
export const cleanupOldEvents = async (maxAgeDays: number = 30): Promise<void> => {
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

  try {
    const result = await prisma.securityEventLog.deleteMany({
      where: {
        createdAt: { lt: cutoffDate },
      },
    });

    if (result.count > 0) {
      logger.info(
        `Deleted ${result.count} persisted security events older than ${maxAgeDays} days`
      );
    }
  } catch (error) {
    logger.error('Failed to cleanup persisted security events', {
      error: error instanceof Error ? error.message : String(error),
    });
  }
};

const persistSecurityEvent = async (event: SecurityEvent): Promise<void> => {
  try {
    await prisma.securityEventLog.create({
      data: {
        type: event.type,
        severity: event.severity,
        ipAddress: event.ipAddress,
        userAgent: event.userAgent,
        userId: event.userId,
        email: event.email,
        path: event.path,
        method: event.method,
        details: event.details ? (event.details as Prisma.InputJsonValue) : undefined,
        metadata: event.metadata ? (event.metadata as Prisma.InputJsonValue) : undefined,
        createdAt: event.timestamp,
      },
    });
  } catch (error) {
    logger.error('Failed to persist security event', {
      error: error instanceof Error ? error.message : String(error),
    });
  }
};

const mapRecordToEvent = (record: any): SecurityEvent => ({
  type: record.type as SecurityEventType,
  severity: record.severity as SecurityEvent['severity'],
  timestamp: record.createdAt,
  ipAddress: record.ipAddress || undefined,
  userAgent: record.userAgent || undefined,
  userId: record.userId || undefined,
  email: record.email || undefined,
  path: record.path || undefined,
  method: record.method || undefined,
  details: (record.details as Record<string, any> | null) || undefined,
  metadata: (record.metadata as Record<string, any> | null) || undefined,
});

const buildSecurityEventWhere = (
  filters?: SecurityEventFilters
): any => {
  if (!filters) {
    return {};
  }

  const where: any = {};

  if (filters.type) {
    where.type = filters.type;
  }

  if (filters.severity) {
    where.severity = filters.severity;
  }

  if (filters.ipAddress) {
    where.ipAddress = filters.ipAddress;
  }

  if (filters.userId) {
    where.userId = filters.userId;
  }

  if (filters.startDate || filters.endDate) {
    where.createdAt = {};
    if (filters.startDate) {
      where.createdAt.gte = filters.startDate;
    }
    if (filters.endDate) {
      where.createdAt.lte = filters.endDate;
    }
  }

  return where;
};

const filterInMemoryEvents = (filters?: SecurityEventFilters): SecurityEvent[] => {
  let filtered = [...securityEvents];

  if (filters?.type) {
    filtered = filtered.filter((e) => e.type === filters.type);
  }

  if (filters?.severity) {
    filtered = filtered.filter((e) => e.severity === filters.severity);
  }

  if (filters?.ipAddress) {
    filtered = filtered.filter((e) => e.ipAddress === filters.ipAddress);
  }

  if (filters?.userId) {
    filtered = filtered.filter((e) => e.userId === filters.userId);
  }

  if (filters?.startDate) {
    filtered = filtered.filter((e) => e.timestamp >= filters.startDate!);
  }

  if (filters?.endDate) {
    filtered = filtered.filter((e) => e.timestamp <= filters.endDate!);
  }

  filtered.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  return filtered;
};

const calculateInMemoryStats = (last24Hours: Date) => {
  const eventsByType: Record<string, number> = {};
  const eventsBySeverity: Record<string, number> = {};
  const ipCounts: Record<string, number> = {};
  let recentCriticalEvents = 0;

  securityEvents.forEach((event) => {
    eventsByType[event.type] = (eventsByType[event.type] || 0) + 1;
    eventsBySeverity[event.severity] = (eventsBySeverity[event.severity] || 0) + 1;

    if (event.ipAddress) {
      ipCounts[event.ipAddress] = (ipCounts[event.ipAddress] || 0) + 1;
    }

    if (event.severity === 'critical' && event.timestamp >= last24Hours) {
      recentCriticalEvents++;
    }
  });

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

const dispatchSecurityAlertEmail = (event: SecurityEvent): void => {
  if (!hasSecurityAlertRecipients) {
    return;
  }

  if (!isEmailServiceConfigured()) {
    if (!securityAlertEmailWarningLogged) {
      logger.warn(
        'SECURITY_ALERT_EMAILS está configurado pero el servicio SMTP no está disponible.'
      );
      securityAlertEmailWarningLogged = true;
    }
    return;
  }

  void sendSecurityAlertEmail({
    to: securityAlertRecipients,
    event,
  }).catch((error) => {
    logger.error('Failed to send security alert email', {
      error: error instanceof Error ? error.message : String(error),
    });
  });
};


