import express, {
  CookieOptions,
  NextFunction,
  Request,
  Response,
} from "express";
import cors from "cors";
import type { CorsOptions } from "cors";
import OpenAI from "openai";
import cookieParser from "cookie-parser";
import fs from "fs";
import mime from "mime-types";
import {
  PrismaClient,
  Prisma,
  UserRole,
  AppRole,
  WorkActaStatus,
  CostActaStatus,
  ReportStatus,
  ReportScope,
  ProjectTask,
  CommitmentStatus,
  ModificationType,
  ChatbotFeedbackRating,
} from "@prisma/client";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import "dotenv/config";
import multer from "multer";
import { randomUUID, randomBytes, createHash } from "crypto";
import {
  encryptSignature,
  decryptSignature,
  packEncryptedSignature,
  unpackEncryptedSignature,
  verifySignaturePassword,
} from "./utils/signatureEncryption";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cron from "node-cron";
import swaggerUi from "swagger-ui-express";
import path from "path";
import * as zlib from "zlib";
import {
  authMiddleware,
  refreshAuthMiddleware,
  createAccessToken,
  createRefreshToken,
  AuthRequest,
} from "./middleware/auth";
import { generateWeeklyReportExcel } from "./services/reports/weeklyExcelGenerator";
import { generateReportPdf } from "./services/reports/pdfExport";
import { generateLogEntryPdf } from "./services/logEntries/pdfExport";
import { applySignatureToPdf } from "./services/documents/pdfSigner";
import {
  validateCronogramaXml,
  CronogramaValidationError,
} from "./utils/xmlValidator";
import { logger } from "./logger";
import { secretDiagnostics } from "./config/secrets";
import fsPromises from "fs/promises";
import { sha256 } from "./utils/hash";
import { JsonValue } from "./types/json";
import { validate } from "./middleware/validation";
import { changePasswordSchema } from "./validators/userSchemas";
import { requireLogEntryAccess, verifyLogEntryAccess } from "./middleware/resourcePermissions";
import { validateUploadedFiles } from "./middleware/fileValidationMiddleware";
import { getStorage } from "./storage";
import { csrfTokenMiddleware, csrfProtection } from "./middleware/csrf";
import { recordSecurityEvent, getSecurityEvents, getSecurityStats, cleanupOldEvents } from "./services/securityMonitoring";
import { isAccountLocked, recordFailedAttempt, clearFailedAttempts, getRemainingAttempts } from "./services/accountLockout";
import { validatePasswordStrength as validatePasswordStrengthUtil, PasswordValidationResult } from "./utils/passwordValidation";

type JsonObject = { [Key in string]: JsonValue };

// Importamos los mapas desde el nuevo archivo de utilidades
import {
  actaAreaMap,
  actaStatusMap,
  entryTypeMap,
  entryStatusMap,
  deliveryMethodMap,
  drawingDisciplineMap,
  workActaStatusMap,
  costActaStatusMap,
  reportScopeMap,
  reportStatusMap,
  commitmentStatusMap,
  communicationStatusMap,
  communicationDirectionMap,
  modificationTypeMap,
  roleMap,
} from "./utils/enum-maps";
import {
  normalizeListItems,
  normalizePersonnelEntries,
  normalizeEquipmentEntries,
  normalizeWeatherReport,
} from "./utils/logEntryNormalization";
import {
  sendEmailVerificationEmail,
  sendPasswordResetEmail,
  sendCommitmentReminderEmail,
  isEmailServiceConfigured,
  sendCommunicationAssignmentEmail,
  sendSignatureAssignmentEmail,
  sendTestEmail,
} from "./services/email";
import { buildUserNotifications } from "./services/notifications";
import {
  ChatbotContextSection,
  sectionToText,
  selectRelevantSections,
} from "./services/chatbot/contextUtils";
// El middleware de autenticación ya está importado arriba
const app = express();
const prisma = new PrismaClient();

/**
 * Helper para agregar filtro de tenant a queries
 * Retorna un objeto where que incluye tenantId si hay tenant en el request
 */
function withTenantFilter<T extends { tenantId?: string }>(
  req: Request,
  baseWhere?: T
): T & { tenantId?: string } {
  const tenantId = (req as any).tenant?.id;
  if (!tenantId) {
    return baseWhere || ({} as T);
  }
  return {
    ...baseWhere,
    tenantId,
  } as T & { tenantId?: string };
}

logger.info("Secrets cargados", {
  jwt: {
    access: secretDiagnostics.jwt.access.source,
    refresh: secretDiagnostics.jwt.refresh.source,
    legacy: secretDiagnostics.jwt.legacy.source,
  },
});
const port = 4001;
const isProduction = process.env.NODE_ENV === "production";

const COMETCHAT_APP_ID = process.env.COMETCHAT_APP_ID;
const COMETCHAT_REGION = process.env.COMETCHAT_REGION;
const COMETCHAT_API_KEY = process.env.COMETCHAT_API_KEY;

const getCometChatBaseUrl = () => {
  if (!COMETCHAT_APP_ID || !COMETCHAT_REGION) {
    return null;
  }
  return `https://${COMETCHAT_APP_ID}.api-${COMETCHAT_REGION}.cometchat.io/v3`;
};

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

if (process.env.TRUST_PROXY === "true" || isProduction) {
  app.set("trust proxy", 1);
}

const reverseMap = (map: Record<string, string>) => {
  const reversed: Record<string, string> = {};
  Object.entries(map).forEach(([key, value]) => {
    reversed[value] = key;
  });
  return reversed;
};

const entryTypeReverseMap = reverseMap(entryTypeMap);
const entryStatusReverseMap = reverseMap(entryStatusMap);
const actaAreaReverseMap = reverseMap(actaAreaMap);
const actaStatusReverseMap = reverseMap(actaStatusMap);
const commitmentStatusReverseMap = reverseMap(commitmentStatusMap);
const workActaStatusReverseMap = reverseMap(workActaStatusMap);
const costActaStatusReverseMap = reverseMap(costActaStatusMap);
const reportStatusReverseMap = reverseMap(reportStatusMap);
const reportScopeReverseMap = reverseMap(reportScopeMap);
const deliveryMethodReverseMap = reverseMap(deliveryMethodMap);
const communicationStatusReverseMap = reverseMap(communicationStatusMap);
const communicationDirectionReverseMap = reverseMap(communicationDirectionMap);
const modificationTypeReverseMap = reverseMap(modificationTypeMap);
const roleReverseMap = reverseMap(roleMap);

const DEFAULT_APP_SETTINGS = {
  companyName: "IDU",
  timezone: "America/Bogota",
  locale: "es-ES",
  requireStrongPassword: true,
  enable2FA: false,
  sessionTimeoutMinutes: 60,
  photoIntervalDays: 3,
  defaultProjectVisibility: "private",
};

const MODEL_COST_PER_K_TOKENS: Record<string, number> = {
  "gpt-4o-mini": 0.15,
  "gpt-4o": 0.06,
  "gpt-4.1-mini": 0.14,
  "gpt-3.5-turbo": 0.002,
};

const REFRESH_TOKEN_MAX_AGE = 7 * 24 * 60 * 60 * 1000; // 7 días
const REFRESH_COOKIE_PATH = "/api/auth/refresh";

const buildRefreshCookieOptions = (
  overrides: Partial<CookieOptions> = {},
  includeMaxAge = true
): CookieOptions => {
  const secureCookie = process.env.COOKIE_SECURE === "true" || isProduction;

  const requestedSameSite = process.env.COOKIE_SAMESITE?.toLowerCase();
  const defaultSameSite = secureCookie ? "none" : "lax";
  const sameSiteValue = (
    requestedSameSite === "strict" ||
    requestedSameSite === "lax" ||
    requestedSameSite === "none"
      ? requestedSameSite
      : defaultSameSite
  ) as CookieOptions["sameSite"];

  const baseOptions: CookieOptions = {
    httpOnly: true,
    secure: secureCookie,
    sameSite: sameSiteValue,
    path: REFRESH_COOKIE_PATH,
  };

  if (includeMaxAge) {
    baseOptions.maxAge = REFRESH_TOKEN_MAX_AGE;
  }

  const cookieDomain = process.env.COOKIE_DOMAIN?.trim();
  if (cookieDomain) {
    baseOptions.domain = cookieDomain;
  }

  return { ...baseOptions, ...overrides };
};

const loginRateLimiter = rateLimit({
  windowMs: Number(process.env.LOGIN_RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000),
  max: Number(process.env.LOGIN_RATE_LIMIT_MAX || 10),
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req: Request, res: Response) => {
    res.status(429).json({
      error:
        "Demasiados intentos de inicio de sesión. Inténtalo nuevamente en unos minutos.",
      code: "RATE_LIMIT",
    });
  },
});

const refreshRateLimiter = rateLimit({
  windowMs: Number(process.env.REFRESH_RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000),
  max: Number(process.env.REFRESH_RATE_LIMIT_MAX || 30),
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req: Request, res: Response) => {
    res.status(429).json({
      error:
        "Demasiadas solicitudes de renovación de sesión. Inténtalo nuevamente en unos minutos.",
      code: "RATE_LIMIT",
    });
  },
});

// Rate limiter global para todas las rutas API
const apiRateLimiter = rateLimit({
  windowMs: Number(process.env.API_RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000), // 15 minutos
  max: Number(process.env.API_RATE_LIMIT_MAX || 100), // 100 requests por ventana
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req: Request) => {
    // No aplicar rate limiting a rutas de autenticación (ya tienen su propio limiter)
    return req.path.startsWith('/api/auth/login') || 
           req.path.startsWith('/api/auth/refresh') ||
           req.path.startsWith('/api/docs');
  },
  handler: (req: Request, res: Response) => {
    recordSecurityEvent('RATE_LIMIT_EXCEEDED', 'medium', req, {
      path: req.path,
      method: req.method,
    });
    res.status(429).json({
      error: "Demasiadas solicitudes. Inténtalo nuevamente en unos minutos.",
      code: "RATE_LIMIT",
    });
  },
});

const generateTemporaryPassword = () => {
  const randomPart = randomBytes(4).toString("hex").toUpperCase();
  return `Temp-${randomPart}`;
};

const EMAIL_VERIFICATION_TOKEN_TTL_HOURS = Number(
  process.env.EMAIL_VERIFICATION_TOKEN_TTL_HOURS || 48
);
const PASSWORD_RESET_TOKEN_TTL_MINUTES = Number(
  process.env.PASSWORD_RESET_TOKEN_TTL_MINUTES || 60
);

const generateTokenValue = () => randomBytes(32).toString("hex");
const hashToken = (token: string) =>
  createHash("sha256").update(token).digest("hex");

// Función mejorada de validación de contraseñas con soporte para configuración de app
const validatePasswordStrength = async (password: string): Promise<string | null> => {
  const settings = await prisma.appSetting.findFirst();
  const requireStrong =
    settings?.requireStrongPassword ??
    DEFAULT_APP_SETTINGS.requireStrongPassword;

  // Si no se requiere contraseña fuerte, solo validar longitud mínima
  if (!requireStrong) {
    const minimumLength = 6;
    if (!password || password.length < minimumLength) {
      return `La contraseña debe tener al menos ${minimumLength} caracteres.`;
    }
    return null;
  }

  // Si se requiere contraseña fuerte, usar validación completa
  const validation = validatePasswordStrengthUtil(password);
  if (!validation.isValid) {
    // Retornar el primer error para compatibilidad con código existente
    return validation.errors[0] || "La contraseña no cumple con los requisitos de seguridad.";
  }

  return null;
};

const requireAdmin = (req: AuthRequest, res: Response, next: NextFunction) => {
  if (req.user?.appRole !== "admin") {
    recordSecurityEvent('ACCESS_DENIED', 'high', req, {
      reason: 'Admin access required',
      userRole: req.user?.appRole,
      path: req.path,
      method: req.method,
    });
    return res
      .status(403)
      .json({ error: "Acceso restringido a administradores." });
  }
  return next();
};

const requireEditor = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  if (!req.user) {
    recordSecurityEvent('UNAUTHORIZED_ACCESS_ATTEMPT', 'medium', req, {
      reason: 'User not authenticated',
      path: req.path,
      method: req.method,
    });
    return res.status(401).json({ error: "Usuario no autenticado." });
  }

  if (req.user.appRole === "viewer") {
    recordSecurityEvent('ACCESS_DENIED', 'medium', req, {
      reason: 'Editor access required',
      userRole: req.user.appRole,
      path: req.path,
      method: req.method,
    });
    return res.status(403).json({
      error: "Acceso restringido a editores y administradores.",
    });
  }

  return next();
};

const ensureAppSettings = async () => {
  try {
    let settings = await prisma.appSetting.findFirst();
    if (!settings) {
      settings = await prisma.appSetting.create({
        data: { ...DEFAULT_APP_SETTINGS },
      });
    }
    return settings;
  } catch (error) {
    if (
      error instanceof Prisma.PrismaClientKnownRequestError &&
      error.code === "P2021"
    ) {
      console.warn(
        "La tabla AppSetting no existe todavía. Ejecuta las migraciones (npx prisma migrate deploy) para crearla."
      );
      return null;
    }
    throw error;
  }
};

const formatAppSettings = (settings: any) => ({
  companyName: settings.companyName,
  timezone: settings.timezone,
  locale: settings.locale,
  requireStrongPassword: settings.requireStrongPassword,
  enable2FA: settings.enable2FA,
  sessionTimeoutMinutes: settings.sessionTimeoutMinutes,
  photoIntervalDays: settings.photoIntervalDays,
  defaultProjectVisibility: settings.defaultProjectVisibility,
});

const formatAdminUser = (user: any) => {
  // Determinar el rol basado en la entidad: IDU, Interventoría, Contratista
  let displayRole = roleReverseMap[user.projectRole] || user.projectRole;
  if (user.entity) {
    if (user.entity === 'IDU') {
      displayRole = 'IDU';
    } else if (user.entity === 'INTERVENTORIA') {
      displayRole = 'Interventoría';
    } else if (user.entity === 'CONTRATISTA') {
      displayRole = 'Contratista';
    }
  }
  
  return {
    id: user.id,
    fullName: user.fullName,
    email: user.email,
    projectRole: displayRole,
    appRole: user.appRole,
    entity: user.entity || null,
    cargo: user.cargo || null,
    avatarUrl: user.avatarUrl,
    status: user.status,
    canDownload: user.canDownload ?? true,
    lastLoginAt:
      user.lastLoginAt instanceof Date
        ? user.lastLoginAt.toISOString()
        : user.lastLoginAt,
  };
};

const createDiff = (
  before: Record<string, any>,
  after: Record<string, any>,
  fields: string[]
) => {
  const diff: Record<string, { from: any; to: any }> = {};
  fields.forEach((field) => {
    const beforeValue =
      before[field] instanceof Date
        ? (before[field] as Date).toISOString()
        : before[field];
    const afterValue =
      after[field] instanceof Date
        ? (after[field] as Date).toISOString()
        : after[field];
    if (JSON.stringify(beforeValue) !== JSON.stringify(afterValue)) {
      diff[field] = { from: beforeValue, to: afterValue };
    }
  });
  return diff;
};

const resolveActorInfo = async (req: AuthRequest) => {
  if (!req.user?.userId) {
    return { actorId: undefined, actorEmail: null };
  }
  if (req.user.email) {
    return { actorId: req.user.userId, actorEmail: req.user.email };
  }
  const actor = await prisma.user.findUnique({
    where: { id: req.user.userId },
    select: { email: true },
  });
  return { actorId: req.user.userId, actorEmail: actor?.email ?? null };
};

const recordAuditEvent = async ({
  action,
  entityType,
  entityId,
  diff,
  actorId,
  actorEmail,
}: {
  action: string;
  entityType: string;
  entityId?: string | null;
  diff?: Record<string, { from: any; to: any }>;
  actorId?: string;
  actorEmail?: string | null;
}) => {
  try {
    await prisma.auditLog.create({
      data: {
        action,
        entityType,
        entityId: entityId ?? null,
        diff:
          diff && Object.keys(diff).length > 0
            ? (diff as Prisma.InputJsonValue)
            : undefined,
        actorId: actorId ?? null,
        actorEmail: actorEmail ?? null,
      },
    });
  } catch (error) {
    console.error("Error registrando auditoría:", error);
  }
};

const scheduleDailyCommitmentReminder = () => {
  const cronExpression = process.env.COMMITMENT_REMINDER_CRON || "0 6 * * *";
  const timezone = process.env.REMINDER_TIMEZONE || "America/Bogota";
  const rawDaysAhead = Number(process.env.COMMITMENT_REMINDER_DAYS_AHEAD || 2);
  const daysAheadConfig = Number.isNaN(rawDaysAhead) ? 2 : rawDaysAhead;
  const msPerDay = 24 * 60 * 60 * 1000;

  cron.schedule(
    cronExpression,
    async () => {
      const now = new Date();
      const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
      const target = new Date(today);
      target.setDate(target.getDate() + daysAheadConfig);

      try {
        const upcoming = await prisma.commitment.findMany({
          where: {
            dueDate: {
              gte: today,
              lte: target,
            },
            status: "PENDING",
          },
          include: {
            acta: true,
            responsible: true,
          },
        });

        if (!upcoming.length) {
          logger.debug("ReminderJob: sin compromisos próximos.");
          return;
        }

        const recipients = new Map<
          string,
          {
            name?: string | null;
            commitments: {
              id: string;
              description: string;
              dueDate: Date;
              actaNumber?: string | null;
              actaTitle?: string | null;
              daysUntilDue: number;
            }[];
          }
        >();

        upcoming.forEach((commitment) => {
          logger.info("ReminderJob compromiso próximo", {
            commitmentId: commitment.id,
            description: commitment.description,
            dueDate: commitment.dueDate,
            responsible: commitment.responsible?.email,
          });

          const email = commitment.responsible?.email?.trim().toLowerCase();
          if (!email) {
            logger.warn("ReminderJob: compromiso sin correo de responsable", {
              commitmentId: commitment.id,
              responsibleId: commitment.responsible?.id,
            });
            return;
          }

          const dueDate = new Date(commitment.dueDate);
          const dueDateNormalized = new Date(dueDate);
          dueDateNormalized.setHours(0, 0, 0, 0);
          const daysUntilDue = Math.round(
            (dueDateNormalized.getTime() - today.getTime()) / msPerDay
          );

          const entry = recipients.get(email) ?? {
            name: commitment.responsible?.fullName,
            commitments: [],
          };

          if (!entry.name && commitment.responsible?.fullName) {
            entry.name = commitment.responsible.fullName;
          }

          entry.commitments.push({
            id: commitment.id,
            description: commitment.description,
            dueDate,
            actaNumber: commitment.acta?.number,
            actaTitle: commitment.acta?.title,
            daysUntilDue,
          });

          recipients.set(email, entry);
        });

        if (!recipients.size) {
          logger.warn(
            "ReminderJob: no se enviaron correos por falta de destinatarios válidos."
          );
          return;
        }

        if (!isEmailServiceConfigured()) {
          logger.warn(
            "ReminderJob: SMTP no configurado, se omite envío de correos.",
            {
              recipients: Array.from(recipients.keys()),
            }
          );
          return;
        }

        await Promise.all(
          Array.from(recipients.entries()).map(async ([email, payload]) => {
            try {
              await sendCommitmentReminderEmail({
                to: email,
                recipientName: payload.name,
                commitments: payload.commitments,
                timezone,
                daysAhead: daysAheadConfig,
              });
              logger.info("ReminderJob: correo enviado", {
                email,
                commitments: payload.commitments.length,
              });
            } catch (error) {
              logger.error(
                "ReminderJob: error al enviar correo de recordatorio",
                {
                  email,
                  error,
                }
              );
            }
          })
        );
      } catch (error) {
        logger.error("ReminderJob falló al consultar compromisos", { error });
      }
    },
    {
      timezone: process.env.REMINDER_TIMEZONE || "America/Bogota",
    }
  );
};

const sanitizeFileName = (value: string) =>
  value
    .normalize("NFD")
    .replace(/[^a-zA-Z0-9-_.]+/g, "_")
    .replace(/_{2,}/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 120);

/**
 * Crea una clave de almacenamiento organizada igual que el expediente exportado
 * Estructura: {seccion}/{subfolder?}/{year}/{month}/{uniqueId}-{filename}
 * 
 * Secciones principales (igual que el ZIP del expediente):
 * - bitacora/ - Archivos de bitácoras (adjuntos, PDFs generados, firmas)
 * - actas/ - Archivos de actas de comité
 * - comunicaciones/ - Archivos de comunicaciones
 * - informes/ - Archivos de informes (adjuntos, PDFs generados)
 * - puntos-fijos/{controlPointId}/ - Fotos de puntos fijos (organizadas por punto fijo)
 * - firmas/ - Firmas de usuarios y documentos firmados
 * - planos/ - Planos de obra
 * 
 * @param seccion - Sección principal: 'bitacora', 'actas', 'comunicaciones', 'informes', 'puntos-fijos', 'firmas', 'planos'
 * @param originalName - Nombre original del archivo
 * @param subfolder - Subcarpeta opcional (ej: ID del punto fijo para puntos-fijos)
 * @returns Ruta organizada para almacenamiento
 */
const createStorageKey = (
  seccion: string,
  originalName: string,
  subfolder?: string
) => {
  const now = new Date();
  const year = now.getFullYear().toString();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  
  const ext = path.extname(originalName);
  const baseName = sanitizeFileName(path.basename(originalName, ext)) || "file";
  const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
  
  // Normalizar sección para evitar caracteres inválidos
  const normalizedSeccion = seccion
    .replace(/[^a-zA-Z0-9_-]/g, "")
    .toLowerCase();
  
  // Normalizar subfolder si existe
  const normalizedSubfolder = subfolder
    ? subfolder.replace(/[^a-zA-Z0-9_-]/g, "").toLowerCase()
    : undefined;
  
  const pathParts = [normalizedSeccion];
  if (normalizedSubfolder) {
    pathParts.push(normalizedSubfolder);
  }
  pathParts.push(year, month, `${uniqueSuffix}-${baseName}${ext}`);
  
  return path.posix.join(...pathParts);
};

/**
 * Función de compatibilidad para mantener la estructura antigua si es necesario
 * @deprecated Usar createStorageKey con type y category en su lugar
 */
const createStorageKeyLegacy = (folder: string, originalName: string) => {
  const ext = path.extname(originalName);
  const baseName = sanitizeFileName(path.basename(originalName, ext)) || "file";
  const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
  const normalizedFolder = folder
    .replace(/[^a-zA-Z0-9/_-]/g, "")
    .replace(/\/+$/, "");
  return path.posix.join(normalizedFolder, `${uniqueSuffix}-${baseName}${ext}`);
};

/**
 * Persiste un archivo subido con organización igual que el expediente exportado
 * @param file - Archivo subido
 * @param seccion - Sección principal: 'bitacora', 'actas', 'comunicaciones', 'informes', 'puntos-fijos', 'firmas', 'planos'
 * @param subfolder - Subcarpeta opcional (ej: ID del punto fijo para puntos-fijos)
 * @returns Objeto con la clave de almacenamiento y URL pública
 */
const persistUploadedFile = async (
  file: Express.Multer.File,
  seccion: string,
  subfolder?: string
) => {
  const storage = getStorage();
  const key = createStorageKey(seccion, file.originalname, subfolder);
  await storage.save({ path: key, content: file.buffer });
  return {
    key,
    url: storage.getPublicUrl(key),
  };
};

const resolveServerPublicUrl = () => {
  const raw = process.env.SERVER_PUBLIC_URL?.trim();
  if (raw && raw.length > 0) {
    return raw.replace(/\/+$/, "");
  }
  return `http://localhost:${port}`;
};

const buildAttachmentResponse = (attachment: any) => {
  const publicUrl = resolveServerPublicUrl();
  const downloadPath = `/api/attachments/${attachment.id}/download`;
  const viewPath = `/api/attachments/${attachment.id}/view`;
  const downloadUrl = `${publicUrl}${downloadPath}`;
  const viewUrl = `${publicUrl}${viewPath}`;
  
  return {
    ...attachment,
    // If the attachment has a storagePath and we're using cloud storage, use the original URL
    // Otherwise, fallback to server-proxied URLs for local storage
    url: attachment.storagePath && attachment.url && !attachment.url.includes('localhost') 
      ? attachment.url  // Use the direct Cloudflare R2 URL for cloud storage
      : viewUrl,        // Use server-proxied URL for local storage or legacy attachments
    downloadUrl,
    downloadPath,
    previewUrl: attachment.storagePath && attachment.url && !attachment.url.includes('localhost')
      ? attachment.url  // Use direct URL for cloud storage previews too  
      : viewUrl,
  };
};

const parseBooleanInput = (value: any): boolean => {
  if (typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    return value === 1;
  }
  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();
    if (!normalized.length) {
      return false;
    }
    if (["true", "1", "yes", "y", "si", "sí", "on"].includes(normalized)) {
      return true;
    }
    if (["false", "0", "no", "off"].includes(normalized)) {
      return false;
    }
  }
  return false;
};

ensureAppSettings().catch((error) => {
  console.error("No se pudo inicializar la configuración principal:", error);
});

scheduleDailyCommitmentReminder();

// Programar limpieza de eventos de seguridad antiguos (diariamente a las 2 AM)
const scheduleSecurityEventsCleanup = () => {
  const cronExpression = process.env.SECURITY_CLEANUP_CRON || "0 2 * * *"; // Diariamente a las 2 AM
  const maxAgeDays = Number(process.env.SECURITY_EVENTS_MAX_AGE_DAYS || 30); // Mantener 30 días por defecto

  cron.schedule(cronExpression, async () => {
    try {
      await cleanupOldEvents(maxAgeDays);
      logger.info(`Security events cleanup completed. Max age: ${maxAgeDays} days`);
    } catch (error) {
      logger.error("Error en limpieza de eventos de seguridad", {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  });

  logger.info(`Security events cleanup scheduled. Cron: ${cronExpression}, Max age: ${maxAgeDays} days`);
};

scheduleSecurityEventsCleanup();

const resolveProjectRole = (value?: string): UserRole | undefined => {
  if (!value) return undefined;
  if (roleMap[value]) {
    return roleMap[value];
  }
  const normalized = value.toUpperCase();
  if ((UserRole as any)[normalized]) {
    return normalized as UserRole;
  }
  return undefined;
};

const resolveStorageKeyFromUrl = (fileUrl?: string | null): string | null => {
  if (!fileUrl) return null;
  try {
    const parsed = new URL(fileUrl);
    const pathname = parsed.pathname.replace(/^\/+/, "");
    if (pathname.startsWith("uploads/")) {
      return pathname.replace(/^uploads\//, "");
    }
  } catch (error) {
    // Not a valid absolute URL, fall back to relative handling
    const sanitized = fileUrl.replace(/^\/+/, "");
    if (sanitized.startsWith("uploads/")) {
      return sanitized.replace(/^uploads\//, "");
    }
  }
  if (fileUrl.startsWith("uploads/")) {
    return fileUrl.replace(/^uploads\//, "");
  }
  if (fileUrl.startsWith("/uploads/")) {
    return fileUrl.replace(/^\/uploads\//, "");
  }
  return null;
};

const loadAttachmentBuffer = async (attachment: any): Promise<Buffer> => {
  const storage = getStorage();
  const storagePath =
    attachment.storagePath || resolveStorageKeyFromUrl(attachment.url);
  if (!storagePath) {
    throw new Error("No se pudo determinar la ubicación del archivo adjunto.");
  }
  return storage.read(storagePath);
};

/**
 * Carga y desencripta la firma del usuario
 * @param userSignature - Objeto UserSignature de la BD
 * @param userPassword - Contraseña del usuario para desencriptar (requerida si la firma está encriptada)
 * @returns Buffer de la firma desencriptada
 */
const loadUserSignatureBuffer = async (
  userSignature: any,
  userPassword?: string
): Promise<Buffer> => {
  const storage = getStorage();
  
  // Si hay storagePath, intentar cargar desde ahí (puede estar encriptada o no)
  if (userSignature.storagePath) {
    try {
      const buffer = await storage.read(userSignature.storagePath);
      
      // Intentar desencriptar si tenemos contraseña
      if (userPassword) {
        try {
          const encryptedData = unpackEncryptedSignature(buffer);
          return decryptSignature(encryptedData, userPassword);
        } catch (decryptError) {
          // Si falla la desencriptación, puede ser una firma antigua sin encriptar
          // o la contraseña es incorrecta
          console.warn("No se pudo desencriptar la firma, intentando como archivo sin encriptar...", decryptError);
          // Continuar con el buffer original (firma antigua sin encriptar)
        }
      }
      
      // Si no hay contraseña o es una firma antigua, retornar el buffer tal cual
      return buffer;
    } catch (error) {
      console.warn("No se pudo leer la firma desde storage.", {
        storagePath: userSignature.storagePath,
        error,
      });
    }
  }

  // Fallback: intentar desde URL (firmas antiguas)
  if (userSignature.url) {
    const candidates = [
      userSignature.storagePath,
      resolveStorageKeyFromUrl(userSignature.url),
    ].filter((value): value is string => Boolean(value));

    for (const candidate of candidates) {
      try {
        const buffer = await storage.read(candidate);
        // Si hay contraseña, intentar desencriptar
        if (userPassword) {
          try {
            const encryptedData = unpackEncryptedSignature(buffer);
            return decryptSignature(encryptedData, userPassword);
          } catch {
            // Firma antigua sin encriptar
            return buffer;
          }
        }
        return buffer;
      } catch (error) {
        console.warn("No se pudo leer la firma desde storage.", {
          candidate,
          error,
        });
      }
    }

    // Intentar descargar desde URL directa
    if (typeof userSignature.url === "string") {
      try {
        const response = await fetch(userSignature.url);
        if (!response.ok) {
          throw new Error(`Descarga fallida con status ${response.status}`);
        }
        const arrayBuffer = await response.arrayBuffer();
        return Buffer.from(arrayBuffer);
      } catch (error) {
        console.warn("No se pudo descargar la firma desde la URL.", {
          url: userSignature.url,
          error,
        });
      }
    }
  }

  throw new Error("No se pudo cargar la firma manuscrita del usuario.");
};

const mapUserBasic = (user: any) => {
  if (!user) {
    return null;
  }
  return {
    id: user.id,
    fullName: user.fullName,
    email: user.email,
    avatarUrl: user.avatarUrl,
    appRole: user.appRole,
    projectRole: user.projectRole,
    entity: user.entity || null,
    cargo: user.cargo || null,
  };
};

const LOG_ENTRY_FIELD_LABELS: Record<string, string> = {
  title: "Título",
  description: "Descripción",
  type: "Tipo",
  status: "Estado",
  subject: "Asunto",
  location: "Ubicación",
  entryDate: "Fecha de entrada",
  activityStartDate: "Fecha inicio actividad",
  activityEndDate: "Fecha fin actividad",
  isConfidential: "Confidencial",
  activitiesPerformed: "Actividades realizadas",
  materialsUsed: "Materiales utilizados",
  workforce: "Personal en obra",
  weatherConditions: "Condiciones climáticas",
  additionalObservations: "Observaciones adicionales",
  scheduleDay: "Día del plazo",
  locationDetails: "Detalles de localización",
  contractorObservations: "Observaciones del contratista",
  interventoriaObservations: "Observaciones de la interventoría",
  safetyFindings: "Componente SST - Observaciones de interventoría",
  safetyContractorResponse: "Componente SST - Respuesta del contratista",
  environmentFindings: "Componente ambiental - Observaciones de interventoría",
  environmentContractorResponse:
    "Componente ambiental - Respuesta del contratista",
  socialActivities: "Componente social - Registro de actividades",
  socialObservations: "Componente social - Observaciones de interventoría",
  socialContractorResponse: "Componente social - Respuesta del contratista",
  socialPhotoSummary: "Componente social - Registro fotográfico",
  contractorPersonnel: "Personal del contratista",
  interventoriaPersonnel: "Personal de la interventoría",
  equipmentResources: "Equipos y recursos",
  executedActivities: "Ejecución de actividades",
  executedQuantities: "Cantidades ejecutadas",
  scheduledActivities: "Actividades programadas",
  qualityControls: "Controles de calidad",
  materialsReceived: "Materiales recibidos",
  safetyNotes: "HSEQ / SST",
  projectIssues: "Control, novedades e incidencias",
  siteVisits: "Visitas de obra",
  weatherReport: "Reporte climático",
};

const logEntryResponseInclude = {
  author: true,
  attachments: true,
  comments: {
    include: { author: true },
    orderBy: { timestamp: "asc" },
  },
  signatures: { include: { signer: true } },
  signatureTasks: {
    include: { signer: true },
    orderBy: { assignedAt: "asc" },
  },
  reviewTasks: {
    include: { reviewer: true },
    orderBy: { assignedAt: "asc" },
  } as any,
  assignees: true,
  history: { include: { user: true }, orderBy: { timestamp: "desc" } },
  contractorReviewer: true,
} as const;

const getStatusDisplayName = (status: string) =>
  entryStatusReverseMap[status] || status;

const getFieldLabel = (fieldKey: string) =>
  LOG_ENTRY_FIELD_LABELS[fieldKey] || fieldKey;

const extractUserIds = (input: unknown): string[] => {
  if (!input) return [];
  let rawValue = input;

  if (typeof input === "string") {
    const trimmed = input.trim();
    if (!trimmed) return [];
    try {
      rawValue = JSON.parse(trimmed);
    } catch (error) {
      return [trimmed];
    }
  }

  const items = Array.isArray(rawValue) ? rawValue : [rawValue];
  const ids = new Set<string>();

  items.forEach((item) => {
    if (!item) return;
    if (typeof item === "string") {
      ids.add(item);
      return;
    }
    if (typeof item === "object" && "id" in item && (item as any).id) {
      ids.add((item as any).id);
    }
  });

  return Array.from(ids);
};

// Simple ZIP builder without external deps (no compression - STORED method)
const buildSimpleZip = (files: Array<{ name: string; data: Buffer }>): Buffer => {
  type ZipRecord = {
    localHeader: Buffer;
    data: Buffer;
    centralHeader: Buffer;
    offset: number;
  };
  const records: ZipRecord[] = [];
  let offset = 0;
  const crcTable = (() => {
    const table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) {
        c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      }
      table[n] = c >>> 0;
    }
    return table;
  })();
  const crc32 = (buf: Buffer): number => {
    let c = 0 ^ -1;
    for (let i = 0; i < buf.length; i++) {
      c = (c >>> 8) ^ crcTable[(c ^ buf[i]) & 0xFF];
    }
    return (c ^ -1) >>> 0;
  };
  const fileToMsDosTime = (date: Date) => {
    const dosTime =
      (date.getHours() << 11) |
      (date.getMinutes() << 5) |
      Math.floor(date.getSeconds() / 2);
    const dosDate =
      ((date.getFullYear() - 1980) << 9) |
      ((date.getMonth() + 1) << 5) |
      date.getDate();
    return { dosTime, dosDate };
  };
  for (const f of files) {
    const nameBuf = Buffer.from(f.name.replace(/\\/g, "/"));
    const crc = crc32(f.data) >>> 0;
    const size = f.data.length;
    const now = new Date();
    const { dosTime, dosDate } = fileToMsDosTime(now);
    const local = Buffer.alloc(30 + nameBuf.length);
    let o = 0;
    local.writeUInt32LE(0x04034b50, o); o += 4; // local file header signature
    local.writeUInt16LE(20, o); o += 2; // version needed
    local.writeUInt16LE(0, o); o += 2; // general purpose
    local.writeUInt16LE(0, o); o += 2; // compression (0 = stored)
    local.writeUInt16LE(dosTime, o); o += 2;
    local.writeUInt16LE(dosDate, o); o += 2;
    local.writeUInt32LE(crc >>> 0, o); o += 4;
    local.writeUInt32LE(size, o); o += 4; // compressed size
    local.writeUInt32LE(size, o); o += 4; // uncompressed size
    local.writeUInt16LE(nameBuf.length, o); o += 2; // file name length
    local.writeUInt16LE(0, o); o += 2; // extra length
    nameBuf.copy(local, o);
    const central = Buffer.alloc(46 + nameBuf.length);
    o = 0;
    central.writeUInt32LE(0x02014b50, o); o += 4; // central header signature
    central.writeUInt16LE(20, o); o += 2; // version made by
    central.writeUInt16LE(20, o); o += 2; // version needed
    central.writeUInt16LE(0, o); o += 2; // general purpose
    central.writeUInt16LE(0, o); o += 2; // compression
    central.writeUInt16LE(dosTime, o); o += 2;
    central.writeUInt16LE(dosDate, o); o += 2;
    central.writeUInt32LE(crc >>> 0, o); o += 4;
    central.writeUInt32LE(size, o); o += 4;
    central.writeUInt32LE(size, o); o += 4;
    central.writeUInt16LE(nameBuf.length, o); o += 2;
    central.writeUInt16LE(0, o); o += 2; // extra
    central.writeUInt16LE(0, o); o += 2; // comment
    central.writeUInt16LE(0, o); o += 2; // disk number
    central.writeUInt16LE(0, o); o += 2; // internal attr
    central.writeUInt32LE(0, o); o += 4; // external attr
    central.writeUInt32LE(offset, o); o += 4; // relative offset
    nameBuf.copy(central, o);
    records.push({ localHeader: local, data: f.data, centralHeader: central, offset });
    offset += local.length + f.data.length;
  }
  const centralDir = Buffer.concat(records.map(r => r.centralHeader));
  const eocd = Buffer.alloc(22);
  let p = 0;
  eocd.writeUInt32LE(0x06054b50, p); p += 4;
  eocd.writeUInt16LE(0, p); p += 2; // disk
  eocd.writeUInt16LE(0, p); p += 2; // start
  eocd.writeUInt16LE(records.length, p); p += 2;
  eocd.writeUInt16LE(records.length, p); p += 2;
  eocd.writeUInt32LE(centralDir.length, p); p += 4;
  eocd.writeUInt32LE(offset, p); p += 4;
  eocd.writeUInt16LE(0, p); p += 2; // comment len
  const body = Buffer.concat(records.flatMap(r => [r.localHeader, r.data]));
  return Buffer.concat([body, centralDir, eocd]);
};

interface SignatureRecord {
  id: string;
  signerId?: string;
  signer?: {
    id: string;
    [key: string]: any;
  };
  signedAt?: Date | string | null;
  signatureTaskId?: string | null;
}

interface NormalizedSignature {
  id: string;
  logEntryId: string;
  signerId: string;
  signer: {
    id: string;
    fullName?: string;
    email?: string;
    avatarUrl?: string;
    appRole?: string;
    projectRole?: string;
    entity?: string | null;
    cargo?: string | null;
  } | null;
  signedAt: Date | string | null;
  signatureTaskId: string | null;
  signatureTaskStatus: "SIGNED" | "PENDING";
}

interface SignatureTask {
  id: string;
  status: "SIGNED" | "PENDING";
  assignedAt: Date | string | null;
  signedAt?: Date | string | null;
  signer: {
    id: string;
    fullName?: string;
    email?: string;
    [key: string]: any;
  };
}

function normalizeSignedAt(date: string | Date | null | undefined): Date {
  if (!date) {
    return new Date();
  }
  return typeof date === "string" ? new Date(date) : date;
}

function normalizeSignatureStatus(
  status: string | undefined
): "SIGNED" | "PENDING" {
  if (status?.toUpperCase() === "SIGNED") {
    return "SIGNED";
  }
  return "PENDING";
}

const formatLogEntry = (entry: any) => {
  const formattedSignatureTasks: SignatureTask[] = (
    entry.signatureTasks || []
  ).map((task: any) => ({
    id: task.id,
    status: task.status || "PENDING",
    assignedAt: task.assignedAt ? new Date(task.assignedAt) : null,
    signedAt: task.signedAt ? new Date(task.signedAt) : null,
    signer: mapUserBasic(task.signer),
  }));

  const totalSignatureTasks = formattedSignatureTasks.length;
  const signedSignatureTasks = formattedSignatureTasks.filter(
    (task: SignatureTask) => task.status === "SIGNED"
  );
  const pendingSignatureTasks = formattedSignatureTasks.filter(
    (task: SignatureTask) => task.status !== "SIGNED"
  );

  const requiredSigners =
    formattedSignatureTasks.length > 0
      ? formattedSignatureTasks
          .map((task: SignatureTask) => task.signer)
          .filter(
            (signer): signer is NonNullable<ReturnType<typeof mapUserBasic>> =>
              Boolean(signer)
          )
      : entry.author
      ? [mapUserBasic(entry.author)].filter(
          (s): s is NonNullable<ReturnType<typeof mapUserBasic>> => Boolean(s)
        )
      : [];

  const normalizeSignedAt = (value: any): string | null => {
    if (!value) return null;
    if (value instanceof Date) return value.toISOString();
    if (typeof value === "string") return value;
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
  };

  // Process existing signatures with proper type checking
  const existingSignatures: NormalizedSignature[] = (entry.signatures || [])
    .map((sig: SignatureRecord) => {
      const signerId = sig.signerId || sig.signer?.id;
      if (!signerId) return null;

      const signedAt = normalizeSignedAt(sig.signedAt);
      return {
        id: sig.id,
        logEntryId: entry.id,
        signerId,
        signer: mapUserBasic(sig.signer),
        signedAt,
        signatureTaskId: sig.signatureTaskId || null,
        signatureTaskStatus: signedAt ? "SIGNED" : "PENDING",
      };
    })
    .filter((sig: any): sig is NormalizedSignature => sig !== null);

  // Create a map to check existing signatures
  const signedByUserId = new Map(
    existingSignatures.map((sig: NormalizedSignature) => [sig.signerId, sig])
  );

  // Create a copy of existing signatures to modify
  const normalizedSignatures = existingSignatures.map(
    (sig: NormalizedSignature) => ({ ...sig })
  );

  // Process signature tasks
  formattedSignatureTasks.forEach((task: SignatureTask) => {
    const signer = task.signer;
    if (!signer) return;

    const signerId = signer.id;
    const existingSignatureIndex = normalizedSignatures.findIndex(
      (sig) => sig.signerId === signerId
    );

    if (existingSignatureIndex === -1) {
      // No existing signature found, create a new one
      // Solo establecer signedAt si la tarea está realmente firmada
      const signedAt = task.status === "SIGNED" && task.signedAt 
        ? normalizeSignedAt(task.signedAt) 
        : null;
      
      normalizedSignatures.push({
        id: randomUUID(), // Use UUID for unique ID generation
        logEntryId: entry.id,
        signerId,
        signer: mapUserBasic(signer),
        signedAt: signedAt,
        signatureTaskId: task.id,
        signatureTaskStatus: task.status || "PENDING",
      });
    } else {
      // Update existing signature with task information while preserving the signature
      const existingSignature = normalizedSignatures[existingSignatureIndex];
      existingSignature.signatureTaskId = task.id;
      existingSignature.signatureTaskStatus = task.status || "PENDING";

      // Only update signedAt if the task is marked as signed
      if (task.status === "SIGNED" && task.signedAt) {
        existingSignature.signedAt = normalizeSignedAt(task.signedAt);
      } else if (task.status !== "SIGNED") {
        // Si la tarea no está firmada, asegurar que signedAt sea null
        existingSignature.signedAt = null;
      }
    }
  });

  // Asegurar que las firmas existentes se muestren correctamente
  // Si hay una firma en la tabla Signature pero no en normalizedSignatures, agregarla
  (entry.signatures || []).forEach((signature: any) => {
    const signerId = signature.signerId || signature.signer?.id;
    if (!signerId) return;

    const alreadyIncluded = normalizedSignatures.some(
      (sig) => sig.signerId === signerId
    );
    if (!alreadyIncluded) {
      normalizedSignatures.push({
        id: signature.id,
        logEntryId: entry.id,
        signerId,
        signer: mapUserBasic(signature.signer),
        signedAt: normalizeSignedAt(signature.signedAt),
        signatureTaskId: null,
        signatureTaskStatus: signature.signedAt ? "SIGNED" : "PENDING",
      });
    }
  });

  return {
    ...entry,
    type: entryTypeReverseMap[entry.type] || entry.type,
    status: entryStatusReverseMap[entry.status] || entry.status,
    entryDate:
      entry.entryDate instanceof Date
        ? entry.entryDate.toISOString()
        : entry.entryDate,
    activitiesPerformed: entry.activitiesPerformed || "",
    materialsUsed: entry.materialsUsed || "",
    workforce: entry.workforce || "",
    weatherConditions: entry.weatherConditions || "",
    additionalObservations: entry.additionalObservations || "",
    comments: (entry.comments || []).map((comment: any) => ({
      ...comment,
      timestamp:
        comment.timestamp instanceof Date
          ? comment.timestamp.toISOString()
          : comment.timestamp,
    })),
    attachments: (entry.attachments || []).map(buildAttachmentResponse),
    signatures: normalizedSignatures,
    assignees: (entry.assignees || []).map(mapUserBasic).filter(Boolean),
    scheduleDay: entry.scheduleDay || "",
    locationDetails: entry.locationDetails || "",
    weatherReport: normalizeWeatherReport(entry.weatherReport),
    contractorPersonnel: normalizePersonnelEntries(entry.contractorPersonnel),
    interventoriaPersonnel: normalizePersonnelEntries(
      entry.interventoriaPersonnel
    ),
    equipmentResources: normalizeEquipmentEntries(entry.equipmentResources),
    executedActivities: normalizeListItems(entry.executedActivities),
    executedQuantities: normalizeListItems(entry.executedQuantities),
    scheduledActivities: normalizeListItems(entry.scheduledActivities),
    qualityControls: normalizeListItems(entry.qualityControls),
    materialsReceived: normalizeListItems(entry.materialsReceived),
    safetyNotes: normalizeListItems(entry.safetyNotes),
    projectIssues: normalizeListItems(entry.projectIssues),
    siteVisits: normalizeListItems(entry.siteVisits),
    contractorObservations: entry.contractorObservations || "",
    interventoriaObservations: entry.interventoriaObservations || "",
    safetyFindings: entry.safetyFindings || "",
    safetyContractorResponse: entry.safetyContractorResponse || "",
    environmentFindings: entry.environmentFindings || "",
    environmentContractorResponse: entry.environmentContractorResponse || "",
    socialActivities: normalizeListItems(entry.socialActivities),
    socialObservations: entry.socialObservations || "",
    socialContractorResponse: entry.socialContractorResponse || "",
    socialPhotoSummary: entry.socialPhotoSummary || "",
    requiredSignatories: requiredSigners,
    signatureTasks: formattedSignatureTasks,
    reviewTasks: (entry.reviewTasks || []).map((task: any) => ({
      id: task.id,
      status: task.status || "PENDING",
      assignedAt: task.assignedAt ? new Date(task.assignedAt).toISOString() : null,
      completedAt: task.completedAt ? new Date(task.completedAt).toISOString() : null,
      reviewer: mapUserBasic(task.reviewer),
    })),
    signatureSummary: (() => {
      const totalTasks = totalSignatureTasks;
      const signedTasksCount = signedSignatureTasks.length;
      const pendingTasksCount = pendingSignatureTasks.length;

      const totalSignatures =
        totalTasks > 0 ? totalTasks : normalizedSignatures.length;
      const signedSignaturesCount =
        totalTasks > 0
          ? signedTasksCount
          : normalizedSignatures.filter(
              (sig) => sig.signatureTaskStatus === "SIGNED"
            ).length;
      const pendingSignaturesCount =
        totalSignatures - signedSignaturesCount;

      return {
        total: totalSignatures,
        signed: signedSignaturesCount,
        pending: pendingSignaturesCount,
        completed:
          totalSignatures > 0 && pendingSignaturesCount === 0,
      };
    })(),
    pendingSignatureSignatories: pendingSignatureTasks
      .map((task) => task.signer)
      .filter(
        (signer): signer is NonNullable<ReturnType<typeof mapUserBasic>> =>
          Boolean(signer)
      ),
    contractorReviewCompleted: Boolean(entry.contractorReviewCompleted),
    contractorReviewCompletedAt: entry.contractorReviewCompletedAt
      ? new Date(entry.contractorReviewCompletedAt).toISOString()
      : null,
    contractorReviewer: entry.contractorReviewer
      ? mapUserBasic(entry.contractorReviewer)
      : null,
    history: (entry.history || []).map((change: any) => ({
      id: change.id,
      fieldName: change.fieldName,
      oldValue: change.oldValue,
      newValue: change.newValue,
      timestamp:
        change.timestamp instanceof Date
          ? change.timestamp.toISOString()
          : change.timestamp,
      user: mapUserBasic(change.user) || {
        id: "system",
        fullName: "Sistema",
        avatarUrl: "",
        email: "",
        appRole: "viewer",
        projectRole: "ADMIN",
      },
    })),
  };
};

const formatActa = (acta: any) => ({
  ...acta,
  area: actaAreaReverseMap[acta.area] || acta.area,
  status: actaStatusReverseMap[acta.status] || acta.status,
  attachments: (acta.attachments || []).map(buildAttachmentResponse),
  commitments: (acta.commitments || []).map((commitment: any) => ({
    ...commitment,
    status: commitmentStatusReverseMap[commitment.status] || commitment.status,
  })),
  signatures: (acta.signatures || []).map((signature: any) => ({
    ...signature,
    signedAt:
      signature.signedAt instanceof Date
        ? signature.signedAt.toISOString()
        : signature.signedAt,
  })),
});

const formatWorkActa = (acta: any) => ({
  ...acta,
  date: acta.date instanceof Date ? acta.date.toISOString() : acta.date,
  status: workActaStatusReverseMap[acta.status] || acta.status,
  attachments: (acta.attachments || []).map(buildAttachmentResponse),
  items: (acta.items || []).map((item: any) => ({
    ...item,
    quantity:
      typeof item.quantity === "number" ? item.quantity : Number(item.quantity),
  })),
});

const recordLogEntryChanges = async (
  logEntryId: string,
  userId: string | undefined,
  changes: {
    fieldName: string;
    oldValue?: string | null;
    newValue?: string | null;
  }[]
) => {
  if (!changes.length) return;
  await prisma.logEntryHistory.createMany({
    data: changes.map((change) => ({
      logEntryId,
      fieldName: change.fieldName,
      oldValue: change.oldValue ?? null,
      newValue: change.newValue ?? null,
      userId: userId || null,
    })),
  });
};

const formatCommunication = (communication: any) => {
  return {
    id: communication.id,
    radicado: communication.radicado,
    subject: communication.subject,
    description: communication.description,
    senderDetails: {
      entity: communication.senderEntity,
      personName: communication.senderName,
      personTitle: communication.senderTitle,
    },
    recipientDetails: {
      entity: communication.recipientEntity,
      personName: communication.recipientName,
      personTitle: communication.recipientTitle,
    },
    signerName: communication.signerName,
    sentDate:
      communication.sentDate instanceof Date
        ? communication.sentDate.toISOString()
        : communication.sentDate,
    dueDate:
      communication.dueDate instanceof Date &&
      !isNaN(communication.dueDate.getTime())
        ? communication.dueDate.toISOString()
        : communication.dueDate,
    deliveryMethod:
      deliveryMethodReverseMap[communication.deliveryMethod] ||
      communication.deliveryMethod,
    direction:
      communicationDirectionReverseMap[communication.direction] ||
      communication.direction,
    requiresResponse: Boolean(communication.requiresResponse),
    responseDueDate:
      communication.responseDueDate instanceof Date &&
      !isNaN(communication.responseDueDate.getTime())
        ? communication.responseDueDate.toISOString()
        : communication.responseDueDate,
    notes: communication.notes,
    status:
      communicationStatusReverseMap[communication.status] ||
      communication.status,
    uploader: mapUserBasic(communication.uploader),
    assignee: mapUserBasic(communication.assignee),
    assignedAt:
      communication.assignedAt instanceof Date
        ? communication.assignedAt.toISOString()
        : communication.assignedAt,
    parentId: communication.parentId || null,
    attachments: (communication.attachments || []).map(buildAttachmentResponse),
    statusHistory: (communication.statusHistory || []).map((history: any) => ({
      ...history,
      status: communicationStatusReverseMap[history.status] || history.status,
      timestamp:
        history.timestamp instanceof Date
          ? history.timestamp.toISOString()
          : history.timestamp,
      user: mapUserBasic(history.user) || {
        id: "system",
        fullName: "Sistema",
        email: "",
        avatarUrl: "",
        appRole: "viewer",
        projectRole: "ADMIN",
      },
    })),
    createdAt:
      communication.createdAt instanceof Date
        ? communication.createdAt.toISOString()
        : communication.createdAt,
    updatedAt:
      communication.updatedAt instanceof Date
        ? communication.updatedAt.toISOString()
        : communication.updatedAt,
  };
};

const formatReportRecord = (report: any) => {
  const formattedSignatures = (report.signatures || []).map(
    (signature: any) => ({
      ...signature,
      signedAt:
        signature.signedAt instanceof Date
          ? signature.signedAt.toISOString()
          : signature.signedAt,
    })
  );

  return {
    ...report,
    reportScope:
      reportScopeReverseMap[report.reportScope] || report.reportScope,
    status: reportStatusReverseMap[report.status] || report.status,
    submissionDate:
      report.submissionDate instanceof Date
        ? report.submissionDate.toISOString()
        : report.submissionDate,
    createdAt:
      report.createdAt instanceof Date
        ? report.createdAt.toISOString()
        : report.createdAt,
    updatedAt:
      report.updatedAt instanceof Date
        ? report.updatedAt.toISOString()
        : report.updatedAt,
    attachments: (report.attachments || []).map(buildAttachmentResponse),
    signatures: formattedSignatures,
  };
};

interface ReportVersion {
  id: string;
  version: number;
  status: string;
  submissionDate: string | null;
  createdAt: string | null;
}

const normalizeOrigin = (origin?: string | null) => {
  if (!origin) return null;
  const trimmed = origin.trim();
  if (!trimmed) return null;
  return trimmed.replace(/\/+$/, "");
};

const DEFAULT_ALLOWED_ORIGINS = [
  "http://localhost:3000",
  "http://localhost:3001",
  "http://localhost:5173",
  "https://bdigitales.com",
  "https://www.bdigitales.com",
  "https://bdo-client.vercel.app",
  "https://bdo-client-git-main-bitacora-de-obras-projects.vercel.app",
  "https://bdo-client-bitacora-de-obras-projects.vercel.app",
];

const envAllowedOrigins = (process.env.CORS_ALLOWED_ORIGINS || "")
  .split(",")
  .map(normalizeOrigin)
  .filter((value): value is string => Boolean(value));

const inferredOrigins = [
  normalizeOrigin(process.env.FRONTEND_URL),
  normalizeOrigin(process.env.APP_BASE_URL),
  normalizeOrigin(process.env.SERVER_PUBLIC_URL),
];

const allowedOrigins = Array.from(
  new Set([
    ...DEFAULT_ALLOWED_ORIGINS,
    ...envAllowedOrigins,
    ...inferredOrigins.filter((value): value is string => Boolean(value)),
  ])
);

const corsOptions: CorsOptions = {
  origin(origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) {
    // Permitir requests sin origen (ej. curl) y orígenes registrados
    if (!origin) {
      callback(null, true);
      return;
    }
    
    // Normalizar el origen del request (igual que normalizeOrigin)
    const normalizedRequestOrigin = normalizeOrigin(origin);
    
    if (normalizedRequestOrigin && allowedOrigins.includes(normalizedRequestOrigin)) {
      callback(null, true);
    } else {
      // Log para debugging
      logger.warn("CORS blocked origin", {
        origin,
        normalizedOrigin: normalizedRequestOrigin,
        allowedOrigins,
      });
      callback(new Error(`Origin ${origin} not allowed by CORS`));
    }
  },
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "X-XSRF-TOKEN",
    "x-xsrf-token",
    "X-CSRF-Token",
    "x-csrf-token",
    "Accept",
    "Origin",
    "X-Requested-With",
  ],
  exposedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token"],
  credentials: true,
  preflightContinue: false, // Responder inmediatamente al preflight
  optionsSuccessStatus: 200, // Algunos navegadores antiguos requieren 200
};

const mapReportVersionSummary = (report: any): ReportVersion => ({
  id: report.id,
  version: report.version || 1,
  status: reportStatusReverseMap[report.status] || report.status,
  submissionDate:
    report.submissionDate instanceof Date
      ? report.submissionDate.toISOString()
      : report.submissionDate,
  createdAt:
    report.createdAt instanceof Date
      ? report.createdAt.toISOString()
      : report.createdAt,
});

// Log de orígenes permitidos al iniciar (solo en desarrollo o si hay problemas)
if (!isProduction || process.env.LOG_CORS === "true") {
  logger.info("CORS configuration", {
    allowedOrigins: allowedOrigins,
    defaultOrigins: DEFAULT_ALLOWED_ORIGINS,
    envOrigins: envAllowedOrigins,
    inferredOrigins: inferredOrigins.filter((value): value is string => Boolean(value)),
  });
}

// Aplicar CORS antes que cualquier otro middleware para asegurar que los preflight requests se manejen correctamente
app.use(cors(corsOptions));

// Middleware de detección de tenant (después de CORS, antes de otros middlewares)
import { detectTenantMiddleware, requireTenantMiddleware } from "./middleware/tenant";
app.use(detectTenantMiddleware);

// Manejar preflight requests explícitamente para asegurar que siempre respondan
// Esto es crítico porque algunos navegadores fallan si el preflight no responde correctamente
app.options("*", (req, res) => {
  const origin = req.headers.origin;
  const normalizedOrigin = normalizeOrigin(origin);
  
  if (origin && normalizedOrigin && allowedOrigins.includes(normalizedOrigin)) {
    res.header("Access-Control-Allow-Origin", origin);
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-XSRF-TOKEN, x-xsrf-token, X-CSRF-Token, x-csrf-token, Accept, Origin, X-Requested-With");
    res.header("Access-Control-Allow-Credentials", "true");
    res.header("Access-Control-Max-Age", "86400"); // 24 horas
    res.sendStatus(200);
  } else {
    res.sendStatus(403);
  }
});

// Configuración mejorada de Helmet para seguridad
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    crossOriginEmbedderPolicy: false, // Permitir recursos embebidos desde otros orígenes
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"], // Permitir inline styles para compatibilidad
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"], // Permitir imágenes de cualquier origen HTTPS
        connectSrc: ["'self'"],
        fontSrc: ["'self'", "data:"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    hsts: {
      maxAge: 31536000, // 1 año
      includeSubDomains: true,
      preload: true,
    },
    frameguard: {
      action: "deny", // Prevenir clickjacking
    },
    noSniff: true, // Prevenir MIME type sniffing
    xssFilter: true, // Habilitar filtro XSS del navegador
    referrerPolicy: {
      policy: "strict-origin-when-cross-origin",
    },
    permittedCrossDomainPolicies: false,
  })
);

app.use("/api/auth/login", loginRateLimiter);
app.use("/api/auth/refresh", refreshRateLimiter);
// Rate limiting global para todas las rutas API (excepto las que tienen su propio limiter)
app.use("/api/", apiRateLimiter);

const openApiDocumentPath = path.join(__dirname, "../openapi/openapi.json");
app.use(
  "/api/docs",
  async (_req: Request, res: Response, next: NextFunction) => {
    try {
      await fsPromises.access(openApiDocumentPath);
      next();
    } catch (error) {
      console.warn(
        "No se encontró openapi/openapi.json. Usa npm run generate-docs para generarlo."
      );
      res.status(503).json({ error: "Documentación no disponible." });
    }
  },
  swaggerUi.serve,
  swaggerUi.setup(undefined, {
    swaggerOptions: {
      url: "/api/docs/json",
    },
  })
);

app.get("/api/docs/json", async (_req: Request, res: Response) => {
  try {
    const spec = await fsPromises.readFile(openApiDocumentPath, "utf-8");
    res.type("application/json").send(spec);
  } catch (error) {
    console.error("Error leyendo la especificación OpenAPI:", error);
    res.status(503).json({ error: "Especificación OpenAPI no disponible." });
  }
});

// Crear directorio de uploads si no existe
const uploadsDir = path.resolve(
  process.env.UPLOADS_DIR || path.join(__dirname, "../uploads")
);
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configuración de middlewares
app.use(cookieParser()); // Permite que Express maneje cookies

// Middleware de timeout para prevenir requests colgados (30 segundos por defecto)
const REQUEST_TIMEOUT_MS = Number(process.env.REQUEST_TIMEOUT_MS || 30000); // 30 segundos
app.use((req: Request, res: Response, next: NextFunction) => {
  const timeout = setTimeout(() => {
    if (!res.headersSent) {
      res.status(408).json({
        error: "Request timeout",
        message: "La solicitud tardó demasiado tiempo en procesarse.",
        code: "REQUEST_TIMEOUT",
      });
    }
  }, REQUEST_TIMEOUT_MS);

  // Limpiar timeout cuando la respuesta se envía
  res.on('finish', () => {
    clearTimeout(timeout);
  });

  next();
});

// Límite más estricto para JSON (2MB global, endpoints específicos pueden tener más)
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

// CSRF Protection: Generar token CSRF para requests GET
app.use(csrfTokenMiddleware);

// CSRF Protection: Verificar token en requests modificadores
app.use(csrfProtection);

// Middleware global para debug - solo en desarrollo
if (!isProduction) {
  app.use((req, res, next) => {
    if (req.method === "POST") {
      console.log("🌐 GLOBAL MIDDLEWARE: Petición POST detectada");
      console.log("🌐 GLOBAL MIDDLEWARE: Path:", req.path);
      console.log("🌐 GLOBAL MIDDLEWARE: URL:", req.url);
      console.log("🌐 GLOBAL MIDDLEWARE: Method:", req.method);
      console.log("🌐 GLOBAL MIDDLEWARE: Content-Type:", req.headers["content-type"]);
      console.log("🌐 GLOBAL MIDDLEWARE: Origin:", req.headers.origin);
      if (req.path.includes("log-entries") || req.url.includes("log-entries")) {
        console.log("🌐 GLOBAL MIDDLEWARE: ⚠️ ESTA ES UNA PETICIÓN A LOG-ENTRIES ⚠️");
      }
    }
    next();
  });
}

// Configuración de multer
const multerConfig = {
  storage: multer.memoryStorage(),
  fileFilter: (
    req: express.Request,
    file: Express.Multer.File,
    cb: multer.FileFilterCallback
  ) => {
    const allowedMimes = [
      "image/jpeg",
      "image/png",
      "application/pdf",
      "image/gif",
      "image/webp",
      // Planos CAD
      "application/acad",
      "image/vnd.dwg",
      "application/x-dwg",
      "image/x-dwg",
      "application/dxf",
      "image/vnd.dxf",
      // XML para cronogramas
      "text/xml",
      "application/xml",
      "text/xml; charset=utf-8",
    ];

    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(
        new Error(
          "Tipo de archivo no permitido. Solo se permiten imágenes (JPG, PNG, GIF, WEBP), PDFs, planos CAD (DWG, DXF) y archivos XML."
        )
      );
    }
  },
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB
    files: 5,
  },
};

const upload = multer(multerConfig);
const signatureUpload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (
    _req: express.Request,
    file: Express.Multer.File,
    cb: multer.FileFilterCallback
  ) => {
    const allowedMimes = [
      "image/png",
      "image/jpeg",
      "image/jpg",
      "application/pdf",
    ];
    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(
        new Error(
          "Tipo de archivo no permitido. Solo se permiten firmas en PNG, JPG o PDF."
        )
      );
    }
  },
  limits: {
    fileSize: 2 * 1024 * 1024,
    files: 1,
  },
});

// Servir archivos estáticos
app.use("/uploads", express.static(uploadsDir));

app.get("/api/attachments/:id/download", async (req, res) => {
  try {
    const { id } = req.params;
    const attachment = await prisma.attachment.findUnique({ where: { id } });

    if (!attachment) {
      return res.status(404).json({ error: "Adjunto no encontrado." });
    }

    // Validar tenant a través del recurso relacionado
    const tenantId = (req as any).tenant?.id;
    if (tenantId && attachment) {
      let resourceTenantId: string | null = null;
      
      if (attachment.logEntryId) {
        const logEntry = await prisma.logEntry.findUnique({
          where: { id: attachment.logEntryId },
          select: { tenantId: true } as any,
        });
        resourceTenantId = (logEntry as any)?.tenantId || null;
      } else if (attachment.actaId) {
        const acta = await prisma.acta.findUnique({
          where: { id: attachment.actaId },
          select: { tenantId: true } as any,
        });
        resourceTenantId = (acta as any)?.tenantId || null;
      } else if (attachment.reportId) {
        const report = await prisma.report.findUnique({
          where: { id: attachment.reportId },
          select: { tenantId: true } as any,
        });
        resourceTenantId = (report as any)?.tenantId || null;
      } else if (attachment.communicationId) {
        const communication = await prisma.communication.findUnique({
          where: { id: attachment.communicationId },
          select: { tenantId: true } as any,
        });
        resourceTenantId = (communication as any)?.tenantId || null;
      } else if (attachment.costActaId) {
        const costActa = await prisma.costActa.findUnique({
          where: { id: attachment.costActaId },
          select: { tenantId: true } as any,
        });
        resourceTenantId = (costActa as any)?.tenantId || null;
      }
      
      if (resourceTenantId && resourceTenantId !== tenantId) {
        return res.status(404).json({ error: "Adjunto no encontrado." });
      }
    }

    const storageDriver = process.env.STORAGE_DRIVER || "local";
    if (
      storageDriver === "s3" &&
      attachment.url &&
      attachment.url.startsWith("http")
    ) {
      return res.redirect(attachment.url);
    }

    let filePath: string | null = null;
    if (attachment.url) {
      try {
        const parsedUrl = new URL(attachment.url);
        let candidatePath = parsedUrl.pathname || "";
        if (candidatePath.startsWith("/uploads/")) {
          candidatePath = candidatePath.replace("/uploads/", "");
        } else {
          candidatePath = candidatePath.replace(/^\/+/, "");
        }
        const resolvedPath = path.resolve(uploadsDir, candidatePath);
        if (resolvedPath.startsWith(uploadsDir)) {
          filePath = resolvedPath;
        }
      } catch (error) {
        // Si la URL no es válida, intentamos usarla directamente como ruta relativa
        const relativePath = attachment.url.startsWith("/uploads/")
          ? attachment.url.replace("/uploads/", "")
          : attachment.url.replace(/^\/+/, "");
        const resolvedPath = path.resolve(uploadsDir, relativePath);
        if (resolvedPath.startsWith(uploadsDir)) {
          filePath = resolvedPath;
        }
      }
    }

    if (!filePath || !fs.existsSync(filePath)) {
      return res
        .status(404)
        .json({ error: "Archivo no disponible en el servidor." });
    }

    const mimeType =
      attachment.type || mime.lookup(filePath) || "application/octet-stream";

    res.setHeader("Content-Type", mimeType as string);
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${attachment.fileName}"`
    );

    res.sendFile(filePath);
  } catch (error) {
    console.error("Error al descargar adjunto:", error);
    res.status(500).json({ error: "No se pudo descargar el adjunto." });
  }
});

// Vista previa/inline de adjuntos (no fuerza descarga)
app.get("/api/attachments/:id/view", async (req, res) => {
  try {
    const { id } = req.params;
    const attachment = await prisma.attachment.findUnique({ where: { id } });

    if (!attachment) {
      return res.status(404).json({ error: "Adjunto no encontrado." });
    }

    // Validar tenant a través del recurso relacionado
    const tenantId = (req as any).tenant?.id;
    if (tenantId && attachment) {
      let resourceTenantId: string | null = null;
      
      if (attachment.logEntryId) {
        const logEntry = await prisma.logEntry.findUnique({
          where: { id: attachment.logEntryId },
          select: { tenantId: true } as any,
        });
        resourceTenantId = (logEntry as any)?.tenantId || null;
      } else if (attachment.actaId) {
        const acta = await prisma.acta.findUnique({
          where: { id: attachment.actaId },
          select: { tenantId: true } as any,
        });
        resourceTenantId = (acta as any)?.tenantId || null;
      } else if (attachment.reportId) {
        const report = await prisma.report.findUnique({
          where: { id: attachment.reportId },
          select: { tenantId: true } as any,
        });
        resourceTenantId = (report as any)?.tenantId || null;
      } else if (attachment.communicationId) {
        const communication = await prisma.communication.findUnique({
          where: { id: attachment.communicationId },
          select: { tenantId: true } as any,
        });
        resourceTenantId = (communication as any)?.tenantId || null;
      } else if (attachment.costActaId) {
        const costActa = await prisma.costActa.findUnique({
          where: { id: attachment.costActaId },
          select: { tenantId: true } as any,
        });
        resourceTenantId = (costActa as any)?.tenantId || null;
      }
      
      if (resourceTenantId && resourceTenantId !== tenantId) {
        return res.status(404).json({ error: "Adjunto no encontrado." });
      }
    }

    const storageDriver = process.env.STORAGE_DRIVER || "local";
    if (
      storageDriver === "s3" &&
      attachment.url &&
      attachment.url.startsWith("http")
    ) {
      // Si usamos S3, redirigimos a la URL pública. Idealmente firmada con Content-Disposition=inline.
      return res.redirect(attachment.url);
    }

    let filePath: string | null = null;
    if (attachment.url) {
      try {
        const parsedUrl = new URL(attachment.url);
        let candidatePath = parsedUrl.pathname || "";
        if (candidatePath.startsWith("/uploads/")) {
          candidatePath = candidatePath.replace("/uploads/", "");
        } else {
          candidatePath = candidatePath.replace(/^\/+/, "");
        }
        const resolvedPath = path.resolve(uploadsDir, candidatePath);
        if (resolvedPath.startsWith(uploadsDir)) {
          filePath = resolvedPath;
        }
      } catch {
        const relativePath = attachment.url.startsWith("/uploads/")
          ? attachment.url.replace("/uploads/", "")
          : attachment.url.replace(/^\/+/, "");
        const resolvedPath = path.resolve(uploadsDir, relativePath);
        if (resolvedPath.startsWith(uploadsDir)) {
          filePath = resolvedPath;
        }
      }
    }

    if (!filePath || !fs.existsSync(filePath)) {
      return res
        .status(404)
        .json({ error: "Archivo no disponible en el servidor." });
    }

    const mimeType =
      attachment.type || mime.lookup(filePath) || "application/octet-stream";

    res.setHeader("Content-Type", mimeType as string);
    res.setHeader(
      "Content-Disposition",
      `inline; filename="${attachment.fileName}"`
    );

    res.sendFile(filePath);
  } catch (error) {
    console.error("Error al mostrar adjunto:", error);
    res.status(500).json({ error: "No se pudo mostrar el adjunto." });
  }
});

app.post(
  "/api/attachments/:id/sign",
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const userId = req.user?.userId;
      if (!userId) {
        return res.status(401).json({ error: "Usuario no autenticado." });
      }
      const consentRaw = req.body?.consent;
      const consent =
        consentRaw === true ||
        consentRaw === "true" ||
        consentRaw === 1 ||
        consentRaw === "1";
      if (!consent) {
        return res.status(400).json({
          error: "Debes aceptar el consentimiento para firmar el documento.",
        });
      }

      const consentStatementRaw =
        typeof req.body?.consentStatement === "string"
          ? req.body.consentStatement.trim()
          : "";
      const consentStatement =
        consentStatementRaw.length > 0
          ? consentStatementRaw
          : "El usuario consiente el uso de su firma manuscrita digital para este documento.";

      const page =
        req.body?.page !== undefined ? Number(req.body.page) : undefined;
      let x = req.body?.x !== undefined ? Number(req.body.x) : undefined;
      let y = req.body?.y !== undefined ? Number(req.body.y) : undefined;
      const width =
        req.body?.width !== undefined ? Number(req.body.width) : undefined;
      const height =
        req.body?.height !== undefined ? Number(req.body.height) : undefined;
      const baselineRaw = req.body?.baseline;
      const baseline =
        baselineRaw === true ||
        baselineRaw === "true" ||
        baselineRaw === 1 ||
        baselineRaw === "1";
      const baselineRatio =
        req.body?.baselineRatio !== undefined &&
        req.body?.baselineRatio !== null
          ? Number(req.body.baselineRatio)
          : undefined;
      let baselineEffective = baseline;
      let normalizedBaselineRatio =
        baselineRatio !== undefined
          ? Math.min(Math.max(baselineRatio, 0), 1)
          : undefined;

      if (
        (page !== undefined && Number.isNaN(page)) ||
        (x !== undefined && Number.isNaN(x)) ||
        (y !== undefined && Number.isNaN(y)) ||
        (width !== undefined && Number.isNaN(width)) ||
        (height !== undefined && Number.isNaN(height)) ||
        (baselineRatio !== undefined && Number.isNaN(baselineRatio))
      ) {
        return res
          .status(400)
          .json({ error: "Las coordenadas de firma no son válidas." });
      }

      const signature = await prisma.userSignature.findUnique({
        where: { userId },
      });

      if (!signature) {
        return res.status(400).json({
          error:
            "Debes registrar tu firma manuscrita antes de firmar documentos.",
        });
      }

      const attachment = await prisma.attachment.findUnique({ where: { id } });
      if (!attachment) {
        return res.status(404).json({ error: "Adjunto no encontrado." });
      }

      // Validar tenant a través del recurso relacionado
      const tenantId = (req as any).tenant?.id;
      if (tenantId && attachment) {
        let resourceTenantId: string | null = null;
        
        if (attachment.logEntryId) {
          const logEntry = await prisma.logEntry.findUnique({
            where: { id: attachment.logEntryId },
            select: { tenantId: true } as any,
          });
          resourceTenantId = (logEntry as any)?.tenantId || null;
        } else if (attachment.actaId) {
          const acta = await prisma.acta.findUnique({
            where: { id: attachment.actaId },
            select: { tenantId: true } as any,
          });
          resourceTenantId = (acta as any)?.tenantId || null;
        } else if (attachment.reportId) {
          const report = await prisma.report.findUnique({
            where: { id: attachment.reportId },
            select: { tenantId: true } as any,
          });
          resourceTenantId = (report as any)?.tenantId || null;
        } else if (attachment.communicationId) {
          const communication = await prisma.communication.findUnique({
            where: { id: attachment.communicationId },
            select: { tenantId: true } as any,
          });
          resourceTenantId = (communication as any)?.tenantId || null;
        } else if (attachment.costActaId) {
          const costActa = await prisma.costActa.findUnique({
            where: { id: attachment.costActaId },
            select: { tenantId: true } as any,
          });
          resourceTenantId = (costActa as any)?.tenantId || null;
        }
        
        if (resourceTenantId && resourceTenantId !== tenantId) {
          return res.status(404).json({ error: "Adjunto no encontrado." });
        }
      }

      if (attachment.type !== "application/pdf") {
        return res
          .status(400)
          .json({ error: "Solo se pueden firmar archivos PDF." });
      }

      // Determinar el documento base para acumulación de firmas: usar el último PDF firmado si existe
      let baseAttachment = attachment;
      {
        let documentType = "attachment";
        let documentId: string = attachment.id;
        if (attachment.logEntryId) {
          documentType = "logEntry";
          documentId = attachment.logEntryId;
        } else if (attachment.reportId) {
          documentType = "report";
          documentId = attachment.reportId;
        } else if (attachment.actaId) {
          documentType = "acta";
          documentId = attachment.actaId;
        } else if (attachment.communicationId) {
          documentType = "communication";
          documentId = attachment.communicationId;
        } else if (attachment.workActaId) {
          documentType = "workActa";
          documentId = attachment.workActaId;
        } else if (attachment.weeklyReportId) {
          documentType = "weeklyReport";
          documentId = attachment.weeklyReportId;
        } else if (attachment.costActaId) {
          documentType = "costActa";
          documentId = attachment.costActaId;
        }

        const latestSignature = await prisma.documentSignatureLog.findFirst({
          where: { documentType, documentId },
          orderBy: { createdAt: "desc" },
          include: { signedAttachment: true },
        });
        if (latestSignature?.signedAttachment?.id) {
          baseAttachment = latestSignature.signedAttachment as any;
        }

        // Reglas anti-duplicado para firmas manuscritas en anotaciones
        if (documentType === "logEntry") {
          const logEntry = await prisma.logEntry.findUnique({
            where: { id: documentId },
            include: { signatureTasks: true },
          });
          if (!logEntry) {
            return res.status(404).json({ error: "Anotación no encontrada." });
          }
          if (logEntry.status === "SIGNED") {
            return res.status(409).json({
              error: "El documento ya fue completamente firmado.",
              code: "DOCUMENT_LOCKED",
            });
          }
          const task = logEntry.signatureTasks.find(
            (t: any) => t.signerId === userId
          );
          if (!task) {
            return res.status(403).json({
              error: "No tienes tarea de firma asignada en esta anotación.",
            });
          }
          if (task.status === "SIGNED") {
            return res.status(409).json({
              error: "Ya has firmado esta anotación.",
              code: "ALREADY_SIGNED",
            });
          }
        }
      }

      // Obtener la contraseña del body para desencriptar la firma
      const { password: signaturePassword } = req.body || {};
      if (!signaturePassword) {
        return res.status(400).json({
          error: "Se requiere la contraseña para usar tu firma manuscrita.",
        });
      }

      // Verificar que la contraseña sea correcta
      const signer = await prisma.user.findUnique({
        where: { id: userId },
        select: { password: true },
      });
      if (!signer) {
        return res.status(404).json({ error: "Usuario no encontrado." });
      }
      const passwordMatches = await bcrypt.compare(signaturePassword, signer.password);
      if (!passwordMatches) {
        return res.status(401).json({
          error: "Contraseña incorrecta.",
        });
      }

      const [originalBuffer, signatureBuffer] = await Promise.all([
        loadAttachmentBuffer(baseAttachment),
        loadUserSignatureBuffer(signature, signaturePassword),
      ]);

      // Si no recibimos coordenadas, calcularlas automáticamente para alinear con el cuadro del firmante
      if ((x === undefined || y === undefined) && baseAttachment.logEntryId) {
        const logEntry = await prisma.logEntry.findUnique({
          where: { id: baseAttachment.logEntryId },
          include: {
            author: true,
            assignees: true,
            signatures: { include: { signer: true } },
            signatureTasks: {
              include: { signer: true },
              orderBy: { assignedAt: "asc" },
            },
          },
        });
        if (logEntry) {
          // Priorizar el índice tal como aparece en signatureTasks (que define el orden en PDF)
          const orderedTasks = (logEntry.signatureTasks || [])
            .filter((t: any) => t?.signer?.id)
            .sort(
              (a: any, b: any) =>
                new Date(a.assignedAt || 0).getTime() -
                new Date(b.assignedAt || 0).getTime()
            );
          let signerIndex = orderedTasks.findIndex(
            (t: any) => t.signer?.id === userId
          );
          if (signerIndex < 0) {
            // Si el firmante no está en tareas, ubicar en el primer recuadro pendiente
            signerIndex = orderedTasks.findIndex(
              (t: any) => t.status !== "SIGNED"
            );
          }
          if (signerIndex < 0) signerIndex = 0; // último recurso
          const MARGIN = 48; // Debe coincidir con pdfExport
          const BOX_H = 110;
          const GAP = 16;
          const LINE_Y = 72; // línea de firma relativa al inicio del box
          const LINE_X = 70; // desplazamiento respecto al margen izquierdo
          y =
            y === undefined ? MARGIN + signerIndex * (BOX_H + GAP) + LINE_Y : y;
          x = x === undefined ? MARGIN + LINE_X : x;
          if (width === undefined) {
            // ancho moderado para no invadir otros recuadros
            (width as any) = 220;
          }
          if (height === undefined) {
            // alto pequeño para caber entre la línea y el borde inferior
            (height as any) = 28;
          }
          baselineEffective = true;
          if (normalizedBaselineRatio === undefined)
            normalizedBaselineRatio = 0.25;
        }
      }

      const signedBuffer = await applySignatureToPdf({
        originalPdf: originalBuffer,
        signature: {
          buffer: signatureBuffer,
          mimeType: signature.mimeType || "image/png",
        },
        position: {
          page,
          x,
          y,
          width,
          height,
          baseline: baselineEffective,
          baselineRatio: normalizedBaselineRatio,
          fromTop: true,
        },
      });

      const storage = getStorage();
      const parsedFileName = path.parse(attachment.fileName || "documento.pdf");
      const signedFileName = `${parsedFileName.name}-firmado-${Date.now()}.pdf`;
      const signedKey = createStorageKey(
        "firmas",
        signedFileName
      );
      await storage.save({ path: signedKey, content: signedBuffer });
      const signedUrl = storage.getPublicUrl(signedKey);

      const signedAttachment = await prisma.attachment.create({
        data: {
          fileName: signedFileName,
          url: signedUrl,
          storagePath: signedKey,
          size: signedBuffer.length,
          type: "application/pdf",
          logEntryId: attachment.logEntryId ?? undefined,
          communicationId: attachment.communicationId ?? undefined,
          actaId: attachment.actaId ?? undefined,
          costActaId: attachment.costActaId ?? undefined,
          reportId: attachment.reportId ?? undefined,
          workActaId: attachment.workActaId ?? undefined,
          weeklyReportId: attachment.weeklyReportId ?? undefined,
          commentId: attachment.commentId ?? undefined,
        },
      });

      let documentType = "attachment";
      let documentId: string = attachment.id;
      if (attachment.logEntryId) {
        documentType = "logEntry";
        documentId = attachment.logEntryId;
      } else if (attachment.reportId) {
        documentType = "report";
        documentId = attachment.reportId;
      } else if (attachment.actaId) {
        documentType = "acta";
        documentId = attachment.actaId;
      } else if (attachment.communicationId) {
        documentType = "communication";
        documentId = attachment.communicationId;
      } else if (attachment.workActaId) {
        documentType = "workActa";
        documentId = attachment.workActaId;
      } else if (attachment.weeklyReportId) {
        documentType = "weeklyReport";
        documentId = attachment.weeklyReportId;
      } else if (attachment.costActaId) {
        documentType = "costActa";
        documentId = attachment.costActaId;
      }

      const signatureLog = await prisma.documentSignatureLog.create({
        data: {
          signerId: userId,
          documentType,
          documentId,
          originalPdfId: attachment.id,
          signedAttachmentId: signedAttachment.id,
        },
      });

      const responsePayload: any = {
        originalAttachmentId: baseAttachment.id,
        signedAttachment: buildAttachmentResponse(signedAttachment),
        auditLogId: signatureLog.id,
      };

      if (attachment.logEntryId) {
        await prisma.logEntrySignatureTask.updateMany({
          where: {
            logEntryId: attachment.logEntryId,
            signerId: userId,
          },
          data: {
            status: "SIGNED",
            signedAt: new Date(),
          },
        });

        const updatedTasks = await prisma.logEntrySignatureTask.findMany({
          where: { logEntryId: attachment.logEntryId },
          select: { status: true },
        });

        if (
          updatedTasks.length > 0 &&
          updatedTasks.every((task) => task.status === "SIGNED")
        ) {
          await prisma.logEntry.update({
            where: { id: attachment.logEntryId },
            data: { status: "SIGNED" },
          });
        }

        const refreshedEntry = await prisma.logEntry.findUnique({
          where: { id: attachment.logEntryId },
          include: {
            author: true,
            attachments: true,
            comments: {
              include: { author: true },
              orderBy: { timestamp: "asc" },
            },
            signatures: { include: { signer: true } },
            assignees: true,
            signatureTasks: {
              include: { signer: true },
              orderBy: { assignedAt: "asc" },
            },
            history: {
              include: { user: true },
              orderBy: { timestamp: "desc" },
            },
          },
        });
        if (refreshedEntry) {
          responsePayload.entry = formatLogEntry(refreshedEntry);
        }
      }

      res.status(201).json(responsePayload);
    } catch (error) {
      console.error("Error al firmar el documento PDF:", error);
      if (error instanceof Error) {
        res.status(400).json({ error: error.message });
      } else {
        res
          .status(500)
          .json({ error: "No se pudo firmar el documento solicitado." });
      }
    }
  }
);

// Endpoint temporal para migrar URLs de almacenamiento local a Cloudflare R2
app.post(
  "/api/admin/migrate-urls-to-r2",
  authMiddleware,
  requireAdmin,
  async (req: AuthRequest, res) => {
    try {
      const storage = getStorage();

      // Solo ejecutar si estamos usando Cloudflare R2
      if (process.env.STORAGE_DRIVER !== "cloudflare") {
        return res.status(400).json({
          error:
            "Esta migración solo funciona cuando STORAGE_DRIVER=cloudflare",
        });
      }

      console.log("Iniciando migración de URLs a Cloudflare R2...");

      // Buscar todos los attachments que tienen URLs locales
      const localAttachments = await prisma.attachment.findMany({
        where: {
          OR: [
            { url: { startsWith: "http://localhost" } },
            { url: { startsWith: "https://localhost" } },
            { url: { startsWith: "/uploads/" } },
            { url: { contains: "/uploads/" } },
          ],
        },
      });

      console.log(
        `Encontrados ${localAttachments.length} archivos con URLs locales`
      );

      let migratedCount = 0;
      let errorCount = 0;

      for (const attachment of localAttachments) {
        try {
          // Extraer el storage path desde la URL local
          let storagePath = attachment.storagePath;

          if (!storagePath && attachment.url) {
            // Intentar extraer el path desde la URL
            const urlPath = attachment.url.replace(/^.*\/uploads\//, "");
            storagePath = urlPath;
          }

          if (storagePath) {
            // Generar la nueva URL de Cloudflare R2
            const newUrl = storage.getPublicUrl(storagePath);

            // Actualizar el attachment con la nueva URL
            await prisma.attachment.update({
              where: { id: attachment.id },
              data: {
                url: newUrl,
                storagePath: storagePath,
              },
            });

            console.log(`✅ Migrado: ${attachment.fileName} -> ${newUrl}`);
            migratedCount++;
          } else {
            console.log(
              `⚠️  No se pudo determinar storagePath para: ${attachment.fileName}`
            );
            errorCount++;
          }
        } catch (error) {
          console.error(`❌ Error migrando ${attachment.fileName}:`, error);
          errorCount++;
        }
      }

      // También migrar UserSignatures si existen
      const localSignatures = await prisma.userSignature.findMany({
        where: {
          url: { contains: "localhost" },
        },
      });

      for (const signature of localSignatures) {
        try {
          if (signature.storagePath) {
            const newUrl = storage.getPublicUrl(signature.storagePath);
            await prisma.userSignature.update({
              where: { id: signature.id },
              data: { url: newUrl },
            });
            console.log(`✅ Firma migrada: ${signature.fileName} -> ${newUrl}`);
            migratedCount++;
          }
        } catch (error) {
          console.error(
            `❌ Error migrando firma ${signature.fileName}:`,
            error
          );
          errorCount++;
        }
      }

      res.json({
        success: true,
        message: `Migración completada. ${migratedCount} archivos migrados, ${errorCount} errores.`,
        migrated: migratedCount,
        errors: errorCount,
        totalProcessed: localAttachments.length + localSignatures.length,
      });
    } catch (error) {
      logger.error("Error durante la migración", {
        error: error instanceof Error ? error.message : String(error),
      });
      res.status(500).json({
        error: "Error durante la migración de URLs",
      });
    }
  }
);

// Database migration fix endpoint - SOLO PARA EMERGENCIAS
app.post(
  "/api/admin/fix-migrations",
  authMiddleware,
  requireAdmin,
  async (req: AuthRequest, res) => {
    try {
      console.log("🔧 Iniciando corrección de migraciones...");

      // Verificar que estemos en producción
      if (process.env.NODE_ENV !== "production") {
        return res.status(400).json({
          error: "Este endpoint solo se debe usar en producción",
        });
      }

      // Ejecutar comando para resolver migraciones fallidas
      const { exec } = require("child_process");
      const util = require("util");
      const execAsync = util.promisify(exec);

      try {
        // Primero, marcar la migración fallida como resuelta
        console.log("Marcando migración fallida como resuelta...");
        await execAsync(
          "npx prisma migrate resolve --applied 20250325100000_add_report_versions"
        );

        // Luego, aplicar las migraciones pendientes
        console.log("Aplicando migraciones pendientes...");
        await execAsync("npx prisma migrate deploy");

        console.log("✅ Migraciones corregidas exitosamente");

        res.json({
          success: true,
          message: "Migraciones de base de datos corregidas exitosamente",
          timestamp: new Date().toISOString(),
        });
      } catch (migrationError) {
        console.error("Error en migración:", migrationError);

        // Si falla, intentar solo deploy
        try {
          console.log("Intentando solo deploy...");
          await execAsync("npx prisma migrate deploy --accept-data-loss");

          res.json({
            success: true,
            message: "Migraciones aplicadas con data loss acceptance",
            warning: "Se usó --accept-data-loss",
            timestamp: new Date().toISOString(),
          });
        } catch (deployError) {
          throw deployError;
        }
      }
    } catch (error) {
      logger.error("Error corrigiendo migraciones", {
        error: error instanceof Error ? error.message : String(error),
      });
      res.status(500).json({
        error: "Error corrigiendo migraciones de base de datos",
      });
    }
  }
);

// Security monitoring endpoints (admin only)
app.get(
  "/api/admin/security/events",
  authMiddleware,
  requireAdmin,
  async (req: AuthRequest, res) => {
    try {
      const {
        type,
        severity,
        ipAddress,
        userId,
        startDate,
        endDate,
        limit = 100,
      } = req.query;

      const filters: any = {};
      if (type) filters.type = type;
      if (severity) filters.severity = severity;
      if (ipAddress) filters.ipAddress = ipAddress as string;
      if (userId) filters.userId = userId as string;
      if (startDate) filters.startDate = new Date(startDate as string);
      if (endDate) filters.endDate = new Date(endDate as string);
      filters.limit = parseInt(limit as string, 10) || 100;

      const events = await getSecurityEvents(filters);

      res.json({
        events,
        count: events.length,
        filters,
      });
    } catch (error) {
      logger.error("Error obteniendo eventos de seguridad", {
        error: error instanceof Error ? error.message : String(error),
        userId: req.user?.userId,
      });
      res.status(500).json({
        error: "No se pudieron obtener los eventos de seguridad.",
      });
    }
  }
);

app.get(
  "/api/admin/security/stats",
  authMiddleware,
  requireAdmin,
  async (req: AuthRequest, res) => {
    try {
      const stats = await getSecurityStats();
      res.json(stats);
    } catch (error) {
      logger.error("Error obteniendo estadísticas de seguridad", {
        error: error instanceof Error ? error.message : String(error),
        userId: req.user?.userId,
      });
      res.status(500).json({
        error: "No se pudieron obtener las estadísticas de seguridad.",
      });
    }
  }
);



// Health check endpoint
app.get("/", (req, res) => {
  res.json({
    status: "OK",
    message: "BDO Server API is running",
    timestamp: new Date().toISOString(),
    version: "1.0.0",
  });
});

app.get("/health", (req, res) => {
  res.json({
    status: "healthy",
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    storage: process.env.STORAGE_DRIVER || "local",
    lastUpdate: "2025-11-17 22:50",
  });
});

// Endpoint público para obtener usuarios de demostración
app.get("/api/public/demo-users", async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      where: { status: "active" },
      select: {
        id: true,
        fullName: true,
        email: true,
        projectRole: true,
        appRole: true,
        status: true,
        entity: true,
        cargo: true,
        avatarUrl: true,
      },
      orderBy: { fullName: "asc" },
    });

    const sanitized = users.map((user) => ({
      id: user.id,
      fullName: user.fullName,
      email: user.email,
      projectRole: user.projectRole,
      appRole: user.appRole,
      entity: user.entity || null,
      cargo: user.cargo || null,
      avatarUrl: user.avatarUrl || null,
      status: user.status,
    }));

    res.json(sanitized);
  } catch (error) {
    console.error("Error obteniendo usuarios de demo:", error);
    res.status(500).json({
      error: "Error interno del servidor",
      message: "No se pudieron obtener los usuarios de demostración",
    });
  }
});

app.get(
  "/api/notifications",
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const userId = req.user?.userId;
      if (!userId) {
        return res.status(401).json({ error: "Usuario no autenticado." });
      }

      const notifications = await buildUserNotifications(prisma, userId);
      res.json(notifications);
    } catch (error) {
      console.error("Error al obtener notificaciones:", error);
      res
        .status(500)
        .json({ error: "No se pudieron cargar las notificaciones." });
    }
  }
);

app.patch(
  "/api/notifications/:id/read",
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const userId = req.user?.userId;
      if (!userId) {
        return res.status(401).json({ error: "Usuario no autenticado." });
      }

      const { id } = req.params;
      const notification = await prisma.notification.findUnique({
        where: { id },
      });

      if (!notification) {
        return res.status(404).json({ error: "Notificación no encontrada." });
      }

      if (notification.recipientId !== userId) {
        return res.status(403).json({ error: "No autorizado." });
      }

      await prisma.notification.update({
        where: { id },
        data: { isRead: true },
      });

      res.json({ success: true });
    } catch (error) {
      console.error("Error al marcar notificación como leída:", error);
      res.status(500).json({ error: "No se pudo actualizar la notificación." });
    }
  }
);

app.get(
  "/api/project-details",
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const where = withTenantFilter(req);
      const project = await prisma.project.findFirst({
        where: Object.keys(where).length > 0 ? (where as any) : undefined,
        include: {
          keyPersonnel: {
            orderBy: {
              sortOrder: 'asc',
            },
          },
          corredorVialElements: {
            orderBy: {
              sortOrder: 'asc',
            },
          },
        },
      });

      if (!project) {
        return res
          .status(404)
          .json({ error: "No se encontró ningún proyecto." });
      }

      res.json(project);
    } catch (error) {
      console.error("Error al obtener detalles del proyecto:", error);
      res
        .status(500)
        .json({ error: "Error al obtener detalles del proyecto." });
    }
  }
);

app.get(
  "/api/contract-modifications",
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      // Si se solicita el summary, calcular y retornar el resumen
      if (req.query.summary === "1") {
        const where = withTenantFilter(req);
        const project = await prisma.project.findFirst({
          where: Object.keys(where).length > 0 ? (where as any) : undefined,
        });
        if (!project) {
          return res.status(404).json({
            error: "No se encontró ningún proyecto.",
          });
        }

        const modWhere = withTenantFilter(req);
        const modifications = await prisma.contractModification.findMany({
          where: Object.keys(modWhere).length > 0 ? (modWhere as any) : undefined,
          orderBy: { date: "desc" },
        });

        // El tope del 50% se calcula sobre el valor inicial del contrato
        const baseValue = project.initialValue || 0;
        const cap = baseValue * 0.5;

        // Separar adiciones que afectan el 50% de las que no (incorporaciones por mayores cantidades)
        const additionsAffecting = modifications
          .filter((mod) => 
            mod.type === "ADDITION" && 
            mod.value !== null && 
            (mod.affectsFiftyPercent === true || mod.affectsFiftyPercent === null) // null se trata como true por compatibilidad
          )
          .reduce((sum, mod) => sum + (mod.value || 0), 0);

        const additionsNonAffecting = modifications
          .filter((mod) => 
            mod.type === "ADDITION" && 
            mod.value !== null && 
            mod.affectsFiftyPercent === false
          )
          .reduce((sum, mod) => sum + (mod.value || 0), 0);

        const usedPercent = baseValue > 0 ? (additionsAffecting / baseValue) * 100 : 0;
        const remainingCap = Math.max(cap - additionsAffecting, 0);

        return res.json({
          baseValue,
          cap,
          additionsAffecting,
          additionsNonAffecting,
          usedPercent,
          remainingCap,
        });
      }

      // Si no es summary, retornar la lista normal
      const modWhere = withTenantFilter(req);
      const modifications = await prisma.contractModification.findMany({
        where: Object.keys(modWhere).length > 0 ? (modWhere as any) : undefined,
        orderBy: { date: "desc" },
        include: {
          attachment: true,
        },
      });

      const formatted = modifications.map((modification) => ({
        ...modification,
        date:
          modification.date instanceof Date
            ? modification.date.toISOString()
            : modification.date,
        type:
          modificationTypeReverseMap[modification.type] || modification.type,
        attachment: modification.attachment
          ? buildAttachmentResponse(modification.attachment)
          : null,
      }));

      res.json(formatted);
    } catch (error) {
      console.error("Error al obtener modificaciones contractuales:", error);
      res.status(500).json({
        error: "Error al obtener modificaciones contractuales.",
      });
    }
  }
);

app.post(
  "/api/contract-modifications",
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { number, type, date, value, days, justification, attachmentId, affectsFiftyPercent } =
        req.body ?? {};

      if (!number || !type || !date || !justification) {
        return res.status(400).json({
          error:
            "Faltan campos requeridos (número, tipo, fecha y justificación son obligatorios).",
        });
      }

      const prismaType = modificationTypeMap[type];
      if (!prismaType) {
        return res
          .status(400)
          .json({ error: "Tipo de modificación no reconocido." });
      }

      const parsedValueRaw =
        value !== undefined && value !== null && `${value}`.trim() !== ""
          ? Number(value)
          : null;
      const parsedValue =
        parsedValueRaw !== null && Number.isNaN(parsedValueRaw)
          ? null
          : parsedValueRaw;

      const parsedDaysRaw =
        days !== undefined && days !== null && `${days}`.trim() !== ""
          ? parseInt(days, 10)
          : null;
      const parsedDays =
        parsedDaysRaw !== null && Number.isNaN(parsedDaysRaw)
          ? null
          : parsedDaysRaw;

      // Para adiciones, affectsFiftyPercent es true por defecto (solo false si es incorporación por mayores cantidades)
      // Para otros tipos (prórrogas), no aplica
      const affectsFiftyPercentValue = 
        prismaType === "ADDITION" 
          ? (affectsFiftyPercent !== undefined ? Boolean(affectsFiftyPercent) : true)
          : null;

      // Asignar tenantId si está disponible
      const tenantId = (req as any).tenant?.id;
      const modData: any = {
        number,
        type: prismaType,
        date: new Date(date),
        value: parsedValue,
        days: parsedDays,
        justification,
        affectsFiftyPercent: affectsFiftyPercentValue,
        attachment: attachmentId
          ? { connect: { id: attachmentId } }
          : undefined,
      };
      if (tenantId) {
        modData.tenantId = tenantId;
      }

      const newModification = await prisma.contractModification.create({
        data: modData,
        include: {
          attachment: true,
        },
      });

      const formatted = {
        ...newModification,
        date:
          newModification.date instanceof Date
            ? newModification.date.toISOString()
            : newModification.date,
        type:
          modificationTypeReverseMap[newModification.type] ||
          newModification.type,
        attachment: newModification.attachment
          ? buildAttachmentResponse(newModification.attachment)
          : null,
      };

      res.status(201).json(formatted);
    } catch (error) {
      console.error("Error al crear modificación contractual:", error);
      if ((error as any)?.code === "P2002") {
        return res
          .status(409)
          .json({ error: "Ya existe una modificación con este número." });
      }
      res
        .status(500)
        .json({ error: "Error al crear la modificación contractual." });
    }
  }
);

app.post(
  "/api/chat/cometchat/session",
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const baseUrl = getCometChatBaseUrl();
      if (!baseUrl || !COMETCHAT_API_KEY) {
        return res
          .status(501)
          .json({ error: "CometChat no está configurado en el servidor." });
      }

      const userId = req.user?.userId;
      if (!userId) {
        return res.status(401).json({ error: "Usuario no autenticado." });
      }

      const dbUser = await prisma.user.findUnique({ where: { id: userId } });
      if (!dbUser) {
        return res.status(404).json({ error: "Usuario no encontrado." });
      }

      const headers: Record<string, string> = {
        accept: "application/json",
        "content-type": "application/json",
        apiKey: COMETCHAT_API_KEY,
      };

      const uid = dbUser.id;

      const userResponse = await fetch(`${baseUrl}/users/${uid}`, { headers });
      if (userResponse.status === 404) {
        const createResponse = await fetch(`${baseUrl}/users`, {
          method: "POST",
          headers,
          body: JSON.stringify({
            uid,
            name: dbUser.fullName || dbUser.email || uid,
            avatar: dbUser.avatarUrl || undefined,
            metadata: {
              email: dbUser.email,
              projectRole: dbUser.projectRole,
              appRole: dbUser.appRole,
            },
          }),
        });

        if (!createResponse.ok) {
          const body = await createResponse.text();
          logger.error("CometChat: error creando usuario", {
            status: createResponse.status,
            body,
          });
          return res
            .status(500)
            .json({ error: "No se pudo crear el usuario en CometChat." });
        }
      } else if (!userResponse.ok) {
        const body = await userResponse.text();
        logger.error("CometChat: error consultando usuario", {
          status: userResponse.status,
          body,
        });
        return res.status(500).json({
          error: "No se pudo sincronizar el usuario con CometChat.",
        });
      }

      const tokenResponse = await fetch(`${baseUrl}/users/${uid}/auth_tokens`, {
        method: "POST",
        headers,
      });

      if (!tokenResponse.ok) {
        const body = await tokenResponse.text();
        logger.error("CometChat: error generando token", {
          status: tokenResponse.status,
          body,
        });
        return res.status(500).json({
          error: "No se pudo generar el token de acceso para CometChat.",
        });
      }

      const tokenPayload: any = await tokenResponse.json();
      const authToken = tokenPayload?.data?.authToken;
      if (!authToken) {
        logger.error("CometChat: respuesta sin authToken", {
          data: tokenPayload,
        });
        return res
          .status(500)
          .json({ error: "Respuesta inválida de CometChat." });
      }

      res.json({
        appId: COMETCHAT_APP_ID,
        region: COMETCHAT_REGION,
        authToken,
      });
    } catch (error) {
      console.error("Error al generar sesión de CometChat:", error);
      res.status(500).json({
        error: "No se pudo iniciar sesión en CometChat.",
      });
    }
  }
);

// --- RUTAS PARA ACTAS DE COMITÉ ---
app.get("/api/actas", async (req, res) => {
  try {
    const where = withTenantFilter(req);
    const actas = await prisma.acta.findMany({
      where: Object.keys(where).length > 0 ? (where as any) : undefined,
      orderBy: { date: "desc" },
      include: {
        attachments: true,
        commitments: { include: { responsible: true } },
        signatures: { include: { signer: true } },
      },
    });
    res.json(actas.map(formatActa));
  } catch (error) {
    console.error("Error al obtener actas:", error);
    res.status(500).json({ error: "No se pudieron obtener las actas." });
  }
});

app.get("/api/actas/:id", authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { id } = req.params;
    const where = withTenantFilter(req, { id } as any);
    const acta = await prisma.acta.findFirst({
      where: Object.keys(where).length > 1 ? (where as any) : { id },
      include: {
        attachments: true,
        commitments: { include: { responsible: true } },
        signatures: { include: { signer: true } },
      },
    });

    if (!acta) {
      return res.status(404).json({ error: "Acta no encontrada." });
    }
    
    // Verificar que el tenant coincida si hay tenant
    if ((req as any).tenant && (acta as any).tenantId !== (req as any).tenant.id) {
      return res.status(404).json({ error: "Acta no encontrada." });
    }

    res.json(formatActa(acta));
  } catch (error) {
    console.error("Error al obtener acta:", error);
    res.status(500).json({ error: "No se pudo obtener el acta." });
  }
});

app.post("/api/actas", async (req, res) => {
  try {
    const {
      number,
      title,
      date,
      area,
      status,
      summary,
      commitments = [],
      attachments = [],
      requiredSignatories = [],
    } = req.body ?? {};

    if (!number || !title || !date) {
      return res.status(400).json({
        error: "Número, título y fecha son obligatorios para crear un acta.",
      });
    }

    const prismaArea = actaAreaMap[area] || "OTHER";
    const prismaStatus = actaStatusMap[status] || "DRAFT";

    // Asignar tenantId si está disponible
    const tenantId = (req as any).tenant?.id;
    const actaData: any = {
      number,
      title,
      date: new Date(date),
      area: prismaArea,
      status: prismaStatus,
      summary,
    };
    if (tenantId) {
      actaData.tenantId = tenantId;
    }

    const newActa = await prisma.acta.create({
      data: {
        ...actaData,
        commitments: {
          create: commitments.map((commitment: any) => ({
            description: commitment.description,
            dueDate: commitment.dueDate ? new Date(commitment.dueDate) : null,
            status: "PENDING",
            responsible: commitment.responsible?.id
              ? { connect: { id: commitment.responsible.id } }
              : undefined,
          })),
        },
        attachments: {
          create: attachments.map((att: any) => ({
            fileName: att.fileName,
            url: att.url,
            size: att.size,
            type: att.type,
          })),
        },
        requiredSignatoriesJson: JSON.stringify(
          (requiredSignatories || []).map((u: any) => u.id)
        ),
      },
      include: {
        commitments: { include: { responsible: true } },
        attachments: true,
        signatures: { include: { signer: true } },
      },
    });

    res.status(201).json(formatActa(newActa));
  } catch (error) {
    console.error("Error al crear el acta:", error);
    res.status(500).json({ error: "No se pudo crear el acta." });
  }
});

app.put("/api/actas/:id", authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { id } = req.params;
    const { number, title, date, area, status, summary } = req.body ?? {};

    // Verificar que el acta pertenezca al tenant
    const where = withTenantFilter(req, { id } as any);
    const existingActa = await prisma.acta.findFirst({
      where: Object.keys(where).length > 1 ? (where as any) : { id },
    });

    if (!existingActa) {
      return res.status(404).json({ error: "Acta no encontrada." });
    }
    
    // Verificar que el tenant coincida si hay tenant
    if ((req as any).tenant && (existingActa as any).tenantId !== (req as any).tenant.id) {
      return res.status(404).json({ error: "Acta no encontrada." });
    }

    const data: Record<string, unknown> = {};
    if (number) data.number = number;
    if (title) data.title = title;
    if (summary !== undefined) data.summary = summary;
    if (date) {
      const parsed = new Date(date);
      if (!Number.isNaN(parsed.getTime())) {
        data.date = parsed;
      }
    }
    if (area) {
      data.area =
        actaAreaMap[area] ||
        actaAreaMap[actaAreaReverseMap[area] || "Otro"] ||
        "OTHER";
    }
    if (status) {
      data.status =
        actaStatusMap[status] ||
        actaStatusMap[actaStatusReverseMap[status] || "En Borrador"] ||
        "DRAFT";
    }

    const updatedActa = await prisma.acta.update({
      where: { id },
      data,
      include: {
        commitments: {
          include: { responsible: true },
          orderBy: { dueDate: "asc" },
        },
        attachments: true,
        signatures: { include: { signer: true } },
      },
    });

    res.json(formatActa(updatedActa));
  } catch (error) {
    console.error("Error al actualizar acta:", error);
    if ((error as any)?.code === "P2025") {
      return res.status(404).json({ error: "Acta no encontrada." });
    }
    res.status(500).json({ error: "No se pudo actualizar el acta." });
  }
});

app.put(
  "/api/actas/:actaId/commitments/:commitmentId",
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { commitmentId } = req.params;
      const { status } = req.body ?? {};

      if (!status) {
        return res.status(400).json({ error: "El estado es obligatorio." });
      }

      const prismaStatus =
        commitmentStatusMap[status] ||
        commitmentStatusMap[
          commitmentStatusReverseMap[status] || "Pendiente"
        ] ||
        "PENDING";

      const updatedCommitment = await prisma.commitment.update({
        where: { id: commitmentId },
        data: { status: prismaStatus },
        include: { responsible: true },
      });

      res.json({
        ...updatedCommitment,
        status:
          commitmentStatusReverseMap[updatedCommitment.status] ||
          updatedCommitment.status,
      });
    } catch (error) {
      console.error("Error al actualizar compromiso:", error);
      if ((error as any)?.code === "P2025") {
        return res.status(404).json({ error: "Compromiso no encontrado." });
      }
      res.status(500).json({ error: "No se pudo actualizar el compromiso." });
    }
  }
);

app.post(
  "/api/actas/:actaId/commitments/:commitmentId/reminder",
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { actaId, commitmentId } = req.params;

      // Verificar que el acta pertenezca al tenant primero
      const tenantId = (req as any).tenant?.id;
      const actaWhere = tenantId ? { id: actaId, tenantId } as any : { id: actaId };
      const acta = await prisma.acta.findFirst({
        where: actaWhere,
        select: { id: true },
      });
      
      if (!acta) {
        return res.status(404).json({ error: "Acta no encontrada." });
      }

      const commitment = await prisma.commitment.findFirst({
        where: { id: commitmentId, actaId },
        include: {
          responsible: true,
          acta: { select: { number: true, title: true } },
        },
      });

      if (!commitment) {
        return res.status(404).json({ error: "Compromiso no encontrado." });
      }

      if (commitment.responsible?.email) {
        try {
          const dueDate = commitment.dueDate ?? new Date();
          const msDiff = dueDate.getTime() - Date.now();
          const daysUntilDue = Math.floor(msDiff / (1000 * 60 * 60 * 24));

          await sendCommitmentReminderEmail({
            to: commitment.responsible.email,
            recipientName: commitment.responsible.fullName,
            commitments: [
              {
                id: commitment.id,
                description: commitment.description,
                dueDate,
                actaNumber: commitment.acta?.number ?? null,
                actaTitle: commitment.acta?.title ?? null,
                daysUntilDue,
              },
            ],
          });
        } catch (emailError) {
          console.warn(
            "No se pudo enviar correo de recordatorio de compromiso.",
            emailError
          );
        }
      }

      res.json({ message: "Recordatorio procesado correctamente." });
    } catch (error) {
      console.error("Error al enviar recordatorio de compromiso:", error);
      res.status(500).json({ error: "No se pudo enviar el recordatorio." });
    }
  }
);

app.post(
  "/api/actas/:id/signatures",
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const { signerId, password } = req.body ?? {};

      if (!signerId || !password) {
        return res
          .status(400)
          .json({ error: "Se requieren el firmante y la contraseña." });
      }

      const signer = await prisma.user.findUnique({ where: { id: signerId } });
      if (!signer) {
        return res.status(404).json({ error: "Firmante no encontrado." });
      }

      const validPassword = await bcrypt.compare(password, signer.password);
      if (!validPassword) {
        return res.status(401).json({ error: "Contraseña incorrecta." });
      }

      // Verificar que el acta pertenezca al tenant
      const where = withTenantFilter(req, { id } as any);
      const acta = await prisma.acta.findFirst({
        where: Object.keys(where).length > 1 ? (where as any) : { id },
      });
      if (!acta) {
        return res.status(404).json({ error: "Acta no encontrada." });
      }
      
      // Verificar que el tenant coincida si hay tenant
      if ((req as any).tenant && (acta as any).tenantId !== (req as any).tenant.id) {
        return res.status(404).json({ error: "Acta no encontrada." });
      }

      const existingSignature = await prisma.signature.findFirst({
        where: { actaId: id, signerId },
      });

      if (existingSignature) {
        await prisma.signature.update({
          where: { id: existingSignature.id },
          data: { signedAt: new Date() },
        });
      } else {
        await prisma.signature.create({
          data: {
            signer: { connect: { id: signerId } },
            acta: { connect: { id } },
          },
        });
      }

      const updatedActa = await prisma.acta.findUnique({
        where: { id },
        include: {
          commitments: {
            include: { responsible: true },
            orderBy: { dueDate: "asc" },
          },
          attachments: true,
          signatures: { include: { signer: true } },
        },
      });

      if (!updatedActa) {
        return res
          .status(404)
          .json({ error: "Acta no encontrada tras firmar." });
      }

      res.json(formatActa(updatedActa));
    } catch (error) {
      console.error("Error al firmar acta:", error);
      res.status(500).json({ error: "No se pudo firmar el acta." });
    }
  }
);

// --- RUTAS DE BITÁCORA ---
app.get("/api/log-entries", authMiddleware, async (req: AuthRequest, res) => {
  try {
    const where = withTenantFilter(req);
    const entries = await prisma.logEntry.findMany({
      where: Object.keys(where).length > 0 ? (where as any) : undefined,
      orderBy: { createdAt: "desc" },
      include: logEntryResponseInclude as any,
    });

    const formattedEntries = entries.map((entry) => ({
      ...formatLogEntry(entry),
      attachments: (entry.attachments || []).map(buildAttachmentResponse),
    }));

    res.json(formattedEntries);
  } catch (error) {
    logger.error("Error al obtener anotaciones", {
      error: error instanceof Error ? error.message : String(error),
      stack: isProduction ? undefined : (error instanceof Error ? error.stack : undefined),
    });
    res.status(500).json({ 
      error: "No se pudieron obtener las anotaciones.",
    });
  }
});

app.post(
  "/api/log-entries",
  (req, res, next) => {
    console.log("🔵 MIDDLEWARE: Petición POST /api/log-entries recibida");
    console.log("🔵 MIDDLEWARE: Content-Type:", req.headers["content-type"]);
    console.log("🔵 MIDDLEWARE: Body keys (antes de multer):", Object.keys(req.body || {}));
    next();
  },
  authMiddleware,
  (req, res, next) => {
    console.log("🟢 MIDDLEWARE: Después de authMiddleware");
    console.log("🟢 MIDDLEWARE: User autenticado:", (req as AuthRequest).user?.userId);
    next();
  },
  (req, res, next) => {
    upload.array("attachments", 10)(req, res, (err) => {
      if (err) {
        console.error("❌ ERROR en multer:", err);
        return res.status(400).json({ error: "Error procesando archivos: " + err.message });
      }
      console.log("🟡 MIDDLEWARE: Después de upload.array");
      console.log("🟡 MIDDLEWARE: Files recibidos:", req.files?.length || 0);
      console.log("🟡 MIDDLEWARE: Body keys (después de multer):", Object.keys(req.body || {}));
      next();
    });
  },
  validateUploadedFiles, // Validar magic bytes después de multer
  async (req: AuthRequest, res) => {
    console.log("=== INICIO POST /api/log-entries ===");
    console.log("DEBUG: Método:", req.method);
    console.log("DEBUG: URL:", req.url);
    console.log("DEBUG: Headers content-type:", req.headers["content-type"]);
    try {
      const userId = req.user?.userId;
      console.log("DEBUG: User ID:", userId);
      if (!userId) {
        console.error("❌ ERROR: Usuario no autenticado");
        return res.status(401).json({ error: "Usuario no autenticado." });
      }
      
      console.log("DEBUG: req.body existe?", !!req.body);
      console.log("DEBUG: req.body keys:", Object.keys(req.body || {}));

      const {
        title,
        description,
        type,
        status,
        subject,
        location,
        entryDate,
        activityStartDate,
        activityEndDate,
        isConfidential,
        projectId,
        assigneeIds = [],
        scheduleDay,
      } = req.body ?? {};

      // Leer requiredSignatories directamente de req.body (no del destructuring)
      // porque puede no estar presente y el destructuring le asignaría []
      const rawRequiredSignatories = (req.body as any)?.requiredSignatories;
      
      console.log("DEBUG: Body completo recibido:", Object.keys(req.body || {}));
      console.log("DEBUG: requiredSignatories recibido:", {
        raw: rawRequiredSignatories,
        type: typeof rawRequiredSignatories,
        exists: rawRequiredSignatories !== undefined,
      });

      console.log("DEBUG: Campos extraídos:", {
        title: title ? `${title.substring(0, 50)}...` : null,
        description: description ? `${description.substring(0, 50)}...` : null,
        type,
        status,
        projectId,
        hasEntryDate: !!entryDate,
        hasActivityDates: !!activityStartDate || !!activityEndDate,
        isConfidential,
        assigneeIdsCount: Array.isArray(assigneeIds) ? assigneeIds.length : 0,
      });

      if (!title || !description || !type) {
        console.error("❌ ERROR: Campos obligatorios faltantes", {
          hasTitle: !!title,
          hasDescription: !!description,
          hasType: !!type,
        });
        return res.status(400).json({
          error: "Título, descripción y tipo son obligatorios.",
        });
      }

      if (!projectId || typeof projectId !== "string") {
        console.error("❌ ERROR: projectId inválido", {
          projectId,
          type: typeof projectId,
        });
        return res
          .status(400)
          .json({ error: "El identificador del proyecto es obligatorio." });
      }

      const prismaType = entryTypeMap[type] || entryTypeMap["General"];
      const prismaStatus =
        entryStatusMap[status] ||
        entryStatusMap[entryStatusReverseMap[status] || "Borrador"] ||
        "DRAFT";

      const entryDateValue = entryDate ? new Date(entryDate) : new Date();
      const activityStartValue = activityStartDate
        ? new Date(activityStartDate)
        : entryDateValue;
      const activityEndValue = activityEndDate
        ? new Date(activityEndDate)
        : entryDateValue;

      const storage = getStorage();
      const attachmentRecords: {
        fileName: string;
        url: string;
        size: number;
        type: string;
        storagePath: string;
      }[] = [];

      if (req.files && Array.isArray(req.files)) {
        for (const file of req.files as Express.Multer.File[]) {
          const key = createStorageKey(
            "bitacora",
            file.originalname
          );
          await storage.save({ path: key, content: file.buffer });
          attachmentRecords.push({
            fileName: file.originalname,
            url: storage.getPublicUrl(key),
            size: file.size,
            type: file.mimetype,
            storagePath: key,
          });
        }
      }
      
      // Procesar requiredSignatories (puede venir como JSON string o array)
      // Con multipart/form-data, los campos JSON vienen como strings
      let requiredSignerIds: string[] = [];
      
      console.log("═══════════════════════════════════════════════════════");
      console.log("🔍 PROCESANDO REQUIRED SIGNATORIES");
      console.log("═══════════════════════════════════════════════════════");
      console.log("rawRequiredSignatories:", rawRequiredSignatories);
      console.log("Tipo:", typeof rawRequiredSignatories);
      console.log("Es undefined?", rawRequiredSignatories === undefined);
      console.log("Es null?", rawRequiredSignatories === null);
      console.log("Es string vacío?", rawRequiredSignatories === "");
      
      if (rawRequiredSignatories !== undefined && rawRequiredSignatories !== null && rawRequiredSignatories !== "") {
        try {
          let parsed: any;
          if (typeof rawRequiredSignatories === "string") {
            console.log("Es string, parseando JSON...");
            parsed = JSON.parse(rawRequiredSignatories);
          } else if (Array.isArray(rawRequiredSignatories)) {
            console.log("Es array, usando directamente...");
            parsed = rawRequiredSignatories;
          } else {
            console.log("Es otro tipo, usando directamente...");
            parsed = rawRequiredSignatories;
          }
          console.log("✅ Parseado exitosamente:", parsed);
          requiredSignerIds = extractUserIds(parsed);
          console.log("✅ IDs extraídos:", requiredSignerIds);
        } catch (e: any) {
          console.error("❌ ERROR procesando requiredSignatories:", e.message);
          console.error("Stack:", e.stack);
          requiredSignerIds = [];
        }
      } else {
        console.log("⚠️ requiredSignatories no está presente o está vacío");
      }

      // Incluir al autor si no está en la lista
      const uniqueSignerIds = Array.from(
        new Set([...requiredSignerIds, userId])
      );
      console.log("✅ uniqueSignerIds final (incluyendo autor):", uniqueSignerIds);
      console.log("═══════════════════════════════════════════════════════");

      // Procesar scheduleDay
      let parsedScheduleDay: number | null = null;
      if (scheduleDay !== undefined && scheduleDay !== null && scheduleDay !== "") {
        if (typeof scheduleDay === "string") {
          // Extraer el número del string "Día X del proyecto" o similar
          const match = scheduleDay.match(/Día\s+(\d+)/i);
          if (match) {
            parsedScheduleDay = parseInt(match[1], 10);
          } else {
            // Si no coincide con el patrón, intentar parsear directamente
            const directParse = parseInt(scheduleDay, 10);
            parsedScheduleDay = isNaN(directParse) ? null : directParse;
          }
        } else if (typeof scheduleDay === "number") {
          parsedScheduleDay = scheduleDay;
        }
      }

      console.log("DEBUG: Intentando crear LogEntry en Prisma...");
      let logEntry;
      try {
        // Asignar tenantId si está disponible
        const tenantId = (req as any).tenant?.id;
        const logEntryData: any = {
          title,
          description,
          type: prismaType,
          status: prismaStatus,
          entryDate: entryDateValue,
          subject: typeof subject === "string" ? subject : "",
          location: typeof location === "string" ? location : "",
          activityStartDate: activityStartValue,
          activityEndDate: activityEndValue,
          isConfidential: parseBooleanInput(isConfidential),
          scheduleDay: parsedScheduleDay,
          author: { connect: { id: userId } },
          project: { connect: { id: projectId } },
        };
        if (tenantId) {
          logEntryData.tenantId = tenantId;
        }
        
        logEntry = await prisma.logEntry.create({
          data: {
            ...logEntryData,
            assignees: {
              connect: (Array.isArray(assigneeIds) ? assigneeIds : [])
                .filter((id) => typeof id === "string" && id.trim().length > 0)
                .map((id) => ({ id })),
            },
            attachments: {
              create: attachmentRecords.map((att) => ({
                fileName: att.fileName,
                url: att.url,
                size: att.size,
                type: att.type,
                storagePath: att.storagePath,
              })),
            },
          },
        });
      console.log("✅ LogEntry creado exitosamente:", { id: logEntry.id, title: logEntry.title });
      
      // Registrar la creación inicial en el historial
      try {
        const author = await prisma.user.findUnique({ 
          where: { id: userId }, 
          select: { fullName: true } 
        });
        const authorName = author?.fullName || "Usuario";
        
        await prisma.logEntryHistory.create({
          data: {
            logEntryId: logEntry.id,
            userId: userId,
            fieldName: "created",
            oldValue: null,
            newValue: `Anotación creada por ${authorName}`,
            timestamp: new Date(),
          },
        });
        console.log("✅ Historial de creación registrado");
      } catch (historyError) {
        console.warn("⚠️ No se pudo registrar el historial de creación:", historyError);
        if (historyError instanceof Error) {
          console.warn("Historial error message:", historyError.message);
        }
        // No fallar la creación si hay error con el historial
      }
      } catch (prismaError: any) {
        console.error("❌ ERROR al crear LogEntry en Prisma:", prismaError);
        if (prismaError instanceof Prisma.PrismaClientKnownRequestError) {
          console.error("Prisma error code:", prismaError.code);
          console.error("Prisma error meta:", prismaError.meta);
          if (prismaError.code === "P2002") {
            const target = (prismaError.meta as any)?.target;
            const isEntryDateConstraint = 
              (Array.isArray(target) && target.includes("LogEntry_projectId_entryDate_key")) ||
              (typeof target === "string" && target === "LogEntry_projectId_entryDate_key");
            
            if (isEntryDateConstraint) {
              console.log("✅ Error de constraint de fecha detectado, retornando 409");
              return res.status(409).json({
                error:
                  "Ya existe una bitácora registrada para este proyecto en la fecha seleccionada.",
              });
            }
          }
        }
        throw prismaError; // Re-lanzar para que sea capturado por el catch externo
      }

      // Crear tareas de revisión para los asignados (si hay asignados y el estado es NEEDS_REVIEW)
      const assigneeArray = Array.isArray(assigneeIds) ? assigneeIds : [];
      const validAssigneeIds = assigneeArray
        .filter((id) => typeof id === "string" && id.trim().length > 0);
      
      if (validAssigneeIds.length > 0 && prismaStatus === "NEEDS_REVIEW") {
        console.log("DEBUG: ===== CREACIÓN DE TAREAS DE REVISIÓN =====");
        console.log("DEBUG: assigneeIds:", validAssigneeIds);
        
        try {
          await (prisma as any).logEntryReviewTask.createMany({
            data: validAssigneeIds.map((assigneeId) => ({
              logEntryId: logEntry.id,
              reviewerId: assigneeId,
              status: "PENDING",
              assignedAt: new Date(),
            })),
            skipDuplicates: true,
          });
          console.log("DEBUG: ✓ Tareas de revisión creadas exitosamente");
        } catch (error: any) {
          console.error("DEBUG: ✗ ERROR creando tareas de revisión:", error);
          // No fallar la creación si hay error con las tareas de revisión
        }
      }

      // Crear tareas de firma para los firmantes requeridos
      console.log("DEBUG: ===== CREACIÓN DE TAREAS DE FIRMA =====");
      console.log("DEBUG: requiredSignerIds extraídos:", requiredSignerIds);
      console.log("DEBUG: userId (autor):", userId);
      console.log("DEBUG: uniqueSignerIds (incluyendo autor):", uniqueSignerIds);
      console.log("DEBUG: Cantidad de firmantes:", uniqueSignerIds.length);
      
      if (uniqueSignerIds.length > 0) {
        // Verificar que ningún firmante sea un viewer
        const signers = await prisma.user.findMany({
          where: { id: { in: uniqueSignerIds } },
          select: { id: true, appRole: true, fullName: true },
        });
        
        const viewerSigners = signers.filter((s) => s.appRole === "viewer");
        if (viewerSigners.length > 0) {
          const viewerNames = viewerSigners.map((s) => s.fullName).join(", ");
          return res.status(400).json({
            error: `Los usuarios con rol 'viewer' no pueden ser firmantes: ${viewerNames}`,
            code: "VIEWER_CANNOT_BE_SIGNER",
          });
        }
        
        const createdTasks: string[] = [];
        for (const signerId of uniqueSignerIds) {
          try {
            console.log("DEBUG: Intentando crear tarea para signerId:", signerId);
            const task = await prisma.logEntrySignatureTask.create({
              data: {
                logEntryId: logEntry.id,
                signerId,
                status: "PENDING",
                assignedAt: new Date(),
                signedAt: null, // Explícitamente null para tareas pendientes
              },
            });
            createdTasks.push(task.id);
            console.log("DEBUG: ✓ Tarea de firma creada exitosamente:", {
              taskId: task.id,
              signerId: signerId,
              logEntryId: logEntry.id,
            });

            // Enviar correo de notificación al firmante
            try {
              const signer = await prisma.user.findUnique({
                where: { id: signerId },
                select: { email: true, fullName: true },
              });

              if (signer && signer.email) {
                const author = await prisma.user.findUnique({
                  where: { id: userId },
                  select: { fullName: true },
                });

                await sendSignatureAssignmentEmail({
                  to: signer.email,
                  recipientName: signer.fullName,
                  assignerName: author?.fullName || "Un usuario",
                  logEntry: {
                    id: logEntry.id,
                    folioNumber: logEntry.folioNumber,
                    title: logEntry.title,
                    entryDate: logEntry.entryDate,
                  },
                });
                console.log("DEBUG: ✓ Correo de notificación enviado a:", signer.email);
              }
            } catch (emailError: any) {
              console.error("DEBUG: ✗ ERROR enviando correo de notificación:", {
                signerId: signerId,
                error: emailError.message,
              });
              // No fallar la creación de la bitácora si el correo falla
            }
          } catch (error: any) {
            console.error("DEBUG: ✗ ERROR creando tarea de firma:", {
              signerId: signerId,
              error: error.message,
              code: error.code,
              meta: error.meta,
            });
          }
        }
        console.log("DEBUG: Total de tareas creadas:", createdTasks.length, "de", uniqueSignerIds.length);
        console.log("DEBUG: IDs de tareas creadas:", createdTasks);
      } else {
        console.warn("DEBUG: ⚠️ No hay firmantes para crear tareas de firma (uniqueSignerIds está vacío)");
      }
      console.log("DEBUG: ===== FIN CREACIÓN DE TAREAS DE FIRMA =====");

      const entryWithRelations = await prisma.logEntry.findUnique({
        where: { id: logEntry.id },
        include: logEntryResponseInclude as any,
      });

      if (!entryWithRelations) {
        throw new Error("No se pudo recuperar la anotación recién creada.");
      }

      let formattedEntry;
      try {
        formattedEntry = formatLogEntry(entryWithRelations);
        console.log("DEBUG: ===== RESPUESTA FINAL =====");
        console.log("DEBUG: Anotación ID:", formattedEntry.id);
        console.log("DEBUG: Tareas de firma en entryWithRelations:", entryWithRelations.signatureTasks?.length || 0);
        console.log("DEBUG: Tareas de firma en formattedEntry:", formattedEntry.signatureTasks?.length || 0);
        if (entryWithRelations.signatureTasks && entryWithRelations.signatureTasks.length > 0) {
          console.log("DEBUG: Detalles de tareas de firma:", entryWithRelations.signatureTasks.map((t: any) => ({
            id: t.id,
            signerId: t.signerId,
            signerName: t.signer?.fullName,
            status: t.status,
          })));
        }
        console.log("DEBUG: Firmas normalizadas:", formattedEntry.signatures?.map((s: any) => ({
          signerId: s.signerId,
          signerName: s.signer?.fullName,
          signedAt: s.signedAt,
          signatureTaskStatus: s.signatureTaskStatus,
        })));
        console.log("DEBUG: Resumen de firmas:", formattedEntry.signatureSummary);
        console.log("DEBUG: ===== FIN RESPUESTA =====");
      } catch (formatError: any) {
        console.error("❌ ERROR al formatear la anotación:", formatError);
        console.error("Stack:", formatError.stack);
        throw formatError;
      }
      console.log("=== FIN POST /api/log-entries ===");
      res.status(201).json(formattedEntry);
    } catch (error) {
      console.error("❌ ERROR al crear anotación:", error);
      if (error instanceof Error) {
        console.error("Error message:", error.message);
        console.error("Error stack:", error.stack);
      }
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        console.error("Prisma error code:", error.code);
        console.error("Prisma error meta:", error.meta);
        if (error.code === "P2002") {
          const target = (error.meta as any)?.target;
          const isEntryDateConstraint = 
            (Array.isArray(target) && target.includes("LogEntry_projectId_entryDate_key")) ||
            (typeof target === "string" && target === "LogEntry_projectId_entryDate_key");
          
          if (isEntryDateConstraint) {
            console.log("✅ Error de constraint de fecha detectado en catch externo, retornando 409");
            return res.status(409).json({
              error:
                "Ya existe una bitácora registrada para este proyecto en la fecha seleccionada.",
            });
          }
        }
      }
      res.status(500).json({ 
        error: "No se pudo crear la anotación.",
        details: error instanceof Error ? error.message : String(error)
      });
    }
  }
);

app.get(
  "/api/log-entries/:id",
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const where = withTenantFilter(req, { id } as any);
      const entry = await prisma.logEntry.findFirst({
        where: Object.keys(where).length > 1 ? where : { id },
        include: logEntryResponseInclude as any,
      });

      if (!entry) {
        return res.status(404).json({ error: "Anotación no encontrada." });
      }
      
      // Verificar que el tenant coincida si hay tenant
      if ((req as any).tenant && (entry as any).tenantId !== (req as any).tenant.id) {
        return res.status(404).json({ error: "Anotación no encontrada." });
      }

      const formattedEntry = {
        ...formatLogEntry(entry),
        attachments: (entry.attachments || []).map(buildAttachmentResponse),
      };

      res.json(formattedEntry);
    } catch (error) {
      console.error("Error al obtener anotación:", error);
      res.status(500).json({ error: "No se pudo obtener la anotación." });
    }
  }
);

app.post(
  "/api/log-entries/:id/send-to-contractor",
  authMiddleware,
  requireEditor,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const userId = req.user?.userId;

      if (!userId) {
        return res.status(401).json({ error: "Usuario no autenticado." });
      }

      // Verificar que el log entry pertenezca al tenant
      const where = withTenantFilter(req, { id } as any);
      const entry = await prisma.logEntry.findFirst({
        where: Object.keys(where).length > 1 ? (where as any) : { id },
        include: { author: true },
      });

      if (!entry) {
        return res.status(404).json({ error: "Anotación no encontrada." });
      }
      
      // Verificar que el tenant coincida si hay tenant
      if ((req as any).tenant && (entry as any).tenantId !== (req as any).tenant.id) {
        return res.status(404).json({ error: "Anotación no encontrada." });
      }

      if (entry.status !== "DRAFT") {
        return res.status(400).json({
          error:
            "Solo puedes enviar al contratista una anotación que esté en borrador.",
          code: "INVALID_STATUS_FOR_CONTRACTOR_REVIEW",
        });
      }

      const currentUser = await prisma.user.findUnique({
        where: { id: userId },
        select: { id: true, fullName: true, appRole: true, projectRole: true },
      });

      if (!currentUser) {
        return res.status(404).json({ error: "Usuario no encontrado." });
      }

      const isAdmin = currentUser.appRole === "admin";
      const isAuthor = entry.authorId === userId;

      if (!isAuthor && !isAdmin) {
        return res.status(403).json({
          error:
            "Solo la interventoría que creó la anotación (o un administrador) puede enviarla al contratista.",
          code: "ONLY_AUTHOR_CAN_SEND_CONTRACTOR",
        });
      }

      const updatedEntry = await prisma.logEntry.update({
        where: { id },
        data: {
          status: "SUBMITTED",
          contractorReviewCompleted: false,
          contractorReviewCompletedAt: null,
          contractorReviewerId: null,
        },
        include: logEntryResponseInclude as any,
      });

      await recordLogEntryChanges(id, userId, [
        {
          fieldName: getFieldLabel("status"),
          oldValue: getStatusDisplayName(entry.status),
          newValue: getStatusDisplayName("SUBMITTED"),
        },
        {
          fieldName: "Flujo",
          oldValue: null,
          newValue: `${currentUser.fullName || "Usuario"} envió la anotación al contratista para revisión.`,
        },
      ]);

      const formattedEntry = {
        ...formatLogEntry(updatedEntry),
        attachments: (updatedEntry.attachments || []).map(buildAttachmentResponse),
      };

      res.json(formattedEntry);
    } catch (error) {
      console.error("Error al enviar anotación al contratista:", error);
      res.status(500).json({
        error: "No se pudo enviar la anotación al contratista.",
      });
    }
  }
);

app.post(
  "/api/log-entries/:id/contractor-review/complete",
  authMiddleware,
  requireEditor,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const userId = req.user?.userId;

      if (!userId) {
        return res.status(401).json({ error: "Usuario no autenticado." });
      }

      // Verificar que el log entry pertenezca al tenant
      const where = withTenantFilter(req, { id } as any);
      const entry = await prisma.logEntry.findFirst({
        where: Object.keys(where).length > 1 ? (where as any) : { id },
        include: { assignees: true },
      });

      if (!entry) {
        return res.status(404).json({ error: "Anotación no encontrada." });
      }
      
      // Verificar que el tenant coincida si hay tenant
      if ((req as any).tenant && (entry as any).tenantId !== (req as any).tenant.id) {
        return res.status(404).json({ error: "Anotación no encontrada." });
      }

      if (entry.status !== "SUBMITTED") {
        return res.status(400).json({
          error:
            "Solo se puede completar la revisión del contratista cuando la anotación está en estado 'Revisión contratista'.",
          code: "NOT_IN_CONTRACTOR_REVIEW",
        });
      }

      if (entry.contractorReviewCompleted) {
        return res.status(409).json({
          error: "La revisión del contratista ya fue registrada.",
          code: "CONTRACTOR_REVIEW_ALREADY_COMPLETED",
        });
      }

      const currentUser = await prisma.user.findUnique({
        where: { id: userId },
        select: { id: true, fullName: true, appRole: true, projectRole: true },
      });

      if (!currentUser) {
        return res.status(404).json({ error: "Usuario no encontrado." });
      }

      const isAdmin = currentUser.appRole === "admin";
      const isContractor = currentUser.projectRole === "CONTRACTOR_REP";
      const isAssignee =
        entry.assignees?.some((assignee: any) => assignee.id === userId) ||
        false;

      if (!isAdmin && !isContractor && !isAssignee) {
        return res.status(403).json({
          error:
            "Solo un representante del contratista asignado puede cerrar la revisión.",
          code: "CONTRACTOR_ONLY_ACTION",
        });
      }

      const updatedEntry = await prisma.logEntry.update({
        where: { id },
        data: {
          status: "NEEDS_REVIEW",
          contractorReviewCompleted: true,
          contractorReviewCompletedAt: new Date(),
          contractorReviewerId: userId,
        },
        include: logEntryResponseInclude as any,
      });

      await recordLogEntryChanges(id, userId, [
        {
          fieldName: getFieldLabel("status"),
          oldValue: getStatusDisplayName("SUBMITTED"),
          newValue: getStatusDisplayName("NEEDS_REVIEW"),
        },
        {
          fieldName: "Flujo",
          oldValue: null,
          newValue: `${currentUser.fullName || "Usuario"} completó la revisión del contratista.`,
        },
      ]);

      const formattedEntry = {
        ...formatLogEntry(updatedEntry),
        attachments: (updatedEntry.attachments || []).map(buildAttachmentResponse),
      };

      res.json(formattedEntry);
    } catch (error) {
      console.error("Error al completar revisión del contratista:", error);
      res.status(500).json({
        error: "No se pudo completar la revisión del contratista.",
      });
    }
  }
);

app.post(
  "/api/log-entries/:id/return-to-contractor",
  authMiddleware,
  requireEditor,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const userId = req.user?.userId;
      const { reason } = req.body ?? {};

      if (!userId) {
        return res.status(401).json({ error: "Usuario no autenticado." });
      }

      // Verificar que el log entry pertenezca al tenant
      const where = withTenantFilter(req, { id } as any);
      const entry = await prisma.logEntry.findFirst({
        where: Object.keys(where).length > 1 ? (where as any) : { id },
        include: { author: true },
      });

      if (!entry) {
        return res.status(404).json({ error: "Anotación no encontrada." });
      }
      
      // Verificar que el tenant coincida si hay tenant
      if ((req as any).tenant && (entry as any).tenantId !== (req as any).tenant.id) {
        return res.status(404).json({ error: "Anotación no encontrada." });
      }

      if (entry.status !== "NEEDS_REVIEW") {
        return res.status(400).json({
          error:
            "Solo se puede devolver al contratista una anotación que esté en revisión final.",
          code: "NOT_IN_FINAL_REVIEW",
        });
      }

      const currentUser = await prisma.user.findUnique({
        where: { id: userId },
        select: { id: true, fullName: true, appRole: true },
      });

      if (!currentUser) {
        return res.status(404).json({ error: "Usuario no encontrado." });
      }

      const isAdmin = currentUser.appRole === "admin";
      const isAuthor = entry.authorId === userId;

      if (!isAuthor && !isAdmin) {
        return res.status(403).json({
          error:
            "Solo la interventoría que elaboró la anotación puede devolverla al contratista.",
          code: "ONLY_AUTHOR_CAN_RETURN",
        });
      }

      const cleanedReason =
        typeof reason === "string" && reason.trim().length > 0
          ? reason.trim().slice(0, 500)
          : null;

      const updatedEntry = await prisma.logEntry.update({
        where: { id },
        data: {
          status: "SUBMITTED",
          contractorReviewCompleted: false,
          contractorReviewCompletedAt: null,
          contractorReviewerId: null,
        },
        include: logEntryResponseInclude as any,
      });

      const changeSet: Array<{
        fieldName: string;
        oldValue: string | null;
        newValue: string | null;
      }> = [
        {
          fieldName: getFieldLabel("status"),
          oldValue: getStatusDisplayName("NEEDS_REVIEW"),
          newValue: getStatusDisplayName("SUBMITTED"),
        },
        {
          fieldName: "Flujo",
          oldValue: null,
          newValue: `${currentUser.fullName || "Usuario"} devolvió la anotación al contratista para nuevos comentarios.`,
        },
      ];

      if (cleanedReason) {
        changeSet.push({
          fieldName: "Motivo devolución",
          oldValue: null,
          newValue: cleanedReason,
        });
      }

      await recordLogEntryChanges(id, userId, changeSet);

      const formattedEntry = {
        ...formatLogEntry(updatedEntry),
        attachments: (updatedEntry.attachments || []).map(
          buildAttachmentResponse
        ),
      };

      res.json(formattedEntry);
    } catch (error) {
      console.error("Error al devolver anotación al contratista:", error);
      res.status(500).json({
        error: "No se pudo devolver la anotación al contratista.",
      });
    }
  }
);

app.post(
  "/api/log-entries/:id/approve-for-signature",
  authMiddleware,
  requireEditor,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const userId = req.user?.userId;

      if (!userId) {
        return res.status(401).json({ error: "Usuario no autenticado." });
      }

      // Verificar que el log entry pertenezca al tenant
      const where = withTenantFilter(req, { id } as any);
      const entry = await prisma.logEntry.findFirst({
        where: Object.keys(where).length > 1 ? (where as any) : { id },
        include: { author: true },
      });

      if (!entry) {
        return res.status(404).json({ error: "Anotación no encontrada." });
      }
      
      // Verificar que el tenant coincida si hay tenant
      if ((req as any).tenant && (entry as any).tenantId !== (req as any).tenant.id) {
        return res.status(404).json({ error: "Anotación no encontrada." });
      }

      if (entry.status !== "NEEDS_REVIEW") {
        return res.status(400).json({
          error:
            "Solo se puede aprobar para firmas una anotación que esté en revisión final de interventoría.",
          code: "NOT_IN_FINAL_REVIEW",
        });
      }

      if (!entry.contractorReviewCompleted) {
        return res.status(400).json({
          error:
            "Debes esperar a que el contratista complete su revisión antes de aprobar para firma.",
          code: "CONTRACTOR_REVIEW_PENDING",
        });
      }

      const currentUser = await prisma.user.findUnique({
        where: { id: userId },
        select: { id: true, fullName: true, appRole: true },
      });

      if (!currentUser) {
        return res.status(404).json({ error: "Usuario no encontrado." });
      }

      const isAdmin = currentUser.appRole === "admin";
      const isAuthor = entry.authorId === userId;

      if (!isAuthor && !isAdmin) {
        return res.status(403).json({
          error:
            "Solo la interventoría que elaboró la anotación puede aprobarla para firmas.",
          code: "ONLY_AUTHOR_CAN_APPROVE",
        });
      }

      const updatedEntry = await prisma.logEntry.update({
        where: { id },
        data: { status: "APPROVED" },
        include: logEntryResponseInclude as any,
      });

      await recordLogEntryChanges(id, userId, [
        {
          fieldName: getFieldLabel("status"),
          oldValue: getStatusDisplayName("NEEDS_REVIEW"),
          newValue: getStatusDisplayName("APPROVED"),
        },
        {
          fieldName: "Flujo",
          oldValue: null,
          newValue: `${currentUser.fullName || "Usuario"} aprobó la anotación y la dejó lista para firma.`,
        },
      ]);

      const formattedEntry = {
        ...formatLogEntry(updatedEntry),
        attachments: (updatedEntry.attachments || []).map(buildAttachmentResponse),
      };

      res.json(formattedEntry);
    } catch (error) {
      console.error("Error al aprobar anotación para firma:", error);
      res.status(500).json({
        error: "No se pudo aprobar la anotación para firmas.",
      });
    }
  }
);

app.put(
  "/api/log-entries/:id",
  authMiddleware,
  requireEditor,
  (req, res, next) => {
    // Solo usar multer si el Content-Type es multipart/form-data
    const contentType = req.headers["content-type"] || "";
    if (contentType.includes("multipart/form-data")) {
      upload.array("attachments", 10)(req, res, (err) => {
        if (err) {
          return res.status(400).json({ error: "Error procesando archivos: " + err.message });
        }
        next();
      });
    } else {
      // Si es JSON, continuar sin multer
      next();
    }
  },
  validateUploadedFiles, // Validar magic bytes después de multer (si hay archivos)
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const userId = req.user?.userId;

      if (!userId) {
        return res.status(401).json({ error: "Usuario no autenticado." });
      }

      // Verificar acceso al recurso usando el middleware de permisos
      // Obtener tenantId del request si está disponible
      const tenantId = (req as any).tenant?.id;
      
      const { entry: existingEntry, hasAccess, reason } = await verifyLogEntryAccess(
        id,
        userId,
        true, // requireWriteAccess = true
        tenantId
      );

      if (!hasAccess || !existingEntry) {
        recordSecurityEvent('ACCESS_DENIED', 'medium', req, {
          reason: reason || 'Resource access denied',
          resourceType: 'logEntry',
          resourceId: id,
          requireWrite: true,
        });
        return res.status(403).json({
          error: reason || "No tienes acceso a este recurso",
          code: "ACCESS_DENIED",
        });
      }

      const { status: statusFromBody } = req.body ?? {};
      let requestedStatus = existingEntry.status;
      if (statusFromBody !== undefined) {
        const incomingStatus =
          entryStatusMap[statusFromBody] ||
          entryStatusMap[entryStatusReverseMap[statusFromBody] || ""] ||
          statusFromBody;
        if (incomingStatus && incomingStatus !== existingEntry.status) {
          return res.status(400).json({
            error: "El estado de la anotación solo puede cambiar mediante las acciones del flujo (enviar, revisar o aprobar).",
            code: "STATUS_READ_ONLY",
          });
        }
        requestedStatus =
          typeof incomingStatus === "string"
            ? incomingStatus
            : existingEntry.status;
      }

      const currentUser = await prisma.user.findUnique({
        where: { id: userId },
        select: {
          id: true,
          fullName: true,
          appRole: true,
          projectRole: true,
        },
      });

      if (!currentUser) {
        return res.status(404).json({
          error: "Usuario no encontrado.",
        });
      }

      const isAdmin = currentUser.appRole === "admin";
      const isAuthor = existingEntry.authorId === userId;
      const isContractorUser = currentUser.projectRole === "CONTRACTOR_REP";
      const status = existingEntry.status;

      if (status === "DRAFT") {
        if (!isAuthor && !isAdmin) {
          return res.status(403).json({
            error:
              "Solo la interventoría que creó la anotación (o un administrador) puede modificarla mientras está en borrador.",
            code: "DRAFT_ONLY_AUTHOR",
          });
        }
      } else if (status === "SUBMITTED") {
        if (!isContractorUser && !isAdmin) {
          return res.status(403).json({
            error:
              "Solo el contratista asignado puede agregar observaciones durante su fase de revisión.",
            code: "CONTRACTOR_REVIEW_ONLY",
          });
        }
      } else if (status === "NEEDS_REVIEW") {
        if (!isAuthor && !isAdmin) {
          return res.status(403).json({
            error:
              "Solo la interventoría puede ajustar la anotación durante la revisión final.",
            code: "FINAL_REVIEW_ONLY_AUTHOR",
          });
        }
      } else {
        return res.status(403).json({
          error: `No se puede editar una anotación en estado '${entryStatusReverseMap[status] || status}'.`,
          code: "ENTRY_NOT_EDITABLE",
          currentStatus: status,
        });
      }

      if (
        status === "SUBMITTED" &&
        req.files &&
        Array.isArray(req.files) &&
        (req.files as Express.Multer.File[]).length > 0
      ) {
        return res.status(403).json({
          error:
            "Durante la revisión del contratista no se pueden adjuntar archivos ni fotografías.",
          code: "CONTRACTOR_ATTACHMENTS_NOT_ALLOWED",
        });
      }

      const {
        title,
        description,
        type,
        subject,
        location,
        entryDate,
        activityStartDate,
        activityEndDate,
        isConfidential,
        assigneeIds,
        requiredSignatories,
      } = req.body ?? {};

      // Preparar datos de actualización
      const updateData: any = {};

      if (title !== undefined) updateData.title = title;
      if (description !== undefined) updateData.description = description;
      if (type !== undefined) updateData.type = entryTypeMap[type] || existingEntry.type;
      if (subject !== undefined) updateData.subject = typeof subject === "string" ? subject : "";
      if (location !== undefined) updateData.location = typeof location === "string" ? location : "";
      if (entryDate !== undefined) updateData.entryDate = entryDate ? new Date(entryDate) : existingEntry.entryDate;
      if (activityStartDate !== undefined) updateData.activityStartDate = activityStartDate ? new Date(activityStartDate) : existingEntry.activityStartDate;
      if (activityEndDate !== undefined) updateData.activityEndDate = activityEndDate ? new Date(activityEndDate) : existingEntry.activityEndDate;
      if (isConfidential !== undefined) updateData.isConfidential = parseBooleanInput(isConfidential);

      // Manejar campos JSON
      const jsonFields = [
        "contractorPersonnel",
        "interventoriaPersonnel",
        "equipmentResources",
        "executedActivities",
        "executedQuantities",
        "scheduledActivities",
        "qualityControls",
        "materialsReceived",
        "safetyNotes",
        "projectIssues",
        "siteVisits",
        "weatherReport",
      "socialActivities",
      ];

      for (const field of jsonFields) {
        if (req.body[field] !== undefined) {
          try {
            const value = typeof req.body[field] === "string" ? JSON.parse(req.body[field]) : req.body[field];
            updateData[field] = value;
          } catch (e) {
            console.warn(`Error parseando campo JSON ${field}:`, e);
          }
        }
      }

      // Manejar campos de texto
      const textFields = [
        "activitiesPerformed",
        "materialsUsed",
        "workforce",
        "weatherConditions",
        "additionalObservations",
        "locationDetails",
        "contractorObservations",
        "interventoriaObservations",
      "safetyFindings",
      "safetyContractorResponse",
      "environmentFindings",
      "environmentContractorResponse",
      "socialObservations",
      "socialContractorResponse",
      "socialPhotoSummary",
      ];

      for (const field of textFields) {
        if (req.body[field] !== undefined) {
          updateData[field] = typeof req.body[field] === "string" ? req.body[field] : "";
        }
      }

      // Manejar scheduleDay como entero nullable
      if (req.body.scheduleDay !== undefined) {
        const scheduleDayValue = req.body.scheduleDay;
        const currentScheduleDay = existingEntry.scheduleDay;
        
        // Si viene como null/vacío y el valor actual es 0 (valor por defecto), no actualizar
        // Esto evita que se cambie de 0 a null cuando el usuario no modificó el campo
        if ((scheduleDayValue === "" || scheduleDayValue === null || scheduleDayValue === undefined)) {
          // Solo actualizar a null si el valor actual no es 0 (valor por defecto)
          // Si el valor actual es 0, asumimos que no se modificó y no lo actualizamos
          if (currentScheduleDay !== 0 && currentScheduleDay !== null) {
            updateData.scheduleDay = null;
          }
          // Si currentScheduleDay es 0, no hacemos nada (no actualizamos)
        } else {
          let parsed: number;
          if (typeof scheduleDayValue === "string") {
            // Extraer el número del string "Día X del proyecto" o similar
            const match = scheduleDayValue.match(/Día\s+(\d+)/i);
            if (match) {
              parsed = parseInt(match[1], 10);
            } else {
              // Si no coincide con el patrón, intentar parsear directamente
              parsed = parseInt(scheduleDayValue, 10);
            }
          } else {
            parsed = scheduleDayValue;
          }
          const finalValue = isNaN(parsed) ? null : parsed;
          
          // Solo actualizar si el valor es diferente al actual
          if (finalValue !== currentScheduleDay) {
            updateData.scheduleDay = finalValue;
          }
        }
      }

      // Manejar asignados
      if (assigneeIds !== undefined) {
        if (status === "SUBMITTED") {
          return res.status(403).json({
            error:
              "Durante la revisión del contratista no se pueden reasignar responsables.",
            code: "CONTRACTOR_CANNOT_ASSIGN",
          });
        }
        const assigneeArray = Array.isArray(assigneeIds) ? assigneeIds : [];
        const validAssigneeIds = assigneeArray
          .filter((id) => typeof id === "string" && id.trim().length > 0);
        updateData.assignees = { set: validAssigneeIds.map((id) => ({ id })) };
        
        // Si el estado es NEEDS_REVIEW, crear/actualizar tareas de revisión
        if (requestedStatus === "NEEDS_REVIEW" || existingEntry.status === "NEEDS_REVIEW") {
          try {
            // Obtener tareas de revisión existentes
            const existingReviewTasks = await (prisma as any).logEntryReviewTask.findMany({
              where: { logEntryId: id },
            });
            
            const existingReviewerIds = new Set(existingReviewTasks.map((t: any) => t.reviewerId));
            const newReviewerIds = new Set(validAssigneeIds);
            
            // Eliminar tareas de revisores que ya no están asignados
            const toRemove = existingReviewTasks.filter((t: any) => !newReviewerIds.has(t.reviewerId));
            if (toRemove.length > 0) {
              await (prisma as any).logEntryReviewTask.deleteMany({
                where: {
                  id: { in: toRemove.map((t: any) => t.id) },
                  status: "PENDING", // Solo eliminar tareas pendientes
                },
              });
            }
            
            // Crear tareas para nuevos revisores
            const toAdd = validAssigneeIds.filter((reviewerId: string) => !existingReviewerIds.has(reviewerId));
            if (toAdd.length > 0) {
              await (prisma as any).logEntryReviewTask.createMany({
                data: toAdd.map((reviewerId) => ({
                  logEntryId: id,
                  reviewerId,
                  status: "PENDING",
                  assignedAt: new Date(),
                })),
                skipDuplicates: true,
              });
            }
          } catch (e: any) {
            console.warn("Error actualizando tareas de revisión:", e);
            // No fallar la actualización si hay error con las tareas de revisión
          }
        }
      }

      // Procesar archivos adjuntos nuevos
      const storage = getStorage();
      const newAttachments: any[] = [];

      if (req.files && Array.isArray(req.files)) {
        for (const file of req.files as Express.Multer.File[]) {
          const key = createStorageKey("bitacora", file.originalname);
          await storage.save({ path: key, content: file.buffer });
          newAttachments.push({
            fileName: file.originalname,
            url: storage.getPublicUrl(key),
            size: file.size,
            type: file.mimetype,
            storagePath: key,
          });
        }
      }

      if (newAttachments.length > 0) {
        updateData.attachments = {
          create: newAttachments,
        };
      }

      const effectiveUpdateKeys = Object.keys(updateData).filter(
        (key) => key !== "attachments"
      );

      if (status === "SUBMITTED") {
        const contractorAllowedFields = new Set([
          "contractorObservations",
          "safetyContractorResponse",
          "environmentContractorResponse",
          "socialContractorResponse",
        ]);
        const disallowed = effectiveUpdateKeys.filter(
          (key) => !contractorAllowedFields.has(key)
        );
        if (disallowed.length > 0) {
          return res.status(403).json({
            error:
              "Durante la revisión del contratista solo se pueden actualizar las respuestas del contratista.",
            code: "CONTRACTOR_FIELDS_LOCKED",
            disallowedFields: disallowed,
          });
        }
      }

      // Registrar cambios en el historial
      const changes: Array<{ fieldName: string; oldValue: string | null; newValue: string | null }> = [];
      
      // Obtener información del usuario que está haciendo los cambios
      const modifierName = currentUser.fullName || "Usuario";
      
      // Función helper para comparar valores y detectar si realmente cambió
      const valuesAreEqual = (oldVal: any, newVal: any): boolean => {
        // Normalizar valores vacíos: null, undefined, string vacío, array vacío se tratan como "vacío"
        const normalizeEmpty = (val: any): any => {
          // Si es null o undefined, retornar null
          if (val === null || val === undefined) {
            return null;
          }
          
          // Si es string vacío, retornar null
          if (typeof val === "string" && val.trim() === "") {
            return null;
          }
          
          // Si es array vacío, retornar null (para campos JSON)
          if (Array.isArray(val) && val.length === 0) {
            return null;
          }
          
          // Si es objeto vacío {}, retornar null
          if (typeof val === "object" && !Array.isArray(val) && Object.keys(val).length === 0) {
            return null;
          }
          
          return val;
        };
        
        const normalizedOld = normalizeEmpty(oldVal);
        const normalizedNew = normalizeEmpty(newVal);
        
        // Si ambos están vacíos (null/undefined/string vacío/array vacío), son iguales
        if (normalizedOld === null && normalizedNew === null) {
          return true;
        }
        
        // Si uno está vacío y el otro no, son diferentes
        if ((normalizedOld === null) !== (normalizedNew === null)) {
          return false;
        }
        
        // Si ambos están vacíos, ya retornamos arriba
        if (normalizedOld === null || normalizedNew === null) {
          return true;
        }
        
        // Para objetos/arrays (campos JSON), comparar como string JSON
        if (typeof normalizedOld === "object" && typeof normalizedNew === "object") {
          // Para arrays, comparar longitudes primero
          if (Array.isArray(normalizedOld) && Array.isArray(normalizedNew)) {
            if (normalizedOld.length !== normalizedNew.length) {
              return false;
            }
            if (normalizedOld.length === 0) {
              return true; // Ambos arrays vacíos ya fueron normalizados a null arriba, pero por si acaso
            }
          }
          
          try {
            const oldStr = JSON.stringify(normalizedOld);
            const newStr = JSON.stringify(normalizedNew);
            return oldStr === newStr;
          } catch (e) {
            return String(normalizedOld) === String(normalizedNew);
          }
        }
        
        // Para fechas, comparar timestamps
        if (normalizedOld instanceof Date && normalizedNew instanceof Date) {
          return normalizedOld.getTime() === normalizedNew.getTime();
        }
        
        // Para strings, comparar sin espacios al inicio/final
        if (typeof normalizedOld === "string" && typeof normalizedNew === "string") {
          return normalizedOld.trim() === normalizedNew.trim();
        }
        
        // Para números, comparar directamente (incluyendo 0)
        if (typeof normalizedOld === "number" && typeof normalizedNew === "number") {
          return normalizedOld === normalizedNew;
        }
        
        // Comparación normal
        return normalizedOld === normalizedNew;
      };
      
      // Función helper para formatear valores
      const formatValue = (value: any, fieldName: string): string | null => {
        // Si es null o undefined, retornar null
        if (value === null || value === undefined) {
          return null;
        }
        
        // Si es string vacío, retornar null
        if (typeof value === "string" && value.trim() === "") {
          return null;
        }
        
        // Si es array vacío, retornar null (para campos JSON)
        if (Array.isArray(value) && value.length === 0) {
          return null;
        }
        
        // Si es objeto vacío {}, retornar null
        if (typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 0) {
          return null;
        }
        
        // Para campos de fecha
        if (fieldName.includes("Date") && value instanceof Date) {
          return value.toLocaleString("es-CO");
        }
        
        // Para arrays con estructura [{text: "..."}] (campos de listas de texto)
        if (Array.isArray(value) && value.length > 0) {
          // Verificar si todos los elementos tienen estructura {text: "..."}
          const hasTextStructure = value.every(
            (item) => typeof item === "object" && item !== null && "text" in item && typeof item.text === "string"
          );
          
          if (hasTextStructure) {
            // Extraer solo los textos y unirlos con saltos de línea o comas
            const texts = value.map((item) => item.text).filter((text) => text && text.trim() !== "");
            if (texts.length === 0) {
              return null;
            }
            // Si hay solo un elemento, mostrarlo directamente
            if (texts.length === 1) {
              return texts[0].substring(0, 200);
            }
            // Si hay múltiples elementos, unirlos con comas o mostrar solo los primeros
            const displayText = texts.join(", ");
            return displayText.length > 200 ? displayText.substring(0, 200) + "..." : displayText;
          }
          
          // Si no tiene estructura de texto, formatear como JSON
          try {
            return JSON.stringify(value).substring(0, 200);
          } catch (e) {
            return String(value).substring(0, 200);
          }
        }
        
        // Para objetos (no arrays) que no están vacíos
        if (typeof value === "object" && !Array.isArray(value)) {
          try {
            return JSON.stringify(value).substring(0, 200);
          } catch (e) {
            return String(value).substring(0, 200);
          }
        }
        
        // Para strings, limitar longitud
        const strValue = String(value);
        return strValue.length > 200 ? strValue.substring(0, 200) + "..." : strValue;
      };
      
      // Registrar cambios en campos normales
      for (const [key, newValue] of Object.entries(updateData)) {
        if (key === "assignees" || key === "attachments") continue; // Estos se manejan por separado
        
        const oldValue = (existingEntry as any)[key];
        
        // Comparar valores usando la función helper
        // Solo registrar si realmente hay un cambio
        if (!valuesAreEqual(oldValue, newValue)) {
          const formattedOldValue = formatValue(oldValue, key);
          const formattedNewValue = formatValue(newValue, key);
          
          // Verificación adicional: no registrar si ambos valores formateados representan "vacío"
          const bothEmpty = (
            (formattedOldValue === null || formattedOldValue === "" || formattedOldValue === "vacío" || formattedOldValue === "null") &&
            (formattedNewValue === null || formattedNewValue === "" || formattedNewValue === "vacío" || formattedNewValue === "null" || formattedNewValue === "[]")
          );
          
          // También verificar si ambos representan arrays vacíos
          const bothEmptyArrays = (
            (formattedOldValue === null || formattedOldValue === "" || formattedOldValue === "vacío" || formattedOldValue === "[]") &&
            (formattedNewValue === null || formattedNewValue === "" || formattedNewValue === "vacío" || formattedNewValue === "[]")
          );
          
          // Solo registrar si hay un cambio real y no son ambos "vacío"
          if (formattedOldValue !== formattedNewValue && !bothEmpty && !bothEmptyArrays) {
            // Usar el nombre en español si existe en el mapeo, sino usar el nombre original
            const displayFieldName = LOG_ENTRY_FIELD_LABELS[key] || key;
            
            console.log(`DEBUG: Cambio detectado en campo ${displayFieldName} (${key}):`, {
              oldValue: formattedOldValue,
              newValue: formattedNewValue,
            });
            
            changes.push({
              fieldName: displayFieldName,
              oldValue: formattedOldValue,
              newValue: formattedNewValue,
            });
          } else {
            console.log(`DEBUG: Campo ${key} sin cambio real (ignorado):`, {
              oldValue: formattedOldValue,
              newValue: formattedNewValue,
              bothEmpty,
              bothEmptyArrays,
            });
          }
        } else {
          console.log(`DEBUG: Campo ${key} sin cambio (ignorado - valores iguales)`);
        }
      }

      // Registrar cambios en asignados
      if (assigneeIds !== undefined) {
        const oldAssigneeNames = existingEntry.assignees.map((a: any) => a.fullName).join(", ") || "Ninguno";
        const newAssigneeIds = Array.isArray(assigneeIds) ? assigneeIds : [];
        const newAssignees = await prisma.user.findMany({
          where: { id: { in: newAssigneeIds } },
          select: { fullName: true },
        });
        const newAssigneeNames = newAssignees.map((a) => a.fullName).join(", ") || "Ninguno";
        
        if (oldAssigneeNames !== newAssigneeNames) {
          changes.push({
            fieldName: "assignees",
            oldValue: oldAssigneeNames,
            newValue: `${newAssigneeNames} (modificado por ${modifierName})`,
          });
        }
      }

      // Registrar cambios en archivos adjuntos
      if (newAttachments.length > 0) {
        const newFileNames = newAttachments.map((a) => a.fileName).join(", ");
        changes.push({
          fieldName: "attachments",
          oldValue: null,
          newValue: `Archivos agregados por ${modifierName}: ${newFileNames}`,
        });
      }

      // Actualizar la anotación
      console.log("DEBUG: Actualizando anotación con updateData:", {
        entryId: id,
        keys: Object.keys(updateData),
        hasAssignees: !!updateData.assignees,
        hasAttachments: !!updateData.attachments,
        updateDataSample: Object.keys(updateData).slice(0, 5).reduce((acc: any, key) => {
          acc[key] = typeof updateData[key] === 'object' ? '[Object]' : String(updateData[key]).substring(0, 50);
          return acc;
        }, {}),
      });
      
      let updatedEntry;
      try {
        updatedEntry = await prisma.logEntry.update({
          where: { id },
          data: updateData,
          include: logEntryResponseInclude as any,
        });
        console.log("DEBUG: Anotación actualizada exitosamente");
      } catch (updateError: any) {
        console.error("DEBUG: ERROR al actualizar en Prisma:", updateError);
        if (updateError instanceof Prisma.PrismaClientKnownRequestError) {
          console.error("DEBUG: Prisma error code:", updateError.code);
          console.error("DEBUG: Prisma error meta:", updateError.meta);
        }
        throw updateError; // Re-lanzar para que sea capturado por el catch externo
      }

      // Registrar cambios en el historial ANTES de actualizar
      console.log("DEBUG: Cambios detectados antes de actualizar:", {
        entryId: id,
        userId,
        changesCount: changes.length,
        changes: changes.map(c => ({ 
          fieldName: c.fieldName, 
          oldValue: c.oldValue?.substring(0, 50) || null, 
          newValue: c.newValue?.substring(0, 50) || null 
        })),
      });
      
      if (changes.length > 0) {
        try {
          console.log("DEBUG: Registrando cambios en historial:", {
            entryId: id,
            userId,
            changesCount: changes.length,
            changes: changes.map(c => ({ fieldName: c.fieldName, hasOldValue: !!c.oldValue, hasNewValue: !!c.newValue })),
          });
          await recordLogEntryChanges(id, userId, changes);
          console.log("DEBUG: Cambios registrados en historial exitosamente");
        } catch (historyError: any) {
          console.error("DEBUG: ERROR al registrar cambios en historial:", historyError);
          if (historyError instanceof Error) {
            console.error("Historial error message:", historyError.message);
            console.error("Historial error stack:", historyError.stack);
          }
          // No fallar la actualización si hay error con el historial
          // Solo loguear el error
        }
      } else {
        console.log("DEBUG: No se detectaron cambios para registrar en historial");
      }

      // Actualizar tareas de firma si se cambian los firmantes requeridos
      if (requiredSignatories !== undefined) {
        if (status === "SUBMITTED") {
          return res.status(403).json({
            error:
              "Durante la revisión del contratista no se pueden modificar los firmantes requeridos.",
            code: "CONTRACTOR_CANNOT_EDIT_SIGNERS",
          });
        }
        try {
          let requiredSignerIds: string[] = [];
          
          if (requiredSignatories) {
            const parsed = typeof requiredSignatories === "string" 
              ? JSON.parse(requiredSignatories) 
              : requiredSignatories;
            requiredSignerIds = extractUserIds(parsed);
          }

          // Incluir al autor si no está en la lista
          const uniqueSignerIds = Array.from(new Set([...requiredSignerIds, existingEntry.authorId]));

          // Verificar que ningún firmante sea viewer
          const signers = await prisma.user.findMany({
            where: { id: { in: uniqueSignerIds } },
            select: { id: true, appRole: true, fullName: true },
          });
          
          const viewerSigners = signers.filter((s) => s.appRole === "viewer");
          if (viewerSigners.length > 0) {
            const viewerNames = viewerSigners.map((s) => s.fullName).join(", ");
            return res.status(400).json({
              error: `Los usuarios con rol 'viewer' no pueden ser firmantes: ${viewerNames}`,
              code: "VIEWER_CANNOT_BE_SIGNER",
            });
          }

          // Obtener tareas de firma existentes para comparar
          const existingTasks = await prisma.logEntrySignatureTask.findMany({
            where: { logEntryId: id },
            include: { signer: { select: { fullName: true } } },
          });

          const existingSignerIds = new Set(existingTasks.map((t) => t.signerId));
          const newSignerIds = new Set(uniqueSignerIds);
          const oldSignerNames = existingTasks.map((t) => t.signer.fullName).join(", ") || "Ninguno";
          const newSignerNames = signers.map((s) => s.fullName).join(", ") || "Ninguno";

          // Registrar cambio en el historial si hay diferencia
          if (oldSignerNames !== newSignerNames) {
            await recordLogEntryChanges(id, userId, [{
              fieldName: "requiredSignatories",
              oldValue: oldSignerNames,
              newValue: newSignerNames,
            }]);
          }

          // Eliminar tareas de firmantes que ya no están en la lista
          const toRemove = existingTasks.filter((t) => !newSignerIds.has(t.signerId));
          if (toRemove.length > 0) {
            await prisma.logEntrySignatureTask.deleteMany({
              where: {
                id: { in: toRemove.map((t) => t.id) },
                status: "PENDING", // Solo eliminar tareas pendientes
              },
            });
          }

          // Crear tareas para nuevos firmantes
          const toAdd = uniqueSignerIds.filter((id) => !existingSignerIds.has(id));
          if (toAdd.length > 0) {
            await prisma.logEntrySignatureTask.createMany({
              data: toAdd.map((signerId) => ({
                logEntryId: id,
                signerId,
                status: "PENDING",
                assignedAt: new Date(),
              })),
              skipDuplicates: true,
            });

            // Enviar correos de notificación a los nuevos firmantes
            for (const signerId of toAdd) {
              try {
                const signer = await prisma.user.findUnique({
                  where: { id: signerId },
                  select: { email: true, fullName: true },
                });

                if (signer && signer.email) {
                  await sendSignatureAssignmentEmail({
                    to: signer.email,
                    recipientName: signer.fullName,
                    assignerName: currentUser.fullName || "Un usuario",
                    logEntry: {
                      id: id,
                      folioNumber: existingEntry.folioNumber,
                      title: existingEntry.title,
                      entryDate: existingEntry.entryDate,
                    },
                  });
                  console.log("DEBUG: ✓ Correo de notificación enviado a:", signer.email);
                }
              } catch (emailError: any) {
                console.error("DEBUG: ✗ ERROR enviando correo de notificación:", {
                  signerId: signerId,
                  error: emailError.message,
                });
                // No fallar la actualización si el correo falla
              }
            }
          }
        } catch (e: any) {
          console.warn("Error actualizando tareas de firma:", e);
          // No fallar la actualización si hay error con las tareas de firma
        }
      }

      // Recargar la entrada con todas las relaciones actualizadas
      const finalEntry = await prisma.logEntry.findUnique({
        where: { id },
        include: logEntryResponseInclude as any,
      });

      if (!finalEntry) {
        throw new Error("No se pudo recuperar la anotación actualizada.");
      }

      const formattedEntry = {
        ...formatLogEntry(finalEntry),
        attachments: (finalEntry.attachments || []).map(buildAttachmentResponse),
      };

      res.json(formattedEntry);
    } catch (error) {
      console.error("Error al actualizar anotación:", error);
      if (error instanceof Error) {
        console.error("Error message:", error.message);
        console.error("Error stack:", error.stack);
      }
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        console.error("Prisma error code:", error.code);
        console.error("Prisma error meta:", error.meta);
        if (error.code === "P2025") {
          return res.status(404).json({ error: "Anotación no encontrada." });
        }
        if (error.code === "P2002") {
          const target = (error.meta as any)?.target;
          const isEntryDateConstraint = 
            (Array.isArray(target) && target.includes("LogEntry_projectId_entryDate_key")) ||
            (typeof target === "string" && target === "LogEntry_projectId_entryDate_key");
          
          if (isEntryDateConstraint) {
            return res.status(409).json({
              error: "Ya existe una bitácora registrada para este proyecto en la fecha seleccionada.",
            });
          }
        }
      }
      res.status(500).json({ 
        error: "No se pudo actualizar la anotación.",
        details: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined
      });
    }
  }
);

app.delete(
  "/api/log-entries/:id",
  authMiddleware,
  requireAdmin,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const userId = req.user?.userId;

      if (!userId) {
        return res.status(401).json({ error: "Usuario no autenticado." });
      }

      // Verificar que el log entry pertenezca al tenant
      const where = withTenantFilter(req, { id } as any);
      const entry = await prisma.logEntry.findFirst({
        where: Object.keys(where).length > 1 ? (where as any) : { id },
        include: {
          attachments: true,
          author: {
            select: {
              id: true,
              fullName: true,
              email: true,
            },
          },
        },
      });

      if (!entry) {
        return res.status(404).json({ error: "Anotación no encontrada." });
      }
      
      // Verificar que el tenant coincida si hay tenant
      if ((req as any).tenant && (entry as any).tenantId !== (req as any).tenant.id) {
        return res.status(404).json({ error: "Anotación no encontrada." });
      }

      // Eliminar archivos adjuntos del storage
      const storage = getStorage();
      if (entry.attachments && entry.attachments.length > 0) {
        for (const attachment of entry.attachments) {
          if (attachment.storagePath) {
            try {
              await storage.remove(attachment.storagePath);
            } catch (storageError) {
              console.warn(
                `No se pudo eliminar el archivo del storage: ${attachment.storagePath}`,
                storageError
              );
              // Continuar con la eliminación aunque falle el storage
            }
          }
        }
      }

      // Eliminar relaciones manualmente antes de eliminar la anotación
      await prisma.$transaction([
        // Eliminar tareas de revisión
        prisma.logEntryReviewTask.deleteMany({
          where: { logEntryId: id },
        }),
        // Eliminar tareas de firma
        prisma.logEntrySignatureTask.deleteMany({
          where: { logEntryId: id },
        }),
        // Eliminar historial
        prisma.logEntryHistory.deleteMany({
          where: { logEntryId: id },
        }),
        // Eliminar comentarios (y sus attachments)
        prisma.comment.deleteMany({
          where: { logEntryId: id },
        }),
        // Eliminar firmas
        prisma.signature.deleteMany({
          where: { logEntryId: id },
        }),
        // Eliminar attachments
        prisma.attachment.deleteMany({
          where: { logEntryId: id },
        }),
        // Finalmente, eliminar la anotación
        prisma.logEntry.delete({
          where: { id },
        }),
      ]);

      // Registrar evento de seguridad
      recordSecurityEvent('LOG_ENTRY_DELETED', 'high', req, {
        logEntryId: id,
        authorId: entry.authorId,
        authorEmail: entry.author.email,
        folioNumber: entry.folioNumber,
        title: entry.title,
      });

      logger.info("Anotación eliminada por administrador", {
        logEntryId: id,
        folioNumber: entry.folioNumber,
        deletedBy: userId,
        authorId: entry.authorId,
      });

      res.status(204).send();
    } catch (error) {
      logger.error("Error al eliminar la anotación", {
        error: error instanceof Error ? error.message : String(error),
        logEntryId: req.params.id,
        userId: req.user?.userId,
      });
      res.status(500).json({
        error: "No se pudo eliminar la anotación.",
        details: error instanceof Error ? error.message : String(error),
      });
    }
  }
);

app.post(
  "/api/log-entries/:id/comments",
  authMiddleware,
  requireEditor,
  (req: AuthRequest, res) => {
    const uploadMiddleware = upload.array("attachments", 5);

    uploadMiddleware(req, res, async (err) => {
      if (err instanceof multer.MulterError) {
        return res.status(400).json({ error: err.message });
      }
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      // Validar archivos después de multer
      validateUploadedFiles(req, res, async () => {
      try {
        const { id } = req.params;
        const { content, authorId } = req.body ?? {};
        const userId = req.user?.userId;

        if (!content || typeof content !== "string" || !content.trim()) {
          return res.status(400).json({
            error: "El contenido del comentario es obligatorio.",
          });
        }

        if (!userId) {
          return res.status(401).json({ error: "Usuario no autenticado." });
        }

        // Verificar acceso al log entry antes de permitir comentar
        const tenantId = (req as any).tenant?.id;
        const { entry: logEntry, hasAccess, reason } = await verifyLogEntryAccess(
          id,
          userId,
          false, // Solo lectura necesaria para comentar
          tenantId
        );

        if (!hasAccess || !logEntry) {
          recordSecurityEvent('ACCESS_DENIED', 'medium', req, {
            reason: reason || 'Resource access denied for commenting',
            resourceType: 'logEntry',
            resourceId: id,
            requireWrite: false,
          });
          return res.status(403).json({
            error: reason || "No tienes acceso a este recurso",
            code: "ACCESS_DENIED",
          });
        }

        const resolvedAuthorId = req.user?.userId || authorId;
        if (!resolvedAuthorId || typeof resolvedAuthorId !== "string") {
          return res.status(401).json({
            error: "No se pudo determinar el autor del comentario.",
          });
        }

        const author = await prisma.user.findUnique({
          where: { id: resolvedAuthorId },
        });
        if (!author) {
          return res.status(404).json({ error: "Autor no encontrado." });
        }

        const uploadedFiles = Array.isArray(req.files)
          ? (req.files as Express.Multer.File[])
          : [];
        const createdAttachments: { id: string }[] = [];

        for (const file of uploadedFiles) {
          try {
            if (!file.buffer) {
              logger.warn("Archivo sin buffer recibido", {
                originalName: file.originalname,
              });
              continue;
            }
            // Comentarios de bitácoras van en la sección bitacora
            const stored = await persistUploadedFile(
              file,
              "bitacora"
            );
            const attachment = await prisma.attachment.create({
              data: {
                fileName: file.originalname,
                url: stored.url,
                storagePath: stored.key,
                size: file.size,
                type: file.mimetype,
              },
            });
            createdAttachments.push({ id: attachment.id });
          } catch (uploadError) {
            console.error("Error al guardar adjunto del comentario:", uploadError);
          }
        }

        const newComment = await prisma.comment.create({
          data: {
            content: content.trim(),
            author: { connect: { id: author.id } },
            logEntry: { connect: { id } },
            attachments: createdAttachments.length
              ? { connect: createdAttachments }
              : undefined,
          },
          include: { author: true, attachments: true },
        });

        // Extraer menciones del comentario y crear notificaciones
        const mentionPattern = /@\[([a-f0-9-]{36})\]/g; // Formato @[userId]
        const mentionedUserIds = new Set<string>();
        let match;
        while ((match = mentionPattern.exec(content)) !== null) {
          mentionedUserIds.add(match[1]);
        }

        // Crear notificaciones para cada usuario mencionado (excepto el autor)
        if (mentionedUserIds.size > 0) {
          const allUsers = await prisma.user.findMany({
            where: {
              id: { in: Array.from(mentionedUserIds) },
              status: "active",
            },
            select: { id: true, fullName: true },
          });

          const notificationsToCreate = allUsers
            .filter((user) => user.id !== author.id) // No notificar al autor
            .map((user) => ({
              type: "mention",
              message: `${author.fullName} te mencionó en un comentario`,
              recipientId: user.id,
              commentId: newComment.id,
              relatedItemType: "logEntry",
              relatedItemId: id,
              relatedView: "logbook",
            }));

          if (notificationsToCreate.length > 0) {
            await prisma.notification.createMany({
              data: notificationsToCreate,
            });
          }
        }

        await recordLogEntryChanges(id, req.user?.userId, [
          {
            fieldName: "Comentario Añadido",
            newValue: `${author.fullName}: ${content.trim()}`,
          },
        ]);

        res.status(201).json({
          ...newComment,
          attachments: (newComment.attachments || []).map(
            buildAttachmentResponse
          ),
        });
      } catch (error) {
        console.error("Error al crear comentario de bitácora:", error);
        res.status(500).json({ error: "No se pudo crear el comentario." });
      }
      }); // Cerrar callback de validateUploadedFiles
    });
  }
);

app.post(
  "/api/log-entries/:id/reviews/complete",
  authMiddleware,
  requireEditor,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const userId = req.user?.userId;

      if (!userId) {
        return res.status(401).json({ error: "Usuario no autenticado." });
      }

      // Verificar que el log entry pertenezca al tenant
      const where = withTenantFilter(req, { id } as any);
      const entry = await prisma.logEntry.findFirst({
        where: Object.keys(where).length > 1 ? (where as any) : { id },
        include: {
          reviewTasks: { include: { reviewer: true } },
          assignees: true,
        },
      });

      if (!entry) {
        return res.status(404).json({ error: "Anotación no encontrada." });
      }
      
      // Verificar que el tenant coincida si hay tenant
      if ((req as any).tenant && (entry as any).tenantId !== (req as any).tenant.id) {
        return res.status(404).json({ error: "Anotación no encontrada." });
      }

      // Verificar que el usuario esté asignado como revisor
      const isAssignee = entry.assignees.some((a: any) => a.id === userId);
      const currentUser = await prisma.user.findUnique({ where: { id: userId } });
      const isAdmin = currentUser?.appRole === "admin";

      if (!isAssignee && !isAdmin) {
        return res.status(403).json({
          error: "No tienes permisos para completar la revisión. Solo los asignados o un administrador pueden completar revisiones.",
          code: "INSUFFICIENT_PERMISSIONS",
        });
      }

      // Buscar la tarea de revisión del usuario
      let reviewTask = entry.reviewTasks.find((task: any) => task.reviewerId === userId);

      if (!reviewTask) {
        // Si no existe, crearla (puede pasar si se asignó después de crear la anotación)
        reviewTask = await (prisma as any).logEntryReviewTask.create({
          data: {
            logEntryId: id,
            reviewerId: userId,
            status: "COMPLETED",
            assignedAt: new Date(),
            completedAt: new Date(),
          },
          include: { reviewer: true },
        });
      } else {
        // Actualizar la tarea existente
        if (reviewTask.status === "COMPLETED") {
          return res.status(409).json({
            error: "Ya has completado tu revisión de esta anotación.",
            code: "REVIEW_ALREADY_COMPLETED",
          });
        }

        reviewTask = await (prisma as any).logEntryReviewTask.update({
          where: { id: reviewTask.id },
          data: {
            status: "COMPLETED",
            completedAt: new Date(),
          },
          include: { reviewer: true },
        });
      }

      // Registrar en el historial
      if (reviewTask) {
        await recordLogEntryChanges(id, userId, [{
          fieldName: "reviewCompleted",
          oldValue: null,
          newValue: `Revisión completada por ${reviewTask.reviewer?.fullName || "Usuario"}`,
        }]);
      }

      // Obtener la anotación actualizada
      const updatedEntry = await prisma.logEntry.findUnique({
        where: { id },
        include: {
          author: true,
          attachments: true,
          comments: {
            include: { author: true },
            orderBy: { timestamp: "asc" },
          },
          signatures: { include: { signer: true } },
          signatureTasks: { include: { signer: true }, orderBy: { assignedAt: "asc" } },
          reviewTasks: { include: { reviewer: true }, orderBy: { assignedAt: "asc" } } as any,
          assignees: true,
          history: { include: { user: true }, orderBy: { timestamp: "desc" } },
        },
      });

      if (!updatedEntry) {
        return res.status(404).json({ error: "Anotación no encontrada." });
      }

      const formattedEntry = {
        ...formatLogEntry(updatedEntry),
        attachments: (updatedEntry.attachments || []).map(buildAttachmentResponse),
      };

      res.json(formattedEntry);
    } catch (error) {
      console.error("Error al completar revisión:", error);
      res.status(500).json({ error: "No se pudo completar la revisión." });
    }
  }
);

app.post(
  "/api/log-entries/:id/signatures",
  authMiddleware,
  requireEditor,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const { signerId, password } = req.body ?? {};

      if (!signerId || !password) {
        return res
          .status(400)
          .json({ error: "Se requieren el firmante y la contraseña." });
      }

      const signer = await prisma.user.findUnique({ where: { id: signerId } });
      if (!signer) {
        return res.status(404).json({ error: "Firmante no encontrado." });
      }

      // Los usuarios con rol "viewer" no pueden firmar
      if (signer.appRole === "viewer") {
        return res.status(403).json({
          error: "Los usuarios con rol 'viewer' no pueden firmar documentos.",
          code: "VIEWER_CANNOT_SIGN",
        });
      }

      const passwordMatches = await bcrypt.compare(password, signer.password);
      if (!passwordMatches) {
        return res.status(401).json({
          error: "Contraseña incorrecta.",
          code: "INVALID_SIGNATURE_PASSWORD",
        });
      }

      // Verificar que el log entry pertenezca al tenant
      const where = withTenantFilter(req, { id } as any);
      const entry = await prisma.logEntry.findFirst({
        where: Object.keys(where).length > 1 ? (where as any) : { id },
        include: {
          signatureTasks: { include: { signer: true } },
          attachments: true,
        },
      });

      if (!entry) {
        return res.status(404).json({ error: "Anotación no encontrada." });
      }
      
      // Verificar que el tenant coincida si hay tenant
      if ((req as any).tenant && (entry as any).tenantId !== (req as any).tenant.id) {
        return res.status(404).json({ error: "Anotación no encontrada." });
      }

      if (entry.status !== "APPROVED" && entry.status !== "SIGNED") {
        return res.status(403).json({
          error:
            "La anotación aún no está lista para firmas. Debe estar aprobada por la interventoría.",
          code: "SIGNATURES_NOT_ALLOWED",
        });
      }

      let myTask =
        (entry.signatureTasks || []).find(
          (task) => task.signerId === signerId
        ) ?? null;

      if (!myTask) {
        myTask = await prisma.logEntrySignatureTask.findUnique({
          where: { logEntryId_signerId: { logEntryId: id, signerId } },
          include: { signer: true },
        });
      }

      if (!myTask) {
        console.warn("Creando tarea de firma en caliente.", {
          logEntryId: id,
          signerId,
        });
        myTask = await prisma.logEntrySignatureTask.create({
          data: {
            logEntry: { connect: { id } },
            signer: { connect: { id: signerId } },
            status: "PENDING",
          },
          include: { signer: true },
        });
        entry.signatureTasks = [...(entry.signatureTasks || []), myTask];
      }

      if (!myTask) {
        return res.status(403).json({
          error: "No fue posible asignarte la tarea de firma.",
        });
      }

      if (myTask.status === "SIGNED") {
        return res.status(409).json({
          error: "Ya has firmado esta anotación.",
          code: "ALREADY_SIGNED",
        });
      }

      const existingSignature = await prisma.signature.findFirst({
        where: { logEntryId: id, signerId },
      });
      if (existingSignature) {
        return res.status(409).json({
          error: "Ya has firmado esta anotación.",
          code: "ALREADY_SIGNED",
        });
      }

      const signedAtDate = new Date();
      
      // Actualizar el estado de la tarea ANTES de generar/aplicar la firma al PDF
      // para que el PDF muestre "Firmado" en lugar de "Pendiente de firma"
      await prisma.logEntrySignatureTask.update({
        where: { id: myTask.id },
        data: { status: "SIGNED", signedAt: signedAtDate },
      });

      await prisma.signature.create({
        data: {
          signer: { connect: { id: signerId } },
          logEntry: { connect: { id } },
          signedAt: signedAtDate,
        },
      });

      const userSignature = await prisma.userSignature.findUnique({
        where: { userId: signerId },
      });

      if (userSignature) {
        try {
          // Regenerar el PDF para que muestre el estado actualizado ("Firmado" con fecha)
          console.log("Regenerando PDF para reflejar el estado actualizado de las firmas...");
          let basePdf: any = null;
          try {
            const baseUrl =
              process.env.SERVER_PUBLIC_URL || `http://localhost:${port}`;
            const tenantId = (req as any).tenant?.id;
            await generateLogEntryPdf({
              prisma,
              logEntryId: id,
              uploadsDir: process.env.UPLOADS_DIR || "./uploads",
              baseUrl,
              tenantId,
            });
            console.log("PDF regenerado exitosamente con el estado actualizado");

            // Buscar el PDF recién regenerado (el más reciente sin "firmado" en el nombre)
            basePdf = await prisma.attachment.findFirst({
              where: {
                logEntryId: id,
                type: "application/pdf",
                fileName: { not: { contains: "firmado" } },
              },
              orderBy: { createdAt: "desc" },
            });
          } catch (regenerateError) {
            console.warn("No se pudo regenerar el PDF, usando PDF existente:", regenerateError);
            // Fallback: buscar PDF existente
            basePdf = await prisma.attachment.findFirst({
              where: {
                logEntryId: id,
                type: "application/pdf",
                fileName: { not: { contains: "firmado" } },
              },
              orderBy: { createdAt: "desc" },
            });
          }

          if (basePdf) {
            console.log(
              `Aplicando TODAS las firmas manuscritas al PDF regenerado: ${basePdf.fileName} (ID: ${basePdf.id})`
            );

            // Cargar el PDF base regenerado
            let currentPdfBuffer = await loadAttachmentBuffer(basePdf);
            const originalPdfSize = currentPdfBuffer.length;
            
            // Obtener todas las firmas que ya están firmadas (incluyendo la nueva)
            const allSignatures = await prisma.signature.findMany({
              where: { logEntryId: id },
              include: { signer: true },
              orderBy: { signedAt: "asc" },
            });

            // Obtener tareas de firma ordenadas para calcular posiciones
            const logEntryWithTasks = await prisma.logEntry.findUnique({
              where: { id },
              include: {
                signatureTasks: {
                  include: { signer: true },
                  orderBy: { assignedAt: "asc" },
                },
              },
            });

            const orderedTasks =
              (logEntryWithTasks?.signatureTasks || [])
                .filter((t: any) => t?.signer?.id)
                .sort(
                  (a: any, b: any) =>
                    new Date(a.assignedAt || 0).getTime() -
                    new Date(b.assignedAt || 0).getTime()
                ) || [];

            // Valores que coinciden con pdfExport.ts
            const PAGE_MARGIN = 48;
            const SIGNATURE_BOX_HEIGHT = 110;
            const SIGNATURE_BOX_GAP = 16;
            const SIGNATURE_LINE_OFFSET = 72;
            const SIGNATURE_SECTION_START_Y = PAGE_MARGIN + 17.5;
            const LINE_X = PAGE_MARGIN + 70;

            // Aplicar todas las firmas manuscritas en orden
            console.log(`Aplicando ${allSignatures.length} firma(s) manuscrita(s) al PDF...`);
            for (const signature of allSignatures) {
              const signerId = signature.signerId || signature.signer?.id;
              if (!signerId) continue;

              const userSig = await prisma.userSignature.findUnique({
                where: { userId: signerId },
              });

              if (!userSig) {
                console.warn(`No se encontró firma manuscrita para el usuario ${signerId}`);
                continue;
              }

              // Calcular índice del firmante
              let signerIndex = orderedTasks.findIndex(
                (t: any) => t.signer?.id === signerId
              );
              if (signerIndex < 0) signerIndex = 0;

              const currentY = SIGNATURE_SECTION_START_Y + signerIndex * (SIGNATURE_BOX_HEIGHT + SIGNATURE_BOX_GAP);
              const yPos = currentY + SIGNATURE_LINE_OFFSET;

              console.log(`Aplicando firma de ${signature.signer?.fullName} en posición:`, {
                signerIndex,
                y: yPos,
                x: LINE_X,
              });

              try {
                // Usar la contraseña del firmante para desencriptar su firma
                // Nota: esto solo funciona si el firmante actual es quien está firmando
                // Para otros firmantes, sus firmas se aplicarán cuando ellos firmen con su contraseña
                const signaturePassword = signature.signer?.id === signerId ? password : undefined;
                const signatureBuffer = await loadUserSignatureBuffer(userSig, signaturePassword);
                currentPdfBuffer = await applySignatureToPdf({
                  originalPdf: currentPdfBuffer,
                  signature: {
                    buffer: signatureBuffer,
                    mimeType: userSig.mimeType || "image/png",
                  },
                  position: {
                    page: undefined, // última página
                    x: LINE_X,
                    y: yPos,
                    width: 220,
                    height: 28,
                    baseline: true,
                    baselineRatio: 0.25,
                    fromTop: true,
                  },
                });
                console.log(`✅ Firma de ${signature.signer?.fullName} aplicada exitosamente`);
              } catch (sigError) {
                console.error(`❌ Error aplicando firma de ${signature.signer?.fullName}:`, sigError);
              }
            }
            
            const signedBuffer = currentPdfBuffer;
            console.log(`PDF con todas las firmas generado:`, {
              originalSize: originalPdfSize,
              signedSize: signedBuffer.length,
              totalSignatures: allSignatures.length,
            });

            // Crear nuevo PDF firmado para acumular firmas
            const storage = getStorage();
            const parsedFileName = path.parse(
              basePdf.fileName || "documento.pdf"
            );
            // Remover el sufijo -firmado si existe para evitar nombres como "documento-firmado-firmado.pdf"
            const baseName = parsedFileName.name.replace(/-firmado(-\d+)?$/, '');
            // Usar sufijo -firmado con timestamp para crear versiones únicas
            const signedFileName = `${baseName}-firmado-${Date.now()}.pdf`;
            // Firmas de bitácoras van en la sección bitacora
            const signedKey = createStorageKey(
              "bitacora",
              signedFileName
            );
            
            console.log(`Guardando PDF firmado en storage:`, {
              key: signedKey,
              fileName: signedFileName,
              size: signedBuffer.length,
            });
            
            try {
              await storage.save({ path: signedKey, content: signedBuffer });
              console.log(`✅ PDF guardado exitosamente en storage`);
            } catch (storageError) {
              console.error(`❌ ERROR al guardar PDF en storage:`, storageError);
              throw storageError; // Re-lanzar para que sea capturado por el catch externo
            }
            
            const signedUrl = storage.getPublicUrl(signedKey);
            console.log(`URL pública generada: ${signedUrl}`);

            // Crear nuevo adjunto firmado
            const newAttachment = await prisma.attachment.create({
              data: {
                fileName: signedFileName,
                url: signedUrl,
                storagePath: signedKey,
                size: signedBuffer.length,
                type: "application/pdf",
                logEntry: { connect: { id } },
              },
            });

            console.log(
              `PDF firmado creado exitosamente: ${signedFileName} (URL: ${signedUrl})`
            );
            console.log(`Adjunto creado en BD:`, {
              id: newAttachment.id,
              fileName: newAttachment.fileName,
              url: newAttachment.url,
              storagePath: newAttachment.storagePath,
              size: newAttachment.size,
            });
          } else {
            console.warn(
              "No se pudo encontrar o generar un PDF base para aplicar la firma."
            );
          }
        } catch (pdfError) {
          console.error(
            "❌ ERROR: La firma manuscrita no pudo aplicarse al PDF, pero la firma quedó registrada.",
            pdfError
          );
          if (pdfError instanceof Error) {
            console.error("Stack trace:", pdfError.stack);
          }
        }
      }

      // El estado ya fue actualizado antes de aplicar la firma al PDF
      // No necesitamos actualizarlo de nuevo aquí

      const updated = await prisma.logEntry.findUnique({
        where: { id },
        include: {
          author: true,
          attachments: true,
          comments: {
            include: { author: true },
            orderBy: { timestamp: "asc" },
          },
          signatures: { include: { signer: true } },
          signatureTasks: { include: { signer: true } },
          reviewTasks: { include: { reviewer: true }, orderBy: { assignedAt: "asc" } } as any,
          assignees: true,
          history: { include: { user: true }, orderBy: { timestamp: "desc" } },
        },
      });

      if (!updated) {
        return res
          .status(404)
          .json({ error: "Anotación no encontrada tras firmar." });
      }

      console.log(`Adjuntos en la entrada actualizada:`, {
        total: updated.attachments?.length || 0,
        attachments: (updated.attachments || []).map((att: any) => ({
          id: att.id,
          fileName: att.fileName,
          type: att.type,
          url: att.url,
        })),
      });

      const formatted = formatLogEntry(updated);
      console.log(`Adjuntos en la respuesta formateada:`, {
        total: formatted.attachments?.length || 0,
        attachments: (formatted.attachments || []).map((att: any) => ({
          id: att.id,
          fileName: att.fileName,
          type: att.type,
          url: att.url,
        })),
      });

      res.json(formatted);
    } catch (error) {
      console.error("Error al firmar anotación:", error);
      res.status(500).json({ error: "No se pudo firmar la anotación." });
    }
  }
);

// Export ZIP of PDFs
app.post(
  "/api/log-entries/export-zip",
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { startDate, endDate, type, status, authorId } = req.body || {};
      const where: any = {};
      if (startDate || endDate) {
        where.entryDate = {};
        if (startDate) where.entryDate.gte = new Date(startDate);
        if (endDate) where.entryDate.lte = new Date(endDate);
      }
      if (type && type !== "all") where.type = entryTypeMap[type] || type;
      if (status && status !== "all") where.status = entryStatusMap[status] || status;
      if (authorId && authorId !== "all") where.authorId = authorId;

      // Filtrar por tenant
      const tenantWhere = withTenantFilter(req, where);
      const finalWhere = Object.keys(tenantWhere).length > Object.keys(where).length 
        ? tenantWhere 
        : where;

      const entries = await prisma.logEntry.findMany({
        where: Object.keys(finalWhere).length > 0 ? (finalWhere as any) : undefined,
        orderBy: { entryDate: "asc" },
        include: {
          attachments: true,
        },
      });

      const storage = getStorage();
      const files: Array<{ name: string; data: Buffer }> = [];

      for (const entry of entries) {
        // intentar encontrar un PDF existente no firmado (último generado)
        let pdfAttachment =
          (entry.attachments || [])
            .filter((a: any) => (a.type || "").includes("pdf"))
            .sort(
              (a: any, b: any) =>
                new Date(b.createdAt || 0).getTime() -
                new Date(a.createdAt || 0).getTime()
            )[0] || null;

        // si no hay, generar
        if (!pdfAttachment) {
          try {
            const tenantId = (req as any).tenant?.id;
            await generateLogEntryPdf({
              prisma,
              logEntryId: entry.id,
              uploadsDir: process.env.UPLOADS_DIR || "./uploads",
              baseUrl:
                process.env.SERVER_PUBLIC_URL ||
                `http://localhost:${port}`,
              tenantId,
            });
            // buscar de nuevo
            const refreshed = await prisma.logEntry.findUnique({
              where: { id: entry.id },
              include: { attachments: true },
            });
            pdfAttachment =
              (refreshed?.attachments || [])
                .filter((a: any) => (a.type || "").includes("pdf"))
                .sort(
                  (a: any, b: any) =>
                    new Date(b.createdAt || 0).getTime() -
                    new Date(a.createdAt || 0).getTime()
                )[0] || null;
          } catch (e) {
            console.warn("No se pudo generar PDF para", entry.id, e);
          }
        }

        if (!pdfAttachment?.storagePath) {
          continue;
        }

        try {
          const buffer = await storage.load(pdfAttachment.storagePath);
          const safeTitle = (entry.title || "Anotacion")
            .replace(/[^a-zA-Z0-9 _.-]/g, "")
            .substring(0, 80)
            .trim()
            .replace(/\s+/g, "_");
          const name = `Folio_${entry.folioNumber}_${safeTitle || "Anotacion"}.pdf`;
          files.push({ name, data: buffer });
        } catch (e) {
          console.warn("No se pudo cargar PDF para", entry.id, e);
        }
      }

      if (files.length === 0) {
        return res.status(404).json({ error: "No se encontraron PDFs para exportar." });
      }

      const zipBuffer = buildSimpleZip(files);
      const fileName = `bitacoras_${new Date().toISOString().slice(0,10)}.zip`;
      res.setHeader("Content-Type", "application/zip");
      res.setHeader("Content-Disposition", `attachment; filename="${fileName}"`);
      res.send(zipBuffer);
    } catch (error) {
      console.error("Error al exportar ZIP de bitácoras:", error);
      res.status(500).json({ error: "No se pudo generar el archivo ZIP." });
    }
  }
);

// --- RUTAS PARA COMUNICACIONES ---
app.get("/api/communications", async (req, res) => {
  try {
    const where = withTenantFilter(req);
    const communications = await prisma.communication.findMany({
      where: Object.keys(where).length > 0 ? (where as any) : undefined,
      orderBy: { sentDate: "desc" },
      include: {
        uploader: true,
        assignee: true,
        attachments: true,
        statusHistory: {
          include: { user: true },
          orderBy: { timestamp: "asc" },
        },
      },
    });
    const formatted = communications.map((communication) => ({
      ...formatCommunication(communication),
      attachments: (communication.attachments || []).map(
        buildAttachmentResponse
      ),
    }));
    res.json(formatted);
  } catch (error) {
    console.error("Error al obtener comunicaciones:", error);
    res.status(500).json({ error: "No se pudieron obtener las comunicaciones." });
  }
});

app.get("/api/communications/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const where = withTenantFilter(req, { id } as any);
    const communication = await prisma.communication.findFirst({
      where: Object.keys(where).length > 1 ? (where as any) : { id },
      include: {
        uploader: true,
        assignee: true,
        attachments: true,
        statusHistory: {
          include: { user: true },
          orderBy: { timestamp: "asc" },
        },
      },
    });

    if (!communication) {
      return res.status(404).json({ error: "Comunicación no encontrada." });
    }
    
    // Verificar que el tenant coincida si hay tenant
    if ((req as any).tenant && (communication as any).tenantId !== (req as any).tenant.id) {
      return res.status(404).json({ error: "Comunicación no encontrada." });
    }

    const formatted = formatCommunication(communication);
    formatted.attachments = (communication.attachments || []).map(
      buildAttachmentResponse
    );
    res.json(formatted);
  } catch (error) {
    console.error("Error al obtener la comunicación:", error);
    res.status(500).json({ error: "No se pudo obtener la comunicación." });
  }
});

app.post("/api/communications", async (req, res) => {
  try {
    const {
      radicado,
      subject,
      description,
      senderDetails,
      recipientDetails,
      signerName,
      sentDate,
      dueDate,
      deliveryMethod,
      notes,
      parentId,
      direction,
      requiresResponse,
      responseDueDate,
      assigneeId,
      uploaderId,
      attachments = [],
    } = req.body ?? {};

    if (!radicado || !subject || !description || !uploaderId || !sentDate) {
      return res.status(400).json({
        error:
          "radicado, asunto, descripción, fecha de envío y usuario cargador son obligatorios.",
      });
    }

    const prismaDeliveryMethod = deliveryMethodMap[deliveryMethod] || "SYSTEM";
    const prismaDirection =
      communicationDirectionMap[direction] ||
      communicationDirectionMap[
        communicationDirectionReverseMap[direction] || "Recibida"
      ] ||
      "RECEIVED";
    const normalizedRequiresResponse = Boolean(requiresResponse);

    // Asignar tenantId si está disponible
    const tenantId = (req as any).tenant?.id;
    const commData: any = {
      radicado,
      subject,
      description,
      senderEntity: senderDetails?.entity,
      senderName: senderDetails?.personName,
      senderTitle: senderDetails?.personTitle,
      recipientEntity: recipientDetails?.entity,
      recipientName: recipientDetails?.personName,
      recipientTitle: recipientDetails?.personTitle,
      signerName,
      sentDate: new Date(sentDate),
      dueDate: dueDate ? new Date(dueDate) : null,
      deliveryMethod: prismaDeliveryMethod,
      notes,
      status: "PENDIENTE",
      direction: prismaDirection,
      requiresResponse: normalizedRequiresResponse,
      responseDueDate:
        normalizedRequiresResponse && responseDueDate
          ? new Date(responseDueDate)
          : null,
      uploader: { connect: { id: uploaderId } },
      assignee: assigneeId ? { connect: { id: assigneeId } } : undefined,
      assignedAt: assigneeId ? new Date() : null,
      parent: parentId ? { connect: { id: parentId } } : undefined,
      attachments: Array.isArray(attachments)
        ? {
            connect: attachments
              .filter((att: any) => att?.id)
              .map((att: any) => ({ id: att.id })),
          }
        : undefined,
      statusHistory: {
        create: {
          status: communicationStatusMap["Pendiente"] || "PENDIENTE",
          user: { connect: { id: uploaderId } },
        },
      },
    };
    if (tenantId) {
      commData.tenantId = tenantId;
    }

    const newComm = await prisma.communication.create({
      data: commData,
      include: {
        uploader: true,
        assignee: true,
        attachments: true,
        statusHistory: {
          include: { user: true },
          orderBy: { timestamp: "asc" },
        },
      },
    });

    if (newComm.assignee && newComm.assignee.email) {
      try {
        await sendCommunicationAssignmentEmail({
          to: newComm.assignee.email,
          recipientName: newComm.assignee.fullName,
          assignerName: newComm.uploader?.fullName,
          communication: {
            radicado: newComm.radicado,
            subject: newComm.subject,
            sentDate: newComm.sentDate,
            responseDueDate: newComm.responseDueDate ?? undefined,
          },
        });
      } catch (emailError) {
        logger.warn(
          "No se pudo enviar el correo de asignación de comunicación.",
          emailError
        );
      }
    }

    const formatted = formatCommunication(newComm);
    formatted.attachments = (newComm.attachments || []).map(
      buildAttachmentResponse
    );
    res.status(201).json(formatted);
  } catch (error) {
    console.error("Error al crear la comunicación:", error);
    res.status(500).json({ error: "No se pudo crear la comunicación." });
  }
});

app.put(
  "/api/communications/:id/status",
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body ?? {};

      if (!status) {
        return res.status(400).json({ error: "El estado es obligatorio." });
      }

      const userId = req.user?.userId;
      if (!userId) {
        return res.status(401).json({ error: "No autorizado." });
      }

      const prismaStatus =
        communicationStatusMap[status] ||
        communicationStatusMap[
          communicationStatusReverseMap[status] || "Pendiente"
        ] ||
        "PENDIENTE";

      // Verificar que la comunicación pertenezca al tenant
      const where = withTenantFilter(req, { id } as any);
      const existingComm = await prisma.communication.findFirst({
        where: Object.keys(where).length > 1 ? (where as any) : { id },
      });

      if (!existingComm) {
        return res.status(404).json({ error: "Comunicación no encontrada." });
      }
      
      // Verificar que el tenant coincida si hay tenant
      if ((req as any).tenant && (existingComm as any).tenantId !== (req as any).tenant.id) {
        return res.status(404).json({ error: "Comunicación no encontrada." });
      }

      const updated = await prisma.communication.update({
        where: { id },
        data: {
          status: prismaStatus,
          statusHistory: {
            create: {
              status: prismaStatus,
              user: { connect: { id: userId } },
            },
          },
        },
        include: {
          uploader: true,
          assignee: true,
          attachments: true,
          statusHistory: {
            include: { user: true },
            orderBy: { timestamp: "asc" },
          },
        },
      });

      res.json(formatCommunication(updated));
    } catch (error) {
      console.error("Error al actualizar estado de la comunicación:", error);
      if ((error as any)?.code === "P2025") {
        return res.status(404).json({ error: "Comunicación no encontrada." });
      }
      res.status(500).json({ error: "No se pudo actualizar el estado." });
    }
  }
);

app.put(
  "/api/communications/:id/assignment",
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const { assigneeId } = req.body as { assigneeId?: string | null };

      // Verificar que la comunicación pertenezca al tenant
      const where = withTenantFilter(req, { id } as any);
      const current = await prisma.communication.findFirst({
        where: Object.keys(where).length > 1 ? (where as any) : { id },
        select: { assigneeId: true },
      });

      if (!current) {
        return res.status(404).json({ error: "Comunicación no encontrada." });
      }
      
      // Verificar que el tenant coincida si hay tenant
      if ((req as any).tenant && (current as any).tenantId !== (req as any).tenant.id) {
        return res.status(404).json({ error: "Comunicación no encontrada." });
      }

      const normalizedAssigneeId =
        assigneeId && assigneeId.trim().length > 0 ? assigneeId.trim() : null;

      if (current.assigneeId === normalizedAssigneeId) {
        const communication = await prisma.communication.findUnique({
          where: { id },
          include: {
            uploader: true,
            assignee: true,
            attachments: true,
            statusHistory: {
              include: { user: true },
              orderBy: { timestamp: "asc" },
            },
          },
        });
        if (!communication) {
          return res.status(404).json({ error: "Comunicación no encontrada." });
        }
        return res.json(formatCommunication(communication));
      }

      const updated = await prisma.communication.update({
        where: { id },
        data: {
          assignee: normalizedAssigneeId
            ? { connect: { id: normalizedAssigneeId } }
            : { disconnect: true },
          assignedAt: normalizedAssigneeId ? new Date() : null,
        },
        include: {
          uploader: true,
          assignee: true,
          attachments: true,
          statusHistory: {
            include: { user: true },
            orderBy: { timestamp: "asc" },
          },
        },
      });

      if (normalizedAssigneeId && updated.assignee?.email) {
        try {
          let assignerName: string | undefined;
          if (req.user?.userId) {
            const assigner = await prisma.user.findUnique({
              where: { id: req.user.userId },
              select: { fullName: true },
            });
            assignerName = assigner?.fullName || undefined;
          }

          await sendCommunicationAssignmentEmail({
            to: updated.assignee.email,
            recipientName: updated.assignee.fullName,
            assignerName,
            communication: {
              radicado: updated.radicado,
              subject: updated.subject,
              sentDate: updated.sentDate,
              responseDueDate: updated.responseDueDate ?? undefined,
            },
          });
        } catch (emailError) {
          logger.warn(
            "No se pudo enviar el correo de asignación de comunicación.",
            emailError
          );
        }
      }

      res.json(formatCommunication(updated));
    } catch (error) {
      console.error("Error al actualizar asignación de comunicación:", error);
      if ((error as any)?.code === "P2025") {
        return res.status(404).json({ error: "Comunicación no encontrada." });
      }
      res.status(500).json({ error: "No se pudo actualizar la asignación." });
    }
  }
);

// --- RUTAS DEL ASISTENTE VIRTUAL ---
app.post("/api/chatbot/query", authMiddleware, async (req: AuthRequest, res) => {
  const { query, history } = req.body ?? {};
  const userId = req.user?.userId;

  if (!query || typeof query !== "string") {
    return res
      .status(400)
      .json({ error: "No se proporcionó una consulta válida (query)." });
  }
  if (!userId) {
    return res.status(401).json({ error: "Usuario no autenticado." });
  }

  try {
    const conversationHistory: Array<{
      role: "assistant" | "user";
      content: string;
    }> = Array.isArray(history)
      ? history
          .filter(
            (item: any) =>
              item &&
              typeof item.content === "string" &&
              item.content.trim() &&
              (item.role === "user" || item.role === "assistant")
          )
          .map((item: any) => ({
            role: item.role,
            content: item.content.slice(0, 1500),
          }))
          .slice(-6)
      : [];

    // Preparar query de commitments con filtro de tenant antes del Promise.all
    const tenantId = (req as any).tenant?.id;
    const commitmentQueryPromise = tenantId
      ? (async () => {
          const actaIds = (await prisma.acta.findMany({
            where: { tenantId } as any,
            select: { id: true },
          })).map((a: any) => a.id);
          
          return prisma.commitment.findMany({
            where: {
              status: "PENDING",
              dueDate: { gte: new Date() },
              actaId: { in: actaIds },
            },
            include: {
              responsible: {
                select: { fullName: true, projectRole: true },
              },
            },
            orderBy: { dueDate: "asc" },
            take: 10,
          });
        })()
      : prisma.commitment.findMany({
          where: {
            status: "PENDING",
            dueDate: { gte: new Date() },
          },
          include: {
            responsible: {
              select: { fullName: true, projectRole: true },
            },
          },
          orderBy: { dueDate: "asc" },
          take: 10,
        });

    const [
      project,
      contractModifications,
      ultimaAnotacion,
      contractItems,
      workActas,
      projectTasks,
      communications,
      actas,
      costActas,
      reports,
      drawings,
      controlPoints,
      pendingCommitments,
      recentLogEntries,
    ] = await Promise.all([
      prisma.project.findFirst({ 
        where: (req as any).tenant ? { tenantId: (req as any).tenant.id } as any : undefined,
        include: { keyPersonnel: true } 
      }),
      prisma.contractModification.findMany({
        where: (req as any).tenant ? { tenantId: (req as any).tenant.id } as any : undefined,
        orderBy: { date: "desc" },
        take: 10,
      }),
      prisma.logEntry.findFirst({
        where: (req as any).tenant ? { tenantId: (req as any).tenant.id } as any : undefined,
        orderBy: { createdAt: "desc" },
        include: { author: { select: { fullName: true } } },
      }),
      // ContractItems no tienen tenantId directo, pero están relacionados con workActas que sí lo tienen
      // Filtrar workActas primero si hay tenant
      prisma.contractItem.findMany({
        include: {
          workActaItems: {
            where: (req as any).tenant 
              ? { workActa: { tenantId: (req as any).tenant.id } as any }
              : undefined,
            include: {
              workActa: {
                select: { id: true, number: true, date: true, status: true },
              },
            },
          },
        },
        orderBy: { itemCode: "asc" },
      }),
      prisma.workActa.findMany({
        where: (req as any).tenant ? { tenantId: (req as any).tenant.id } as any : undefined,
        include: {
          items: {
            include: {
              contractItem: {
                select: {
                  id: true,
                  itemCode: true,
                  description: true,
                  unit: true,
                  unitPrice: true,
                },
              },
            },
          },
        },
        orderBy: { date: "desc" },
        take: 10,
      }),
      prisma.projectTask.findMany({
        where: (req as any).tenant ? { tenantId: (req as any).tenant.id } as any : undefined,
        orderBy: { startDate: "asc" },
        take: 20,
      }),
      prisma.communication.findMany({
        where: (req as any).tenant ? { tenantId: (req as any).tenant.id } as any : undefined,
        orderBy: { sentDate: "desc" },
        take: 10,
      }),
      prisma.acta.findMany({
        where: (req as any).tenant ? { tenantId: (req as any).tenant.id } as any : undefined,
        orderBy: { date: "desc" },
        take: 10,
        include: {
          commitments: {
            include: {
              responsible: {
                select: { fullName: true, projectRole: true },
              },
            },
          },
        },
      }),
      prisma.costActa.findMany({
        where: (req as any).tenant ? { tenantId: (req as any).tenant.id } as any : undefined,
        orderBy: { submissionDate: "desc" },
        take: 10,
      }),
      prisma.report.findMany({
        where: (req as any).tenant ? { tenantId: (req as any).tenant.id } as any : undefined,
        orderBy: { submissionDate: "desc" },
        take: 10,
        include: {
          author: {
            select: { fullName: true, projectRole: true },
          },
        },
      }),
      // Drawings no tienen tenantId en el schema actual, pero podemos filtrar si se agrega en el futuro
      // Por ahora, obtener todos (puede que drawings sean compartidos entre tenants o no implementados aún)
      prisma.drawing.findMany({
        orderBy: { code: "asc" },
        take: 20,
        include: {
          versions: {
            orderBy: { versionNumber: "desc" },
            take: 1,
          },
        },
      }),
      prisma.controlPoint.findMany({
        where: (req as any).tenant ? { tenantId: (req as any).tenant.id } as any : undefined,
        include: {
          photos: {
            orderBy: { date: "desc" },
            take: 3,
          },
        },
        take: 10,
      }),
      commitmentQueryPromise,
      prisma.logEntry.findMany({
        where: (req as any).tenant ? { tenantId: (req as any).tenant.id } as any : undefined,
        orderBy: { createdAt: "desc" },
        take: 10,
        include: {
          author: { select: { fullName: true, projectRole: true } },
          assignees: { select: { fullName: true, projectRole: true } },
        },
      }),
    ]);

    const formatCurrency = (value?: number | null) => {
      if (value === null || value === undefined || Number.isNaN(value)) {
        return "N/D";
      }
      return new Intl.NumberFormat("es-CO", {
        style: "currency",
        currency: "COP",
        maximumFractionDigits: 0,
      }).format(value);
    };

    const formatDate = (dateLike?: Date | string | null) => {
      if (!dateLike) {
        return "N/D";
      }
      const date = dateLike instanceof Date ? dateLike : new Date(dateLike);
      if (Number.isNaN(date.getTime())) {
        return "N/D";
      }
      return date.toLocaleDateString("es-CO", {
        year: "numeric",
        month: "long",
        day: "numeric",
      });
    };

    const formatNumber = (value?: number | null, decimals = 2) => {
      if (value === null || value === undefined || Number.isNaN(value)) {
        return "0";
      }
      return new Intl.NumberFormat("es-CO", {
        minimumFractionDigits: decimals,
        maximumFractionDigits: decimals,
      }).format(value);
    };

    const formatPercentage = (value?: number | null, decimals = 1) => {
      if (value === null || value === undefined || Number.isNaN(value)) {
        return "0%";
      }
      return `${value.toFixed(decimals)}%`;
    };

    const contextSections: ChatbotContextSection[] = [];

    if (project) {
      const startDate = project.startDate ? new Date(project.startDate) : null;
      const initialEndDate = project.initialEndDate
        ? new Date(project.initialEndDate)
        : null;

      const totalAdditionsValue = contractModifications
        .filter((mod: any) => mod.type === "ADDITION" && mod.value)
        .reduce((sum: number, mod: any) => sum + (mod.value || 0), 0);

      const totalExtensionsDays = contractModifications
        .filter((mod: any) => mod.type === "TIME_EXTENSION" && mod.days)
        .reduce((sum: number, mod: any) => sum + (mod.days || 0), 0);

      let initialDurationDays: number | null = null;
      if (startDate && initialEndDate) {
        initialDurationDays = Math.ceil(
          (initialEndDate.getTime() - startDate.getTime()) /
            (1000 * 60 * 60 * 24)
        );
      }

      let currentEndDate: Date | null = initialEndDate
        ? new Date(initialEndDate)
        : null;
      if (currentEndDate) {
        currentEndDate.setDate(currentEndDate.getDate() + totalExtensionsDays);
      }

      const projectSummary: string[] = [
        `Nombre: ${project.name}`,
        `Contrato: ${project.contractId}`,
        `Objeto: ${project.object}`,
        `Contratista: ${project.contractorName}`,
        `Interventoría: ${project.supervisorName}`,
        `Valor inicial: ${formatCurrency(project.initialValue)}`,
        `Valor de adiciones: ${formatCurrency(totalAdditionsValue)}`,
        `Valor total vigente: ${formatCurrency(
          project.initialValue + totalAdditionsValue
        )}`,
        `Fecha de inicio: ${formatDate(startDate)}`,
      ];

      if (initialEndDate) {
        projectSummary.push(
          `Fecha de finalización contractual original: ${formatDate(
            initialEndDate
          )}`
        );
      }

      if (currentEndDate) {
        projectSummary.push(
          `Fecha de finalización vigente: ${formatDate(currentEndDate)}`
        );
      }

      if (initialDurationDays !== null) {
        projectSummary.push(`Plazo inicial: ${initialDurationDays} días`);
        projectSummary.push(
          `Plazo total vigente: ${
            initialDurationDays + totalExtensionsDays
          } días`
        );
      }

      if (totalExtensionsDays) {
        projectSummary.push(
          `Días adicionales por prórrogas: ${totalExtensionsDays}`
        );
      }

      if (project.keyPersonnel?.length) {
        const highlightedPersonnel = project.keyPersonnel
          .slice(0, 5)
          .map(
            (person: any) =>
              `${person.role} (${person.company}): ${person.name} | Correo: ${
                person.email
              } | Teléfono: ${person.phone || "N/D"}`
          )
          .join("\n- ");
        projectSummary.push(
          `Personal clave relevante:\n- ${highlightedPersonnel}${
            project.keyPersonnel.length > 5
              ? "\n- ... (ver más en la plataforma)"
              : ""
          }`
        );
      }

      contextSections.push({
        id: "project-overview",
        heading: "Resumen ejecutivo del proyecto",
        body: projectSummary.join("\n"),
        priority: 2,
      });

      if (contractModifications.length) {
        const modificationsSummary = contractModifications
          .slice(0, 5)
          .map((mod: any) => {
            const partes: string[] = [
              `${mod.number} - ${
                modificationTypeReverseMap[mod.type] || mod.type
              }`,
            ];
            partes.push(`Fecha: ${formatDate(mod.date)}`);
            if (mod.value !== null && mod.value !== undefined) {
              partes.push(`Valor: ${formatCurrency(mod.value)}`);
            }
            if (mod.days !== null && mod.days !== undefined) {
              partes.push(`Días: ${mod.days}`);
            }
            return `• ${partes.join(" | ")}`;
          })
          .join("\n");
        contextSections.push({
          id: "contract-modifications",
          heading: "Modificaciones contractuales recientes (máx. 5)",
          body: modificationsSummary,
          priority: 1,
        });
      }
    }

    if (contractItems.length) {
      const itemsWithProgress = contractItems.map((item: any) => {
        const executedQuantity = item.workActaItems.reduce((sum: number, entry: any) => {
          const quantity =
            typeof entry.quantity === "number"
              ? entry.quantity
              : Number(entry.quantity) || 0;
          return sum + quantity;
        }, 0);

        const percentage =
          item.contractQuantity > 0
            ? (executedQuantity / item.contractQuantity) * 100
            : 0;

        const latestEntry = item.workActaItems
          .filter((entry: any) => entry.workActa?.date)
          .sort((a: any, b: any) => {
            const dateA = a.workActa?.date
              ? new Date(a.workActa.date as unknown as string).getTime()
              : 0;
            const dateB = b.workActa?.date
              ? new Date(b.workActa.date as unknown as string).getTime()
              : 0;
            return dateB - dateA;
          })[0];

        let lastActaSummary = "";
        if (latestEntry?.workActa) {
          const acta = latestEntry.workActa;
          const actaStatus =
            workActaStatusReverseMap[acta.status] || acta.status;
          lastActaSummary = ` Último reporte: acta ${acta.number} (${formatDate(
            acta.date
          )}) en estado ${actaStatus}.`;
        }

        return {
          itemCode: item.itemCode,
          description: item.description,
          unit: item.unit,
          contractQuantity: item.contractQuantity,
          executedQuantity,
          percentage,
          lastActaSummary,
        };
      });

      const topItems = itemsWithProgress
        .sort(
          (a: any, b: any) =>
            b.percentage - a.percentage ||
            b.executedQuantity - a.executedQuantity
        )
        .slice(0, 8);

      if (topItems.length) {
        const lines = topItems.map(
          (item: any) =>
            `• ${item.itemCode} - ${item.description}: Contratado ${formatNumber(
              item.contractQuantity,
              2
            )} ${item.unit}, Ejecutado ${formatNumber(
              item.executedQuantity,
              2
            )} ${item.unit} (avance ${formatPercentage(
              item.percentage,
              1
            )}).${item.lastActaSummary}`
        );
        contextSections.push({
          id: "contract-items-progress",
          heading: "Avance por ítems contractuales clave",
          body: lines.join("\n"),
        });
      }
    }

    if (workActas.length) {
      const workActaLines = workActas.map((acta: any) => {
        const totalQuantity = acta.items.reduce((sum: number, item: any) => {
          const quantity =
            typeof item.quantity === "number"
              ? item.quantity
              : Number(item.quantity) || 0;
          return sum + quantity;
        }, 0);

        const totalValue = acta.items.reduce((sum: number, item: any) => {
          const quantity =
            typeof item.quantity === "number"
              ? item.quantity
              : Number(item.quantity) || 0;
          const unitPrice = item.contractItem?.unitPrice || 0;
          return sum + quantity * unitPrice;
        }, 0);

        const principales = acta.items
          .slice(0, 3)
          .map((item: any) => {
            const code = item.contractItem?.itemCode || "N/D";
            const qty =
              typeof item.quantity === "number"
                ? item.quantity
                : Number(item.quantity) || 0;
            const unit = item.contractItem?.unit || "";
            return `${code}: ${formatNumber(qty, 2)} ${unit}`;
          })
          .join("; ");

        const status =
          workActaStatusReverseMap[acta.status] || acta.status;

        return `• ${acta.number} (${formatDate(
          acta.date
        )}) – Estado: ${status}. Cantidad total reportada: ${formatNumber(
          totalQuantity,
          2
        )}. Valor estimado: ${formatCurrency(
          totalValue
        )}. Ítems destacados: ${principales || "sin ítems cargados"}.`;
      });

      contextSections.push({
        id: "work-actas",
        heading: "Actas de obra más recientes (máx. 5)",
        body: workActaLines.join("\n"),
      });
    }

    if (projectTasks.length) {
      const taskLines = projectTasks.map((task: any) => {
        const label = task.isSummary ? "hito" : "tarea";
        return `• ${task.name} (${label}): avance ${formatPercentage(
          task.progress,
          0
        )}, inicio ${formatDate(task.startDate)}, fin ${formatDate(
          task.endDate
        )}, duración ${task.duration} días.`;
      });

      contextSections.push({
        id: "project-tasks",
        heading: "Tareas del cronograma consultadas (máx. 10)",
        body: taskLines.join("\n"),
      });
    }

    if (ultimaAnotacion) {
      const ultimaAnotacionResumen = [
        `Título: ${ultimaAnotacion.title}`,
        `Descripción: ${ultimaAnotacion.description}`,
        `Autor: ${ultimaAnotacion.author?.fullName || "No especificado"}`,
        `Fecha: ${formatDate(ultimaAnotacion.createdAt)}`,
        `Tipo: ${
          entryTypeReverseMap[ultimaAnotacion.type] ||
          ultimaAnotacion.type
        }`,
        `Estado: ${
          entryStatusReverseMap[ultimaAnotacion.status] ||
          ultimaAnotacion.status
        }`,
      ].join("\n");

      contextSections.push({
        id: "last-log-entry",
        heading: "Última anotación registrada en la bitácora",
        body: ultimaAnotacionResumen,
        priority: 1,
      });
    }

    if (communications.length) {
      const communicationsSummary = communications
        .map((comm: any) => {
          const sender = comm.senderEntity || "No especificado";
          const recipient = comm.recipientEntity || "No especificado";
          const status =
            communicationStatusReverseMap[comm.status] || comm.status;
          return `• Radicado ${comm.radicado}: "${comm.subject}" - De: ${sender} - Para: ${recipient} - Estado: ${status} - Fecha: ${formatDate(
            comm.sentDate
          )}`;
        })
        .join("\n");

      contextSections.push({
        id: "communications",
        heading: "Comunicaciones oficiales recientes",
        body: communicationsSummary,
      });
    }

    if (actas.length) {
      const actasSummary = actas
        .map((acta: any) => {
          const area = actaAreaReverseMap[acta.area] || acta.area;
          const status = actaStatusReverseMap[acta.status] || acta.status;
          const commitmentsCount = acta.commitments?.length || 0;
          return `• ${acta.number}: "${acta.title}" - Área: ${area} - Estado: ${status} - Compromisos: ${commitmentsCount} - Fecha: ${formatDate(
            acta.date
          )}`;
        })
        .join("\n");

      contextSections.push({
        id: "committee-actas",
        heading: "Actas de comité recientes",
        body: actasSummary,
      });
    }

    if (costActas.length) {
      const costActasSummary = costActas
        .map((acta: any) => {
          const status =
            costActaStatusReverseMap[acta.status] || acta.status;
          return `• ${acta.number}: Período ${acta.period} - Valor: ${formatCurrency(
            acta.billedAmount
          )} - Estado: ${status} - Fecha: ${formatDate(
            acta.submissionDate
          )}`;
        })
        .join("\n");

      contextSections.push({
        id: "cost-actas",
        heading: "Actas de costo recientes",
        body: costActasSummary,
      });
    }

    if (reports.length) {
      const reportsSummary = reports
        .map((report: any) => {
          const scope =
            reportScopeReverseMap[report.reportScope] || report.reportScope;
          const status = reportStatusReverseMap[report.status] || report.status;
          return `• ${report.type} ${report.number}: ${scope} - Estado: ${status} - Autor: ${report.author?.fullName} - Fecha: ${formatDate(
            report.submissionDate
          )}`;
        })
        .join("\n");

      contextSections.push({
        id: "reports",
        heading: "Informes recientes",
        body: reportsSummary,
      });
    }

    if (drawings.length) {
      const drawingsSummary = drawings
        .map((drawing: any) => {
          const discipline =
            drawingDisciplineMap[drawing.discipline] || drawing.discipline;
          const status =
            drawing.status === "VIGENTE" ? "Vigente" : "Obsoleto";
          const versionsCount = drawing.versions?.length || 0;
          return `• ${drawing.code}: "${drawing.title}" - Disciplina: ${discipline} - Estado: ${status} - Versiones: ${versionsCount}`;
        })
        .join("\n");

      contextSections.push({
        id: "drawings",
        heading: "Planos del proyecto",
        body: drawingsSummary,
      });
    }

    if (controlPoints.length) {
      const controlPointsSummary = controlPoints
        .map((point: any) => {
          const photosCount = point.photos?.length || 0;
          return `• ${point.name}: ${point.description} - Ubicación: ${point.location} - Fotos: ${photosCount}`;
        })
        .join("\n");

      contextSections.push({
        id: "control-points",
        heading: "Puntos de control fotográfico",
        body: controlPointsSummary,
      });
    }

    if (pendingCommitments.length) {
      const commitmentsSummary = pendingCommitments
        .map((commitment: any) => {
          const responsible =
            commitment.responsible?.fullName || "No asignado";
          const role = commitment.responsible?.projectRole || "";
          return `• ${commitment.description} - Responsable: ${responsible} (${role}) - Vence: ${formatDate(
            commitment.dueDate
          )}`;
        })
        .join("\n");

      contextSections.push({
        id: "pending-commitments",
        heading: "Compromisos pendientes",
        body: commitmentsSummary,
        priority: 1,
      });
    }

    if (recentLogEntries.length) {
      const logEntriesSummary = recentLogEntries
        .map((entry: any) => {
          const author = entry.author?.fullName || "No especificado";
          const type = entryTypeReverseMap[entry.type] || entry.type;
          const status = entryStatusReverseMap[entry.status] || entry.status;
          const assignees =
            entry.assignees?.map((a: any) => a.fullName).join(", ") ||
            "Sin asignados";
          return `• "${entry.title}" - Autor: ${author} - Tipo: ${type} - Estado: ${status} - Asignados: ${assignees} - Fecha: ${formatDate(
            entry.createdAt
          )}`;
        })
        .join("\n");

      contextSections.push({
        id: "recent-log-entries",
        heading: "Anotaciones recientes en bitácora",
        body: logEntriesSummary,
      });
    }

    const fallbackContext =
      contextSections.length > 0
        ? contextSections.map(sectionToText).join("\n\n")
        : "No se encontró información contextual relevante en la base de datos.";

    let selectedContextSections: ChatbotContextSection[] = [];
    let retrievalPrompt = String(query);
    let contexto = fallbackContext;

    if (contextSections.length) {
      retrievalPrompt = conversationHistory.length
        ? `${conversationHistory[conversationHistory.length - 1].content}\n${query}`
        : String(query);
      const selectedSections = await selectRelevantSections({
        query: retrievalPrompt,
        sections: contextSections,
        openaiClient: openai,
        maxSections: 6,
      });

      if (selectedSections.length) {
        selectedContextSections = selectedSections;
        contexto = selectedSections.map(sectionToText).join("\n\n");
      } else {
        selectedContextSections = contextSections.slice(
          0,
          Math.min(6, contextSections.length)
        );
        contexto = selectedContextSections.map(sectionToText).join("\n\n");
      }
    } else {
      selectedContextSections = [];
    }

    const systemPrompt = [
      "Eres Aurora, asistente virtual de la plataforma Bitácora de Obra.",
      "Ayudas a residentes, interventores y contratistas a entender el estado del proyecto usando la información auditada que recibes.",
      "",
      "Guías obligatorias:",
      "1. Utiliza únicamente el contexto suministrado; no inventes datos ni supongas valores faltantes.",
      "2. Indica con claridad cuando un dato no aparezca en el contexto e invita a consultar al responsable correspondiente.",
      "3. Prioriza riesgos, vencimientos próximos, responsables y fechas clave.",
      "4. Redacta en español colombiano técnico, tono profesional y directo.",
      "5. Mantén la respuesta en máximo dos párrafos o viñetas breves (máx. 6 frases).",
      "6. Si el usuario pide procedimientos o recomendaciones, apóyate en el contexto; si no existe, di que no está disponible.",
      "7. Incluye cifras, unidades y fuentes del contexto cuando sea posible.",
      "",
      "Ejemplo de estilo cuando falta información:",
      "«No encuentro inspecciones de seguridad en el contexto entregado; por favor revisa la bitácora o consulta al residente de obra.»",
    ].join("\n");

    const exampleMessages: Array<{ role: "user" | "assistant"; content: string }> = [
      {
        role: "user",
        content:
          "Ejemplo (no responder al usuario real): ¿Qué compromisos vencen esta semana?",
      },
      {
        role: "assistant",
        content:
          "Ejemplo: Los compromisos con vencimiento más próximo son... (lista los hitos relevantes con fecha y responsable).",
      },
      {
        role: "user",
        content:
          "Ejemplo (no responder al usuario real): Dame cifras aunque no estén en el contexto.",
      },
      {
        role: "assistant",
        content:
          "Ejemplo: No puedo inventar datos; según el contexto compartido no hay cifras disponibles para esa consulta.",
      },
    ];

    const contextMessage = {
      role: "system" as const,
      content: `Contexto operativo del proyecto (usar estrictamente):\n${contexto}`,
    };

    const messages: Array<{
      role: "system" | "user" | "assistant";
      content: string;
    }> = [
      { role: "system", content: systemPrompt },
      ...exampleMessages,
      ...conversationHistory,
      contextMessage,
      { role: "user", content: String(query) },
    ];

    const chatModel = process.env.OPENAI_CHAT_MODEL || "gpt-4o-mini";

    const completion = await openai.chat.completions.create({
      model: chatModel,
      temperature: 0.2,
      messages,
    });

    const botResponse =
      completion.choices?.[0]?.message?.content?.trim() ||
      "No pude generar una respuesta.";

    const promptTokens = completion.usage?.prompt_tokens ?? 0;
    const completionTokens = completion.usage?.completion_tokens ?? 0;
    const totalTokens = promptTokens + completionTokens;
    const costPer1K = MODEL_COST_PER_K_TOKENS[chatModel] ?? 0;
    const estimatedCost =
      costPer1K > 0 && totalTokens > 0
        ? (totalTokens / 1000) * costPer1K
        : 0;
    const costIncrementDecimal = new Prisma.Decimal(estimatedCost.toFixed(4));

    let interactionId: string | null = null;

    try {
      const newInteractionId = randomUUID();
      interactionId = newInteractionId;
      await prisma.chatbotInteraction.create({
        data: {
          id: newInteractionId,
          userId,
          question: String(query),
          answer: botResponse,
          model: chatModel,
          tokensPrompt: promptTokens,
          tokensCompletion: completionTokens,
          selectedSections: selectedContextSections.map((section) => ({
            id: section.id,
            heading: section.heading,
          })),
          metadata: {
            totalSectionsAvailable: contextSections.length,
            selectedCount: selectedContextSections.length,
            hasConversationHistory: conversationHistory.length > 0,
            retrievalPromptLength: retrievalPrompt.length,
            totalTokens,
            estimatedCost,
          },
        },
      });
    } catch (loggingError) {
      console.warn(
        "No fue posible guardar la interacción del chatbot:",
        loggingError
      );
    }

    try {
      const usageDate = new Date();
      usageDate.setHours(0, 0, 0, 0);

      await prisma.chatbotUsage.upsert({
        where: {
          userId_date: {
            userId,
            date: usageDate,
          },
        },
        update: {
          queryCount: { increment: 1 },
          tokensUsed: { increment: totalTokens },
          cost: { increment: costIncrementDecimal },
          model: chatModel,
        },
        create: {
          userId,
          date: usageDate,
          queryCount: 1,
          tokensUsed: totalTokens,
          cost: costIncrementDecimal,
          model: chatModel,
        },
      });
    } catch (usageError) {
      console.warn(
        "No se pudo actualizar las métricas de uso del chatbot:",
        usageError
      );
    }

    res.json({
      response: botResponse,
      interactionId,
      contextSections: selectedContextSections.map((section) => ({
        id: section.id,
        heading: section.heading,
      })),
    });
  } catch (error: any) {
    console.error("Error al contactar la API de OpenAI:", error);
    if (error.response) {
      console.error("Detalle del error:", error.response.data);
      if (error.response.status === 401) {
        return res.status(500).json({
          error: "La clave de API de OpenAI no es válida. Revisa tu .env.",
        });
      }
      if (error.response.status === 429) {
        return res.status(500).json({
          error: "Límite de cuota de OpenAI excedido. Revisa tu facturación.",
        });
      }
    }
    res.status(500).json({ error: "Error al procesar la respuesta del chatbot." });
  }
});

app.post(
  "/api/chatbot/feedback",
  authMiddleware,
  async (req: AuthRequest, res) => {
    const { interactionId, rating, comment, tags } = req.body ?? {};
    const userId = req.user?.userId;

    if (!interactionId || typeof interactionId !== "string") {
      return res
        .status(400)
        .json({ error: "interactionId es obligatorio para enviar feedback." });
    }
    if (rating !== "POSITIVE" && rating !== "NEGATIVE") {
      return res.status(400).json({
        error: "rating debe ser POSITIVE o NEGATIVE.",
      });
    }
    if (!userId) {
      return res.status(401).json({ error: "Usuario no autenticado." });
    }

    try {
      const interaction = await prisma.chatbotInteraction.findUnique({
        where: { id: interactionId },
        select: { userId: true },
      });

      if (!interaction) {
        return res
          .status(404)
          .json({ error: "No se encontró la interacción especificada." });
      }

      if (interaction.userId !== userId) {
        return res.status(403).json({
          error: "No tienes permisos para calificar esta interacción.",
        });
      }

      const metadata =
        tags && Array.isArray(tags) && tags.length ? { tags } : undefined;

      await prisma.chatbotFeedback.upsert({
        where: { interactionId },
        update: {
          rating: rating as ChatbotFeedbackRating,
          comment: typeof comment === "string" ? comment : undefined,
          metadata,
        },
        create: {
          interactionId,
          rating: rating as ChatbotFeedbackRating,
          comment: typeof comment === "string" ? comment : undefined,
          metadata,
        },
      });

      res.json({ success: true });
    } catch (error) {
      console.error("Error al registrar feedback del chatbot:", error);
      res
        .status(500)
        .json({ error: "No se pudo guardar el feedback del chatbot." });
    }
  }
);

// --- RUTAS DE FIRMA DEL USUARIO ---
app.get("/api/users/me/signature", authMiddleware, async (req: AuthRequest, res) => {
  try {
    const userId = req.user?.userId;
    if (!userId) {
      return res.status(401).json({ error: "Usuario no autenticado." });
    }

    const signature = await prisma.userSignature.findUnique({
      where: { userId },
    });

    if (!signature) {
      return res.json({ signature: null });
    }

    // NO exponer la firma encriptada - solo metadatos
    // La firma solo se puede obtener desencriptada con el endpoint específico que requiere contraseña
    res.json({
      signature: {
        id: signature.id,
        fileName: signature.fileName,
        mimeType: signature.mimeType,
        size: signature.size,
        hasSignature: true,
        createdAt: signature.createdAt,
        updatedAt: signature.updatedAt,
      },
    });
  } catch (error) {
    console.error("Error al obtener la firma del usuario:", error);
    res.status(500).json({ error: "No se pudo obtener la firma guardada." });
  }
});

/**
 * Endpoint para obtener la firma desencriptada (requiere contraseña)
 * Solo el usuario puede acceder a su propia firma desencriptada
 */
app.post(
  "/api/users/me/signature/decrypt",
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const userId = req.user?.userId;
      if (!userId) {
        return res.status(401).json({ error: "Usuario no autenticado." });
      }

      const { password } = req.body || {};
      if (!password || typeof password !== "string") {
        return res.status(400).json({
          error: "Se requiere la contraseña para desencriptar la firma.",
        });
      }

      // Verificar que la contraseña sea correcta
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { password: true },
      });

      if (!user) {
        return res.status(404).json({ error: "Usuario no encontrado." });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({
          error: "Contraseña incorrecta.",
        });
      }

      const signature = await prisma.userSignature.findUnique({
        where: { userId },
      });

      if (!signature || !signature.storagePath) {
        return res.status(404).json({ error: "No hay firma registrada." });
      }

      // Cargar la firma encriptada desde storage
      const storage = getStorage();
      const encryptedBuffer = await storage.load(signature.storagePath);

      // Desencriptar usando la contraseña del usuario
      const encryptedData = unpackEncryptedSignature(encryptedBuffer);
      const decryptedBuffer = decryptSignature(encryptedData, password);

      // Retornar como base64 para que el frontend pueda usarla
      const base64Signature = decryptedBuffer.toString("base64");
      const dataUrl = `data:${signature.mimeType || "image/png"};base64,${base64Signature}`;

      res.json({
        signature: {
          id: signature.id,
          fileName: signature.fileName,
          mimeType: signature.mimeType,
          size: signature.size,
          dataUrl, // Firma desencriptada como data URL
        },
      });
    } catch (error) {
      console.error("Error al desencriptar la firma:", error);
      if (error instanceof Error && error.message.includes("Unsupported state")) {
        return res.status(401).json({
          error: "Contraseña incorrecta o firma corrupta.",
        });
      }
      res.status(500).json({ error: "No se pudo desencriptar la firma." });
    }
  }
);

app.post(
  "/api/users/me/signature",
  authMiddleware,
  signatureUpload.single("signature"),
  async (req: AuthRequest, res) => {
    try {
      const userId = req.user?.userId;
      if (!userId) {
        return res.status(401).json({ error: "Usuario no autenticado." });
      }

      const file = req.file;
      if (!file || !file.buffer) {
        return res
          .status(400)
          .json({ error: "No se recibió ningún archivo válido." });
      }

      // Requerir contraseña para encriptar la firma
      const { password } = req.body || {};
      if (!password || typeof password !== "string") {
        return res.status(400).json({
          error: "Se requiere la contraseña del usuario para proteger la firma.",
        });
      }

      // Verificar que la contraseña sea correcta
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { password: true },
      });

      if (!user) {
        return res.status(404).json({ error: "Usuario no encontrado." });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({
          error: "Contraseña incorrecta. La firma requiere tu contraseña para ser protegida.",
        });
      }

      const existing = await prisma.userSignature.findUnique({
        where: { userId },
      });

      // Encriptar la firma usando la contraseña del usuario
      const encryptedData = encryptSignature(file.buffer, password);
      const encryptedBuffer = packEncryptedSignature(encryptedData);

      // Guardar la firma encriptada en storage
      const storage = getStorage();
      const key = createStorageKey("firmas", file.originalname);
      await storage.save({ path: key, content: encryptedBuffer });
      
      // NO guardar la URL pública ni el hash del archivo original
      // Solo guardar metadatos y el hash del archivo encriptado para verificación
      const hash = sha256(encryptedBuffer);

      let newSignature: any = null;
      await prisma.$transaction(async (tx) => {
        if (existing) {
          // Eliminar firma anterior del storage
          if (existing.storagePath) {
            await storage.remove(existing.storagePath).catch((error) => {
              console.warn(
                "No se pudo eliminar la firma anterior del almacenamiento.",
                { error }
              );
            });
          }
          await tx.userSignature.delete({ where: { id: existing.id } });
        }
        newSignature = await tx.userSignature.create({
          data: {
            userId,
            fileName: file.originalname,
            mimeType: file.mimetype,
            size: file.size, // Tamaño original
            storagePath: key,
            // NO guardar URL pública - la firma está encriptada
            url: null,
            hash, // Hash del archivo encriptado
          },
        });
      });

      if (!newSignature) {
        throw new Error("No se pudo registrar la nueva firma.");
      }

      res.status(201).json({
        signature: {
          id: newSignature.id,
          fileName: newSignature.fileName,
          mimeType: newSignature.mimeType,
          size: newSignature.size,
          // NO exponer URL ni hash - la firma está protegida
          hasSignature: true,
          createdAt: newSignature.createdAt,
          updatedAt: newSignature.updatedAt,
        },
        message: "Firma guardada y protegida con encriptación. Solo tú puedes acceder a ella con tu contraseña.",
      });
    } catch (error) {
      console.error("Error al guardar la firma del usuario:", error);
      res.status(500).json({ error: "No se pudo guardar la firma." });
    }
  }
);

app.delete(
  "/api/users/me/signature",
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const userId = req.user?.userId;
      if (!userId) {
        return res.status(401).json({ error: "Usuario no autenticado." });
      }

      const existing = await prisma.userSignature.findUnique({
        where: { userId },
      });
      if (!existing) {
        return res
          .status(404)
          .json({ error: "No hay firma registrada para el usuario." });
      }

      const storage = getStorage();
      await prisma.userSignature.delete({ where: { id: existing.id } });
      if (existing.storagePath) {
        await storage.remove(existing.storagePath).catch((error) => {
          console.warn(
            "No se pudo eliminar el archivo de firma del almacenamiento.",
            { error }
          );
        });
      }

      res.status(204).send();
    } catch (error) {
      console.error("Error al eliminar la firma del usuario:", error);
      res.status(500).json({ error: "No se pudo eliminar la firma." });
    }
  }
);

// --- RUTAS PARA PLANOS (DRAWINGS) ---
app.get("/api/drawings", async (_req, res) => {
  try {
    const drawings = await prisma.drawing.findMany({
      orderBy: { createdAt: "desc" },
      include: {
        versions: {
          orderBy: { versionNumber: "desc" },
          include: { uploader: true },
        },
        comments: {
          include: { author: true, attachments: true },
          orderBy: { timestamp: "asc" },
        },
      },
    });

    const formatted = drawings.map((drawing) => ({
      ...drawing,
      discipline:
        Object.keys(drawingDisciplineMap).find(
          (key) => drawingDisciplineMap[key] === drawing.discipline
        ) || drawing.discipline,
      versions: (drawing.versions || []).map((version: any) => {
        const normalizeUrl = (url: string) =>
          typeof url === "string" ? url.replace("/download", "/view") : url;
        return {
          ...version,
          url: normalizeUrl(version.url),
          createdAt:
            version.createdAt instanceof Date
              ? version.createdAt.toISOString()
              : version.createdAt,
        };
      }),
      comments: (drawing.comments || []).map((comment: any) => ({
        ...comment,
        timestamp:
          comment.timestamp instanceof Date
            ? comment.timestamp.toISOString()
            : comment.timestamp,
        attachments: (comment.attachments || []).map(buildAttachmentResponse),
      })),
    }));

    res.json(formatted);
  } catch (error) {
    console.error("Error al obtener los planos:", error);
    res.status(500).json({ error: "No se pudieron obtener los planos." });
  }
});

app.get("/api/drawings/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const drawing = await prisma.drawing.findUnique({
      where: { id },
      include: {
        versions: {
          orderBy: { versionNumber: "desc" },
          include: { uploader: true },
        },
        comments: {
          include: { author: true, attachments: true },
          orderBy: { timestamp: "asc" },
        },
      },
    });

    if (!drawing) {
      return res.status(404).json({ error: "Plano no encontrado." });
    }

    const formatted = {
      ...drawing,
      discipline:
        Object.keys(drawingDisciplineMap).find(
          (key) => drawingDisciplineMap[key] === drawing.discipline
        ) || drawing.discipline,
      versions: (drawing.versions || []).map((version: any) => {
        const normalizeUrl = (url: string) =>
          typeof url === "string" ? url.replace("/download", "/view") : url;
        return {
          ...version,
          url: normalizeUrl(version.url),
          createdAt:
            version.createdAt instanceof Date
              ? version.createdAt.toISOString()
              : version.createdAt,
        };
      }),
      comments: (drawing.comments || []).map((comment: any) => ({
        ...comment,
        timestamp:
          comment.timestamp instanceof Date
            ? comment.timestamp.toISOString()
            : comment.timestamp,
        attachments: (comment.attachments || []).map(buildAttachmentResponse),
      })),
    };

    res.json(formatted);
  } catch (error) {
    console.error("Error al obtener el plano:", error);
    res.status(500).json({ error: "No se pudo obtener el plano solicitado." });
  }
});

app.post(
  "/api/drawings",
  authMiddleware,
  requireEditor,
  async (req: AuthRequest, res) => {
    try {
      const { code, title, discipline, version } = req.body ?? {};
      if (!code || !title || !discipline || !version) {
        return res
          .status(400)
          .json({ error: "Faltan datos para crear el plano." });
      }

      const prismaDiscipline = drawingDisciplineMap[discipline] || "OTHER";

      const newDrawing = await prisma.drawing.create({
        data: {
          code,
          title,
          discipline: prismaDiscipline,
          status: "VIGENTE",
          versions: {
            create: [
              {
                versionNumber: 1,
                fileName: version.fileName,
                url: version.url,
                size: version.size,
                uploader: { connect: { id: version.uploaderId } },
              },
            ],
          },
        },
        include: {
          versions: { include: { uploader: true } },
          comments: { include: { author: true } },
        },
      });

      const formatted = {
        ...newDrawing,
        discipline:
          Object.keys(drawingDisciplineMap).find(
            (key) => drawingDisciplineMap[key] === newDrawing.discipline
          ) || newDrawing.discipline,
      };

      res.status(201).json(formatted);
    } catch (error) {
      console.error("Error al crear el plano:", error);
      if ((error as any)?.code === "P2002") {
        return res
          .status(409)
          .json({ error: "Ya existe un plano con este código." });
      }
      res.status(500).json({ error: "No se pudo crear el plano." });
    }
  }
);

app.post(
  "/api/drawings/:id/versions",
  authMiddleware,
  requireEditor,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const { version } = req.body ?? {};

      if (!version) {
        return res
          .status(400)
          .json({ error: "Faltan los datos de la nueva versión." });
      }

      const existingDrawing = await prisma.drawing.findUnique({
        where: { id },
        include: { versions: { orderBy: { versionNumber: "desc" } } },
      });

      if (!existingDrawing) {
        return res.status(404).json({ error: "El plano no fue encontrado." });
      }

      const latestVersionNumber =
        existingDrawing.versions[0]?.versionNumber || 0;

      const updatedDrawing = await prisma.drawing.update({
        where: { id },
        data: {
          status: "VIGENTE",
          versions: {
            create: {
              versionNumber: latestVersionNumber + 1,
              fileName: version.fileName,
              url: version.url,
              size: version.size,
              uploader: { connect: { id: version.uploaderId } },
            },
          },
        },
        include: {
          versions: {
            orderBy: { versionNumber: "desc" },
            include: { uploader: true },
          },
          comments: { include: { author: true } },
        },
      });

      const formatted = {
        ...updatedDrawing,
        discipline:
          Object.keys(drawingDisciplineMap).find(
            (key) => drawingDisciplineMap[key] === updatedDrawing.discipline
          ) || updatedDrawing.discipline,
      };

      res.status(201).json(formatted);
    } catch (error) {
      console.error("Error al añadir nueva versión:", error);
      res.status(500).json({ error: "No se pudo añadir la nueva versión." });
    }
  }
);

app.post(
  "/api/drawings/:id/comments",
  authMiddleware,
  requireEditor,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const { content, authorId } = req.body ?? {};
      const resolvedAuthorId = req.user?.userId || authorId;

      if (!content || !resolvedAuthorId) {
        return res
          .status(400)
          .json({ error: "El contenido y el autor son obligatorios." });
      }

      const newComment = await prisma.comment.create({
        data: {
          content,
          author: { connect: { id: resolvedAuthorId } },
          drawing: { connect: { id } },
        },
        include: { author: true },
      });

      res.status(201).json(newComment);
    } catch (error) {
      console.error("Error al añadir el comentario al plano:", error);
      res.status(500).json({ error: "No se pudo añadir el comentario." });
    }
  }
);

// --- RUTAS DE CARGA DE ARCHIVOS ---
app.post(
  "/api/upload",
  authMiddleware,
  requireEditor,
  upload.single("file"),
  async (req: AuthRequest, res) => {
    try {
      const file = req.file;
      if (!file || !file.buffer) {
        return res
          .status(400)
          .json({ error: "No se subió ningún archivo válido." });
      }

      // Determinar la sección basada en el tipo de archivo y contexto (igual que el expediente exportado)
      const fileType = req.body?.type || "document"; // 'document', 'photo', 'drawing'
      const context = req.body?.context || req.body?.section; // 'bitacora', 'actas', 'comunicaciones', 'informes', etc.
      const controlPointId = req.body?.controlPointId; // ID del punto fijo para fotos
      
      let seccion: string;
      let subfolder: string | undefined;
      
      if (fileType === "photo") {
        seccion = "puntos-fijos";
        // Si hay controlPointId, usarlo como subcarpeta
        if (controlPointId && typeof controlPointId === "string") {
          subfolder = controlPointId;
        }
      } else if (fileType === "drawing") {
        seccion = "planos";
      } else if (context) {
        // Si se especifica un contexto, usarlo (normalizado)
        const normalizedContext = context
          .replace(/[^a-zA-Z0-9_-]/g, "")
          .toLowerCase();
        // Mapear nombres comunes a secciones del expediente
        const contextMap: Record<string, string> = {
          "acta": "actas",
          "actas": "actas",
          "comunicacion": "comunicaciones",
          "comunicaciones": "comunicaciones",
          "informe": "informes",
          "informes": "informes",
          "report": "informes",
          "reports": "informes",
          "bitacora": "bitacora",
          "logentry": "bitacora",
          "log-entry": "bitacora",
        };
        seccion = contextMap[normalizedContext] || normalizedContext;
      } else {
        // Por defecto, archivos generales van a bitacora
        seccion = "bitacora";
      }
      
      const storage = getStorage();
      const key = createStorageKey(seccion, file.originalname, subfolder);
      await storage.save({ path: key, content: file.buffer });
      const stored = {
        key,
        url: storage.getPublicUrl(key),
      };

      const attachment = await prisma.attachment.create({
        data: {
          fileName: file.originalname,
          url: stored.url,
          storagePath: stored.key,
          size: file.size,
          type: file.mimetype,
        },
      });

      res.status(201).json(buildAttachmentResponse(attachment));
    } catch (error) {
      console.error("Error en la subida de archivo:", error);
      res
        .status(500)
        .json({ error: "No se pudo procesar el archivo subido." });
    }
  }
);

// --- RUTAS DE CRONOGRAMA Y CONTROL ---
app.get("/api/project-tasks", async (req, res) => {
  try {
    const where = withTenantFilter(req);
    const tasks = await prisma.projectTask.findMany({
      where: Object.keys(where).length > 0 ? (where as any) : undefined,
      orderBy: { outlineLevel: "asc" },
    });

    const formatted = tasks.map((task) => ({
      ...task,
      startDate: task.startDate.toISOString(),
      endDate: task.endDate.toISOString(),
      dependencies: task.dependencies ? JSON.parse(task.dependencies) : [],
      children: [],
    }));

    res.json(formatted);
  } catch (error) {
    console.error("Error al obtener tareas del proyecto:", error);
    res
      .status(500)
      .json({ error: "No se pudieron obtener las tareas del proyecto." });
  }
});

app.get("/api/control-points", async (req, res) => {
  try {
    // Filtrar por tenant si está disponible
    // Nota: tenantId se agregará después de aplicar la migración
    // Por ahora, usar query raw si hay tenant, o query normal si no
    let points: any[];
    
    if (req.tenant) {
      // Después de la migración, usar findMany con where
      // Por ahora, usar query raw como fallback
      try {
        points = await prisma.$queryRawUnsafe(
          `SELECT * FROM ControlPoint WHERE tenantId = ? ORDER BY createdAt ASC`,
          req.tenant.id
        ) as any[];
      } catch (error) {
        // Si falla (campo no existe aún), usar query normal
        points = await prisma.controlPoint.findMany({
          orderBy: { createdAt: "asc" },
          include: {
            photos: {
              orderBy: [{ order: "asc" }, { date: "asc" }],
              include: { author: true, attachment: true },
            },
          },
        });
      }
    } else {
      points = await prisma.controlPoint.findMany({
        orderBy: { createdAt: "asc" },
        include: {
          photos: {
            orderBy: [{ order: "asc" }, { date: "asc" }],
            include: { author: true, attachment: true },
          },
        },
      });
    }
    
    // Si usamos query raw, necesitamos cargar las relaciones manualmente
    if (req.tenant && points.length > 0 && !points[0].photos) {
      const pointIds = points.map((p: any) => p.id);
      const allPhotos = await prisma.photoEntry.findMany({
        where: { controlPointId: { in: pointIds } },
        include: { author: true, attachment: true },
        orderBy: [{ order: "asc" }, { date: "asc" }],
      });
      
      points = points.map((point: any) => ({
        ...point,
        photos: allPhotos.filter((p: any) => p.controlPointId === point.id),
      }));
    }

    const formatted = points.map((point: any) => ({
      ...point,
      photos: (point.photos || []).map((photo: any) => ({
        ...photo,
        date:
          photo.date instanceof Date ? photo.date.toISOString() : photo.date,
        author: mapUserBasic(photo.author),
        attachment: photo.attachment
          ? buildAttachmentResponse(photo.attachment)
          : null,
      })),
    }));

    res.json(formatted);
  } catch (error) {
    console.error("Error al obtener puntos de control:", error);
    res
      .status(500)
      .json({ error: "No se pudieron obtener los puntos de control." });
  }
});

app.get("/api/contract-items", async (_req, res) => {
  try {
    const items = await prisma.contractItem.findMany({
      include: {
        executions: {
          orderBy: { createdAt: "asc" },
        },
      },
      orderBy: { itemCode: "asc" },
    });
    res.json(items);
  } catch (error) {
    console.error("Error al obtener ítems contractuales:", error);
    res
      .status(500)
      .json({ error: "No se pudieron obtener los ítems contractuales." });
  }
});

app.patch(
  "/api/contract-items/:id/executed-quantity",
  authMiddleware,
  requireEditor,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const { executedQuantity, pkId } = req.body;

      if (executedQuantity === undefined || executedQuantity === null) {
        return res.status(400).json({
          error: "La cantidad ejecutada es obligatoria.",
        });
      }

      if (!pkId) {
        return res.status(400).json({
          error: "El PK_ID es obligatorio.",
        });
      }

      const numQuantity = parseFloat(executedQuantity);
      if (isNaN(numQuantity) || numQuantity < 0) {
        return res.status(400).json({
          error: "La cantidad ejecutada debe ser un número válido mayor o igual a 0.",
        });
      }

      // Crear o actualizar la ejecución para este PK_ID
      const execution = await prisma.contractItemExecution.upsert({
        where: {
          contractItemId_pkId: {
            contractItemId: id,
            pkId: pkId,
          },
        },
        update: {
          quantity: numQuantity,
        },
        create: {
          contractItemId: id,
          pkId: pkId,
          quantity: numQuantity,
        },
      });

      // Calcular la suma total de todas las ejecuciones
      const allExecutions = await prisma.contractItemExecution.findMany({
        where: { contractItemId: id },
      });
      const totalExecuted = allExecutions.reduce((sum: number, exec: { quantity: number }) => sum + exec.quantity, 0);

      // Actualizar el executedQuantity total del item
      const updatedItem = await prisma.contractItem.update({
        where: { id },
        data: { executedQuantity: totalExecuted },
        include: {
          executions: {
            orderBy: { createdAt: "asc" },
          },
        },
      });

      res.json(updatedItem);
    } catch (error) {
      console.error("Error al actualizar cantidad ejecutada:", error);
      if ((error as any)?.code === "P2025") {
        return res.status(404).json({
          error: "El ítem contractual no fue encontrado.",
        });
      }
      res.status(500).json({
        error: "No se pudo actualizar la cantidad ejecutada.",
      });
    }
  }
);

app.get("/api/work-actas", async (req, res) => {
  try {
    const where = withTenantFilter(req);
    const actas = await prisma.workActa.findMany({
      where: Object.keys(where).length > 0 ? (where as any) : undefined,
      orderBy: { date: "desc" },
      include: {
        items: { include: { contractItem: true } },
        attachments: true,
      },
    });
    res.json(actas.map((acta) => formatWorkActa(acta)));
  } catch (error) {
    console.error("Error al obtener actas de avance:", error);
    res
      .status(500)
      .json({ error: "No se pudieron obtener las actas de avance." });
  }
});

app.get("/api/work-actas/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const where = withTenantFilter(req, { id } as any);
    const acta = await prisma.workActa.findFirst({
      where: Object.keys(where).length > 1 ? (where as any) : { id },
      include: {
        items: { include: { contractItem: true } },
        attachments: true,
      },
    });

    if (!acta) {
      return res.status(404).json({ error: "Acta de avance no encontrada." });
    }
    
    // Verificar que el tenant coincida si hay tenant
    if ((req as any).tenant && (acta as any).tenantId !== (req as any).tenant.id) {
      return res.status(404).json({ error: "Acta de avance no encontrada." });
    }

    res.json(formatWorkActa(acta));
  } catch (error) {
    console.error("Error al obtener detalle de acta de avance:", error);
    res
      .status(500)
      .json({ error: "No se pudo obtener el acta de avance solicitada." });
  }
});

app.post(
  "/api/work-actas",
  authMiddleware,
  requireEditor,
  async (req: AuthRequest, res) => {
    try {
      const { number, period, date, status, items, attachments = [] } =
        req.body ?? {};

      if (!number || !period || !date || !Array.isArray(items) || !items.length) {
        return res.status(400).json({
          error: "Faltan datos para crear el acta de avance.",
        });
      }

      const prismaStatus = workActaStatusMap[status] || "DRAFT";

      // Asignar tenantId si está disponible
      const tenantId = (req as any).tenant?.id;
      const workActaData: any = {
        number,
        period,
        date: new Date(date),
        status: prismaStatus,
      };
      if (tenantId) {
        workActaData.tenantId = tenantId;
      }

      const newActa = await prisma.workActa.create({
        data: {
          ...workActaData,
          items: {
            create: items.map(
              (item: { contractItemId: string; quantity: number }) => ({
                quantity: item.quantity,
                contractItem: { connect: { id: item.contractItemId } },
              })
            ),
          },
          attachments: {
            connect: Array.isArray(attachments)
              ? attachments
                  .filter((att: { id: string }) => att && att.id)
                  .map((att: { id: string }) => ({ id: att.id }))
              : [],
          },
        },
        include: {
          items: { include: { contractItem: true } },
          attachments: true,
        },
      });

      res.status(201).json(formatWorkActa(newActa));
    } catch (error) {
      console.error("Error al crear el acta de avance:", error);
      if ((error as any)?.code === "P2002") {
        return res
          .status(409)
          .json({ error: "Ya existe un acta de avance con este número." });
      }
      res.status(500).json({ error: "No se pudo crear el acta de avance." });
    }
  }
);

app.put(
  "/api/work-actas/:id",
  authMiddleware,
  requireEditor,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body ?? {};
      const prismaStatus = workActaStatusMap[status] || undefined;

      if (
        !prismaStatus ||
        !Object.values(WorkActaStatus).includes(prismaStatus)
      ) {
        return res.status(400).json({ error: "Estado inválido proporcionado." });
      }

      // Verificar que el work acta pertenezca al tenant
      const where = withTenantFilter(req, { id } as any);
      const existingActa = await prisma.workActa.findFirst({
        where: Object.keys(where).length > 1 ? (where as any) : { id },
      });

      if (!existingActa) {
        return res.status(404).json({ error: "El acta de avance no fue encontrada." });
      }
      
      // Verificar que el tenant coincida si hay tenant
      if ((req as any).tenant && (existingActa as any).tenantId !== (req as any).tenant.id) {
        return res.status(404).json({ error: "El acta de avance no fue encontrada." });
      }

      const updatedActa = await prisma.workActa.update({
        where: { id },
        data: { status: prismaStatus },
        include: {
          items: { include: { contractItem: true } },
          attachments: true,
        },
      });

      res.json(formatWorkActa(updatedActa));
    } catch (error) {
      console.error("Error al actualizar el acta de avance:", error);
      if ((error as any)?.code === "P2025") {
        return res
          .status(404)
          .json({ error: "El acta de avance no fue encontrada." });
      }
      res.status(500).json({ error: "No se pudo actualizar el acta de avance." });
    }
  }
);

// --- RUTAS PARA INFORMES ---
app.get("/api/reports", async (req, res) => {
  try {
    const { type, scope } = req.query;
    const where: any = withTenantFilter(req);

    if (type) where.type = String(type);
    if (scope && reportScopeMap[String(scope)]) {
      where.reportScope = reportScopeMap[String(scope)];
    }

    const reports = await prisma.report.findMany({
      where: Object.keys(where).length > 0 ? where : undefined,
      orderBy: [{ number: "asc" }, { version: "desc" }],
      include: {
        author: true,
        attachments: true,
        signatures: { include: { signer: true } },
      },
    });

    const grouped = new Map<string, any>();
    reports.forEach((report) => {
      const formatted = formatReportRecord(report);
      const summary = mapReportVersionSummary(report);

      if (!grouped.has(report.number)) {
        grouped.set(report.number, {
          ...formatted,
          versions: [summary],
        });
      } else {
        grouped.get(report.number).versions.push(summary);
      }
    });

    const latest = Array.from(grouped.values()).map((entry) => ({
      ...entry,
      versions: entry.versions.sort((a: any, b: any) => b.version - a.version),
    }));

    latest.sort(
      (a, b) =>
        new Date(b.submissionDate ?? 0).getTime() -
        new Date(a.submissionDate ?? 0).getTime()
    );

    res.json(latest);
  } catch (error) {
    console.error("Error al obtener los informes:", error);
    res.status(500).json({ error: "No se pudieron obtener los informes." });
  }
});

app.get("/api/reports/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const where = withTenantFilter(req, { id } as any);
    const report = await prisma.report.findFirst({
      where: Object.keys(where).length > 1 ? (where as any) : { id },
      include: {
        author: true,
        attachments: true,
        signatures: { include: { signer: true } },
      },
    });

    if (!report) {
      return res.status(404).json({ error: "Informe no encontrado." });
    }
    
    // Verificar que el tenant coincida si hay tenant
    if ((req as any).tenant && (report as any).tenantId !== (req as any).tenant.id) {
      return res.status(404).json({ error: "Informe no encontrado." });
    }

    const formatted = formatReportRecord(report);
    const versionHistory = await prisma.report.findMany({
      where: { number: report.number },
      select: {
        id: true,
        version: true,
        status: true,
        submissionDate: true,
        createdAt: true,
      },
      orderBy: { version: "desc" },
    });

    formatted.versions = versionHistory.map(mapReportVersionSummary);

    res.json(formatted);
  } catch (error) {
    console.error("Error al obtener el informe:", error);
    res.status(500).json({ error: "No se pudo obtener el informe solicitado." });
  }
});

app.post(
  "/api/reports",
  authMiddleware,
  requireEditor,
  async (req: AuthRequest, res) => {
    try {
      const {
        type,
        reportScope,
        number,
        period,
        submissionDate,
        summary,
        authorId,
        requiredSignatories = [],
        attachments = [],
        previousReportId,
      } = req.body ?? {};

      const resolvedAuthorId = req.user?.userId || authorId;

      if (!period || !submissionDate || !summary || !resolvedAuthorId) {
        return res
          .status(400)
          .json({ error: "Faltan datos obligatorios para crear el informe." });
      }

      let resolvedType = type as string | undefined;
      let resolvedScopeDb = reportScope
        ? reportScopeMap[reportScope as string]
        : undefined;
      let resolvedNumber = number as string | undefined;
      let resolvedVersion = 1;
      let previousReportConnect:
        | { connect: { id: string } }
        | undefined = undefined;

      // Asignar tenantId si está disponible
      const tenantId = (req as any).tenant?.id;

      if (previousReportId) {
        // Validar que el informe anterior pertenezca al tenant
        const prevWhere = tenantId ? { id: previousReportId, tenantId } as any : { id: previousReportId };
        const previousReport = await prisma.report.findFirst({
          where: prevWhere,
        });

        if (!previousReport) {
          return res
            .status(404)
            .json({ error: "El informe anterior no fue encontrado." });
        }

        resolvedType = previousReport.type;
        resolvedScopeDb = previousReport.reportScope;
        resolvedNumber = previousReport.number;
        resolvedVersion = previousReport.version + 1;
        previousReportConnect = { connect: { id: previousReport.id } };
      } else {
        if (!resolvedType || !reportScope || !resolvedNumber) {
          return res.status(400).json({
            error:
              "Faltan type, reportScope o number para crear la primera versión del informe.",
          });
        }

        if (!resolvedScopeDb) {
          const mapped = reportScopeMap[reportScope as string];
          if (!mapped) {
            return res.status(400).json({
              error: `El valor de reportScope '${reportScope}' no es válido.`,
            });
          }
          resolvedScopeDb = mapped;
        }
      }

      if (!Array.isArray(attachments)) {
        return res.status(400).json({
          error:
            "El formato de los adjuntos no es válido. Debe ser un arreglo de objetos { id }.",
        });
      }

      const reportData: any = {
        type: resolvedType!,
        reportScope: resolvedScopeDb!,
        number: resolvedNumber!,
        version: resolvedVersion,
        previousReport: previousReportConnect,
        period,
        submissionDate: new Date(submissionDate),
        summary,
        status: "DRAFT",
        author: { connect: { id: resolvedAuthorId } },
      };
      if (tenantId) {
        reportData.tenantId = tenantId;
      }

      const newReport = await prisma.report.create({
        data: {
          ...reportData,
          requiredSignatoriesJson: JSON.stringify(
            requiredSignatories.map((u: any) => u.id)
          ),
          attachments: {
            connect: attachments.map((att: { id: string }) => ({ id: att.id })),
          },
        },
        include: {
          author: true,
          attachments: true,
          signatures: { include: { signer: true } },
        },
      });

      const formatted = formatReportRecord(newReport);
      const versionHistory = await prisma.report.findMany({
        where: { number: newReport.number },
        select: {
          id: true,
          version: true,
          status: true,
          submissionDate: true,
          createdAt: true,
        },
        orderBy: { version: "desc" },
      });

      formatted.versions = versionHistory.map(mapReportVersionSummary);

      res.status(201).json(formatted);
    } catch (error) {
      console.error("Error al crear el informe:", error);
      if ((error as any)?.code === "P2002") {
        return res
          .status(409)
          .json({ error: "Ya existe un informe con este número y versión." });
      }
      res.status(500).json({ error: "No se pudo crear el informe." });
    }
  }
);

app.put(
  "/api/reports/:id",
  authMiddleware,
  requireEditor,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const { status, summary, requiredSignatories = [] } = req.body ?? {};

      const prismaStatus = reportStatusMap[status] || undefined;
      if (!prismaStatus || !Object.values(ReportStatus).includes(prismaStatus)) {
        return res.status(400).json({ error: "Estado inválido proporcionado." });
      }

      // Verificar que el report pertenezca al tenant
      const where = withTenantFilter(req, { id } as any);
      const existingReport = await prisma.report.findFirst({
        where: Object.keys(where).length > 1 ? (where as any) : { id },
      });

      if (!existingReport) {
        return res.status(404).json({ error: "El informe no fue encontrado." });
      }
      
      // Verificar que el tenant coincida si hay tenant
      if ((req as any).tenant && (existingReport as any).tenantId !== (req as any).tenant.id) {
        return res.status(404).json({ error: "El informe no fue encontrado." });
      }

      const updated = await prisma.report.update({
        where: { id },
        data: {
          status: prismaStatus,
          summary,
          requiredSignatoriesJson: JSON.stringify(
            requiredSignatories.map((u: any) => u.id)
          ),
        },
        include: {
          author: true,
          attachments: true,
          signatures: { include: { signer: true } },
        },
      });

      const formatted = formatReportRecord(updated);
      const versionHistory = await prisma.report.findMany({
        where: { number: updated.number },
        select: {
          id: true,
          version: true,
          status: true,
          submissionDate: true,
          createdAt: true,
        },
        orderBy: { version: "desc" },
      });
      formatted.versions = versionHistory.map(mapReportVersionSummary);

      res.json(formatted);
    } catch (error) {
      console.error("Error al actualizar el informe:", error);
      if ((error as any)?.code === "P2025") {
        return res.status(404).json({ error: "El informe no fue encontrado." });
      }
      res.status(500).json({ error: "No se pudo actualizar el informe." });
    }
  }
);

app.post(
  "/api/reports/:id/signatures",
  authMiddleware,
  requireEditor,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const { signerId, password } = req.body ?? {};

      if (!signerId || !password) {
        return res
          .status(400)
          .json({ error: "Se requiere ID del firmante y contraseña." });
      }

      const signer = await prisma.user.findUnique({ where: { id: signerId } });
      if (!signer) {
        return res.status(404).json({ error: "Usuario firmante no encontrado." });
      }

      const passwordMatches = await bcrypt.compare(password, signer.password);
      if (!passwordMatches) {
        return res.status(401).json({ error: "Contraseña incorrecta." });
      }

      // Verificar que el report pertenezca al tenant
      const where = withTenantFilter(req, { id } as any);
      const report = await prisma.report.findFirst({
        where: Object.keys(where).length > 1 ? (where as any) : { id },
      });
      if (!report) {
        return res.status(404).json({ error: "Informe no encontrado." });
      }
      
      // Verificar que el tenant coincida si hay tenant
      if ((req as any).tenant && (report as any).tenantId !== (req as any).tenant.id) {
        return res.status(404).json({ error: "Informe no encontrado." });
      }

      const existing = await prisma.signature.findFirst({
        where: { reportId: id, signerId },
      });

      if (existing) {
        const current = await prisma.report.findUnique({
          where: { id },
          include: {
            author: true,
            attachments: true,
            signatures: { include: { signer: true } },
          },
        });
        if (!current) {
          return res
            .status(404)
            .json({ error: "Informe no encontrado tras validar firma." });
        }
        const formatted = formatReportRecord(current);
        const versionHistory = await prisma.report.findMany({
          where: { number: current.number },
          select: {
            id: true,
            version: true,
            status: true,
            submissionDate: true,
            createdAt: true,
          },
          orderBy: { version: "desc" },
        });
        formatted.versions = versionHistory.map(mapReportVersionSummary);
        return res.json(formatted);
      }

      await prisma.signature.create({
        data: {
          signer: { connect: { id: signerId } },
          report: { connect: { id } },
        },
      });

      const updated = await prisma.report.findUnique({
        where: { id },
        include: {
          author: true,
          attachments: true,
          signatures: { include: { signer: true } },
        },
      });

      if (!updated) {
        return res
          .status(404)
          .json({ error: "Informe no encontrado tras añadir la firma." });
      }

      const formatted = formatReportRecord(updated);
      const versionHistory = await prisma.report.findMany({
        where: { number: updated.number },
        select: {
          id: true,
          version: true,
          status: true,
          submissionDate: true,
          createdAt: true,
        },
        orderBy: { version: "desc" },
      });
      formatted.versions = versionHistory.map(mapReportVersionSummary);

      res.status(201).json(formatted);
    } catch (error) {
      console.error("Error al añadir la firma al informe:", error);
      res.status(500).json({ error: "No se pudo añadir la firma." });
    }
  }
);

app.post(
  "/api/reports/:id/generate-weekly-excel",
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const baseUrl =
        process.env.SERVER_PUBLIC_URL || `http://localhost:${port}`;

      const tenantId = (req as any).tenant?.id;
      const result = await generateWeeklyReportExcel({
        prisma,
        reportId: id,
        uploadsDir,
        baseUrl,
        tenantId,
      });

      const updated = await prisma.report.findUnique({
        where: { id },
        include: {
          author: true,
          attachments: true,
          signatures: { include: { signer: true } },
        },
      });

      if (!updated) {
        return res
          .status(404)
          .json({ error: "Informe no encontrado tras generar el Excel." });
      }

      const formatted = formatReportRecord(updated);
      const versionHistory = await prisma.report.findMany({
        where: { number: updated.number },
        select: {
          id: true,
          version: true,
          status: true,
          submissionDate: true,
          createdAt: true,
        },
        orderBy: { version: "desc" },
      });
      formatted.versions = versionHistory.map(mapReportVersionSummary);

      res.json({
        report: formatted,
        attachment: buildAttachmentResponse(result.attachment),
      });
    } catch (error) {
      console.error("Error al generar el Excel del informe semanal:", error);
      if (error instanceof Error) {
        if (error.message === "Informe no encontrado.") {
          return res.status(404).json({ error: error.message });
        }
        if (error.message.includes("semanales")) {
          return res.status(400).json({ error: error.message });
        }
      }
      res
        .status(500)
        .json({ error: "No se pudo generar el Excel del informe semanal." });
    }
  }
);

app.post(
  "/api/reports/:id/export-pdf",
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const baseUrl =
        process.env.SERVER_PUBLIC_URL || `http://localhost:${port}`;

      const tenantId = (req as any).tenant?.id;
      const result = await generateReportPdf({
        prisma,
        reportId: id,
        uploadsDir,
        baseUrl,
        tenantId,
      });

      const updated = await prisma.report.findUnique({
        where: { id },
        include: {
          author: true,
          attachments: true,
          signatures: { include: { signer: true } },
        },
      });

      if (!updated) {
        return res
          .status(404)
          .json({ error: "Informe no encontrado tras generar el PDF." });
      }

      const formatted = formatReportRecord(updated);
      const versionHistory = await prisma.report.findMany({
        where: { number: updated.number },
        select: {
          id: true,
          version: true,
          status: true,
          submissionDate: true,
          createdAt: true,
        },
        orderBy: { version: "desc" },
      });
      formatted.versions = versionHistory.map(mapReportVersionSummary);

      res.json({
        report: formatted,
        attachment: buildAttachmentResponse(result.attachment),
      });
    } catch (error) {
      console.error("Error al generar PDF del informe:", error);
      if (error instanceof Error && error.message === "Informe no encontrado.") {
        return res.status(404).json({ error: error.message });
      }
      res.status(500).json({ error: "No se pudo generar el PDF." });
    }
  }
);

app.post(
  "/api/log-entries/:id/export-pdf",
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const baseUrl =
        process.env.SERVER_PUBLIC_URL || `http://localhost:${port}`;

      const tenantId = (req as any).tenant?.id;
      const result = await generateLogEntryPdf({
        prisma,
        logEntryId: id,
        uploadsDir: process.env.UPLOADS_DIR || "./uploads",
        baseUrl,
        tenantId,
      });

      const updated = await prisma.logEntry.findUnique({
        where: { id },
        include: {
          author: true,
          attachments: true,
          comments: {
            include: { author: true },
            orderBy: { timestamp: "asc" },
          },
          signatures: { include: { signer: true } },
          signatureTasks: { include: { signer: true } },
          reviewTasks: { include: { reviewer: true }, orderBy: { assignedAt: "asc" } } as any,
          assignees: true,
          history: { include: { user: true }, orderBy: { timestamp: "desc" } },
        },
      });

      if (!updated) {
        return res
          .status(404)
          .json({ error: "Anotación no encontrada tras generar el PDF." });
      }

      res.json({
        entry: formatLogEntry(updated),
        attachment: buildAttachmentResponse(result.attachment),
      });
    } catch (error) {
      console.error("Error al generar PDF de anotación:", error);
      if (error instanceof Error && error.message.includes("no encontrado")) {
        return res.status(404).json({ error: error.message });
      }
      res.status(500).json({ error: "No se pudo generar el PDF." });
    }
  }
);

// --- RUTAS PARA ACTAS DE COSTO ---
app.get("/api/cost-actas", async (req, res) => {
  try {
    const where = withTenantFilter(req);
    const actas = await prisma.costActa.findMany({
      where: Object.keys(where).length > 0 ? (where as any) : undefined,
      orderBy: { submissionDate: "desc" },
      include: {
        observations: { include: { author: true }, orderBy: { timestamp: "asc" } },
        attachments: true,
      },
    });

    res.json(
      actas.map((acta) => ({
        ...acta,
        status:
          Object.keys(costActaStatusMap).find(
            (key) => costActaStatusMap[key] === acta.status
          ) || acta.status,
      }))
    );
  } catch (error) {
    console.error("Error al obtener las actas de costo:", error);
    res
      .status(500)
      .json({ error: "No se pudieron obtener las actas de costo." });
  }
});

app.get("/api/cost-actas/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const where = withTenantFilter(req, { id } as any);
    const acta = await prisma.costActa.findFirst({
      where: Object.keys(where).length > 1 ? (where as any) : { id },
      include: {
        observations: { 
          include: { author: true }, 
          orderBy: { timestamp: "asc" } 
        },
        attachments: true,
      },
    });

    if (!acta) {
      return res.status(404).json({ error: "Acta de costo no encontrada." });
    }
    
    // Verificar que el tenant coincida si hay tenant
    if ((req as any).tenant && (acta as any).tenantId !== (req as any).tenant.id) {
      return res.status(404).json({ error: "Acta de costo no encontrada." });
    }

    res.json({
      ...acta,
      status:
        Object.keys(costActaStatusMap).find(
          (key) => costActaStatusMap[key] === acta.status
        ) || acta.status,
      observations: (acta.observations || []).map((obs) => ({
        ...obs,
        timestamp: obs.timestamp instanceof Date 
          ? obs.timestamp.toISOString() 
          : obs.timestamp,
      })),
      attachments: (acta.attachments || []).map(buildAttachmentResponse),
    });
  } catch (error) {
    console.error("Error al obtener el acta de costo:", error);
    res.status(500).json({ error: "No se pudo obtener el acta solicitada." });
  }
});

app.post(
  "/api/cost-actas",
  authMiddleware,
  requireEditor,
  async (req: AuthRequest, res) => {
    try {
      const {
        number,
        period,
        submissionDate,
        billedAmount,
        totalContractValue,
        periodValue,
        advancePaymentPercentage,
        relatedProgress,
        attachments = [],
      } = req.body ?? {};

      if (
        !number ||
        !period ||
        !submissionDate ||
        billedAmount === undefined ||
        totalContractValue === undefined
      ) {
        return res.status(400).json({
          error: "Faltan datos obligatorios para crear el acta de costo.",
        });
      }

      // Asignar tenantId si está disponible
      const tenantId = (req as any).tenant?.id;
      const costActaData: any = {
        number,
        period,
        submissionDate: new Date(submissionDate),
        billedAmount: Number(billedAmount),
        totalContractValue: Number(totalContractValue),
        periodValue: periodValue !== null && periodValue !== undefined ? Number(periodValue) : null,
        advancePaymentPercentage: advancePaymentPercentage !== null && advancePaymentPercentage !== undefined ? Number(advancePaymentPercentage) : null,
        relatedProgress,
        status: CostActaStatus.SUBMITTED,
      };
      if (tenantId) {
        costActaData.tenantId = tenantId;
      }

      const newActa = await prisma.costActa.create({
        data: {
          ...costActaData,
          attachments: {
            connect: attachments.map((att: { id: string }) => ({ id: att.id })),
          },
        },
        include: {
          observations: { include: { author: true } },
          attachments: true,
        },
      });

      res.status(201).json(newActa);
    } catch (error) {
      console.error("Error al crear el acta de costo:", error);
      if ((error as any)?.code === "P2002") {
        return res
          .status(409)
          .json({ error: "Ya existe un acta de costo con este número." });
      }
      res.status(500).json({ error: "No se pudo crear el acta de costo." });
    }
  }
);

app.put(
  "/api/cost-actas/:id",
  authMiddleware,
  requireEditor,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const { status, relatedProgress, periodValue, advancePaymentPercentage } = req.body ?? {};

      const prismaStatus = costActaStatusMap[status] || undefined;
      if (
        !prismaStatus ||
        !Object.values(CostActaStatus).includes(prismaStatus)
      ) {
        return res.status(400).json({ error: "Estado inválido proporcionado." });
      }

      // Verificar que el cost acta pertenezca al tenant
      const where = withTenantFilter(req, { id } as any);
      const existingActa = await prisma.costActa.findFirst({
        where: Object.keys(where).length > 1 ? (where as any) : { id },
      });

      if (!existingActa) {
        return res.status(404).json({ error: "El acta de costo no fue encontrada." });
      }
      
      // Verificar que el tenant coincida si hay tenant
      if ((req as any).tenant && (existingActa as any).tenantId !== (req as any).tenant.id) {
        return res.status(404).json({ error: "El acta de costo no fue encontrada." });
      }

      const updateData: Prisma.CostActaUpdateInput = {
        status: prismaStatus,
        relatedProgress,
      };

      if (periodValue !== undefined) {
        updateData.periodValue = periodValue !== null ? Number(periodValue) : null;
      }
      if (advancePaymentPercentage !== undefined) {
        updateData.advancePaymentPercentage = advancePaymentPercentage !== null ? Number(advancePaymentPercentage) : null;
      }

      if (prismaStatus === CostActaStatus.APPROVED) {
        const approvalDate = new Date();
        const paymentDueDate = new Date(approvalDate);
        paymentDueDate.setDate(paymentDueDate.getDate() + 30);

        updateData.approvalDate = approvalDate;
        updateData.paymentDueDate = paymentDueDate;
      }

      const updatedActa = await prisma.costActa.update({
        where: { id },
        data: updateData,
        include: {
          observations: { include: { author: true }, orderBy: { timestamp: "asc" } },
          attachments: true,
        },
      });

      res.json({
        ...updatedActa,
        status:
          Object.keys(costActaStatusMap).find(
            (key) => costActaStatusMap[key] === updatedActa.status
          ) || updatedActa.status,
      });
    } catch (error) {
      console.error("Error al actualizar el acta de costo:", error);
      if ((error as any)?.code === "P2025") {
        return res
          .status(404)
          .json({ error: "El acta de costo no fue encontrada." });
      }
      res.status(500).json({ error: "No se pudo actualizar el acta de costo." });
    }
  }
);

app.post(
  "/api/cost-actas/:id/observations",
  authMiddleware,
  requireEditor,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const { text, authorId } = req.body ?? {};
      const resolvedAuthorId = req.user?.userId || authorId;

      if (!text || !resolvedAuthorId) {
        return res.status(400).json({
          error: "El texto y el autor son obligatorios para la observación.",
        });
      }

      // Verificar que el cost acta pertenezca al tenant
      const where = withTenantFilter(req, { id } as any);
      const costActa = await prisma.costActa.findFirst({
        where: Object.keys(where).length > 1 ? (where as any) : { id },
      });

      if (!costActa) {
        return res.status(404).json({
          error: "El acta de costo no fue encontrada.",
        });
      }
      
      // Verificar que el tenant coincida si hay tenant
      if ((req as any).tenant && (costActa as any).tenantId !== (req as any).tenant.id) {
        return res.status(404).json({
          error: "El acta de costo no fue encontrada.",
        });
      }

      const newObservation = await prisma.observation.create({
        data: {
          text,
          author: { connect: { id: resolvedAuthorId } },
          costActa: { connect: { id } },
        },
        include: { author: true },
      });

      res.status(201).json({
        ...newObservation,
        timestamp: newObservation.timestamp instanceof Date 
          ? newObservation.timestamp.toISOString() 
          : newObservation.timestamp,
      });
    } catch (error) {
      console.error("Error al añadir la observación:", error);
      if ((error as any)?.code === "P2025") {
        return res.status(404).json({
          error:
            "El acta de costo o el usuario autor no fueron encontrados.",
        });
      }
      res.status(500).json({ error: "No se pudo añadir la observación." });
    }
  }
);

// Endpoint para agregar attachments a cost actas
app.post(
  "/api/cost-actas/:id/attachments",
  authMiddleware,
  requireEditor,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const { attachmentId } = req.body ?? {};

      if (!attachmentId) {
        return res.status(400).json({
          error: "El ID del adjunto es obligatorio.",
        });
      }

      // Verificar que el acta pertenezca al tenant
      const where = withTenantFilter(req, { id } as any);
      const costActa = await prisma.costActa.findFirst({
        where: Object.keys(where).length > 1 ? (where as any) : { id },
      });

      if (!costActa) {
        return res.status(404).json({
          error: "Acta de cobro no encontrada.",
        });
      }
      
      // Verificar que el tenant coincida si hay tenant
      if ((req as any).tenant && (costActa as any).tenantId !== (req as any).tenant.id) {
        return res.status(404).json({
          error: "Acta de cobro no encontrada.",
        });
      }

      // Verificar que el attachment existe y no esté ya vinculado a otro documento
      const attachment = await prisma.attachment.findUnique({
        where: { id: attachmentId },
      });

      if (!attachment) {
        return res.status(404).json({
          error: "Adjunto no encontrado.",
        });
      }

      // Si el attachment ya está vinculado a este acta, retornar éxito
      if (attachment.costActaId === id) {
        return res.status(200).json(buildAttachmentResponse(attachment));
      }

      // Vincular el attachment al acta
      const updatedAttachment = await prisma.attachment.update({
        where: { id: attachmentId },
        data: {
          costActa: { connect: { id } },
        },
      });

      res.status(200).json(buildAttachmentResponse(updatedAttachment));
    } catch (error) {
      console.error("Error al vincular el adjunto al acta de cobro:", error);
      if ((error as any)?.code === "P2025") {
        return res.status(404).json({
          error: "El acta de cobro o el adjunto no fueron encontrados.",
        });
      }
      if ((error as any)?.code === "P2002") {
        return res.status(409).json({
          error: "El adjunto ya está vinculado a otro documento.",
        });
      }
      res.status(500).json({ error: "No se pudo vincular el adjunto." });
    }
  }
);

// --- RUTAS PARA CONTROL PUNTOS ---
app.post(
  "/api/control-points",
  authMiddleware,
  requireEditor,
  async (req: AuthRequest, res) => {
    try {
      const { name, description, location } = req.body ?? {};

      if (!name) {
        return res
          .status(400)
          .json({ error: "El nombre del punto de control es obligatorio." });
      }

      // Asignar tenantId si está disponible (después de migración)
      const data: any = { name, description, location };
      if (req.tenant) {
        data.tenantId = req.tenant.id;
      }

      const newPoint = await prisma.controlPoint.create({
        data,
        include: {
          photos: { include: { author: true }, orderBy: [{ order: "asc" }, { date: "asc" }] },
        },
      });

      res.status(201).json(newPoint);
    } catch (error) {
      console.error("Error al crear el punto de control:", error);
      res.status(500).json({ error: "No se pudo crear el punto de control." });
    }
  }
);

app.post(
  "/api/control-points/:id/photos",
  authMiddleware,
  requireEditor,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const { notes, authorId, attachmentId } = req.body ?? {};
      const resolvedAuthorId = req.user?.userId || authorId;

      if (!resolvedAuthorId || !attachmentId) {
        return res
          .status(400)
          .json({ error: "Faltan datos del autor o del archivo adjunto." });
      }

      // Verificar que el control point pertenezca al tenant
      const where = withTenantFilter(req, { id } as any);
      const pointExists = await prisma.controlPoint.findFirst({
        where: Object.keys(where).length > 1 ? (where as any) : { id },
        include: { photos: true },
      });
      if (!pointExists) {
        return res.status(404).json({ error: "Punto de control no encontrado." });
      }
      
      // Verificar que el tenant coincida si hay tenant
      if ((req as any).tenant && (pointExists as any).tenantId !== (req as any).tenant.id) {
        return res.status(404).json({ error: "Punto de control no encontrado." });
      }

      const attachment = await prisma.attachment.findUnique({
        where: { id: attachmentId },
      });
      if (!attachment) {
        return res.status(404).json({ error: "Archivo adjunto no encontrado." });
      }

      // Asignar el orden basado en el número de fotos existentes
      const nextOrder = pointExists.photos.length;

      const newPhoto = await prisma.photoEntry.create({
        data: {
          notes,
          url: attachment.url,
          order: nextOrder, // Asignar orden secuencial
          author: { connect: { id: resolvedAuthorId } },
          controlPoint: { connect: { id } },
          attachment: { connect: { id: attachmentId } },
        },
        include: { author: true, attachment: true },
      });

      res.status(201).json({
        ...newPhoto,
        url: newPhoto.attachment?.url || newPhoto.url,
      });
    } catch (error) {
      console.error("Error al añadir la foto:", error);
      if ((error as any)?.code === "P2025") {
        return res.status(404).json({
          error:
            "El autor, punto de control o archivo adjunto no fueron encontrados.",
        });
      }
      res.status(500).json({ error: "No se pudo añadir la foto." });
    }
  }
);

// Endpoint para actualizar el orden de las fotos de un punto fijo
app.put(
  "/api/control-points/:id/photos/reorder",
  authMiddleware,
  requireEditor,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const { photoIds } = req.body ?? {}; // Array de IDs en el nuevo orden

      if (!Array.isArray(photoIds) || photoIds.length === 0) {
        return res.status(400).json({ error: "Se requiere un array de IDs de fotos en el nuevo orden." });
      }

      // Verificar que el control point pertenezca al tenant
      const where = withTenantFilter(req, { id } as any);
      const pointExists = await prisma.controlPoint.findFirst({
        where: Object.keys(where).length > 1 ? (where as any) : { id },
        include: { photos: true },
      });

      if (!pointExists) {
        return res.status(404).json({ error: "Punto de control no encontrado." });
      }
      
      // Verificar que el tenant coincida si hay tenant
      if ((req as any).tenant && (pointExists as any).tenantId !== (req as any).tenant.id) {
        return res.status(404).json({ error: "Punto de control no encontrado." });
      }

      // Verificar que todos los IDs pertenezcan a este punto fijo
      const photoIdsInPoint = pointExists.photos.map((p) => p.id);
      const allIdsValid = photoIds.every((photoId: string) => photoIdsInPoint.includes(photoId));
      if (!allIdsValid) {
        return res.status(400).json({ error: "Algunos IDs de fotos no pertenecen a este punto fijo." });
      }

      // Actualizar el orden de cada foto en una transacción
      await prisma.$transaction(
        photoIds.map((photoId: string, index: number) =>
          prisma.photoEntry.update({
            where: { id: photoId },
            data: { order: index },
          })
        )
      );

      // Obtener las fotos actualizadas
      const updatedPoint = await prisma.controlPoint.findUnique({
        where: { id },
        include: {
          photos: {
            orderBy: [{ order: "asc" }, { date: "asc" }],
            include: { author: true, attachment: true },
          },
        },
      });

      res.json({
        message: "Orden de fotos actualizado correctamente.",
        photos: updatedPoint?.photos || [],
      });
    } catch (error) {
      console.error("Error al actualizar el orden de las fotos:", error);
      res.status(500).json({ error: "No se pudo actualizar el orden de las fotos." });
    }
  }
);

// --- RUTA PARA IMPORTAR CRONOGRAMA ---
app.post(
  "/api/project-tasks/import",
  authMiddleware,
  requireEditor,
  async (req: AuthRequest, res) => {
    try {
      let incomingTasks: any[] | undefined;
      if (Array.isArray((req.body as any)?.tasks)) {
        incomingTasks = (req.body as any).tasks;
      } else if (typeof (req.body as any)?.xml === "string") {
        const parsed = await validateCronogramaXml((req.body as any).xml);
        incomingTasks = parsed;
      }

      if (!Array.isArray(incomingTasks)) {
        return res
          .status(400)
          .json({ error: "Formato inválido. Envía tareas normalizadas o XML válido." });
      }

      const MAX_NAME_LENGTH = Number(
        process.env.CRON_XML_MAX_NAME_LENGTH || 512
      );

      const sanitizedTasks = incomingTasks.map((task: any, index: number) => {
        const id =
          typeof task?.id === "string" && task.id.trim().length > 0
            ? task.id.trim()
            : randomUUID();
        const name =
          typeof task?.name === "string" && task.name.trim().length > 0
            ? task.name.trim()
            : `Tarea ${index + 1}`;
        const safeName =
          name.length > MAX_NAME_LENGTH
            ? name.slice(0, MAX_NAME_LENGTH)
            : name;

        const parsedStart = new Date(task?.startDate);
        if (Number.isNaN(parsedStart.getTime())) {
          throw new Error(`La tarea "${safeName}" no tiene una fecha de inicio válida.`);
        }

        const parsedEnd = new Date(task?.endDate || task?.startDate);
        if (Number.isNaN(parsedEnd.getTime())) {
          throw new Error(`La tarea "${safeName}" no tiene una fecha de fin válida.`);
        }
        if (parsedEnd < parsedStart) {
          parsedEnd.setTime(parsedStart.getTime());
        }

        const progressValue = Math.max(
          0,
          Math.min(100, parseInt(`${task?.progress ?? 0}`, 10) || 0)
        );
        const durationValue = Math.max(
          1,
          parseInt(`${task?.duration ?? 1}`, 10) || 1
        );
        const outlineLevelValue = Math.max(
          1,
          parseInt(`${task?.outlineLevel ?? 1}`, 10) || 1
        );
        const isSummaryValue =
          task?.isSummary === true ||
          task?.isSummary === 1 ||
          (typeof task?.isSummary === "string" &&
            task.isSummary.toLowerCase() === "true");

        const dependencyArray = Array.isArray(task?.dependencies)
          ? task.dependencies
              .map((dep: any) => `${dep}`.trim())
              .filter((dep: string) => dep.length > 0)
          : [];

        const taskData: any = {
          id,
          taskId: id,
          name: safeName,
          startDate: parsedStart,
          endDate: parsedEnd,
          progress: progressValue,
          duration: durationValue,
          isSummary: isSummaryValue,
          outlineLevel: outlineLevelValue,
          dependencies: dependencyArray.length
            ? JSON.stringify(dependencyArray)
            : null,
        };
        
        // Asignar tenantId si está disponible
        const tenantId = (req as any).tenant?.id;
        if (tenantId) {
          taskData.tenantId = tenantId;
        }
        
        return taskData;
      });

      const tenantId = (req as any).tenant?.id;
      await prisma.$transaction(async (tx) => {
        // Eliminar solo las tareas del tenant actual
        const deleteWhere: any = tenantId ? { tenantId } : {};
        await tx.projectTask.deleteMany({ where: deleteWhere });
        
        if (sanitizedTasks.length) {
          await tx.projectTask.createMany({ data: sanitizedTasks });
        }
      });

      // Obtener solo las tareas del tenant actual
      const whereClause: any = tenantId ? { tenantId } : undefined;
      const updatedTasks = await prisma.projectTask.findMany({
        where: whereClause,
        orderBy: { outlineLevel: "asc" },
      });

      const formatted = updatedTasks.map((task) => ({
        ...task,
        startDate: task.startDate.toISOString(),
        endDate: task.endDate.toISOString(),
        dependencies: task.dependencies ? JSON.parse(task.dependencies) : [],
        children: [],
      }));

      res.status(201).json(formatted);
    } catch (error) {
      console.error("Error al importar tareas del cronograma:", error);
      if (error instanceof CronogramaValidationError) {
        return res.status(400).json({ error: error.message });
      }
      res.status(500).json({ error: "No se pudo importar el cronograma." });
    }
  }
);

// --- RUTAS ADMINISTRATIVAS ---
app.get(
  "/api/admin/users",
  authMiddleware,
  requireAdmin,
  async (req: AuthRequest, res) => {
    try {
      // Filtrar usuarios por tenant
      const where = withTenantFilter(req);
      const users = await prisma.user.findMany({
        where: Object.keys(where).length > 0 ? (where as any) : undefined,
        orderBy: { fullName: "asc" },
      });
      res.json(users.map(formatAdminUser));
    } catch (error) {
      console.error("Error al obtener usuarios admin:", error);
      res.status(500).json({ error: "No se pudieron cargar los usuarios." });
    }
  }
);

app.post(
  "/api/admin/users/invite",
  authMiddleware,
  requireAdmin,
  async (req: AuthRequest, res) => {
    try {
      const { fullName, email, appRole, projectRole, entity } = req.body ?? {};

      if (!fullName || !email) {
        return res.status(400).json({
          error: "Se requieren nombre completo y email.",
          code: "MISSING_REQUIRED_FIELDS",
        });
      }

      if (!appRole || !["admin", "editor", "viewer"].includes(appRole)) {
        return res.status(400).json({
          error: "Rol de aplicación inválido.",
          code: "INVALID_APP_ROLE",
        });
      }

      // Verificar si el usuario ya existe (considerando tenant)
      const tenantId = (req as any).tenant?.id;
      const whereClause: any = tenantId
        ? { email: email.toLowerCase().trim(), tenantId }
        : { email: email.toLowerCase().trim() };
      
      const existingUser = await prisma.user.findFirst({
        where: whereClause,
      });

      if (existingUser) {
        return res.status(409).json({
          error: "Ya existe un usuario con este email.",
          code: "USER_ALREADY_EXISTS",
        });
      }

      // Resolver el rol de proyecto
      const resolvedRole = projectRole ? resolveProjectRole(projectRole) : undefined;
      if (projectRole && !resolvedRole) {
        return res.status(400).json({
          error: "Rol de proyecto inválido.",
          code: "INVALID_PROJECT_ROLE",
        });
      }

      // Validar entidad si se proporciona
      if (entity && !["IDU", "INTERVENTORIA", "CONTRATISTA"].includes(entity.toUpperCase())) {
        return res.status(400).json({
          error: "Entidad inválida. Usa 'IDU', 'INTERVENTORIA' o 'CONTRATISTA'.",
          code: "INVALID_ENTITY",
        });
      }

      // Generar contraseña temporal
      const temporaryPassword = Math.random().toString(36).slice(-12) + Math.random().toString(36).slice(-12);
      const hashedPassword = await bcrypt.hash(temporaryPassword, 10);

      // Crear el usuario
      const userData: any = {
        email: email.toLowerCase().trim(),
        password: hashedPassword,
        fullName: fullName.trim(),
        appRole: appRole as AppRole,
        projectRole: resolvedRole || "CONTRACTOR_REP", // Valor por defecto
        entity: entity ? entity.toUpperCase() : null,
        status: "active",
        canDownload: true, // Por defecto todos pueden descargar
      };
      
      // Asignar tenantId si está disponible
      if (tenantId) {
        userData.tenantId = tenantId;
      }
      
      const newUser = await prisma.user.create({
        data: userData,
      });

      // Registrar en auditoría
      const actorInfo = await resolveActorInfo(req);
      const userDiff = createDiff(
        {},
        {
          email: newUser.email,
          fullName: newUser.fullName,
          appRole: newUser.appRole,
          projectRole: newUser.projectRole,
          entity: newUser.entity,
        },
        ["email", "fullName", "appRole", "projectRole", "entity"]
      );
      await recordAuditEvent({
        action: "USER_CREATED",
        entityType: "user",
        entityId: newUser.id,
        diff: userDiff,
        actorId: actorInfo.actorId,
        actorEmail: actorInfo.actorEmail,
      });

      res.status(201).json({
        user: formatAdminUser(newUser),
        temporaryPassword,
      });
    } catch (error) {
      console.error("Error al invitar usuario:", error);
      if ((error as any)?.code === "P2002") {
        return res.status(409).json({
          error: "Ya existe un usuario con este email.",
          code: "USER_ALREADY_EXISTS",
        });
      }
      res.status(500).json({
        error: "No se pudo invitar al usuario.",
        details: `${error}`,
      });
    }
  }
);

app.patch(
  "/api/admin/users/:id",
  authMiddleware,
  requireAdmin,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const { appRole, projectRole, status, entity, cargo, canDownload } = req.body ?? {};

      if (!id) {
        return res.status(400).json({ error: "Se requiere el ID del usuario." });
      }

      const updates: Prisma.UserUpdateInput = {};

      if (appRole !== undefined) {
        if (!["admin", "editor", "viewer"].includes(appRole)) {
          return res.status(400).json({
            error: "Rol de aplicación inválido.",
            code: "INVALID_APP_ROLE",
          });
        }
        updates.appRole = appRole;
      }

      if (projectRole !== undefined) {
        const resolvedRole = resolveProjectRole(projectRole);
        if (!resolvedRole) {
          return res.status(400).json({
            error: "Rol de proyecto inválido.",
            code: "INVALID_PROJECT_ROLE",
          });
        }
        updates.projectRole = resolvedRole;
      }

      if (status !== undefined) {
        if (!["active", "inactive"].includes(status)) {
          return res.status(400).json({
            error: "Estado inválido. Usa 'active' o 'inactive'.",
            code: "INVALID_STATUS",
          });
        }
        updates.status = status;
      }

      if (entity !== undefined) {
        if (entity && !["IDU", "INTERVENTORIA", "CONTRATISTA"].includes(entity.toUpperCase())) {
          return res.status(400).json({
            error: "Entidad inválida. Usa 'IDU', 'INTERVENTORIA' o 'CONTRATISTA'.",
            code: "INVALID_ENTITY",
          });
        }
        updates.entity = entity ? entity.toUpperCase() : null;
      }

      if (cargo !== undefined) {
        updates.cargo = cargo ? String(cargo).trim() : null;
      }

      if (canDownload !== undefined) {
        updates.canDownload = Boolean(canDownload);
      }

      if (Object.keys(updates).length === 0) {
        return res.status(400).json({
          error: "No se recibieron cambios para aplicar.",
          code: "NO_CHANGES_PROVIDED",
        });
      }

      const existingUser = await prisma.user.findUnique({
        where: { id },
      });

      if (!existingUser) {
        return res.status(404).json({ error: "Usuario no encontrado." });
      }

      const updatedUser = await prisma.user.update({
        where: { id },
        data: updates,
      });

      const diff = createDiff(existingUser, updatedUser, [
        "appRole",
        "projectRole",
        "status",
        "entity",
        "cargo",
        "canDownload",
      ]);
      const actorInfo = await resolveActorInfo(req);

      await recordAuditEvent({
        action: "USER_UPDATED",
        entityType: "user",
        entityId: id,
        diff,
        actorId: actorInfo.actorId,
        actorEmail: actorInfo.actorEmail,
      });

      res.json(formatAdminUser(updatedUser));
    } catch (error) {
      console.error("Error al actualizar usuario admin:", error);
      res
        .status(500)
        .json({ error: "No se pudo actualizar el usuario.", details: `${error}` });
    }
  }
);

app.get(
  "/api/admin/audit-logs",
  authMiddleware,
  requireAdmin,
  async (req: AuthRequest, res) => {
    try {
      const limitParam = req.query.limit;
      const limit =
        typeof limitParam === "string"
          ? Math.min(parseInt(limitParam, 10) || 100, 500)
          : 100;

      const logs = await prisma.auditLog.findMany({
        orderBy: { timestamp: "desc" },
        take: limit,
        include: {
          actor: { select: { email: true } },
        },
      });

      res.json(
        logs.map((log) => ({
          id: log.id,
          timestamp:
            log.timestamp instanceof Date
              ? log.timestamp.toISOString()
              : log.timestamp,
          actorEmail: log.actorEmail || log.actor?.email || null,
          action: log.action,
          entityType: log.entityType,
          entityId: log.entityId,
          diff: log.diff ?? undefined,
        }))
      );
    } catch (error) {
      console.error("Error al obtener audit logs:", error);
      res.status(500).json({
        error: "No se pudieron cargar los registros de auditoría.",
      });
    }
  }
);

app.get(
  "/api/admin/settings",
  authMiddleware,
  requireAdmin,
  async (_req: AuthRequest, res) => {
    try {
      const settings = await ensureAppSettings();
      if (!settings) {
        return res.status(503).json({
          error:
            "Configuración no inicializada. Ejecuta las migraciones del servidor para habilitar este módulo.",
        });
      }
      res.json(formatAppSettings(settings));
    } catch (error) {
      console.error("Error al obtener configuración:", error);
      res
        .status(500)
        .json({ error: "No se pudo cargar la configuración de la aplicación." });
    }
  }
);

app.put(
  "/api/admin/settings",
  authMiddleware,
  requireAdmin,
  async (req: AuthRequest, res) => {
    try {
      const {
        companyName,
        timezone,
        locale,
        requireStrongPassword,
        enable2FA,
        sessionTimeoutMinutes,
        photoIntervalDays,
        defaultProjectVisibility,
      } = req.body ?? {};

      const settings = await ensureAppSettings();
      if (!settings) {
        return res.status(503).json({
          error:
            "Configuración no inicializada. Ejecuta las migraciones del servidor para habilitar este módulo.",
        });
      }

      const updates: Prisma.AppSettingUpdateInput = {};

      if (companyName !== undefined) {
        updates.companyName = String(companyName).trim();
      }

      if (timezone !== undefined) {
        updates.timezone = String(timezone).trim();
      }

      if (locale !== undefined) {
        if (!["es-ES", "en-US"].includes(locale)) {
          return res.status(400).json({
            error: "Idioma inválido. Usa 'es-ES' o 'en-US'.",
            code: "INVALID_LOCALE",
          });
        }
        updates.locale = locale;
      }

      if (requireStrongPassword !== undefined) {
        updates.requireStrongPassword = Boolean(requireStrongPassword);
      }

      if (enable2FA !== undefined) {
        updates.enable2FA = Boolean(enable2FA);
      }

      if (sessionTimeoutMinutes !== undefined) {
        const minutes = Number(sessionTimeoutMinutes);
        if (isNaN(minutes) || minutes < 5) {
          return res.status(400).json({
            error: "El tiempo de cierre de sesión debe ser al menos 5 minutos.",
            code: "INVALID_SESSION_TIMEOUT",
          });
        }
        updates.sessionTimeoutMinutes = minutes;
      }

      if (photoIntervalDays !== undefined) {
        const days = Number(photoIntervalDays);
        if (isNaN(days) || days < 1) {
          return res.status(400).json({
            error: "La frecuencia de reporte fotográfico debe ser al menos 1 día.",
            code: "INVALID_PHOTO_INTERVAL",
          });
        }
        updates.photoIntervalDays = days;
      }

      if (defaultProjectVisibility !== undefined) {
        if (!["private", "organization"].includes(defaultProjectVisibility)) {
          return res.status(400).json({
            error: "Visibilidad inválida. Usa 'private' o 'organization'.",
            code: "INVALID_VISIBILITY",
          });
        }
        updates.defaultProjectVisibility = defaultProjectVisibility;
      }

      if (Object.keys(updates).length === 0) {
        return res.status(400).json({
          error: "No se recibieron cambios para aplicar.",
          code: "NO_CHANGES_PROVIDED",
        });
      }

      const updatedSettings = await prisma.appSetting.update({
        where: { id: settings.id },
        data: updates,
      });

      // Registrar en auditoría
      const actorInfo = await resolveActorInfo(req);
      await recordAuditEvent({
        action: "UPDATE_SETTINGS",
        entityType: "AppSetting",
        entityId: updatedSettings.id,
        diff: createDiff(
          formatAppSettings(settings),
          formatAppSettings(updatedSettings),
          [
            "companyName",
            "timezone",
            "locale",
            "requireStrongPassword",
            "enable2FA",
            "sessionTimeoutMinutes",
            "photoIntervalDays",
            "defaultProjectVisibility",
          ]
        ),
        actorId: actorInfo.actorId,
        actorEmail: actorInfo.actorEmail,
      });

      res.json(formatAppSettings(updatedSettings));
    } catch (error) {
      console.error("Error al actualizar configuración:", error);
      res
        .status(500)
        .json({ error: "No se pudo actualizar la configuración.", details: `${error}` });
    }
  }
);

// Endpoint de prueba para enviar correos
app.post(
  "/api/admin/test-email",
  authMiddleware,
  requireAdmin,
  async (req: AuthRequest, res) => {
    try {
      const { to } = req.body ?? {};

      if (!to || typeof to !== "string" || !to.includes("@")) {
        return res.status(400).json({
          error: "Se requiere un correo electrónico válido.",
          code: "INVALID_EMAIL",
        });
      }

      // Validar que el correo sea el permitido para pruebas
      const allowedTestEmail = "mariacamilaarenasd@gmail.com";
      if (to.toLowerCase() !== allowedTestEmail.toLowerCase()) {
        return res.status(403).json({
          error: `Solo se pueden enviar correos de prueba a ${allowedTestEmail}`,
          code: "EMAIL_NOT_ALLOWED",
        });
      }

      const actorInfo = await resolveActorInfo(req);
      const initiatedBy = actorInfo.actorEmail || "Administrador";

      await sendTestEmail(to, initiatedBy);

      res.json({
        message: "Correo de prueba enviado correctamente.",
        to,
      });
    } catch (error) {
      console.error("Error al enviar correo de prueba:", error);
      const errorMessage =
        error instanceof Error ? error.message : "Error desconocido";
      res.status(500).json({
        error: "No se pudo enviar el correo de prueba.",
        details: errorMessage,
      });
    }
  }
);

// --- RUTAS DE AUTENTICACIÓN ---
app.post("/api/auth/register", async (req, res) => {
  const { email, password, fullName, projectRole, appRole } = req.body;

  if (!email || !password || !fullName || !projectRole || !appRole) {
    return res.status(400).json({ error: "Todos los campos son requeridos." });
  }

  const normalizedEmail = String(email).trim().toLowerCase();

  try {
    const passwordError = await validatePasswordStrength(password);
    if (passwordError) {
      return res.status(400).json({ error: passwordError });
    }

    // Buscar usuario considerando tenant (después de migración)
    const tenantId = (req as any).tenant?.id;
    const whereClause: any = tenantId 
      ? { email: normalizedEmail, tenantId }
      : { email: normalizedEmail };
    
    const existingUser = await prisma.user.findFirst({
      where: whereClause,
    });

    if (existingUser) {
      return res.status(409).json({ error: "El email ya está registrado." });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const resolvedProjectRole =
      resolveProjectRole(projectRole) ?? UserRole.RESIDENT;
    const normalizedAppRole =
      typeof appRole === "string" ? appRole.toLowerCase() : "";
    const resolvedAppRole = Object.values(AppRole).includes(
      normalizedAppRole as AppRole
    )
      ? (normalizedAppRole as AppRole)
      : AppRole.viewer;

    // Asignar tenantId si está disponible
    const userData: any = {
      email: normalizedEmail,
      password: hashedPassword,
      fullName,
      projectRole: resolvedProjectRole,
      appRole: resolvedAppRole,
      status: "active",
      tokenVersion: 0,
      emailVerifiedAt: isEmailServiceConfigured() ? null : new Date(),
    };
    if (tenantId) {
      userData.tenantId = tenantId;
    }

    const newUser = await prisma.user.create({
      data: userData,
    });

    let verificationEmailSent = false;

    if (isEmailServiceConfigured()) {
      const token = generateTokenValue();
      const tokenHash = hashToken(token);
      const expiresAt = new Date(
        Date.now() + EMAIL_VERIFICATION_TOKEN_TTL_HOURS * 60 * 60 * 1000
      );

      await prisma.emailVerificationToken.create({
        data: {
          userId: newUser.id,
          tokenHash,
          expiresAt,
        },
      });

      try {
        await sendEmailVerificationEmail({
          to: newUser.email,
          token,
          fullName: newUser.fullName,
        });
        verificationEmailSent = true;
      } catch (mailError) {
        console.error(
          "No se pudo enviar el correo de verificación:",
          mailError
        );
      }
    }

    const { password: _, ...userWithoutPassword } = newUser;
    res.status(201).json({
      ...userWithoutPassword,
      verificationEmailSent,
    });
  } catch (error) {
    console.error("Error en registro:", error);
    res.status(500).json({ error: "Error al crear el usuario." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log("Login request received:", {
      email,
      hasPassword: Boolean(password),
    });

    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "Email y contraseña son requeridos." });
    }

    // Buscar usuario considerando tenant (después de migración)
    const tenantId = (req as any).tenant?.id;
    const whereClause: any = tenantId 
      ? { email, tenantId }
      : { email };
    
    const user = await prisma.user.findFirst({
      where: whereClause,
    });

    console.log("User found:", user ? "yes" : "no");

    if (!user) {
      recordSecurityEvent('LOGIN_FAILED', 'medium', req, { email });
      return res.status(401).json({ error: "Credenciales inválidas." });
    }

    // Verificar si la cuenta está bloqueada
    const lockStatus = isAccountLocked(user.id);
    if (lockStatus.locked) {
      const minutesRemaining = Math.ceil((lockStatus.lockedUntil!.getTime() - Date.now()) / (60 * 1000));
      recordSecurityEvent('LOGIN_BLOCKED', 'high', req, { 
        email, 
        userId: user.id,
        lockedUntil: lockStatus.lockedUntil 
      });
      return res.status(423).json({ 
        error: `Cuenta bloqueada temporalmente debido a múltiples intentos fallidos. Intenta nuevamente en ${minutesRemaining} minuto(s).`,
        code: "ACCOUNT_LOCKED",
        lockedUntil: lockStatus.lockedUntil?.toISOString(),
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    console.log("Password valid:", isPasswordValid ? "yes" : "no");

    if (!isPasswordValid) {
      // Registrar intento fallido
      const lockResult = recordFailedAttempt(user.id);
      const remainingAttempts = getRemainingAttempts(user.id);
      
      recordSecurityEvent('LOGIN_FAILED', 'medium', req, { 
        email, 
        userId: user.id,
        attemptsRemaining: remainingAttempts 
      });

      // Si la cuenta fue bloqueada después de este intento
      if (lockResult.locked) {
        const minutesRemaining = Math.ceil((lockResult.lockedUntil!.getTime() - Date.now()) / (60 * 1000));
        recordSecurityEvent('LOGIN_BLOCKED', 'high', req, { 
          email, 
          userId: user.id,
          lockedUntil: lockResult.lockedUntil 
        });
        return res.status(423).json({ 
          error: `Cuenta bloqueada temporalmente debido a múltiples intentos fallidos. Intenta nuevamente en ${minutesRemaining} minuto(s).`,
          code: "ACCOUNT_LOCKED",
          lockedUntil: lockResult.lockedUntil?.toISOString(),
        });
      }

      return res.status(401).json({ 
        error: "Credenciales inválidas.",
        attemptsRemaining: remainingAttempts,
        code: "INVALID_CREDENTIALS"
      });
    }

    if (user.status !== "active") {
      recordSecurityEvent('ACCESS_DENIED', 'high', req, { email, userId: user.id, reason: 'Account inactive' });
      return res
        .status(403)
        .json({ error: "La cuenta de usuario está inactiva." });
    }

    // Crear tokens de acceso y refresh
    const accessToken = createAccessToken(user.id, user.tokenVersion);
    const refreshToken = createRefreshToken(user.id, user.tokenVersion);

    console.log("Tokens created successfully");

    // Limpiar intentos fallidos después de login exitoso
    clearFailedAttempts(user.id);

    // Actualizar último login
    await prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() },
    });

    // Registrar login exitoso
    recordSecurityEvent('LOGIN_SUCCESS', 'low', req, { email, userId: user.id });

    // Enviar refresh token como cookie httpOnly
    res.cookie("jid", refreshToken, buildRefreshCookieOptions());

    const { password: _, ...userWithoutPassword } = user;

    console.log("Login successful, sending response");

    return res.json({
      accessToken,
      user: userWithoutPassword,
    });
  } catch (error) {
    console.error("Error en login:", error);
    res.status(500).json({ error: "Error interno del servidor." });
  }
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("jid", buildRefreshCookieOptions({}, false));
  res.json({ message: "Logged out successfully" });
});

app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res
        .status(400)
        .json({ error: "Debes proporcionar el correo electrónico." });
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    try {
      // Buscar usuario considerando tenant si está disponible
      const tenantId = (req as any).tenant?.id;
      const whereClause: any = tenantId
        ? { email: normalizedEmail, tenantId }
        : { email: normalizedEmail };
      
      const user = await prisma.user.findFirst({
        where: whereClause,
      });

      if (user) {
        const token = generateTokenValue();
        const tokenHash = hashToken(token);
        const expiresAt = new Date(
          Date.now() + PASSWORD_RESET_TOKEN_TTL_MINUTES * 60 * 1000
        );

        await prisma.$transaction([
          prisma.passwordResetToken.deleteMany({
            where: { userId: user.id },
          }),
          prisma.passwordResetToken.create({
            data: {
              userId: user.id,
              tokenHash,
              expiresAt,
            },
          }),
        ]);

        if (isEmailServiceConfigured()) {
          try {
            await sendPasswordResetEmail({
              to: user.email,
              token,
              fullName: user.fullName,
            });
          } catch (mailError) {
            logger.error("No se pudo enviar el correo de restablecimiento", {
              error: mailError instanceof Error ? mailError.message : String(mailError),
              userId: user.id,
            });
          }
        } else {
          logger.warn("Servicio de correo no configurado", {
            email: user.email,
            token,
          });
        }
      }

      // Siempre retornar el mismo mensaje por seguridad (no revelar si el email existe)
      res.json({
        message:
          "Si el correo existe en nuestra base de datos, enviaremos instrucciones para restablecer la contraseña.",
      });
    } catch (error) {
      logger.error("Error al solicitar restablecimiento de contraseña", {
        error: error instanceof Error ? error.message : String(error),
        email: normalizedEmail,
      });
      res.status(500).json({ error: "No fue posible procesar la solicitud." });
    }
  } catch (error) {
    logger.error("Error en forgot-password endpoint", {
      error: error instanceof Error ? error.message : String(error),
    });
    res.status(500).json({ error: "Error interno del servidor." });
  }
});

app.post("/api/auth/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  if (!token || !password) {
    return res
      .status(400)
      .json({ error: "Token y nueva contraseña son requeridos." });
  }

  try {
    const passwordError = await validatePasswordStrength(password);
    if (passwordError) {
      return res.status(400).json({ error: passwordError });
    }

    const tokenHash = hashToken(token);

    const resetToken = await prisma.passwordResetToken.findUnique({
      where: { tokenHash },
      include: { user: true },
    });

    if (!resetToken || !resetToken.user) {
      return res.status(400).json({ error: "Token inválido o no encontrado." });
    }

    if (resetToken.usedAt) {
      return res
        .status(400)
        .json({ error: "Este token ya fue utilizado, solicita uno nuevo." });
    }

    if (resetToken.expiresAt < new Date()) {
      return res.status(400).json({
        error: "El token ha expirado. Solicita un nuevo enlace de restablecimiento.",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    await prisma.$transaction([
      prisma.user.update({
        where: { id: resetToken.userId },
        data: {
          password: hashedPassword,
          tokenVersion: resetToken.user.tokenVersion + 1,
          emailVerifiedAt: resetToken.user.emailVerifiedAt ?? new Date(),
        },
      }),
      prisma.passwordResetToken.update({
        where: { id: resetToken.id },
        data: { usedAt: new Date() },
      }),
      prisma.passwordResetToken.deleteMany({
        where: {
          userId: resetToken.userId,
          id: { not: resetToken.id },
        },
      }),
    ]);

    res.json({ success: true });
  } catch (error) {
    logger.error("Error al restablecer contraseña", {
      error: error instanceof Error ? error.message : String(error),
      tokenHash: hashToken(token),
    });
    res
      .status(500)
      .json({ error: "No fue posible restablecer la contraseña." });
  }
});

app.post(
  "/api/auth/refresh",
  refreshAuthMiddleware,
  async (req: AuthRequest, res) => {
    try {
      console.log("Refresh token request received");

      if (!req.user) {
        console.log("No user found in request");
        return res.status(401).json({ error: "No user found in request" });
      }

      console.log("User from token:", req.user);

      const user = await prisma.user.findUnique({
        where: { id: req.user.userId },
      });

      if (!user) {
        console.log("User not found in database");
        return res.status(401).json({ error: "User not found" });
      }

      console.log("User found in database");

      // Verificar token version
      if (user.tokenVersion !== req.user.tokenVersion) {
        console.log("Token version mismatch");
        return res.status(401).json({ error: "Token version mismatch" });
      }

      // Crear nuevo access token
      const accessToken = createAccessToken(user.id, user.tokenVersion);
      const refreshToken = createRefreshToken(user.id, user.tokenVersion);

      console.log("New tokens created");

      // Actualizar cookie de refresh token
      res.cookie("jid", refreshToken, buildRefreshCookieOptions());

      console.log("Refresh token cookie set");

      return res.json({ accessToken });
    } catch (error) {
      console.error("Error en refresh token:", error);
      res.status(500).json({ error: "Error al refrescar el token" });
    }
  }
);

// Endpoint para verificar el usuario autenticado
app.get("/api/auth/me", authMiddleware, async (req: AuthRequest, res) => {
  try {
    if (!req.user?.userId) {
      return res.status(401).json({ error: "No authenticated user" });
    }

    const user = await prisma.user.findUnique({
      where: { id: req.user.userId },
      select: {
        id: true,
        email: true,
        fullName: true,
        projectRole: true,
        appRole: true,
        entity: true,
        cargo: true,
        avatarUrl: true,
        status: true,
        canDownload: true,
        lastLoginAt: true,
        emailVerifiedAt: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    if (user.status !== "active") {
      return res.status(403).json({ error: "User account is inactive" });
    }

    res.json(user);
  } catch (error) {
    console.error("Error en /api/auth/me:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Endpoint para cambiar contraseña
app.post(
  "/api/auth/change-password",
  authMiddleware,
  validate(changePasswordSchema),
  async (req: AuthRequest, res) => {
    try {
      const { oldPassword, newPassword } = req.body;

      if (!req.user?.userId) {
        return res.status(401).json({ error: "Usuario no autenticado." });
      }

      const user = await prisma.user.findUnique({
        where: { id: req.user.userId },
      });

      if (!user) {
        return res.status(404).json({ error: "Usuario no encontrado." });
      }

      // Verificar que la contraseña actual sea correcta
      const isOldPasswordValid = await bcrypt.compare(oldPassword, user.password);
      if (!isOldPasswordValid) {
        return res.status(401).json({
          error: "La contraseña actual es incorrecta.",
        });
      }

      // Validar la fortaleza de la nueva contraseña
      const passwordError = await validatePasswordStrength(newPassword);
      if (passwordError) {
        // Validación adicional con la utilidad para obtener más detalles
        const passwordValidation = validatePasswordStrengthUtil(newPassword);
        return res.status(400).json({ 
          error: passwordError,
          details: passwordValidation.errors,
          strength: passwordValidation.strength,
        });
      }

      // Verificar que la nueva contraseña sea diferente a la actual
      const isSamePassword = await bcrypt.compare(newPassword, user.password);
      if (isSamePassword) {
        return res.status(400).json({
          error: "La nueva contraseña debe ser diferente a la actual.",
        });
      }

      // Hashear y actualizar la contraseña
      const hashedNewPassword = await bcrypt.hash(newPassword, 12);

      // Incrementar tokenVersion para invalidar todos los tokens existentes
      await prisma.user.update({
        where: { id: user.id },
        data: {
          password: hashedNewPassword,
          tokenVersion: user.tokenVersion + 1,
        },
      });

      // Registrar en auditoría
      const actorInfo = await resolveActorInfo(req);
      await recordAuditEvent({
        action: "USER_PASSWORD_CHANGED",
        entityType: "user",
        entityId: user.id,
        diff: createDiff(
          { passwordChanged: false },
          { passwordChanged: true },
          ["passwordChanged"]
        ),
        actorId: actorInfo.actorId,
        actorEmail: actorInfo.actorEmail,
      });

      // Registrar evento de seguridad
      recordSecurityEvent('PASSWORD_CHANGE', 'medium', req, {
        userId: user.id,
        email: user.email,
      });

      res.json({ message: "Contraseña actualizada correctamente." });
    } catch (error) {
      logger.error("Error al cambiar contraseña", {
        error: error instanceof Error ? error.message : String(error),
        userId: req.user?.userId,
      });
      res.status(500).json({
        error: "No se pudo cambiar la contraseña.",
      });
    }
  }
);

// Middleware global de manejo de errores (debe ir al final, antes de app.listen)
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  // Log del error completo en el servidor
  logger.error('Error no manejado', {
    error: err.message,
    stack: isProduction ? undefined : err.stack, // Solo stack en desarrollo
    path: req.path,
    method: req.method,
    userId: (req as AuthRequest).user?.userId,
  });

  // Respuesta al cliente - ocultar detalles en producción
  if (isProduction) {
    res.status(err.status || 500).json({
      error: 'Error interno del servidor',
      code: 'INTERNAL_ERROR',
    });
  } else {
    // En desarrollo, mostrar más detalles
    res.status(err.status || 500).json({
      error: err.message || 'Error interno del servidor',
      code: err.code || 'INTERNAL_ERROR',
      ...(err.stack && { stack: err.stack }),
    });
  }
});

app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});
