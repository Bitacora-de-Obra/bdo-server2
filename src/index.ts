import express, { CookieOptions, NextFunction, Request, Response } from "express";
import cors from "cors";
import OpenAI from 'openai';
import cookieParser from "cookie-parser";
import fs from "fs";
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
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cron from "node-cron";
import swaggerUi from "swagger-ui-express";
import path from "path";
import { authMiddleware, refreshAuthMiddleware, createAccessToken, createRefreshToken, AuthRequest } from "./middleware/auth";
import { generateWeeklyReportExcel } from "./services/reports/weeklyExcelGenerator";
import { generateReportPdf } from "./services/reports/pdfExport";
import { generateLogEntryPdf } from "./services/logEntries/pdfExport";
import { applySignatureToPdf } from "./services/documents/pdfSigner";
import { validateCronogramaXml, CronogramaValidationError } from "./utils/xmlValidator";
import { logger } from "./logger";
import fsPromises from "fs/promises";
import { sha256 } from "./utils/hash";
import { JsonValue } from './types/json';

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
import { getStorage } from "./storage";
import {
  sendEmailVerificationEmail,
  sendPasswordResetEmail,
  sendCommitmentReminderEmail,
  isEmailServiceConfigured,
  sendCommunicationAssignmentEmail,
  getEmailConfigurationSummary,
  verifyEmailTransporter,
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
const port = 4001;
const isProduction = process.env.NODE_ENV === "production";

if (isEmailServiceConfigured()) {
  const summary = getEmailConfigurationSummary();
  logger.info(
    `Servicio de correo habilitado (host: ${summary.host}, puerto: ${summary.port}, secure: ${summary.secure ? "sí" : "no"}, remitente: ${summary.defaultFrom}).`
  );
} else {
  logger.warn(
    "Servicio de correo deshabilitado. Configura SMTP_HOST y credenciales SMTP para habilitar el envío de emails."
  );
}

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
  "gpt-4o-mini": 0.150,
  "gpt-4o": 0.060,
  "gpt-4.1-mini": 0.140,
  "gpt-3.5-turbo": 0.002,
};

const REFRESH_TOKEN_MAX_AGE = 7 * 24 * 60 * 60 * 1000; // 7 días
const REFRESH_COOKIE_PATH = "/api/auth/refresh";

const buildRefreshCookieOptions = (
  overrides: Partial<CookieOptions> = {},
  includeMaxAge = true
): CookieOptions => {
  const secureCookie =
    process.env.COOKIE_SECURE === "true" || isProduction;

  const requestedSameSite = process.env.COOKIE_SAMESITE?.toLowerCase();
  const defaultSameSite = secureCookie ? "none" : "lax";
  const sameSiteValue = (requestedSameSite === "strict" || requestedSameSite === "lax" || requestedSameSite === "none"
    ? requestedSameSite
    : defaultSameSite) as CookieOptions["sameSite"];

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

const validatePasswordStrength = async (password: string) => {
  const settings = await prisma.appSetting.findFirst();
  const requireStrong =
    settings?.requireStrongPassword ??
    DEFAULT_APP_SETTINGS.requireStrongPassword;

  const minimumLength = requireStrong ? 8 : 6;

  if (!password || password.length < minimumLength) {
    return `La contraseña debe tener al menos ${minimumLength} caracteres.`;
  }

  if (!requireStrong) {
    return null;
  }

  const hasUppercase = /[A-ZÁÉÍÓÚÑ]/u.test(password);
  const hasLowercase = /[a-záéíóúñ]/u.test(password);
  const hasNumber = /[0-9]/.test(password);

  if (!hasUppercase || !hasLowercase || !hasNumber) {
    return "La contraseña debe incluir mayúsculas, minúsculas y números.";
  }

  return null;
};

const requireAdmin = (req: AuthRequest, res: Response, next: NextFunction) => {
  if (req.user?.appRole !== "admin") {
    return res.status(403).json({ error: "Acceso restringido a administradores." });
  }
  return next();
};

const requireEditor = (req: AuthRequest, res: Response, next: NextFunction) => {
  if (!req.user) {
    return res.status(401).json({ error: "Autenticación requerida." });
  }
  if (req.user.appRole === "viewer") {
    return res
      .status(403)
      .json({ error: "Acceso restringido a editores y administradores." });
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

const formatAdminUser = (user: any) => ({
  id: user.id,
  fullName: user.fullName,
  email: user.email,
  projectRole: roleReverseMap[user.projectRole] || user.projectRole,
  appRole: user.appRole,
  avatarUrl: user.avatarUrl,
  status: user.status,
  lastLoginAt:
    user.lastLoginAt instanceof Date
      ? user.lastLoginAt.toISOString()
      : user.lastLoginAt,
});

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

          const entry =
            recipients.get(email) ?? {
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

const createStorageKey = (folder: string, originalName: string) => {
  const ext = path.extname(originalName);
  const baseName = sanitizeFileName(path.basename(originalName, ext)) || "file";
  const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
  const normalizedFolder = folder.replace(/[^a-zA-Z0-9/_-]/g, "").replace(/\/+$/, "");
  return path.posix.join(normalizedFolder, `${uniqueSuffix}-${baseName}${ext}`);
};

const persistUploadedFile = async (file: Express.Multer.File, folder: string) => {
  const storage = getStorage();
  const key = createStorageKey(folder, file.originalname);
  await storage.save({ path: key, content: file.buffer });
  return {
    key,
    url: storage.getPublicUrl(key),
  };
};

ensureAppSettings().catch((error) => {
  console.error("No se pudo inicializar la configuración principal:", error);
});

scheduleDailyCommitmentReminder();

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

const resolveServerPublicUrl = () => {
  const raw = process.env.SERVER_PUBLIC_URL?.trim();
  if (raw) {
    return raw.replace(/\/+$/, "");
  }
  return `http://localhost:${port}`;
};

const buildAttachmentResponse = (attachment: any) => {
  const relativePath = `/api/attachments/${attachment.id}/download`;
  const publicUrl = resolveServerPublicUrl();

  return {
    ...attachment,
    downloadUrl: `${publicUrl}${relativePath}`,
    downloadPath: relativePath,
  };
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
  const storagePath = attachment.storagePath || resolveStorageKeyFromUrl(attachment.url);
  if (!storagePath) {
    throw new Error("No se pudo determinar la ubicación del archivo adjunto.");
  }
  return storage.read(storagePath);
};

const loadUserSignatureBuffer = async (userSignature: any): Promise<Buffer> => {
  const storage = getStorage();
  return storage.read(userSignature.storagePath);
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
  };
};

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
  } | null;
  signedAt: Date | string | null;
  signatureTaskId: string | null;
  signatureTaskStatus: 'SIGNED' | 'PENDING';
}

interface SignatureTask {
  id: string;
  status: 'SIGNED' | 'PENDING';
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
  return typeof date === 'string' ? new Date(date) : date;
}

function normalizeSignatureStatus(status: string | undefined): 'SIGNED' | 'PENDING' {
  if (status?.toUpperCase() === 'SIGNED') {
    return 'SIGNED';
  }
  return 'PENDING';
}

const formatLogEntry = (entry: any) => {
  const formattedSignatureTasks: SignatureTask[] = (entry.signatureTasks || []).map((task: any) => ({
    id: task.id,
    status: task.status || 'PENDING',
    assignedAt: task.assignedAt ? new Date(task.assignedAt) : null,
    signedAt: task.signedAt ? new Date(task.signedAt) : null,
    signer: mapUserBasic(task.signer)
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
          .filter((signer): signer is NonNullable<ReturnType<typeof mapUserBasic>> => Boolean(signer))
      : entry.author
      ? [mapUserBasic(entry.author)].filter((s): s is NonNullable<ReturnType<typeof mapUserBasic>> => Boolean(s))
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
  const normalizedSignatures = existingSignatures.map((sig: NormalizedSignature) => ({...sig}));

  // Process signature tasks
  formattedSignatureTasks.forEach((task: SignatureTask) => {
    const signer = task.signer;
    if (!signer) return;

    const signerId = signer.id;
    const existingSignatureIndex = normalizedSignatures.findIndex(sig => sig.signerId === signerId);
    
    if (existingSignatureIndex === -1) {
      // No existing signature found, create a new one
      normalizedSignatures.push({
        id: randomUUID(), // Use UUID for unique ID generation
        logEntryId: entry.id,
        signerId,
        signer: mapUserBasic(signer),
        signedAt: normalizeSignedAt(task.signedAt),
        signatureTaskId: task.id,
        signatureTaskStatus: task.status,
      });
    } else {
      // Update existing signature with task information while preserving the signature
      const existingSignature = normalizedSignatures[existingSignatureIndex];
      existingSignature.signatureTaskId = task.id;
      existingSignature.signatureTaskStatus = task.status;
      
      // Only update signedAt if the task is marked as signed
      if (task.status === "SIGNED" && task.signedAt) {
        existingSignature.signedAt = normalizeSignedAt(task.signedAt);
      }
    }
  });

  // Asegurar que las firmas existentes se muestren correctamente
  // Si hay una firma en la tabla Signature pero no en normalizedSignatures, agregarla
  (entry.signatures || []).forEach((signature: any) => {
    const signerId = signature.signerId || signature.signer?.id;
    if (!signerId) return;
    
    const alreadyIncluded = normalizedSignatures.some(sig => sig.signerId === signerId);
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
      attachments: (comment.attachments || []).map(buildAttachmentResponse),
    })),
    attachments: (entry.attachments || []).map(buildAttachmentResponse),
    signatures: normalizedSignatures,
    assignees: (entry.assignees || []).map(mapUserBasic).filter(Boolean),
    scheduleDay: entry.scheduleDay || "",
    locationDetails: entry.locationDetails || "",
    weatherReport: normalizeWeatherReport(entry.weatherReport),
    contractorPersonnel: normalizePersonnelEntries(entry.contractorPersonnel),
    interventoriaPersonnel: normalizePersonnelEntries(entry.interventoriaPersonnel),
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
    requiredSignatories: requiredSigners,
    signatureTasks: formattedSignatureTasks,
    signatureSummary: {
      total: totalSignatureTasks,
      signed: signedSignatureTasks.length,
      pending: pendingSignatureTasks.length,
      completed:
        totalSignatureTasks > 0 && pendingSignatureTasks.length === 0,
    },
    pendingSignatureSignatories: pendingSignatureTasks
      .map((task) => task.signer)
      .filter((signer): signer is NonNullable<ReturnType<typeof mapUserBasic>> =>
        Boolean(signer)
      ),
    history: (entry.history || []).map((change: any) => ({
      id: change.id,
      fieldName: change.fieldName,
      oldValue: change.oldValue,
      newValue: change.newValue,
      timestamp:
        change.timestamp instanceof Date
          ? change.timestamp.toISOString()
          : change.timestamp,
      user:
        mapUserBasic(change.user) || {
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
    signedAt: signature.signedAt instanceof Date ? signature.signedAt.toISOString() : signature.signedAt,
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
  changes: { fieldName: string; oldValue?: string | null; newValue?: string | null }[]
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
    sentDate: communication.sentDate instanceof Date ? communication.sentDate.toISOString() : communication.sentDate,
    dueDate: communication.dueDate instanceof Date && !isNaN(communication.dueDate.getTime()) ? communication.dueDate.toISOString() : communication.dueDate,
    deliveryMethod: deliveryMethodReverseMap[communication.deliveryMethod] || communication.deliveryMethod,
    direction: communicationDirectionReverseMap[communication.direction] || communication.direction,
    requiresResponse: Boolean(communication.requiresResponse),
    responseDueDate:
      communication.responseDueDate instanceof Date && !isNaN(communication.responseDueDate.getTime())
        ? communication.responseDueDate.toISOString()
        : communication.responseDueDate,
    notes: communication.notes,
    status: communicationStatusReverseMap[communication.status] || communication.status,
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
      timestamp: history.timestamp instanceof Date ? history.timestamp.toISOString() : history.timestamp,
      user:
        mapUserBasic(history.user) ||
        {
          id: 'system',
          fullName: 'Sistema',
          email: '',
          avatarUrl: '',
          appRole: 'viewer',
          projectRole: 'ADMIN',
        },
    })),
    createdAt: communication.createdAt instanceof Date ? communication.createdAt.toISOString() : communication.createdAt,
    updatedAt: communication.updatedAt instanceof Date ? communication.updatedAt.toISOString() : communication.updatedAt,
  };
};

const formatReportRecord = (report: any) => {
  const formattedSignatures = (report.signatures || []).map((signature: any) => ({
    ...signature,
    signedAt:
      signature.signedAt instanceof Date
        ? signature.signedAt.toISOString()
        : signature.signedAt,
  }));

  return {
    ...report,
    reportScope:
      reportScopeReverseMap[report.reportScope] || report.reportScope,
    status:
      reportStatusReverseMap[report.status] || report.status,
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

const mapReportVersionSummary = (report: any): ReportVersion => ({
  id: report.id,
  version: report.version || 1,
  status: reportStatusReverseMap[report.status] || report.status,
  submissionDate: report.submissionDate instanceof Date
    ? report.submissionDate.toISOString()
    : report.submissionDate,
  createdAt: report.createdAt instanceof Date
    ? report.createdAt.toISOString()
    : report.createdAt
});

app.use(
  cors({
    origin: ["http://localhost:3000", "http://localhost:3001", "http://localhost:5173"], // Permite puertos de React y Vite
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"], // Incluye OPTIONS para preflight
    allowedHeaders: ["Content-Type", "Authorization"], // Headers permitidos
    credentials: true, // Necesario para cookies/sesiones
    exposedHeaders: ["Content-Type", "Authorization"], // Headers expuestos al cliente
  })
);

app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);

app.use("/api/auth/login", loginRateLimiter);
app.use("/api/auth/refresh", refreshRateLimiter);

const openApiDocumentPath = path.join(__dirname, "../openapi/openapi.json");
app.use("/api/docs", async (_req: Request, res: Response, next: NextFunction) => {
  try {
    await fsPromises.access(openApiDocumentPath);
    next();
  } catch (error) {
    console.warn("No se encontró openapi/openapi.json. Usa npm run generate-docs para generarlo.");
    res.status(503).json({ error: "Documentación no disponible." });
  }
}, swaggerUi.serve, swaggerUi.setup(undefined, {
  swaggerOptions: {
    url: "/api/docs/json",
  },
}));

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
const uploadsDir = path.resolve(process.env.UPLOADS_DIR || path.join(__dirname, "../uploads"));
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configuración de middlewares
app.use(cookieParser()); // Permite que Express maneje cookies
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// Configuración de multer
const multerConfig = {
  storage: multer.memoryStorage(),
  fileFilter: (req: express.Request, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
    const allowedMimes = [
      'image/jpeg',
      'image/png',
      'application/pdf',
      'image/gif',
      'image/webp'
    ];

    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Tipo de archivo no permitido. Solo se permiten imágenes (JPG, PNG, GIF, WEBP) y PDFs.'));
    }
  },
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB
    files: 5
  }
};

const upload = multer(multerConfig);
const signatureUpload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (_req: express.Request, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
    const allowedMimes = ["image/png", "image/jpeg", "image/jpg", "application/pdf"];
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

    const storageDriver = (process.env.STORAGE_DRIVER || 'local');
    if (storageDriver === 's3' && attachment.url && attachment.url.startsWith('http')) {
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
      return res.status(404).json({ error: "Archivo no disponible en el servidor." });
    }

    const mimeType = attachment.type || mime.lookup(filePath) || 'application/octet-stream';

    res.setHeader('Content-Type', mimeType as string);
    res.setHeader('Content-Disposition', `attachment; filename="${attachment.fileName}"`);

    res.sendFile(filePath);
  } catch (error) {
    console.error('Error al descargar adjunto:', error);
    res.status(500).json({ error: 'No se pudo descargar el adjunto.' });
  }
});

app.post("/api/attachments/:id/sign", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
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
      return res.status(400).json({ error: "Debes aceptar el consentimiento para firmar el documento." });
    }

    const consentStatementRaw =
      typeof req.body?.consentStatement === "string"
        ? req.body.consentStatement.trim()
        : "";
    const consentStatement =
      consentStatementRaw.length > 0
        ? consentStatementRaw
        : "El usuario consiente el uso de su firma manuscrita digital para este documento.";

    const page = req.body?.page !== undefined ? Number(req.body.page) : undefined;
    let x = req.body?.x !== undefined ? Number(req.body.x) : undefined;
    let y = req.body?.y !== undefined ? Number(req.body.y) : undefined;
    const width = req.body?.width !== undefined ? Number(req.body.width) : undefined;
    const height = req.body?.height !== undefined ? Number(req.body.height) : undefined;
    const baselineRaw = req.body?.baseline;
    const baseline =
      baselineRaw === true ||
      baselineRaw === "true" ||
      baselineRaw === 1 ||
      baselineRaw === "1";
    const baselineRatio =
      req.body?.baselineRatio !== undefined && req.body?.baselineRatio !== null
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
      return res.status(400).json({ error: "Las coordenadas de firma no son válidas." });
    }

    const signature = await prisma.userSignature.findUnique({
      where: { userId },
    });

    if (!signature) {
      return res.status(400).json({
        error: "Debes registrar tu firma manuscrita antes de firmar documentos.",
      });
    }

    const attachment = await prisma.attachment.findUnique({ where: { id } });
    if (!attachment) {
      return res.status(404).json({ error: "Adjunto no encontrado." });
    }
    if (attachment.type !== "application/pdf") {
      return res.status(400).json({ error: "Solo se pueden firmar archivos PDF." });
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
        if (logEntry.status === 'SIGNED') {
          return res.status(409).json({ error: "El documento ya fue completamente firmado.", code: "DOCUMENT_LOCKED" });
        }
        const task = logEntry.signatureTasks.find((t: any) => t.signerId === userId);
        if (!task) {
          return res.status(403).json({ error: "No tienes tarea de firma asignada en esta anotación." });
        }
        if (task.status === 'SIGNED') {
          return res.status(409).json({ error: "Ya has firmado esta anotación.", code: "ALREADY_SIGNED" });
        }
      }
    }

    const [originalBuffer, signatureBuffer] = await Promise.all([
      loadAttachmentBuffer(baseAttachment),
      loadUserSignatureBuffer(signature),
    ]);

    // Si no recibimos coordenadas, calcularlas automáticamente para alinear con el cuadro del firmante
    if ((x === undefined || y === undefined) && baseAttachment.logEntryId) {
      const logEntry = await prisma.logEntry.findUnique({
        where: { id: baseAttachment.logEntryId },
        include: {
          author: true,
          assignees: true,
          signatures: { include: { signer: true } },
          signatureTasks: { include: { signer: true }, orderBy: { assignedAt: 'asc' } },
        },
      });
      if (logEntry) {
        // Priorizar el índice tal como aparece en signatureTasks (que define el orden en PDF)
        const orderedTasks = (logEntry.signatureTasks || [])
          .filter((t: any) => t?.signer?.id)
          .sort((a: any, b: any) => new Date(a.assignedAt || 0).getTime() - new Date(b.assignedAt || 0).getTime());
        let signerIndex = orderedTasks.findIndex((t: any) => t.signer?.id === userId);
        if (signerIndex < 0) {
          // Si el firmante no está en tareas, ubicar en el primer recuadro pendiente
          signerIndex = orderedTasks.findIndex((t: any) => t.status !== 'SIGNED');
        }
        if (signerIndex < 0) signerIndex = 0; // último recurso
        const MARGIN = 48; // Debe coincidir con pdfExport
        const BOX_H = 110;
        const GAP = 16;
        const LINE_Y = 72; // línea de firma relativa al inicio del box
        const LINE_X = 70; // desplazamiento respecto al margen izquierdo
        y = y === undefined ? MARGIN + signerIndex * (BOX_H + GAP) + LINE_Y : y;
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
        if (normalizedBaselineRatio === undefined) normalizedBaselineRatio = 0.25;
      }
    }

    const signedBuffer = await applySignatureToPdf({
      originalPdf: originalBuffer,
      signature: {
        buffer: signatureBuffer,
        mimeType: signature.mimeType || 'image/png',
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
      `signed-documents/${userId}`,
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
          status: 'SIGNED',
          signedAt: new Date(),
        },
      });

      const updatedTasks = await prisma.logEntrySignatureTask.findMany({
        where: { logEntryId: attachment.logEntryId },
        select: { status: true },
      });

      if (
        updatedTasks.length > 0 &&
        updatedTasks.every((task) => task.status === 'SIGNED')
      ) {
        await prisma.logEntry.update({
          where: { id: attachment.logEntryId },
          data: { status: 'SIGNED' },
        });
      }

      const refreshedEntry = await prisma.logEntry.findUnique({
        where: { id: attachment.logEntryId },
        include: {
          author: true,
          attachments: true,
          comments: { include: { author: true }, orderBy: { timestamp: "asc" } },
          signatures: { include: { signer: true } },
          assignees: true,
          signatureTasks: { include: { signer: true }, orderBy: { assignedAt: "asc" } },
          history: { include: { user: true }, orderBy: { timestamp: "desc" } },
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
      res.status(500).json({ error: "No se pudo firmar el documento solicitado." });
    }
  }
});


// Ruta de ping para verificar que el servidor está funcionando
app.get("/api/ping", (req, res) => {
  console.log("!!! PING RECIBIDO !!!");
  res.json({ message: "pong" });
});

// --- INICIO: Endpoint del Chatbot ---
// --- INICIO: Endpoint del Chatbot (Versión OpenAI) ---
app.post("/api/chatbot/query", authMiddleware, async (req: AuthRequest, res) => {
  const { query, history } = req.body;
  const userId = req.user?.userId;

  if (!query) {
    return res.status(400).json({ error: "No se proporcionó una consulta (query)." });
  }
  if (!userId) {
    return res.status(401).json({ error: "Usuario no autenticado." });
  }

  try {
    const conversationHistory: Array<{ role: "assistant" | "user"; content: string }> = Array.isArray(history)
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
        include: { keyPersonnel: true },
      }),
      prisma.contractModification.findMany({
        orderBy: { date: "desc" },
        take: 10,
      }),
      prisma.logEntry.findFirst({
        orderBy: { createdAt: "desc" },
        include: { author: { select: { fullName: true } } },
      }),
      prisma.contractItem.findMany({
        include: {
          workActaItems: {
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
        orderBy: { startDate: "asc" },
        take: 20,
      }),
      prisma.communication.findMany({
        orderBy: { sentDate: "desc" },
        take: 10,
      }),
      prisma.acta.findMany({
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
        orderBy: { submissionDate: "desc" },
        take: 10,
      }),
      prisma.report.findMany({
        orderBy: { submissionDate: "desc" },
        take: 10,
        include: {
          author: {
            select: { fullName: true, projectRole: true },
          },
        },
      }),
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
        include: {
          photos: {
            orderBy: { date: "desc" },
            take: 3,
          },
        },
        take: 10,
      }),
      prisma.commitment.findMany({
        where: {
          status: "PENDING",
          dueDate: {
            gte: new Date(),
          },
        },
        include: {
          responsible: {
            select: { fullName: true, projectRole: true },
          },
        },
        orderBy: { dueDate: "asc" },
        take: 10,
      }),
      prisma.logEntry.findMany({
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
        .filter((mod) => mod.type === "ADDITION" && mod.value)
        .reduce((sum, mod) => sum + (mod.value || 0), 0);

      const totalExtensionsDays = contractModifications
        .filter((mod) => mod.type === "TIME_EXTENSION" && mod.days)
        .reduce((sum, mod) => sum + (mod.days || 0), 0);

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
            (person) =>
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
          .map((mod) => {
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
      const itemsWithProgress = contractItems.map((item) => {
        const executedQuantity = item.workActaItems.reduce((sum, entry) => {
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
          .filter((entry) => entry.workActa?.date)
          .sort((a, b) => {
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
          (a, b) =>
            b.percentage - a.percentage ||
            b.executedQuantity - a.executedQuantity
        )
        .slice(0, 8);

      if (topItems.length) {
        const lines = topItems.map(
          (item) =>
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
      const workActaLines = workActas.map((acta) => {
        const totalQuantity = acta.items.reduce((sum, item) => {
          const quantity =
            typeof item.quantity === "number"
              ? item.quantity
              : Number(item.quantity) || 0;
          return sum + quantity;
        }, 0);

        const totalValue = acta.items.reduce((sum, item) => {
          const quantity =
            typeof item.quantity === "number"
              ? item.quantity
              : Number(item.quantity) || 0;
          const unitPrice = item.contractItem?.unitPrice || 0;
          return sum + quantity * unitPrice;
        }, 0);

        const principales = acta.items
          .slice(0, 3)
          .map((item) => {
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
      const taskLines = projectTasks.map((task) => {
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
          entryTypeReverseMap[ultimaAnotacion.type] || ultimaAnotacion.type
        }`,
        `Estado: ${
          entryStatusReverseMap[ultimaAnotacion.status] || ultimaAnotacion.status
        }`,
      ].join("\n");

      contextSections.push({
        id: "last-log-entry",
        heading: "Última anotación registrada en la bitácora",
        body: ultimaAnotacionResumen,
        priority: 1,
      });
    }

    // Add communications context
    if (communications.length) {
      const communicationsSummary = communications.map(comm => {
        const sender = comm.senderEntity || "No especificado";
        const recipient = comm.recipientEntity || "No especificado";
        const status = communicationStatusReverseMap[comm.status] || comm.status;
        return `• Radicado ${comm.radicado}: "${comm.subject}" - De: ${sender} - Para: ${recipient} - Estado: ${status} - Fecha: ${formatDate(comm.sentDate)}`;
      }).join("\n");
      
      contextSections.push({
        id: "communications",
        heading: "Comunicaciones oficiales recientes",
        body: communicationsSummary,
      });
    }

    // Add actas context
    if (actas.length) {
      const actasSummary = actas.map(acta => {
        const area = actaAreaReverseMap[acta.area] || acta.area;
        const status = actaStatusReverseMap[acta.status] || acta.status;
        const commitmentsCount = acta.commitments?.length || 0;
        return `• ${acta.number}: "${acta.title}" - Área: ${area} - Estado: ${status} - Compromisos: ${commitmentsCount} - Fecha: ${formatDate(acta.date)}`;
      }).join("\n");
      
      contextSections.push({
        id: "committee-actas",
        heading: "Actas de comité recientes",
        body: actasSummary,
      });
    }

    // Add cost actas context
    if (costActas.length) {
      const costActasSummary = costActas.map(acta => {
        const status = costActaStatusReverseMap[acta.status] || acta.status;
        return `• ${acta.number}: Período ${acta.period} - Valor: ${formatCurrency(acta.billedAmount)} - Estado: ${status} - Fecha: ${formatDate(acta.submissionDate)}`;
      }).join("\n");
      
      contextSections.push({
        id: "cost-actas",
        heading: "Actas de costo recientes",
        body: costActasSummary,
      });
    }

    // Add reports context
    if (reports.length) {
      const reportsSummary = reports.map(report => {
        const scope = reportScopeReverseMap[report.reportScope] || report.reportScope;
        const status = reportStatusReverseMap[report.status] || report.status;
        return `• ${report.type} ${report.number}: ${scope} - Estado: ${status} - Autor: ${report.author?.fullName} - Fecha: ${formatDate(report.submissionDate)}`;
      }).join("\n");
      
      contextSections.push({
        id: "reports",
        heading: "Informes recientes",
        body: reportsSummary,
      });
    }

    // Add drawings context
    if (drawings.length) {
      const drawingsSummary = drawings.map(drawing => {
        const discipline = drawingDisciplineMap[drawing.discipline] || drawing.discipline;
        const status = drawing.status === "VIGENTE" ? "Vigente" : "Obsoleto";
        const versionsCount = drawing.versions?.length || 0;
        return `• ${drawing.code}: "${drawing.title}" - Disciplina: ${discipline} - Estado: ${status} - Versiones: ${versionsCount}`;
      }).join("\n");
      
      contextSections.push({
        id: "drawings",
        heading: "Planos del proyecto",
        body: drawingsSummary,
      });
    }

    // Add control points context
    if (controlPoints.length) {
      const controlPointsSummary = controlPoints.map(point => {
        const photosCount = point.photos?.length || 0;
        return `• ${point.name}: ${point.description} - Ubicación: ${point.location} - Fotos: ${photosCount}`;
      }).join("\n");
      
      contextSections.push({
        id: "control-points",
        heading: "Puntos de control fotográfico",
        body: controlPointsSummary,
      });
    }

    // Add pending commitments context
    if (pendingCommitments.length) {
      const commitmentsSummary = pendingCommitments.map(commitment => {
        const responsible = commitment.responsible?.fullName || "No asignado";
        const role = commitment.responsible?.projectRole || "";
        return `• ${commitment.description} - Responsable: ${responsible} (${role}) - Vence: ${formatDate(commitment.dueDate)}`;
      }).join("\n");
      
      contextSections.push({
        id: "pending-commitments",
        heading: "Compromisos pendientes",
        body: commitmentsSummary,
        priority: 1,
      });
    }

    // Add recent log entries context
    if (recentLogEntries.length) {
      const logEntriesSummary = recentLogEntries.map(entry => {
        const author = entry.author?.fullName || "No especificado";
        const type = entryTypeReverseMap[entry.type] || entry.type;
        const status = entryStatusReverseMap[entry.status] || entry.status;
        const assignees = entry.assignees?.map(a => a.fullName).join(", ") || "Sin asignados";
        return `• "${entry.title}" - Autor: ${author} - Tipo: ${type} - Estado: ${status} - Asignados: ${assignees} - Fecha: ${formatDate(entry.createdAt)}`;
      }).join("\n");
      
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

    const messages: Array<{ role: "system" | "user" | "assistant"; content: string }> = [
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
      console.warn("No fue posible guardar la interacción del chatbot:", loggingError);
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
      console.warn("No se pudo actualizar las métricas de uso del chatbot:", usageError);
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
    // Errores comunes de OpenAI
    if (error.response) {
      console.error("Detalle del error:", error.response.data);
      if (error.response.status === 401) {
        return res.status(500).json({ error: "La clave de API de OpenAI no es válida. Revisa tu .env." });
      }
      if (error.response.status === 429) {
        return res.status(500).json({ error: "Límite de cuota de OpenAI excedido. Revisa tu facturación." });
      }
    }
    res.status(500).json({ error: "Error al procesar la respuesta del chatbot." });
  }
});
// --- FIN: Endpoint del Chatbot ---
// --- FIN: Endpoint del Chatbot ---

app.post("/api/chatbot/feedback", authMiddleware, async (req: AuthRequest, res) => {
  const { interactionId, rating, comment, tags } = req.body ?? {};
  const userId = req.user?.userId;

  if (!interactionId || typeof interactionId !== "string") {
    return res.status(400).json({ error: "interactionId es obligatorio." });
  }
  if (!rating || (rating !== "POSITIVE" && rating !== "NEGATIVE")) {
    return res.status(400).json({ error: "rating debe ser POSITIVE o NEGATIVE." });
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
      return res.status(404).json({ error: "No se encontró la interacción especificada." });
    }

    if (interaction.userId !== userId) {
      return res.status(403).json({ error: "No tienes permisos para calificar esta interacción." });
    }

    const metadata =
      tags && Array.isArray(tags) && tags.length
        ? { tags }
        : undefined;

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
    res.status(500).json({ error: "No se pudo guardar el feedback del chatbot." });
  }
});

app.post("/api/chat/cometchat/session", authMiddleware, async (req: AuthRequest, res) => {
  try {
    const baseUrl = getCometChatBaseUrl();
    if (!baseUrl || !COMETCHAT_API_KEY) {
      return res.status(501).json({ error: "CometChat no está configurado en el servidor." });
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
        logger.error("CometChat: error creando usuario", { status: createResponse.status, body });
        return res.status(500).json({ error: "No se pudo crear el usuario en CometChat." });
      }
    } else if (!userResponse.ok) {
      const body = await userResponse.text();
      logger.error("CometChat: error consultando usuario", { status: userResponse.status, body });
      return res.status(500).json({ error: "No se pudo sincronizar el usuario con CometChat." });
    }

    const tokenResponse = await fetch(`${baseUrl}/users/${uid}/auth_tokens`, {
      method: "POST",
      headers,
    });

    if (!tokenResponse.ok) {
      const body = await tokenResponse.text();
      logger.error("CometChat: error generando token", { status: tokenResponse.status, body });
      return res.status(500).json({ error: "No se pudo generar el token de acceso para CometChat." });
    }

    const tokenPayload: any = await tokenResponse.json();
    const authToken = tokenPayload?.data?.authToken;
    if (!authToken) {
      logger.error("CometChat: respuesta sin authToken", { data: tokenPayload });
      return res.status(500).json({ error: "No se pudo generar el token de acceso para CometChat." });
    }

    res.json({ authToken, expiresAt: tokenPayload?.data?.expiresAt ?? null });
  } catch (error) {
    logger.error("CometChat: error generando sesión", { error });
    res.status(500).json({ error: "No se pudo iniciar la sesión de chat." });
  }
});


// --- Endpoint para subir un único archivo ---
app.post("/api/upload", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
  try {
    // Usar una promesa para manejar la subida del archivo
    await new Promise((resolve, reject) => {
      upload.single("file")(req, res, (err) => {
        if (err instanceof multer.MulterError) {
          // Error de Multer
          if (err.code === 'LIMIT_FILE_SIZE') {
            reject({ status: 413, message: "El archivo excede el tamaño máximo permitido (10MB)." });
          } else if (err.code === 'LIMIT_FILE_COUNT') {
            reject({ status: 413, message: "Se excedió el número máximo de archivos permitidos." });
          } else {
            reject({ status: 400, message: "Error al subir el archivo: " + err.message });
          }
        } else if (err) {
          // Error de validación u otro error
          reject({ status: 400, message: err.message });
        } else {
          resolve(true);
        }
      });
    });

    if (!req.file) {
      return res.status(400).json({ error: "No se subió ningún archivo." });
    }

    if (!req.file.buffer) {
      return res.status(400).json({ error: "El archivo recibido está vacío." });
    }

    const stored = await persistUploadedFile(req.file, "attachments");

    // Crear el registro en la base de datos
    const newAttachment = await prisma.attachment.create({
      data: {
        fileName: req.file.originalname,
        url: stored.url,
        storagePath: stored.key,
        size: req.file.size,
        type: req.file.mimetype,
      },
    });

    res.status(201).json(newAttachment);
  } catch (error: any) {
    console.error("Error en la subida de archivo:", error);
    
    // Si es un error controlado de la subida
    if (error.status) {
      return res.status(error.status).json({ error: error.message });
    }

    // Si es un error de la base de datos
    if ((error as any).code === 'P2002') {
      return res.status(409).json({ error: "Ya existe un archivo con este nombre." });
    }

    // Cualquier otro error
    res.status(500).json({ 
      error: "Error al procesar el archivo.",
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// --- RUTAS DE AUTENTICACIÓN ---
// TODO: Implementar registro y login seguros
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

    const existingUser = await prisma.user.findUnique({
      where: { email: normalizedEmail },
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

    const newUser = await prisma.user.create({
      data: {
        email: normalizedEmail,
        password: hashedPassword,
        fullName,
        projectRole: resolvedProjectRole,
        appRole: resolvedAppRole,
        status: "active",
        tokenVersion: 0,
        emailVerifiedAt: isEmailServiceConfigured() ? null : new Date(),
      },
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
        console.error("No se pudo enviar el correo de verificación:", mailError);
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

app.post("/api/auth/refresh", refreshAuthMiddleware, async (req: AuthRequest, res) => {
  try {
    console.log('Refresh token request received');
    
    if (!req.user) {
      console.log('No user found in request');
      return res.status(401).json({ error: "No user found in request" });
    }

    console.log('User from token:', req.user);

    const user = await prisma.user.findUnique({
      where: { id: req.user.userId }
    });

    if (!user) {
      console.log('User not found in database');
      return res.status(401).json({ error: "User not found" });
    }

    console.log('User found in database');

    // Verificar token version
    if (user.tokenVersion !== req.user.tokenVersion) {
      console.log('Token version mismatch');
      return res.status(401).json({ error: "Token version mismatch" });
    }

    // Crear nuevo access token
    const accessToken = createAccessToken(user.id, user.tokenVersion);
    const refreshToken = createRefreshToken(user.id, user.tokenVersion);

    console.log('New tokens created');

    // Actualizar cookie de refresh token
    res.cookie('jid', refreshToken, buildRefreshCookieOptions());

    console.log('Refresh token cookie set');

    return res.json({ accessToken });
  } catch (error) {
    console.error("Error en refresh token:", error);
    res.status(500).json({ error: "Error al refrescar el token" });
  }
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie('jid', buildRefreshCookieOptions({}, false));
  res.json({ message: "Logged out successfully" });
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log('Login request received:', {
      email,
      hasPassword: Boolean(password),
    });

    if (!email || !password) {
      return res.status(400).json({ error: "Email y contraseña son requeridos." });
    }

    const user = await prisma.user.findUnique({
      where: { email },
    });

    console.log('User found:', user ? 'yes' : 'no');

    if (!user) {
      return res.status(401).json({ error: "Credenciales inválidas." });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    console.log('Password valid:', isPasswordValid ? 'yes' : 'no');

    if (!isPasswordValid) {
      return res.status(401).json({ error: "Credenciales inválidas." });
    }

    if (user.status !== "active") {
      return res.status(403).json({ error: "La cuenta de usuario está inactiva." });
    }

    // Crear tokens de acceso y refresh
    const accessToken = createAccessToken(user.id, user.tokenVersion);
    const refreshToken = createRefreshToken(user.id, user.tokenVersion);

    console.log('Tokens created successfully');

    // Actualizar último login
    await prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() }
    });

    // Enviar refresh token como cookie httpOnly
    res.cookie('jid', refreshToken, buildRefreshCookieOptions());

    const { password: _, ...userWithoutPassword } = user;
    
    console.log('Login successful, sending response');
    
    return res.json({ 
      accessToken,
      user: userWithoutPassword
    });

  } catch (error) {
    console.error("Error en login:", error);
    res.status(500).json({ error: "Error interno del servidor." });
  }
});

app.post("/api/auth/verify-email/:token", async (req, res) => {
  const { token } = req.params;

  if (!token) {
    return res.status(400).json({ error: "Token de verificación inválido." });
  }

  const tokenHash = hashToken(token);

  try {
    const verificationToken = await prisma.emailVerificationToken.findUnique({
      where: { tokenHash },
      include: { user: true },
    });

    if (!verificationToken || !verificationToken.user) {
      return res.status(400).json({ error: "Token no válido o ya utilizado." });
    }

    if (verificationToken.usedAt) {
      return res
        .status(400)
        .json({ error: "Este token ya fue utilizado previamente." });
    }

    if (verificationToken.expiresAt < new Date()) {
      return res.status(400).json({
        error: "El token de verificación ha expirado. Solicita uno nuevo.",
      });
    }

    await prisma.$transaction([
      prisma.user.update({
        where: { id: verificationToken.userId },
        data: {
          emailVerifiedAt: verificationToken.user.emailVerifiedAt ?? new Date(),
          status:
            verificationToken.user.status === "inactive"
              ? "active"
              : verificationToken.user.status,
        },
      }),
      prisma.emailVerificationToken.update({
        where: { id: verificationToken.id },
        data: { usedAt: new Date() },
      }),
      prisma.emailVerificationToken.deleteMany({
        where: {
          userId: verificationToken.userId,
          id: { not: verificationToken.id },
        },
      }),
    ]);

    res.json({ success: true });
  } catch (error) {
    console.error("Error al verificar el email:", error);
    res.status(500).json({ error: "Error al verificar el email." });
  }
});

app.post("/api/auth/forgot-password", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res
      .status(400)
      .json({ error: "Debes proporcionar el correo electrónico." });
  }

  const normalizedEmail = String(email).trim().toLowerCase();

  try {
    const user = await prisma.user.findUnique({
      where: { email: normalizedEmail },
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
          console.error(
            "No se pudo enviar el correo de restablecimiento:",
            mailError
          );
        }
      } else {
        console.warn(
          `Servicio de correo no configurado. Token de restablecimiento para ${user.email}: ${token}`
        );
      }
    }

    res.json({
      message:
        "Si el correo existe en nuestra base de datos, enviaremos instrucciones para restablecer la contraseña.",
    });
  } catch (error) {
    console.error("Error al solicitar restablecimiento de contraseña:", error);
    res.status(500).json({ error: "No fue posible procesar la solicitud." });
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
    console.error("Error al restablecer la contraseña:", error);
    res
      .status(500)
      .json({ error: "No fue posible restablecer la contraseña." });
  }
});

// Endpoint para cambiar contraseña (usuario autenticado)
app.post(
  "/api/auth/change-password",
  authMiddleware,
  async (req: AuthRequest, res) => {
    const userId = req.user?.userId;
    const { oldPassword, newPassword } = req.body;

    if (!userId) {
      return res.status(401).json({ error: "Usuario no autenticado." });
    }

    if (!oldPassword || !newPassword) {
      return res.status(400).json({
        error: "Debes proporcionar la contraseña actual y la nueva.",
      });
    }

    try {
      const user = await prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        return res.status(404).json({ error: "Usuario no encontrado." });
      }

      const isOldPasswordValid = await bcrypt.compare(
        oldPassword,
        user.password
      );

      if (!isOldPasswordValid) {
        return res
          .status(400)
          .json({ error: "La contraseña actual no es correcta." });
      }

      if (oldPassword === newPassword) {
        return res.status(400).json({
          error: "La nueva contraseña debe ser diferente a la anterior.",
        });
      }

      const passwordError = await validatePasswordStrength(newPassword);
      if (passwordError) {
        return res.status(400).json({ error: passwordError });
      }

      const hashedPassword = await bcrypt.hash(newPassword, 12);

      await prisma.user.update({
        where: { id: user.id },
        data: {
          password: hashedPassword,
          tokenVersion: user.tokenVersion + 1,
        },
      });

      res.json({ success: true });
    } catch (error) {
      console.error("Error al cambiar la contraseña:", error);
      res
        .status(500)
        .json({ error: "No se pudo cambiar la contraseña en este momento." });
    }
  }
);

// Endpoint para actualizar perfil de usuario
app.put("/api/auth/profile", authMiddleware, async (req: AuthRequest, res) => {
    const userId = req.user?.userId;
    const { fullName, avatarUrl } = req.body; // Campos permitidos para actualizar
    console.log("Actualización de perfil solicitada por usuario:", userId, req.body);
    
    if (!userId) {
        return res.status(401).json({ error: "Usuario no autenticado." });
    }
    
    try {
        const updateData: { fullName?: string; avatarUrl?: string } = {};
        if (fullName) updateData.fullName = fullName;
        if (avatarUrl) updateData.avatarUrl = avatarUrl; // Considera validación de URL

        if (Object.keys(updateData).length === 0) {
            return res.status(400).json({ error: "No se proporcionaron datos para actualizar." });
        }

        const updatedUser = await prisma.user.update({
            where: { id: userId },
            data: updateData,
            select: { // Devuelve solo los datos públicos
                id: true,
                fullName: true,
                email: true,
                projectRole: true,
                avatarUrl: true,
                appRole: true,
                status: true,
                lastLoginAt: true,
                emailVerifiedAt: true,
            }
        });
        
        res.json(updatedUser);
        
    } catch (error) {
        console.error("Error al actualizar perfil:", error);
         if ((error as any)?.code === 'P2025') {
            return res.status(404).json({ error: "Usuario no encontrado." });
        }
        res.status(500).json({ error: "Error interno al actualizar el perfil." });
    }
});

// --- RUTA PARA VERIFICAR TOKEN Y OBTENER DATOS DEL USUARIO ---
app.get("/api/auth/me", authMiddleware, async (req: AuthRequest, res) => {
  // Si el middleware authMiddleware pasa, significa que el token es válido
  // y req.user contiene el payload ( { userId: '...' } )
  const userId = req.user?.userId;

  if (!userId) {
    // Esto no debería ocurrir si authMiddleware funciona, pero es una guarda de seguridad
    return res
      .status(401)
      .json({ error: "No se pudo identificar al usuario desde el token." });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      // Seleccionamos los campos a devolver (excluimos la contraseña)
      select: {
        id: true,
        fullName: true,
        email: true,
        projectRole: true,
        avatarUrl: true,
        appRole: true,
        status: true,
        lastLoginAt: true,
        emailVerifiedAt: true,
        // Agrega otros campos que necesites en el frontend
      },
    });

    if (!user) {
      return res.status(404).json({ error: "Usuario no encontrado." });
    }

    if (user.status !== "active") {
      return res
        .status(403)
        .json({ error: "La cuenta de usuario está inactiva." });
    }

    res.json(user); // Devolvemos los datos del usuario autenticado
  } catch (error) {
    console.error("Error al obtener datos del usuario (/api/auth/me):", error);
    res.status(500).json({ error: "Error interno del servidor." });
  }
});

app.get("/api/public/demo-users", async (_req, res) => {
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
      },
      orderBy: { fullName: "asc" },
    });

    const sanitized = users.map((user) => ({
      id: user.id,
      fullName: user.fullName,
      email: user.email,
      projectRole: user.projectRole,
      appRole: user.appRole,
      status: user.status,
    }));

    res.json(sanitized);
  } catch (error) {
    console.error("Error al obtener usuarios demo:", error);
    res
      .status(500)
      .json({ error: "No se pudieron cargar los usuarios de demostración." });
  }
});

app.get("/api/users", authMiddleware, async (_req: AuthRequest, res) => {
  try {
    const users = await prisma.user.findMany({
      orderBy: { fullName: "asc" },
    });
    res.json(users.map(formatAdminUser));
  } catch (error) {
    console.error("Error al obtener usuarios (autenticado):", error);
    res.status(500).json({ error: "Error al obtener usuarios." });
  }
});

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
    res.json({
      signature: {
        id: signature.id,
        fileName: signature.fileName,
        mimeType: signature.mimeType,
        size: signature.size,
        url: signature.url,
        hash: signature.hash,
        createdAt: signature.createdAt,
        updatedAt: signature.updatedAt,
      },
    });
  } catch (error) {
    console.error("Error al obtener la firma del usuario:", error);
    res.status(500).json({ error: "No se pudo obtener la firma guardada." });
  }
});

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
        return res.status(400).json({ error: "No se recibió ningún archivo válido." });
      }

      const existing = await prisma.userSignature.findUnique({
        where: { userId },
      });

      const storage = getStorage();
      const key = createStorageKey(`user-signatures/${userId}`, file.originalname);
      await storage.save({ path: key, content: file.buffer });
      const url = storage.getPublicUrl(key);
      const hash = sha256(file.buffer);

      let newSignature: any = null;
      await prisma.$transaction(async (tx) => {
        if (existing) {
          await tx.userSignature.delete({ where: { id: existing.id } });
        }
        newSignature = await tx.userSignature.create({
          data: {
            userId,
            fileName: file.originalname,
            mimeType: file.mimetype,
            size: file.size,
            storagePath: key,
            url,
            hash,
          },
        });
      });

      if (!newSignature) {
        throw new Error("No se pudo registrar la nueva firma.");
      }

      if (existing?.storagePath && existing.storagePath !== key) {
        await storage.remove(existing.storagePath).catch((error) => {
          console.warn("No se pudo eliminar la firma anterior del almacenamiento.", {
            error,
          });
        });
      }

      res.status(201).json({
        signature: {
          id: newSignature.id,
          fileName: newSignature.fileName,
          mimeType: newSignature.mimeType,
          size: newSignature.size,
          url: newSignature.url,
          hash: newSignature.hash,
          createdAt: newSignature.createdAt,
          updatedAt: newSignature.updatedAt,
        },
      });
    } catch (error) {
      console.error("Error al guardar la firma del usuario:", error);
      res.status(500).json({ error: "No se pudo guardar la firma." });
    }
  }
);

app.delete("/api/users/me/signature", authMiddleware, async (req: AuthRequest, res) => {
  try {
    const userId = req.user?.userId;
    if (!userId) {
      return res.status(401).json({ error: "Usuario no autenticado." });
    }

    const existing = await prisma.userSignature.findUnique({
      where: { userId },
    });
    if (!existing) {
      return res.status(404).json({ error: "No hay firma registrada para el usuario." });
    }

    const storage = getStorage();
    await prisma.userSignature.delete({ where: { id: existing.id } });
    if (existing.storagePath) {
      await storage.remove(existing.storagePath).catch((error) => {
        console.warn("No se pudo eliminar el archivo de firma del almacenamiento.", {
          error,
        });
      });
    }

    res.status(204).send();
  } catch (error) {
    console.error("Error al eliminar la firma del usuario:", error);
    res.status(500).json({ error: "No se pudo eliminar la firma." });
  }
});

app.get(
  "/api/admin/users",
  authMiddleware,
  requireAdmin,
  async (req: AuthRequest, res) => {
    try {
      const users = await prisma.user.findMany({
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
      const { fullName, email, appRole, projectRole } = req.body;

      if (!fullName?.trim() || !email?.trim() || !appRole) {
        return res
          .status(400)
          .json({ error: "Nombre completo, email y rol son obligatorios." });
      }

      const normalizedEmail = String(email).trim().toLowerCase();
      const normalizedAppRole = Object.values(AppRole).includes(appRole)
        ? appRole
        : AppRole.viewer;
      const resolvedProjectRole =
        resolveProjectRole(projectRole) ?? UserRole.RESIDENT;

      const existing = await prisma.user.findUnique({
        where: { email: normalizedEmail },
      });

      if (existing) {
        return res
          .status(409)
          .json({ error: "Ya existe un usuario con este correo." });
      }

      const tempPassword = generateTemporaryPassword();
      const hashedPassword = await bcrypt.hash(tempPassword, 12);

      const newUser = await prisma.user.create({
        data: {
          fullName: fullName.trim(),
          email: normalizedEmail,
          appRole: normalizedAppRole,
          projectRole: resolvedProjectRole,
          password: hashedPassword,
          status: "inactive",
        },
      });

      const actorInfo = await resolveActorInfo(req);
      await recordAuditEvent({
        action: "USER_INVITED",
        entityType: "user",
        entityId: newUser.id,
        diff: {
          appRole: { from: null, to: newUser.appRole },
          status: { from: null, to: newUser.status },
        },
        ...actorInfo,
      });

      res.status(201).json({
        user: formatAdminUser(newUser),
        temporaryPassword: tempPassword,
      });
    } catch (error) {
      console.error("Error al invitar usuario:", error);
      res.status(500).json({ error: "No se pudo invitar al usuario." });
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
      const { appRole, status, projectRole } = req.body;

      const updateData: any = {};

      if (appRole) {
        if (!Object.values(AppRole).includes(appRole)) {
          return res.status(400).json({ error: "Rol de aplicación inválido." });
        }
        updateData.appRole = appRole;
      }

      if (status) {
        if (!["active", "inactive"].includes(status)) {
          return res.status(400).json({ error: "Estado inválido." });
        }
        updateData.status = status;
      }

      if (projectRole) {
        const resolved = resolveProjectRole(projectRole);
        if (!resolved) {
          return res
            .status(400)
            .json({ error: "Rol de proyecto inválido." });
        }
        updateData.projectRole = resolved;
      }

      if (Object.keys(updateData).length === 0) {
        return res
          .status(400)
          .json({ error: "No se proporcionaron cambios para actualizar." });
      }

      const existingUser = await prisma.user.findUnique({ where: { id } });
      if (!existingUser) {
        return res.status(404).json({ error: "Usuario no encontrado." });
      }

      const updatedUser = await prisma.user.update({
        where: { id },
        data: updateData,
      });

      const diff = createDiff(existingUser, updatedUser, [
        "appRole",
        "status",
        "projectRole",
      ]);

      if (Object.keys(diff).length > 0) {
        const actorInfo = await resolveActorInfo(req);
        await recordAuditEvent({
          action: "USER_UPDATED",
          entityType: "user",
          entityId: updatedUser.id,
          diff,
          ...actorInfo,
        });
      }

      res.json(formatAdminUser(updatedUser));
    } catch (error) {
      console.error("Error al actualizar usuario:", error);
      res.status(500).json({ error: "No se pudo actualizar el usuario." });
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
        typeof limitParam === "string" ? Math.min(parseInt(limitParam, 10) || 100, 500) : 100;

      const logs = await prisma.auditLog.findMany({
        orderBy: { timestamp: "desc" },
        take: limit,
        include: {
          actor: {
            select: { email: true },
          },
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
      res
        .status(500)
        .json({ error: "No se pudieron cargar los registros de auditoría." });
    }
  }
);

app.get(
  "/api/admin/settings",
  authMiddleware,
  requireAdmin,
  async (req: AuthRequest, res) => {
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
      const current = await ensureAppSettings();
      if (!current) {
        return res.status(503).json({
          error:
            "Configuración no inicializada. Ejecuta las migraciones del servidor para habilitar este módulo.",
        });
      }

      const payload = req.body ?? {};

      const parseBoolean = (value: any) => {
        if (typeof value === "boolean") return value;
        if (typeof value === "string") {
          return value === "true" || value === "1" || value.toLowerCase() === "on";
        }
        return undefined;
      };

      const parseNumber = (value: any) => {
        if (value === undefined || value === null || value === "") return undefined;
        const parsed = Number(value);
        return Number.isFinite(parsed) ? parsed : undefined;
      };

      const updateData: any = {};

      if (payload.companyName !== undefined) {
        updateData.companyName = String(payload.companyName);
      }
      if (payload.timezone !== undefined) {
        updateData.timezone = String(payload.timezone);
      }
      if (payload.locale !== undefined) {
        updateData.locale = String(payload.locale);
      }

      const strongPassword = parseBoolean(payload.requireStrongPassword);
      if (strongPassword !== undefined) {
        updateData.requireStrongPassword = strongPassword;
      }

      const enable2FA = parseBoolean(payload.enable2FA);
      if (enable2FA !== undefined) {
        updateData.enable2FA = enable2FA;
      }

      const sessionTimeout = parseNumber(payload.sessionTimeoutMinutes);
      if (sessionTimeout !== undefined) {
        updateData.sessionTimeoutMinutes = sessionTimeout;
      }

      const photoInterval = parseNumber(payload.photoIntervalDays);
      if (photoInterval !== undefined) {
        updateData.photoIntervalDays = photoInterval;
      }

      if (payload.defaultProjectVisibility !== undefined) {
        updateData.defaultProjectVisibility = String(
          payload.defaultProjectVisibility
        );
      }

      if (Object.keys(updateData).length === 0) {
        return res
          .status(400)
          .json({ error: "No se proporcionaron cambios para actualizar." });
      }

      const updated = await prisma.appSetting.update({
        where: { id: current.id },
        data: updateData,
      });

      const diff = createDiff(current, updated, [
        "companyName",
        "timezone",
        "locale",
        "requireStrongPassword",
        "enable2FA",
        "sessionTimeoutMinutes",
        "photoIntervalDays",
        "defaultProjectVisibility",
      ]);

      if (Object.keys(diff).length > 0) {
        const actorInfo = await resolveActorInfo(req);
        await recordAuditEvent({
          action: "APP_SETTING_CHANGED",
          entityType: "setting",
          entityId: updated.id,
          diff,
          ...actorInfo,
        });
      }

      res.json(formatAppSettings(updated));
    } catch (error) {
      console.error("Error al actualizar configuración:", error);
      res
        .status(500)
        .json({ error: "No se pudo actualizar la configuración." });
    }
  }
);

app.get(
  "/api/admin/system/email",
  authMiddleware,
  requireAdmin,
  async (req: AuthRequest, res) => {
    try {
      const summary = getEmailConfigurationSummary();
      const shouldVerify =
        typeof req.query.verify === "string" &&
        req.query.verify.toLowerCase() === "true";

      let verification:
        | { verified: boolean; error?: string }
        | undefined = undefined;

      if (shouldVerify && summary.configured) {
        try {
          await verifyEmailTransporter();
          verification = { verified: true };
        } catch (error) {
          const message =
            error instanceof Error
              ? error.message
              : "No se pudo verificar la conexión SMTP.";
          verification = { verified: false, error: message };
        }
      } else if (shouldVerify && !summary.configured) {
        verification = {
          verified: false,
          error: "El servicio de correo no está configurado.",
        };
      }

      res.json({
        ...summary,
        verification: verification ?? undefined,
      });
    } catch (error) {
      console.error("Error al consultar estado del correo:", error);
      res.status(500).json({
        error: "No se pudo consultar el estado del servicio de correo.",
      });
    }
  }
);

app.post(
  "/api/admin/system/email/test",
  authMiddleware,
  requireAdmin,
  async (req: AuthRequest, res) => {
    try {
      const toRaw = req.body?.to;
      const toCandidate =
        typeof toRaw === "string" && toRaw.trim().length > 0
          ? toRaw.trim()
          : undefined;
      const target = toCandidate ?? req.user?.email;

      if (!target) {
        return res.status(400).json({
          error:
            "Proporciona un correo de destino en el cuerpo de la solicitud (campo 'to').",
        });
      }

      await sendTestEmail(target, req.user?.email || undefined);
      res.json({
        success: true,
        to: target,
        message: "Correo de prueba enviado correctamente.",
      });
    } catch (error) {
      const message =
        error instanceof Error
          ? error.message
          : "No se pudo enviar el correo de prueba.";
      const normalized = message.toLowerCase();
      const status = normalized.includes("no está configurado") ? 400 : 500;
      console.error("Error al enviar correo de prueba:", error);
      res.status(status).json({ error: message });
    }
  }
);

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

// Endpoint para obtener detalles del proyecto
app.get("/api/project-details", authMiddleware, async (req: AuthRequest, res) => {
  try {
    const project = await prisma.project.findFirst({
      include: {
        keyPersonnel: true
      }
    });

    if (!project) {
      return res.status(404).json({ error: "No se encontró ningún proyecto." });
    }

    res.json(project);
  } catch (error) {
    console.error("Error al obtener detalles del proyecto:", error);
    res.status(500).json({ error: "Error al obtener detalles del proyecto." });
  }
});

// Endpoint para obtener modificaciones contractuales
app.get("/api/contract-modifications", authMiddleware, async (req: AuthRequest, res) => {
  try {
    const modifications = await prisma.contractModification.findMany({
      orderBy: { date: 'desc' },
      include: {
        attachment: true
      }
    });

    const formattedModifications = modifications.map((modification) => ({
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

    res.json(formattedModifications);
  } catch (error) {
    console.error("Error al obtener modificaciones contractuales:", error);
    res.status(500).json({ error: "Error al obtener modificaciones contractuales." });
  }
});

// Endpoint para crear una modificación contractual
app.post("/api/contract-modifications", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
  try {
    const { number, type, date, value, days, justification, attachmentId } = req.body;

    if (!number || !type || !date || !justification) {
      return res.status(400).json({ 
        error: "Faltan campos requeridos (número, tipo, fecha y justificación son obligatorios)." 
      });
    }

    const prismaType = modificationTypeMap[type];
    if (!prismaType) {
      return res.status(400).json({
        error: "Tipo de modificación no reconocido.",
      });
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

    const newModification = await prisma.contractModification.create({
      data: {
        number,
        type: prismaType,
        date: new Date(date),
        value: parsedValue,
        days: parsedDays,
        justification,
        attachment: attachmentId ? { connect: { id: attachmentId } } : undefined
      },
      include: {
        attachment: true
      }
    });

    const formattedModification = {
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

    res.status(201).json(formattedModification);
  } catch (error) {
    console.error("Error al crear modificación contractual:", error);
    if ((error as any).code === 'P2002') {
      return res.status(409).json({ error: "Ya existe una modificación con este número." });
    }
    res.status(500).json({ error: "Error al crear la modificación contractual." });
  }
});
// TODO: Añadir ruta GET /api/auth/me para verificar token

// --- RUTAS PARA COMUNICACIONES ---
app.get("/api/communications", async (req, res) => {
  try {
    const communications = await prisma.communication.findMany({
      orderBy: { sentDate: "desc" },
      include: {
        uploader: true,
        assignee: true,
        attachments: true,
        statusHistory: { include: { user: true }, orderBy: { timestamp: "asc" } },
      },
    });
    const formattedComms = communications.map((communication) => ({
      ...formatCommunication(communication),
      attachments: (communication.attachments || []).map(buildAttachmentResponse),
    }));
    res.json(formattedComms);
  } catch (error) {
    console.error("Error al obtener comunicaciones:", error);
    res.status(500).json({ error: "No se pudieron obtener las comunicaciones." });
  }
});

app.get("/api/communications/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const communication = await prisma.communication.findUnique({
      where: { id },
      include: {
        uploader: true,
        assignee: true,
        attachments: true,
        statusHistory: { include: { user: true }, orderBy: { timestamp: "asc" } },
      },
    });

    if (!communication) {
      return res.status(404).json({ error: "Comunicación no encontrada." });
    }

    const formattedComm = formatCommunication(communication);
    formattedComm.attachments = (communication.attachments || []).map(buildAttachmentResponse);
    res.json(formattedComm);
  } catch (error) {
    console.error("Error al obtener la comunicación:", error);
    res.status(500).json({ error: "No se pudo obtener la comunicación solicitada." });
  }
});

app.post("/api/communications", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
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
      uploaderId: providedUploaderId,
      attachments = [],
    } = req.body;
    const uploaderId = req.user?.userId || providedUploaderId;
    if (!uploaderId) {
      return res.status(400).json({ error: "El usuario que crea la comunicación es obligatorio." });
    }
    const prismaDeliveryMethod = deliveryMethodMap[deliveryMethod] || "SYSTEM";
    const prismaDirection =
      communicationDirectionMap[direction] ||
      communicationDirectionMap[communicationDirectionReverseMap[direction] || "Recibida"] ||
      "RECEIVED";
    const normalizedRequiresResponse = Boolean(requiresResponse);
    const newComm = await prisma.communication.create({
      data: {
        radicado,
        subject,
        description,
        senderEntity: senderDetails.entity,
        senderName: senderDetails.personName,
        senderTitle: senderDetails.personTitle,
        recipientEntity: recipientDetails.entity,
        recipientName: recipientDetails.personName,
        recipientTitle: recipientDetails.personTitle,
        signerName,
        sentDate: new Date(sentDate),
        dueDate: dueDate ? new Date(dueDate) : null,
        deliveryMethod: prismaDeliveryMethod,
        notes,
        status: 'PENDIENTE', // Estado inicial para comunicaciones
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
            status: communicationStatusMap['Pendiente'] || 'PENDIENTE',
            user: { connect: { id: uploaderId } },
          },
        },
      },
      include: {
        uploader: true,
        assignee: true,
        attachments: true,
        statusHistory: { include: { user: true }, orderBy: { timestamp: "asc" } },
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
            responseDueDate: newComm.responseDueDate,
          },
        });
      } catch (emailError) {
        logger.warn("No se pudo enviar el correo de asignación de comunicación.", {
          error: emailError,
          communicationId: newComm.id,
        });
      }
    }
    const formattedComm = formatCommunication(newComm);
    formattedComm.attachments = (newComm.attachments || []).map(buildAttachmentResponse);
    res.status(201).json(formattedComm);
  } catch (error) {
    console.error("Error al crear la comunicación:", error);
    res.status(500).json({ error: "No se pudo crear la comunicación." });
  }
});

app.put("/api/communications/:id/status", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!status) {
      return res.status(400).json({ error: "El estado es obligatorio." });
    }

    const userId = req.user?.userId;
    if (!userId) {
      return res.status(401).json({ error: "No autorizado." });
    }

    const prismaStatus = communicationStatusMap[status] || communicationStatusMap[communicationStatusReverseMap[status] || 'Pendiente'] || 'PENDIENTE';

    const updatedCommunication = await prisma.communication.update({
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
        statusHistory: { include: { user: true }, orderBy: { timestamp: "asc" } },
      },
    });

    const formatted = formatCommunication(updatedCommunication);
    res.json(formatted);
  } catch (error) {
    console.error("Error al actualizar estado de la comunicación:", error);
    if ((error as any)?.code === "P2025") {
      return res.status(404).json({ error: "Comunicación no encontrada." });
    }
    res.status(500).json({ error: "No se pudo actualizar el estado." });
  }
});

app.put("/api/communications/:id/assignment", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
  try {
    const { id } = req.params;
    const { assigneeId } = req.body as { assigneeId?: string | null };

    const current = await prisma.communication.findUnique({
      where: { id },
      select: { assigneeId: true },
    });

    if (!current) {
      return res.status(404).json({ error: "Comunicación no encontrada." });
    }

    const normalizedAssigneeId =
      assigneeId && typeof assigneeId === "string" && assigneeId.trim().length > 0
        ? assigneeId.trim()
        : null;

    if (current.assigneeId === normalizedAssigneeId) {
      const communication = await prisma.communication.findUnique({
        where: { id },
        include: {
          uploader: true,
          assignee: true,
          attachments: true,
          statusHistory: { include: { user: true }, orderBy: { timestamp: "asc" } },
        },
      });
      if (!communication) {
        return res.status(404).json({ error: "Comunicación no encontrada." });
      }
      return res.json(formatCommunication(communication));
    }

    const updatedCommunication = await prisma.communication.update({
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
        statusHistory: { include: { user: true }, orderBy: { timestamp: "asc" } },
      },
    });

    if (normalizedAssigneeId && updatedCommunication.assignee?.email) {
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
          to: updatedCommunication.assignee.email,
          recipientName: updatedCommunication.assignee.fullName,
          assignerName,
          communication: {
            radicado: updatedCommunication.radicado,
            subject: updatedCommunication.subject,
            sentDate: updatedCommunication.sentDate,
            responseDueDate: updatedCommunication.responseDueDate,
          },
        });
      } catch (emailError) {
        logger.warn("No se pudo enviar el correo de asignación de comunicación.", {
          error: emailError,
          communicationId: updatedCommunication.id,
        });
      }
    }

    res.json(formatCommunication(updatedCommunication));
  } catch (error) {
    console.error("Error al asignar la comunicación:", error);
    if ((error as any)?.code === "P2025") {
      return res.status(404).json({ error: "Comunicación no encontrada." });
    }
    res.status(500).json({ error: "No se pudo actualizar la asignación." });
  }
});


// --- RUTAS PARA PLANOS (DRAWINGS) ---
app.get("/api/drawings", async (req, res) => {
  try {
    const drawings = await prisma.drawing.findMany({
      orderBy: { createdAt: "desc" },
      include: {
        versions: {
          orderBy: { versionNumber: "desc" },
          include: { uploader: true },
        },
        comments: { include: { author: true }, orderBy: { timestamp: "asc" } },
      },
    });
    // Formatear la disciplina antes de enviar
    const formattedDrawings = drawings.map((d) => ({
      ...d,
      discipline:
        Object.keys(drawingDisciplineMap).find(
          (key) => drawingDisciplineMap[key] === d.discipline
        ) || d.discipline,
    }));
    res.json(formattedDrawings);
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
        comments: { include: { author: true }, orderBy: { timestamp: "asc" } },
      },
    });

    if (!drawing) {
      return res.status(404).json({ error: "Plano no encontrado." });
    }

    const formattedDrawing = {
      ...drawing,
      discipline:
        Object.keys(drawingDisciplineMap).find(
          (key) => drawingDisciplineMap[key] === drawing.discipline
        ) || drawing.discipline,
    };

    res.json(formattedDrawing);
  } catch (error) {
    console.error("Error al obtener el plano:", error);
    res.status(500).json({ error: "No se pudo obtener el plano solicitado." });
  }
});

app.post("/api/drawings", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
  try {
    const { code, title, discipline, version } = req.body;
    const prismaDiscipline = drawingDisciplineMap[discipline] || "OTHER";
    if (!code || !title || !discipline || !version) {
      return res
        .status(400)
        .json({ error: "Faltan datos para crear el plano." });
    }
    const newDrawing = await prisma.drawing.create({
      data: {
        code,
        title,
        discipline: prismaDiscipline,
        status: 'VIGENTE', // Estado inicial para dibujos
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
      }, // Incluir comments
    });
    // Formatear disciplina en la respuesta
    const formattedDrawing = {
      ...newDrawing,
      discipline:
        Object.keys(drawingDisciplineMap).find(
          (key) => drawingDisciplineMap[key] === newDrawing.discipline
        ) || newDrawing.discipline,
    };
    res.status(201).json(formattedDrawing);
  } catch (error) {
    console.error("Error al crear el plano:", error);
    if ((error as any).code === "P2002") {
      return res
        .status(409)
        .json({ error: "Ya existe un plano con este código." });
    }
    res.status(500).json({ error: "No se pudo crear el plano." });
  }
});

app.post("/api/drawings/:id/versions", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
  try {
    const { id } = req.params;
    const { version } = req.body;
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
    const latestVersionNumber = existingDrawing.versions[0]?.versionNumber || 0;
    const updatedDrawing = await prisma.drawing.update({
      where: { id: id },
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
      }, // Incluir comments
    });
    // Formatear disciplina en la respuesta
    const formattedDrawing = {
      ...updatedDrawing,
      discipline:
        Object.keys(drawingDisciplineMap).find(
          (key) => drawingDisciplineMap[key] === updatedDrawing.discipline
        ) || updatedDrawing.discipline,
    };
    res.status(201).json(formattedDrawing);
  } catch (error) {
    console.error("Error al añadir nueva versión:", error);
    res.status(500).json({ error: "No se pudo añadir la nueva versión." });
  }
});

app.post("/api/drawings/:id/comments", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
  try {
    const { id } = req.params;
    const { content, authorId } = req.body;
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
        drawing: { connect: { id: id } },
      },
      include: { author: true },
    });
    res.status(201).json(newComment);
  } catch (error) {
    console.error("Error al añadir el comentario al plano:", error);
    res.status(500).json({ error: "No se pudo añadir el comentario." });
  }
});

// --- RUTAS PARA ACTAS DE COMITÉ ---
app.get("/api/actas", async (req, res) => {
  try {
    const actas = await prisma.acta.findMany({
      orderBy: { date: "desc" },
      include: {
        attachments: true,
        commitments: { include: { responsible: true } },
        signatures: { include: { signer: true } },
      },
    });
    const formattedActas = actas.map(formatActa);
    res.json(formattedActas);
  } catch (error) {
    console.error("Error al obtener actas:", error);
    res.status(500).json({ error: "No se pudieron obtener las actas." });
  }
});

app.get("/api/actas/:id", authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { id } = req.params;
    const acta = await prisma.acta.findUnique({
      where: { id },
      include: {
        attachments: true,
        commitments: { include: { responsible: true } },
        signatures: { include: { signer: true } },
      },
    });

    if (!acta) {
      return res.status(404).json({ error: "Acta no encontrada." });
    }

    res.json(formatActa(acta));
  } catch (error) {
    console.error("Error al obtener acta:", error);
    res.status(500).json({ error: "No se pudo obtener el acta." });
  }
});

app.post("/api/actas", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
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
    } = req.body;
    const prismaArea = actaAreaMap[area] || "OTHER";
    const prismaStatus = actaStatusMap[status] || "DRAFT";
    const newActa = await prisma.acta.create({
      data: {
        number,
        title,
        date: new Date(date),
        area: prismaArea,
        status: prismaStatus,
        summary,
        commitments: {
          create: commitments.map((c: any) => ({
            description: c.description,
            dueDate: new Date(c.dueDate),
            status: "PENDING",
            responsible: { connect: { id: c.responsible.id } },
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
          requiredSignatories.map((u: any) => u.id)
        ),
      },
      include: {
        commitments: { include: { responsible: true } },
        attachments: true,
        signatures: { include: { signer: true } },
      },
    });
    // Formatear enums en la respuesta
    res.status(201).json(formatActa(newActa));
  } catch (error) {
    console.error("Error al crear el acta:", error);
    res.status(500).json({ error: "No se pudo crear el acta." });
  }
});

app.put("/api/actas/:id", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
  try {
    const { id } = req.params;
    const { number, title, date, area, status, summary } = req.body;

    const data: any = {};
    if (number) data.number = number;
    if (title) data.title = title;
    if (summary !== undefined) data.summary = summary;
    if (date) {
      const parsedDate = new Date(date);
      if (!isNaN(parsedDate.getTime())) {
        data.date = parsedDate;
      }
    }
    if (area) {
      data.area = actaAreaMap[area] || actaAreaMap[actaAreaReverseMap[area] || 'Otro'] || 'OTHER';
    }
    if (status) {
      data.status = actaStatusMap[status] || actaStatusMap[actaStatusReverseMap[status] || 'En Borrador'] || 'DRAFT';
    }

    const updatedActa = await prisma.acta.update({
      where: { id },
      data,
      include: {
        commitments: { include: { responsible: true }, orderBy: { dueDate: "asc" } },
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

app.put("/api/actas/:actaId/commitments/:commitmentId", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
  try {
    const { actaId, commitmentId } = req.params;
    const { status } = req.body;

    if (!status) {
      return res.status(400).json({ error: "El estado es obligatorio." });
    }

    const prismaStatus = commitmentStatusMap[status] || commitmentStatusMap[commitmentStatusReverseMap[status] || 'Pendiente'] || 'PENDING';

    const updatedCommitment = await prisma.commitment.update({
      where: { id: commitmentId },
      data: { status: prismaStatus },
      include: { responsible: true },
    });

    res.json({
      ...updatedCommitment,
      status: commitmentStatusReverseMap[updatedCommitment.status] || updatedCommitment.status,
    });
  } catch (error) {
    console.error("Error al actualizar compromiso:", error);
    if ((error as any)?.code === "P2025") {
      return res.status(404).json({ error: "Compromiso no encontrado." });
    }
    res.status(500).json({ error: "No se pudo actualizar el compromiso." });
  }
});

app.post("/api/actas/:actaId/commitments/:commitmentId/reminder", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
  try {
    const { actaId, commitmentId } = req.params;

    const commitment = await prisma.commitment.findFirst({
      where: { id: commitmentId, actaId },
      include: { responsible: true },
    });

    if (!commitment) {
      return res.status(404).json({ error: "Compromiso no encontrado." });
    }

    // Aquí se podría integrar un servicio de correo. Por ahora solo respondemos OK.
    res.json({ message: "Recordatorio enviado (simulado)." });
  } catch (error) {
    console.error("Error al enviar recordatorio de compromiso:", error);
    res.status(500).json({ error: "No se pudo enviar el recordatorio." });
  }
});

app.post("/api/actas/:id/signatures", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
  try {
    const { id } = req.params;
    const { signerId, password } = req.body;

    if (!signerId || !password) {
      return res.status(400).json({ error: "Se requieren el firmante y la contraseña." });
    }

    const signer = await prisma.user.findUnique({ where: { id: signerId } });
    if (!signer) {
      return res.status(404).json({ error: "Firmante no encontrado." });
    }

    const validPassword = await bcrypt.compare(password, signer.password);
    if (!validPassword) {
      return res.status(401).json({ error: "Contraseña incorrecta." });
    }

    const acta = await prisma.acta.findUnique({ where: { id } });
    if (!acta) {
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
        commitments: { include: { responsible: true }, orderBy: { dueDate: "asc" } },
        attachments: true,
        signatures: { include: { signer: true } },
      },
    });

    if (!updatedActa) {
      return res.status(404).json({ error: "Acta no encontrada tras firmar." });
    }

    res.json(formatActa(updatedActa));
  } catch (error) {
    console.error("Error al firmar acta:", error);
    res.status(500).json({ error: "No se pudo firmar el acta." });
  }
});

// --- RUTAS DE BITÁCORA ---
app.get("/api/log-entries/:id", authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { id } = req.params;
    const entry = await prisma.logEntry.findUnique({
      where: { id },
      include: {
        author: true,
        attachments: true,
        comments: { include: { author: true, attachments: true }, orderBy: { timestamp: "asc" } },
        signatures: { include: { signer: true } },
        assignees: true,
        signatureTasks: { include: { signer: true }, orderBy: { assignedAt: "asc" } },
        history: { include: { user: true }, orderBy: { timestamp: "desc" } },
      },
    });

    if (!entry) {
      return res.status(404).json({ error: "Anotación no encontrada." });
    }

    const formattedEntry = formatLogEntry(entry);
    res.json(formattedEntry);
  } catch (error) {
    console.error("Error al obtener anotación:", error);
    res.status(500).json({ error: "No se pudo obtener la anotación." });
  }
});

app.get("/api/log-entries", authMiddleware, async (req: AuthRequest, res) => {
  // <-- Añade authMiddleware y AuthRequest
  // Ahora puedes acceder a req.user.userId si lo necesitas
  console.log("Usuario autenticado:", req.user?.userId);
  try {
    const entries = await prisma.logEntry.findMany({
      orderBy: { createdAt: "desc" },
      include: {
        author: true,
        attachments: true,
        comments: { include: { author: true, attachments: true }, orderBy: { timestamp: "asc" } },
        signatures: { include: { signer: true } },
        assignees: true,
        signatureTasks: { include: { signer: true }, orderBy: { assignedAt: "asc" } },
        history: { include: { user: true }, orderBy: { timestamp: "desc" } },
      },
    });
    // Formatear enums antes de enviar
    const formattedEntries = entries.map(formatLogEntry);
    res.json(formattedEntries);
  } catch (error) {
    console.error("Error al obtener las anotaciones:", error);
    res.status(500).json({ error: "No se pudieron obtener las anotaciones." });
  }
});

app.post("/api/log-entries", authMiddleware, requireEditor, (req: AuthRequest, res) => {
  const uploadMiddleware = upload.array('attachments', 5);
  
  uploadMiddleware(req, res, async (err) => {
    if (err instanceof multer.MulterError) {
      return res.status(400).json({ error: err.message });
    } else if (err) {
      return res.status(500).json({ error: err.message });
    }

    try {
      console.log('Received form data:', req.body);
      console.log('Received files:', req.files);
      
      // Procesar los datos del formulario
      let formData = {
        ...req.body,
        assignees: [],
        requiredSignatories: [],
        signatures: []
      };

      // Procesar assignees
      if (req.body.assignees) {
        try {
          formData.assignees = JSON.parse(req.body.assignees);
        } catch (e) {
          console.warn('Error processing assignees:', e);
          formData.assignees = [];
        }
      }

      // Procesar requiredSignatories
      if (req.body.requiredSignatories) {
        try {
          formData.requiredSignatories = JSON.parse(req.body.requiredSignatories);
        } catch (e) {
          console.warn('Error processing requiredSignatories:', e);
          formData.requiredSignatories = [];
        }
      }

      // Procesar signatures
      if (req.body.signatures) {
        try {
          formData.signatures = JSON.parse(req.body.signatures);
        } catch (e) {
          console.warn('Error processing signatures:', e);
          formData.signatures = [];
        }
      }

      const parseJsonField = (fieldName: string, fallback: any) => {
        const value = (req.body as any)[fieldName];
        if (value === undefined || value === null || value === "") {
          return fallback;
        }
        if (typeof value === "string") {
          try {
            return JSON.parse(value);
          } catch (e) {
            console.warn(`Error parsing ${fieldName}:`, e);
            return fallback;
          }
        }
        return value;
      };

      formData.weatherReport = parseJsonField("weatherReport", null);
      formData.contractorPersonnel = parseJsonField("contractorPersonnel", []);
      formData.interventoriaPersonnel = parseJsonField("interventoriaPersonnel", []);
      formData.equipmentResources = parseJsonField("equipmentResources", []);
      formData.executedActivities = parseJsonField("executedActivities", []);
      formData.executedQuantities = parseJsonField("executedQuantities", []);
      formData.scheduledActivities = parseJsonField("scheduledActivities", []);
      formData.qualityControls = parseJsonField("qualityControls", []);
      formData.materialsReceived = parseJsonField("materialsReceived", []);
      formData.safetyNotes = parseJsonField("safetyNotes", []);
      formData.projectIssues = parseJsonField("projectIssues", []);
      formData.siteVisits = parseJsonField("siteVisits", []);

      const parseBoolean = (value: unknown): boolean => {
        if (typeof value === "boolean") return value;
        if (typeof value === "string") {
          const normalized = value.trim().toLowerCase();
          return normalized === "true" || normalized === "1" || normalized === "yes" || normalized === "on";
        }
        if (typeof value === "number") {
          return value === 1;
        }
        return false;
      };

      const isConfidentialValue = parseBoolean((formData as any).isConfidential);
      (formData as any).isConfidential = isConfidentialValue;
    
    // Validar campos requeridos
    if (!formData.title?.trim()) {
      return res.status(400).json({ error: "El título es obligatorio." });
    }
    if (!formData.authorId) {
      return res.status(400).json({ error: "El autor es obligatorio." });
    }
    if (!formData.projectId) {
      return res.status(400).json({ error: "El proyecto es obligatorio." });
    }

    const assigneeIds = extractUserIds(formData.assignees);
    const requiredSignerIds = extractUserIds((formData as any).requiredSignatories);

    // Procesar archivos subidos
    const uploadedFiles = (req.files || []) as Express.Multer.File[];
    console.log('Processing files:', uploadedFiles);
    
    const attachments = [];
    for (const file of uploadedFiles) {
      try {
        if (!file.buffer) {
          logger.warn("Archivo sin buffer recibido", { originalName: file.originalname });
          continue;
        }
        const stored = await persistUploadedFile(file, "log-entries");
        const attachment = await prisma.attachment.create({
          data: {
            fileName: file.originalname,
            url: stored.url,
            storagePath: stored.key,
            size: file.size,
            type: file.mimetype,
          },
        });
        attachments.push(attachment);
      } catch (e) {
        console.error('Error creating attachment:', e);
      }
    }

    // Preparar fecha de la entrada diaria
    const rawEntryDate = (formData as any).entryDate || formData.activityStartDate;
    const parsedEntryDate = new Date(rawEntryDate);

    if (isNaN(parsedEntryDate.getTime())) {
      return res.status(400).json({ error: "La fecha de la entrada de bitácora no es válida." });
    }

    const entryDate = new Date(parsedEntryDate);
    entryDate.setHours(0, 0, 0, 0);

    const startDate = new Date(entryDate);
    const endDate = new Date(entryDate);
    endDate.setHours(23, 59, 59, 999);

    const activitiesPerformed = (formData as any).activitiesPerformed ?? "";
    const materialsUsed = (formData as any).materialsUsed ?? "";
    const workforce = (formData as any).workforce ?? "";
    const weatherConditions = (formData as any).weatherConditions ?? "";
    const additionalObservations = (formData as any).additionalObservations ?? "";

    // Validar attachments
    if (!Array.isArray(attachments)) {
      return res.status(400).json({ error: "El formato de los adjuntos no es válido." });
    }

    // Mapear tipos enumerados
    const prismaType = entryTypeMap[formData.type] || "GENERAL";
    const prismaStatus = entryStatusMap[formData.status] || "DRAFT";

    const normalizedWeatherReport = normalizeWeatherReport(
      (formData as any).weatherReport
    );
    const normalizedContractorPersonnel = normalizePersonnelEntries(
      (formData as any).contractorPersonnel
    );
    const normalizedInterventoriaPersonnel = normalizePersonnelEntries(
      (formData as any).interventoriaPersonnel
    );
    const normalizedEquipmentResources = normalizeEquipmentEntries(
      (formData as any).equipmentResources
    );
    const normalizedExecutedActivities = normalizeListItems(
      (formData as any).executedActivities
    );
    const normalizedExecutedQuantities = normalizeListItems(
      (formData as any).executedQuantities
    );
    const normalizedScheduledActivities = normalizeListItems(
      (formData as any).scheduledActivities
    );
    const normalizedQualityControls = normalizeListItems(
      (formData as any).qualityControls
    );
    const normalizedMaterialsReceived = normalizeListItems(
      (formData as any).materialsReceived
    );
    const normalizedSafetyNotes = normalizeListItems(
      (formData as any).safetyNotes
    );
    const normalizedProjectIssues = normalizeListItems(
      (formData as any).projectIssues
    );
    const normalizedSiteVisits = normalizeListItems(
      (formData as any).siteVisits
    );

    // Crear la entrada
    const newEntry = await prisma.logEntry.create({
      data: {
        title: formData.title.trim(),
        description: formData.description?.trim() || "",
        type: prismaType,
        subject: formData.subject?.trim() || "",
        location: formData.location?.trim() || "",
        activityStartDate: startDate,
        activityEndDate: endDate,
        entryDate,
        activitiesPerformed: String(activitiesPerformed),
        materialsUsed: String(materialsUsed),
        workforce: String(workforce),
        weatherConditions: String(weatherConditions),
        additionalObservations: String(additionalObservations),
        isConfidential: isConfidentialValue,
        status: prismaStatus,
        scheduleDay:
          typeof (formData as any).scheduleDay === "string" && (formData as any).scheduleDay.trim() !== ""
            ? parseInt((formData as any).scheduleDay.trim(), 10) || 0
            : 0,
        locationDetails:
          typeof (formData as any).locationDetails === "string"
            ? (formData as any).locationDetails.trim()
            : "",
        weatherReport: normalizedWeatherReport ? JSON.stringify(normalizedWeatherReport) : null,
        contractorPersonnel: JSON.stringify(normalizedContractorPersonnel),
        interventoriaPersonnel: JSON.stringify(normalizedInterventoriaPersonnel),
        equipmentResources: JSON.stringify(normalizedEquipmentResources),
        executedActivities: JSON.stringify(normalizedExecutedActivities),
        executedQuantities: JSON.stringify(normalizedExecutedQuantities),
        scheduledActivities: JSON.stringify(normalizedScheduledActivities),
        qualityControls: JSON.stringify(normalizedQualityControls),
        materialsReceived: JSON.stringify(normalizedMaterialsReceived),
        safetyNotes: JSON.stringify(normalizedSafetyNotes),
        projectIssues: JSON.stringify(normalizedProjectIssues),
        siteVisits: JSON.stringify(normalizedSiteVisits),
        contractorObservations:
          typeof (formData as any).contractorObservations === "string"
            ? (formData as any).contractorObservations.trim()
            : "",
        interventoriaObservations:
          typeof (formData as any).interventoriaObservations === "string"
            ? (formData as any).interventoriaObservations.trim()
            : "",
        author: { connect: { id: formData.authorId } },
        project: { connect: { id: formData.projectId } },
        assignees: {
          connect: assigneeIds.map((id: string) => ({ id })),
        },
        attachments: {
          connect: attachments.map((att) => ({ id: att.id })),
        },
      },
      include: {
        author: true,
        attachments: true,
        comments: true,
        signatures: true,
        assignees: true,
        history: { include: { user: true }, orderBy: { timestamp: "desc" } },
      },
    });

    const uniqueSignerIds = Array.from(
      new Set([
        ...requiredSignerIds,
        ...(formData.authorId ? [formData.authorId] : []),
      ])
    );

    if (uniqueSignerIds.length) {
      for (const signerId of uniqueSignerIds) {
        await prisma.logEntrySignatureTask.create({
          data: {
            logEntryId: newEntry.id,
            signerId,
            // No auto-firmar al autor: todos inician en PENDING
            status: 'PENDING',
            signedAt: undefined,
          },
        });
      }

      const pendingCount = await prisma.logEntrySignatureTask.count({
        where: {
          logEntryId: newEntry.id,
          status: { not: 'SIGNED' },
        },
      });

      if (pendingCount === 0 && newEntry.status !== 'SIGNED') {
        await prisma.logEntry.update({
          where: { id: newEntry.id },
          data: { status: 'SIGNED' },
        });
        newEntry.status = 'SIGNED';
      }
    }

    // Eliminado: no se registra firma automática del autor al crear

    const creationChanges: { fieldName: string; oldValue?: string | null; newValue?: string | null }[] = [];

    attachments.forEach((attachment: any) => {
      creationChanges.push({
        fieldName: 'Adjunto Añadido',
        newValue: attachment.fileName,
      });
    });

    if (assigneeIds.length) {
      const assigneeUsers = await prisma.user.findMany({
        where: { id: { in: assigneeIds } },
      });
      assigneeUsers.forEach((assignee) => {
        creationChanges.push({
          fieldName: 'Asignado Añadido',
          newValue: assignee.fullName,
        });
      });
    }

    if (uniqueSignerIds.length) {
      const signerUsers = await prisma.user.findMany({
        where: { id: { in: uniqueSignerIds } },
      });
      signerUsers.forEach((signer) => {
        creationChanges.push({
          fieldName: 'Firmante Añadido',
          newValue: signer.fullName,
        });
      });
    }

    await recordLogEntryChanges(newEntry.id, req.user?.userId || formData.authorId, creationChanges);

    const entryWithHistory = await prisma.logEntry.findUnique({
      where: { id: newEntry.id },
      include: {
        author: true,
        attachments: true,
        comments: { include: { author: true }, orderBy: { timestamp: "asc" } },
        signatures: { include: { signer: true } },
        assignees: true,
        signatureTasks: { include: { signer: true }, orderBy: { assignedAt: "asc" } },
        history: { include: { user: true }, orderBy: { timestamp: "desc" } },
      },
    });

    res.status(201).json(formatLogEntry(entryWithHistory));
  } catch (error: any) {
    console.error("Error al crear la anotación:", error);

    // Manejar errores específicos
    if (error.code === 'P2002') {
      const target = (error.meta as any)?.target;
      if (
        (Array.isArray(target) && target.includes('LogEntry_projectId_entryDate_key')) ||
        target === 'LogEntry_projectId_entryDate_key'
      ) {
        return res.status(409).json({
          error: "Ya existe una entrada de bitácora registrada para este día en el proyecto."
        });
      }
      return res.status(409).json({
        error: "Ya existe una anotación con este identificador."
      });
    }
    if (error.code === 'P2025') {
      return res.status(404).json({ 
        error: "No se encontró alguno de los recursos referenciados (autor, proyecto, asignados o adjuntos)." 
      });
    }
    if (error instanceof SyntaxError) {
      return res.status(400).json({ 
        error: "Error de sintaxis en los datos enviados.",
        details: error.message
      });
    }
    if (error.message === 'Invalid JSON') {
      return res.status(400).json({
        error: "Formato de datos inválido",
        details: "Los datos enviados no tienen un formato válido. Asegúrate de enviar los datos correctamente."
      });
    }
    if (error.name === 'MulterError') {
      return res.status(400).json({
        error: "Error al subir archivos",
        details: error.message
      });
    }

    // Error general
    res.status(500).json({ 
      error: "Error al crear la anotación.",
      details: process.env.NODE_ENV === 'development' ? error.message : undefined,
      code: error.code || 'UNKNOWN_ERROR'
    });
  }
});

});

app.put("/api/log-entries/:id", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
  try {
    const { id } = req.params;
    const existingEntry = await prisma.logEntry.findUnique({
      where: { id },
      include: {
        attachments: true,
        assignees: true,
        signatureTasks: true,
      },
    });

    if (!existingEntry) {
      return res.status(404).json({ error: "Anotación no encontrada." });
    }

    const {
      title,
      description,
      type,
      subject,
      location,
      activityStartDate,
      activityEndDate,
      entryDate,
      activitiesPerformed,
      materialsUsed,
      workforce,
      weatherConditions,
      additionalObservations,
      isConfidential,
      status,
      assignees = [],
      attachments = [],
      requiredSignatories: requiredSignatoriesPayload,
      scheduleDay,
      locationDetails,
      weatherReport,
      contractorPersonnel,
      interventoriaPersonnel,
      equipmentResources,
      executedActivities,
      executedQuantities,
      scheduledActivities,
      qualityControls,
      materialsReceived,
      safetyNotes,
      projectIssues,
      siteVisits,
      contractorObservations,
      interventoriaObservations,
    } = req.body;

    const prismaType = entryTypeMap[type] || existingEntry.type;
    const prismaStatus = entryStatusMap[status] || existingEntry.status;

    const dataToUpdate: any = {
      assignees: {
        set: assignees.map((user: { id: string }) => ({ id: user.id })),
      },
      attachments: Array.isArray(attachments)
        ? {
            set: attachments
              .filter((att: any) => att?.id)
              .map((att: any) => ({ id: att.id })),
          }
        : undefined,
    };

    const signerAddedIds: string[] = [];
    const signerRemovedIds: string[] = [];
    let updatedSignatureTasks = existingEntry.signatureTasks || [];

    if (requiredSignatoriesPayload !== undefined) {
      const newSignerIds = extractUserIds(requiredSignatoriesPayload);
      const existingSignerIds = updatedSignatureTasks.map((task: any) => task.signerId);

      const toAdd = newSignerIds.filter((id: string) => !existingSignerIds.includes(id));
      const toRemove = existingSignerIds.filter((id: string) => !newSignerIds.includes(id));

      if (toRemove.length) {
        await prisma.logEntrySignatureTask.deleteMany({
          where: {
            logEntryId: id,
            signerId: { in: toRemove },
          },
        });
        signerRemovedIds.push(...toRemove);
      }

      for (const signerId of toAdd) {
        await prisma.logEntrySignatureTask.create({
          data: {
            logEntryId: id,
            signerId,
            // No auto-firmar al autor: siempre iniciar como PENDING
            status: 'PENDING',
            signedAt: undefined,
          },
        });
        signerAddedIds.push(signerId);
      }

      updatedSignatureTasks = await prisma.logEntrySignatureTask.findMany({
        where: { logEntryId: id },
        include: { signer: true },
        orderBy: { assignedAt: 'asc' },
      });

      const pendingCount = updatedSignatureTasks.filter((task: any) => task.status !== 'SIGNED').length;

      if (pendingCount === 0 && updatedSignatureTasks.length > 0) {
        if (dataToUpdate.status === undefined) {
          dataToUpdate.status = 'SIGNED';
        }
      } else if (
        pendingCount > 0 &&
        updatedSignatureTasks.length > 0 &&
        existingEntry.status === 'SIGNED' &&
        dataToUpdate.status === undefined
      ) {
        dataToUpdate.status = 'SUBMITTED';
      }
    } else {
      updatedSignatureTasks = await prisma.logEntrySignatureTask.findMany({
        where: { logEntryId: id },
        include: { signer: true },
        orderBy: { assignedAt: 'asc' },
      });
    }

    if (title !== undefined) dataToUpdate.title = title?.trim();
    if (description !== undefined) dataToUpdate.description = description?.trim() || "";
    if (type !== undefined) dataToUpdate.type = prismaType;
    if (subject !== undefined) dataToUpdate.subject = subject?.trim() || "";
    if (location !== undefined) dataToUpdate.location = location?.trim() || "";
    if (isConfidential !== undefined) dataToUpdate.isConfidential = isConfidential;
    if (status !== undefined) dataToUpdate.status = prismaStatus;
    if (activitiesPerformed !== undefined) dataToUpdate.activitiesPerformed = String(activitiesPerformed ?? "");
    if (materialsUsed !== undefined) dataToUpdate.materialsUsed = String(materialsUsed ?? "");
    if (workforce !== undefined) dataToUpdate.workforce = String(workforce ?? "");
    if (weatherConditions !== undefined) dataToUpdate.weatherConditions = String(weatherConditions ?? "");
    if (additionalObservations !== undefined) dataToUpdate.additionalObservations = String(additionalObservations ?? "");
    if (scheduleDay !== undefined) {
      dataToUpdate.scheduleDay = typeof scheduleDay === "string" ? scheduleDay.trim() : "";
    }
    if (locationDetails !== undefined) {
      dataToUpdate.locationDetails = typeof locationDetails === "string" ? locationDetails.trim() : "";
    }
    if (weatherReport !== undefined) {
      const normalized = normalizeWeatherReport(weatherReport);
      dataToUpdate.weatherReport = normalized ?? Prisma.DbNull;
    }
    if (contractorPersonnel !== undefined) {
      dataToUpdate.contractorPersonnel = normalizePersonnelEntries(contractorPersonnel);
    }
    if (interventoriaPersonnel !== undefined) {
      dataToUpdate.interventoriaPersonnel = normalizePersonnelEntries(interventoriaPersonnel);
    }
    if (equipmentResources !== undefined) {
      dataToUpdate.equipmentResources = normalizeEquipmentEntries(equipmentResources);
    }
    if (executedActivities !== undefined) {
      dataToUpdate.executedActivities = normalizeListItems(executedActivities);
    }
    if (executedQuantities !== undefined) {
      dataToUpdate.executedQuantities = normalizeListItems(executedQuantities);
    }
    if (scheduledActivities !== undefined) {
      dataToUpdate.scheduledActivities = normalizeListItems(scheduledActivities);
    }
    if (qualityControls !== undefined) {
      dataToUpdate.qualityControls = normalizeListItems(qualityControls);
    }
    if (materialsReceived !== undefined) {
      dataToUpdate.materialsReceived = normalizeListItems(materialsReceived);
    }
    if (safetyNotes !== undefined) {
      dataToUpdate.safetyNotes = normalizeListItems(safetyNotes);
    }
    if (projectIssues !== undefined) {
      dataToUpdate.projectIssues = normalizeListItems(projectIssues);
    }
    if (siteVisits !== undefined) {
      dataToUpdate.siteVisits = normalizeListItems(siteVisits);
    }
    if (contractorObservations !== undefined) {
      dataToUpdate.contractorObservations = typeof contractorObservations === "string" ? contractorObservations.trim() : "";
    }
    if (interventoriaObservations !== undefined) {
      dataToUpdate.interventoriaObservations = typeof interventoriaObservations === "string" ? interventoriaObservations.trim() : "";
    }

    if (entryDate !== undefined || activityStartDate !== undefined || activityEndDate !== undefined) {
      const baseDate = entryDate || activityStartDate || existingEntry.entryDate;
      const parsed = new Date(baseDate);
      if (isNaN(parsed.getTime())) {
        return res.status(400).json({ error: "La fecha de la entrada no es válida." });
      }
      const normalized = new Date(parsed);
      normalized.setHours(0, 0, 0, 0);
      const end = new Date(normalized);
      end.setHours(23, 59, 59, 999);

      dataToUpdate.entryDate = normalized;
      dataToUpdate.activityStartDate = normalized;
      dataToUpdate.activityEndDate = end;
    }

    const updatedEntry = await prisma.logEntry.update({
      where: { id },
      data: dataToUpdate,
      include: {
        author: true,
        attachments: true,
        comments: { include: { author: true }, orderBy: { timestamp: "asc" } },
        signatures: { include: { signer: true } },
        assignees: true,
        signatureTasks: { include: { signer: true }, orderBy: { assignedAt: "asc" } },
        history: { include: { user: true }, orderBy: { timestamp: "desc" } },
      },
    });

    const changes: { fieldName: string; oldValue?: string | null; newValue?: string | null }[] = [];

    const formatDate = (value: Date) => value instanceof Date ? value.toISOString() : value;

    if (title !== undefined && title !== existingEntry.title) {
      changes.push({ fieldName: 'Título', oldValue: existingEntry.title, newValue: updatedEntry.title });
    }
    if (description !== undefined && description !== existingEntry.description) {
      changes.push({ fieldName: 'Descripción', oldValue: existingEntry.description, newValue: updatedEntry.description });
    }
    if (type !== undefined && prismaType !== existingEntry.type) {
      changes.push({ fieldName: 'Tipo', oldValue: entryTypeReverseMap[existingEntry.type], newValue: entryTypeReverseMap[updatedEntry.type] });
    }
    if (subject !== undefined && subject !== existingEntry.subject) {
      changes.push({ fieldName: 'Asunto', oldValue: existingEntry.subject, newValue: updatedEntry.subject });
    }
    if (location !== undefined && location !== existingEntry.location) {
      changes.push({ fieldName: 'Ubicación', oldValue: existingEntry.location, newValue: updatedEntry.location });
    }
    if (dataToUpdate.entryDate) {
      const oldValue = formatDate(existingEntry.entryDate);
      const newValue = formatDate(updatedEntry.entryDate);
      if (oldValue !== newValue) {
        changes.push({ fieldName: 'Fecha de Bitácora', oldValue, newValue });
      }
      const oldStart = formatDate(existingEntry.activityStartDate);
      const newStart = formatDate(updatedEntry.activityStartDate);
      if (oldStart !== newStart) {
        changes.push({ fieldName: 'Fecha Inicio Actividad', oldValue: oldStart, newValue: newStart });
      }
      const oldEnd = formatDate(existingEntry.activityEndDate);
      const newEnd = formatDate(updatedEntry.activityEndDate);
      if (oldEnd !== newEnd) {
        changes.push({ fieldName: 'Fecha Fin Actividad', oldValue: oldEnd, newValue: newEnd });
      }
    }
    if (isConfidential !== undefined && isConfidential !== existingEntry.isConfidential) {
      changes.push({
        fieldName: 'Confidencial',
        oldValue: existingEntry.isConfidential ? 'Sí' : 'No',
        newValue: updatedEntry.isConfidential ? 'Sí' : 'No',
      });
    }
    if (status !== undefined && prismaStatus !== existingEntry.status) {
      changes.push({
        fieldName: 'Estado',
        oldValue: entryStatusReverseMap[existingEntry.status],
        newValue: entryStatusReverseMap[updatedEntry.status],
      });
    }

    if (activitiesPerformed !== undefined && activitiesPerformed !== existingEntry.activitiesPerformed) {
      changes.push({
        fieldName: 'Actividades realizadas',
        oldValue: existingEntry.activitiesPerformed,
        newValue: updatedEntry.activitiesPerformed,
      });
    }
    if (materialsUsed !== undefined && materialsUsed !== existingEntry.materialsUsed) {
      changes.push({
        fieldName: 'Materiales utilizados',
        oldValue: existingEntry.materialsUsed,
        newValue: updatedEntry.materialsUsed,
      });
    }
    if (workforce !== undefined && workforce !== existingEntry.workforce) {
      changes.push({
        fieldName: 'Personal en obra',
        oldValue: existingEntry.workforce,
        newValue: updatedEntry.workforce,
      });
    }
    if (weatherConditions !== undefined && weatherConditions !== existingEntry.weatherConditions) {
      changes.push({
        fieldName: 'Condiciones climáticas',
        oldValue: existingEntry.weatherConditions,
        newValue: updatedEntry.weatherConditions,
      });
    }
    if (additionalObservations !== undefined && additionalObservations !== existingEntry.additionalObservations) {
      changes.push({
        fieldName: 'Observaciones adicionales',
        oldValue: existingEntry.additionalObservations,
        newValue: updatedEntry.additionalObservations,
      });
    }

    if (signerAddedIds.length) {
      const addedUsers = await prisma.user.findMany({
        where: { id: { in: signerAddedIds } },
      });
      addedUsers.forEach((user) => {
        changes.push({
          fieldName: 'Firmante Añadido',
          newValue: user.fullName,
        });
      });
    }

    if (signerRemovedIds.length) {
      const removedUsers = await prisma.user.findMany({
        where: { id: { in: signerRemovedIds } },
      });
      removedUsers.forEach((user) => {
        changes.push({
          fieldName: 'Firmante Eliminado',
          oldValue: user.fullName,
        });
      });
    }

    const previousAttachmentIds = new Map((existingEntry.attachments || []).map((att) => [att.id, att]));
    const newAttachmentIds = new Map((updatedEntry.attachments || []).map((att) => [att.id, att]));

    for (const [id, att] of newAttachmentIds.entries()) {
      if (!previousAttachmentIds.has(id)) {
        changes.push({ fieldName: 'Adjunto Añadido', newValue: att.fileName });
      }
    }
    for (const [id, att] of previousAttachmentIds.entries()) {
      if (!newAttachmentIds.has(id)) {
        changes.push({ fieldName: 'Adjunto Eliminado', oldValue: att.fileName });
      }
    }

    const previousAssignees = new Map((existingEntry.assignees || []).map((user) => [user.id, user]));
    const newAssignees = new Map((updatedEntry.assignees || []).map((user) => [user.id, user]));

    for (const [id, user] of newAssignees.entries()) {
      if (!previousAssignees.has(id)) {
        changes.push({ fieldName: 'Asignado Añadido', newValue: user.fullName });
      }
    }
    for (const [id, user] of previousAssignees.entries()) {
      if (!newAssignees.has(id)) {
        changes.push({ fieldName: 'Asignado Eliminado', oldValue: user.fullName });
      }
    }

    await recordLogEntryChanges(id, req.user?.userId, changes);

    const refreshedEntry = await prisma.logEntry.findUnique({
      where: { id },
      include: {
        author: true,
        attachments: true,
        comments: { include: { author: true }, orderBy: { timestamp: "asc" } },
        signatures: { include: { signer: true } },
        assignees: true,
        signatureTasks: { include: { signer: true }, orderBy: { assignedAt: "asc" } },
        history: { include: { user: true }, orderBy: { timestamp: "desc" } },
      },
    });

    res.json(formatLogEntry(refreshedEntry));
  } catch (error: any) {
    console.error("Error al actualizar la anotación:", error);
    if (error.code === 'P2002') {
      const target = (error.meta as any)?.target;
      if (
        (Array.isArray(target) && target.includes('LogEntry_projectId_entryDate_key')) ||
        target === 'LogEntry_projectId_entryDate_key'
      ) {
        return res.status(409).json({
          error: "Ya existe una entrada de bitácora registrada para este día en el proyecto.",
        });
      }
    }
    res.status(500).json({ error: "No se pudo actualizar la anotación." });
  }
});

app.delete("/api/log-entries/:id", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
  try {
    console.log("DELETE /api/log-entries/:id - Eliminando anotación...");
    const { id } = req.params;
    console.log("ID de la anotación:", id);

    // Verificar que la anotación existe
    const existingEntry = await prisma.logEntry.findUnique({
      where: { id },
      include: {
        comments: true,
        signatures: true,
        attachments: true,
      }
    });

    if (!existingEntry) {
      console.log("No se encontró la anotación");
      return res.status(404).json({ error: "Anotación no encontrada." });
    }

    // Verificar permisos
    if (existingEntry.authorId !== req.user?.userId && req.user?.appRole !== 'admin') {
      console.log("Usuario no autorizado para eliminar esta anotación");
      return res.status(403).json({ error: "No tiene permisos para eliminar esta anotación." });
    }

    // Eliminar primero los registros relacionados
    if (existingEntry.comments.length > 0) {
      await prisma.comment.deleteMany({
        where: { logEntryId: id }
      });
    }

    if (existingEntry.signatures.length > 0) {
      await prisma.signature.deleteMany({
        where: { logEntryId: id }
      });
    }

    if (existingEntry.attachments.length > 0) {
      await prisma.attachment.deleteMany({
        where: { logEntryId: id }
      });
    }

    // Eliminar la anotación
    await prisma.logEntry.delete({
      where: { id }
    });

    console.log(`DELETE /api/log-entries/:id - Anotación eliminada con ID: ${id}`);
    res.json({ message: "Anotación eliminada exitosamente" });
  } catch (error) {
    console.error("Error al eliminar anotación:", error);
    res.status(500).json({ error: "No se pudo eliminar la anotación." });
  }
});

app.post("/api/log-entries/:id/comments", authMiddleware, requireEditor, (req: AuthRequest, res) => {
  const uploadMiddleware = upload.array('attachments', 5);
  
  uploadMiddleware(req, res, async (err) => {
    if (err instanceof multer.MulterError) {
      return res.status(400).json({ error: err.message });
    } else if (err) {
      return res.status(500).json({ error: err.message });
    }

    try {
      const { id } = req.params;
      const { content, authorId } = req.body;

      if (!content || !authorId) {
        return res.status(400).json({ error: "Contenido y autor son obligatorios." });
      }

      const logEntry = await prisma.logEntry.findUnique({ where: { id } });
      if (!logEntry) {
        return res.status(404).json({ error: "Anotación no encontrada." });
      }

      const author = await prisma.user.findUnique({ where: { id: authorId } });
      if (!author) {
        return res.status(404).json({ error: "Autor no encontrado." });
      }

      // Procesar archivos subidos
      const uploadedFiles = (req.files || []) as Express.Multer.File[];
      const attachments = [];
      for (const file of uploadedFiles) {
        try {
          if (!file.buffer) {
            logger.warn("Archivo sin buffer recibido", { originalName: file.originalname });
            continue;
          }
          const stored = await persistUploadedFile(file, "comments");
          const attachment = await prisma.attachment.create({
            data: {
              fileName: file.originalname,
              url: stored.url,
              storagePath: stored.key,
              size: file.size,
              type: file.mimetype,
            },
          });
          attachments.push({ id: attachment.id });
        } catch (e) {
          console.error('Error creating attachment:', e);
        }
      }

      const newComment = await prisma.comment.create({
        data: {
          content,
          author: { connect: { id: authorId } },
          logEntry: { connect: { id } },
          attachments: attachments.length > 0 ? { connect: attachments } : undefined,
        },
        include: { 
          author: true,
          attachments: true,
        },
      });

      res.status(201).json(newComment);
    } catch (error) {
      console.error("Error al crear comentario de bitácora:", error);
      res.status(500).json({ error: "No se pudo crear el comentario." });
    }
  });
});

app.post("/api/log-entries/:id/signatures", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
  try {
    const { id } = req.params;
    const { signerId, password } = req.body;

    if (!signerId || !password) {
      return res.status(400).json({ error: "Se requieren el firmante y la contraseña." });
    }

    const signer = await prisma.user.findUnique({ where: { id: signerId } });
    if (!signer) {
      return res.status(404).json({ error: "Firmante no encontrado." });
    }

    const passwordMatches = await bcrypt.compare(password, signer.password);
    if (!passwordMatches) {
      return res.status(401).json({ error: "Contraseña incorrecta.", code: "INVALID_SIGNATURE_PASSWORD" });
    }

    const entryExists = await prisma.logEntry.findUnique({ where: { id } });
    if (!entryExists) {
      return res.status(404).json({ error: "Anotación no encontrada." });
    }

    const entryWithTasks = await prisma.logEntry.findUnique({
      where: { id },
      include: { signatureTasks: true },
    });
    if (!entryWithTasks) {
      return res.status(404).json({ error: "Anotación no encontrada." });
    }
    const myTask = entryWithTasks.signatureTasks.find((t) => t.signerId === signerId);
    if (!myTask) {
      return res.status(403).json({ error: "No tienes tarea de firma asignada en esta anotación." });
    }
    if (myTask.status === 'SIGNED') {
      return res.status(409).json({ error: "Ya has firmado esta anotación.", code: "ALREADY_SIGNED" });
    }

    const existingSignature = await prisma.signature.findFirst({
      where: { logEntryId: id, signerId },
    });

    if (existingSignature) {
      // Idempotente: no crear/actualizar otra firma ni repetir
      return res.status(409).json({ error: "Ya has firmado esta anotación.", code: "ALREADY_SIGNED" });
    }

    // Crear la firma en la base de datos
    await prisma.signature.create({
      data: {
        signer: { connect: { id: signerId } },
        logEntry: { connect: { id } },
        signedAt: new Date(),
      },
    });

    // Si el usuario tiene firma manuscrita registrada, aplicarla al PDF base
    const userSignature = await prisma.userSignature.findUnique({
      where: { userId: signerId },
    });

    if (userSignature) {
      try {
        // Buscar el PDF más reciente firmado para acumular firmas
        // Primero buscar PDFs firmados (que contengan "firmado" en el nombre)
        let basePdf = await prisma.attachment.findFirst({
          where: { 
            logEntryId: id,
            type: "application/pdf",
            fileName: { contains: "firmado" }
          },
          orderBy: { createdAt: "desc" },
        });

        // Si no hay PDFs firmados, buscar el original
        if (!basePdf) {
          basePdf = await prisma.attachment.findFirst({
            where: { 
              logEntryId: id,
              type: "application/pdf",
              fileName: { not: { contains: "firmado" } }
            },
            orderBy: { createdAt: "asc" },
          });
        }

        // Si aún no hay PDF, buscar cualquier PDF
        if (!basePdf) {
          basePdf = await prisma.attachment.findFirst({
            where: { 
              logEntryId: id,
              type: "application/pdf"
            },
            orderBy: { createdAt: "desc" },
          });
        }

        // Si no hay PDF, generar uno automáticamente antes de firmar
        if (!basePdf) {
          console.log("No hay PDF existente, generando uno automáticamente...");
          try {
            const baseUrl = process.env.SERVER_PUBLIC_URL || `http://localhost:4001`;
            const result = await generateLogEntryPdf({
              prisma,
              logEntryId: id,
              uploadsDir: process.env.UPLOADS_DIR || "./uploads",
              baseUrl,
            });
            
            // Buscar el PDF recién generado
            basePdf = await prisma.attachment.findFirst({
              where: { 
                logEntryId: id,
                type: "application/pdf"
              },
              orderBy: { createdAt: "desc" },
            });
            
            if (basePdf) {
              console.log(`PDF generado automáticamente: ${basePdf.fileName}`);
            }
          } catch (pdfError) {
            console.warn("No se pudo generar PDF automáticamente:", pdfError);
          }
        }

        if (basePdf) {
          console.log(`Aplicando firma manuscrita al PDF: ${basePdf.fileName} (ID: ${basePdf.id})`);
          // Aplicar firma manuscrita al PDF base
          const [originalBuffer, signatureBuffer] = await Promise.all([
            loadAttachmentBuffer(basePdf),
            loadUserSignatureBuffer(userSignature),
          ]);

          // Calcular posición automática
          const logEntry = await prisma.logEntry.findUnique({
            where: { id },
            include: { signatureTasks: { include: { signer: true }, orderBy: { assignedAt: 'asc' } } },
          });

          if (logEntry) {
            const orderedTasks = (logEntry.signatureTasks || [])
              .filter((t: any) => t?.signer?.id)
              .sort((a: any, b: any) => new Date(a.assignedAt || 0).getTime() - new Date(b.assignedAt || 0).getTime());
            let signerIndex = orderedTasks.findIndex((t: any) => t.signer?.id === signerId);
            if (signerIndex < 0) signerIndex = 0;

            const MARGIN = 48;
            const BOX_H = 110;
            const GAP = 16;
            const LINE_Y = 72;
            const LINE_X = 70;
            const yPos = MARGIN + signerIndex * (BOX_H + GAP) + LINE_Y;
            const xPos = MARGIN + LINE_X;

            const signedBuffer = await applySignatureToPdf({
              originalPdf: originalBuffer,
              signature: {
                buffer: signatureBuffer,
                mimeType: userSignature.mimeType || 'image/png',
              },
              position: {
                x: xPos,
                y: yPos,
                width: 220,
                height: 28,
                baseline: true,
                baselineRatio: 0.25,
                fromTop: true,
              },
            });

            // Crear nuevo PDF firmado para acumular firmas
            const storage = getStorage();
            const parsedFileName = path.parse(basePdf.fileName || "documento.pdf");
            const signedFileName = `${parsedFileName.name}-firmado-${Date.now()}.pdf`;
            const signedKey = createStorageKey(
              `signed-documents/${signerId}`,
              signedFileName
            );
            await storage.save({ path: signedKey, content: signedBuffer });
            const signedUrl = storage.getPublicUrl(signedKey);

            // Crear nuevo adjunto firmado
            const signedAttachment = await prisma.attachment.create({
              data: {
                fileName: signedFileName,
                url: signedUrl,
                storagePath: signedKey,
                size: signedBuffer.length,
                type: "application/pdf",
                logEntryId: id,
              },
            });

            // Registrar el log de firma
            await prisma.documentSignatureLog.create({
              data: {
                signerId: signerId,
                documentType: "logEntry",
                documentId: id,
                originalPdfId: basePdf.id,
                signedAttachmentId: signedAttachment.id,
              },
            });
          }
        } else {
          console.log("No se encontró PDF para aplicar firma manuscrita");
        }
      } catch (signatureError) {
        console.warn("No se pudo aplicar la firma manuscrita automáticamente:", signatureError);
      }
    }

    await prisma.logEntrySignatureTask.updateMany({
      where: {
        logEntryId: id,
        signerId,
      },
      data: {
        status: 'SIGNED',
        signedAt: new Date(),
      },
    });

    const updatedTasks = await prisma.logEntrySignatureTask.findMany({
      where: { logEntryId: id },
      select: { status: true, signerId: true },
    });

    if (updatedTasks.length > 0 && updatedTasks.every((task) => task.status === 'SIGNED')) {
      const uniqueSignerIds = Array.from(new Set(updatedTasks.map((t) => t.signerId)));
      const signaturesCount = await prisma.signature.count({
        where: { logEntryId: id, signerId: { in: uniqueSignerIds } },
      });
      if (signaturesCount === uniqueSignerIds.length) {
        await prisma.logEntry.update({
          where: { id },
          data: { status: 'SIGNED' },
        });
      }
    }

    const updatedEntry = await prisma.logEntry.findUnique({
      where: { id },
      include: {
        author: true,
        attachments: true,
        comments: { include: { author: true }, orderBy: { timestamp: "asc" } },
        signatures: { include: { signer: true } },
        assignees: true,
        signatureTasks: { include: { signer: true }, orderBy: { assignedAt: "asc" } },
      },
    });

    if (!updatedEntry) {
      return res.status(404).json({ error: "Anotación no encontrada tras firmar." });
    }

    res.json(formatLogEntry(updatedEntry));
  } catch (error) {
    console.error("Error al firmar anotación:", error);
    res.status(500).json({ error: "No se pudo firmar la anotación." });
  }
});

app.post(
  "/api/log-entries/:id/export-pdf",
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const baseUrl =
        process.env.SERVER_PUBLIC_URL || `http://localhost:${port}`;

      const result = await generateLogEntryPdf({
        prisma,
        logEntryId: id,
        uploadsDir,
        baseUrl,
      });

      const refreshedEntry = await prisma.logEntry.findUnique({
        where: { id },
        include: {
          author: true,
          attachments: true,
          comments: { include: { author: true }, orderBy: { timestamp: "asc" } },
          signatures: { include: { signer: true } },
          assignees: true,
          history: { include: { user: true }, orderBy: { timestamp: "desc" } },
        },
      });

      if (!refreshedEntry) {
        return res
          .status(404)
          .json({ error: "Anotación no encontrada tras generar el PDF." });
      }

      res.json({
        entry: formatLogEntry(refreshedEntry),
        attachment: buildAttachmentResponse(result.attachment),
      });
    } catch (error) {
      console.error("Error al generar PDF de la anotación:", error);
      if (error instanceof Error && error.message === "Anotación no encontrada.") {
        return res.status(404).json({ error: error.message });
      }
      res.status(500).json({ error: "No se pudo generar el PDF de la anotación." });
    }
  }
);

// --- RUTAS PARA AVANCE DE OBRA ---
app.get("/api/contract-items", async (req, res) => {
  try {
    const items = await prisma.contractItem.findMany({
      orderBy: { itemCode: "asc" },
    });
    res.json(items);
  } catch (error) {
    console.error("Error al obtener los ítems del contrato:", error);
    res
      .status(500)
      .json({ error: "No se pudieron obtener los ítems del contrato." });
  }
});

app.get("/api/work-actas", authMiddleware, async (req: AuthRequest, res) => {
  try {
    const actas = await prisma.workActa.findMany({
      orderBy: { date: "desc" },
      include: {
        items: { include: { contractItem: true } },
        attachments: true,
      },
    });
    const formattedActas = actas.map((acta) => formatWorkActa(acta));
    res.json(formattedActas);
  } catch (error) {
    console.error("Error al obtener las actas de avance:", error);
    res
      .status(500)
      .json({ error: "No se pudieron obtener las actas de avance." });
  }
});

app.get("/api/work-actas/:id", authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { id } = req.params;
    const acta = await prisma.workActa.findUnique({
      where: { id },
      include: {
        items: { include: { contractItem: true } },
        attachments: true,
      },
    });

    if (!acta) {
      return res.status(404).json({ error: "Acta de avance no encontrada." });
    }

    const formattedActa = formatWorkActa(acta);
    res.json(formattedActa);
  } catch (error) {
    console.error("Error al obtener el detalle del acta de avance:", error);
    res.status(500).json({ error: "No se pudo obtener el acta solicitada." });
  }
});

app.post("/api/work-actas", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
  try {
    const { number, period, date, status, items, attachments = [] } = req.body;
    if (!number || !period || !date || !items || items.length === 0) {
      return res
        .status(400)
        .json({ error: "Faltan datos para crear el acta de avance." });
    }
    // const prismaStatus = (status as WorkActaStatus) || 'DRAFT'; // <-- ELIMINA ESTA LÍNEA
    const prismaStatus = workActaStatusMap[status] || "DRAFT"; // <-- AÑADE ESTA LÍNEA

    const newActa = await prisma.workActa.create({
      data: {
        number,
        period,
        date: new Date(date),
        status: prismaStatus, // <-- USA LA VARIABLE TRADUCIDA
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
    const formattedActa = formatWorkActa(newActa);
    res.status(201).json(formattedActa);
  } catch (error) {
    console.error("Error al crear el acta de avance:", error);
    if ((error as any).code === "P2002") {
      return res
        .status(409)
        .json({ error: "Ya existe un acta de avance con este número." });
    }
    res.status(500).json({ error: "No se pudo crear el acta de avance." });
  }
});

app.put("/api/work-actas/:id", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    const prismaStatus = workActaStatusMap[status] || undefined; // <-- AÑADE ESTA LÍNEA
    if (
      !prismaStatus ||
      !Object.values(WorkActaStatus).includes(prismaStatus)
    ) {
      return res.status(400).json({ error: "Estado inválido proporcionado." });
    }
    const updateData: any = { status: prismaStatus };
    const updatedActa = await prisma.workActa.update({
      where: { id: id },
      data: updateData,
      include: {
        items: { include: { contractItem: true } },
        attachments: true,
      },
    });
    const formattedActa = formatWorkActa(updatedActa);
    res.json(formattedActa);
  } catch (error) {
    console.error("Error al actualizar el acta de avance:", error);
    if ((error as any).code === "P2025") {
      return res
        .status(404)
        .json({ error: "El acta de avance no fue encontrada." });
    }
    res.status(500).json({ error: "No se pudo actualizar el acta de avance." });
  }
});

// --- RUTAS PARA COSTOS INTERVENTORÍA ---

// Obtener todas las actas de costo
app.get("/api/cost-actas", async (req, res) => {
  try {
    const actas = await prisma.costActa.findMany({
      orderBy: { submissionDate: "desc" },
      include: {
        observations: {
          // Incluimos observaciones
          include: { author: true },
          orderBy: { timestamp: "asc" },
        },
        attachments: true, // Incluimos adjuntos
      },
    });
    // Formatear estado antes de enviar
    const formattedActas = actas.map((acta) => ({
      ...acta,
      // Formateamos el estado para que coincida con el frontend
      status:
        Object.keys(costActaStatusMap).find(
          (key) => costActaStatusMap[key] === acta.status
        ) || acta.status,
    }));
    res.json(formattedActas);
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
    const acta = await prisma.costActa.findUnique({
      where: { id },
      include: {
        observations: { include: { author: true }, orderBy: { timestamp: "asc" } },
        attachments: true,
      },
    });

    if (!acta) {
      return res.status(404).json({ error: "Acta de costo no encontrada." });
    }

    const formattedActa = {
      ...acta,
      status:
        Object.keys(costActaStatusMap).find(
          (key) => costActaStatusMap[key] === acta.status
        ) || acta.status,
    };

    res.json(formattedActa);
  } catch (error) {
    console.error("Error al obtener el acta de costo:", error);
    res.status(500).json({ error: "No se pudo obtener el acta solicitada." });
  }
});

// Crear una nueva acta de costo
app.post("/api/cost-actas", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
  try {
    // Recibimos los IDs de los adjuntos que ya se subieron
    const {
      number,
      period,
      submissionDate,
      billedAmount,
      totalContractValue,
      relatedProgress,
      attachments = [], // attachments es ahora un array de objetos { id: string }
    } = req.body;

    if (
      !number ||
      !period ||
      !submissionDate ||
      !billedAmount ||
      !totalContractValue
    ) {
      return res.status(400).json({
        error: "Faltan datos obligatorios para crear el acta de costo.",
      });
    }

    const newCostActa = await prisma.costActa.create({
      data: {
        number,
        period,
        submissionDate: new Date(submissionDate),
        billedAmount: parseFloat(billedAmount),
        totalContractValue: parseFloat(totalContractValue),
        relatedProgress,
        status: CostActaStatus.SUBMITTED, // Estado inicial por defecto
        attachments: {
          // Conectamos los adjuntos existentes usando sus IDs
          connect: attachments.map((att: { id: string }) => ({ id: att.id })),
        },
      },
      include: {
        // Devolvemos el acta creada completa
        observations: { include: { author: true } },
        attachments: true,
      },
    });

    res.status(201).json(newCostActa); // No necesita formateo
  } catch (error) {
    console.error("Error al crear el acta de costo:", error);
    if ((error as any).code === "P2002") {
      // Error de código único duplicado
      return res
        .status(409)
        .json({ error: "Ya existe un acta de costo con este número." });
    }
    res.status(500).json({ error: "No se pudo crear el acta de costo." });
  }
});

app.put("/api/cost-actas/:id", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
  try {
    const { id } = req.params;
    const { status, relatedProgress } = req.body;

    const prismaStatus = costActaStatusMap[status] || undefined;
    if (
      !prismaStatus ||
      !Object.values(CostActaStatus).includes(prismaStatus)
    ) {
      return res.status(400).json({ error: "Estado inválido proporcionado." });
    }

    // Preparamos los datos a actualizar
    const updateData: any = {
      status: prismaStatus,
      relatedProgress: relatedProgress, // Actualizamos relatedProgress si viene
    };

    // Lógica especial si se aprueba: calcular fechas
    if (prismaStatus === "APPROVED") {
      const approvalDate = new Date();
      updateData.approvalDate = approvalDate;
      const paymentDueDate = new Date(approvalDate);
      paymentDueDate.setDate(paymentDueDate.getDate() + 30); // Añade 30 días calendario
      updateData.paymentDueDate = paymentDueDate;
    }

    const updatedActa = await prisma.costActa.update({
      where: { id: id },
      data: updateData,
      include: {
        // Devolvemos el acta completa actualizada
        observations: {
          include: { author: true },
          orderBy: { timestamp: "asc" },
        },
        attachments: true,
      },
    });

    // Formatear estado en la respuesta
    const formattedActa = {
      ...updatedActa,
      status:
        Object.keys(costActaStatusMap).find(
          (key) => costActaStatusMap[key] === updatedActa.status
        ) || updatedActa.status,
    };
    res.json(formattedActa);
  } catch (error) {
    console.error("Error al actualizar el acta de costo:", error);
    if ((error as any).code === "P2025") {
      return res
        .status(404)
        .json({ error: "El acta de costo no fue encontrada." });
    }
    res.status(500).json({ error: "No se pudo actualizar el acta de costo." });
  }
});

// Añadir una observación a un acta de costo
app.post("/api/cost-actas/:id/observations", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
  try {
    const { id } = req.params;
    const { text, authorId } = req.body;

    const resolvedAuthorId = req.user?.userId || authorId;

    if (!text || !resolvedAuthorId) {
      return res.status(400).json({
        error: "El texto y el autor son obligatorios para la observación.",
      });
    }

    const newObservation = await prisma.observation.create({
      data: {
        text,
        author: { connect: { id: resolvedAuthorId } },
        costActa: { connect: { id: id } },
      },
      include: { author: true }, // Devolvemos la observación con el autor
    });

    res.status(201).json(newObservation);
  } catch (error) {
    console.error("Error al añadir la observación:", error);
    if ((error as any).code === "P2025") {
      // Si el acta o el autor no existen
      return res.status(404).json({
        error: "El acta de costo o el usuario autor no fueron encontrados.",
      });
    }
    res.status(500).json({ error: "No se pudo añadir la observación." });
  }
});

// --- RUTAS PARA INFORMES (Reports) ---

// Obtener todos los informes (filtrables por query params ?type=Weekly&scope=OBRA)
app.get("/api/reports", async (req, res) => {
  try {
    const { type, scope } = req.query; // Filtros opcionales del frontend (ej: "Interventoría")

    const whereClause: any = {};
    if (type) whereClause.type = type as string;

    // Traduce el scope del query param al enum de Prisma ANTES de hacer la consulta
    if (scope) {
      const prismaScope = reportScopeMap[scope as string];
      if (prismaScope) {
        whereClause.reportScope = prismaScope;
      }
    }

    const reports = await prisma.report.findMany({
      where: whereClause,
      orderBy: [
        { number: "asc" },
        { version: "desc" },
      ],
      include: {
        author: true,
        attachments: true,
        signatures: { include: { signer: true } },
      },
    });

    const groupedReports = new Map<string, any>();

    reports.forEach((report) => {
      const formatted = formatReportRecord(report);
      const summary = mapReportVersionSummary(report);

      if (!groupedReports.has(report.number)) {
        groupedReports.set(report.number, {
          ...formatted,
          versions: [summary],
        });
      } else {
        const existing = groupedReports.get(report.number);
        existing.versions.push(summary);
      }
    });

    const latestReports = Array.from(groupedReports.values()).map((report) => ({
      ...report,
      versions: report.versions.sort((a: any, b: any) => b.version - a.version),
    }));

    latestReports.sort(
      (a, b) =>
        new Date(b.submissionDate).getTime() -
        new Date(a.submissionDate).getTime()
    );

    res.json(latestReports);
  } catch (error) {
    console.error("Error al obtener los informes:", error);
    res.status(500).json({ error: "No se pudieron obtener los informes." });
  }
});

app.get("/api/reports/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const report = await prisma.report.findUnique({
      where: { id },
      include: {
        author: true,
        attachments: true,
        signatures: { include: { signer: true } },
      },
    });

    if (!report) {
      return res.status(404).json({ error: "Informe no encontrado." });
    }

    const formattedReport = formatReportRecord(report);

    const versionHistory = await prisma.report.findMany({
      where: { number: report.number },
      select: {
        id: true,
        version: true,
        status: true,
        submissionDate: true,
        createdAt: true,
      } as const,
      orderBy: { version: "desc" },
    });

    formattedReport.versions = versionHistory.map(mapReportVersionSummary);

    res.json(formattedReport);
  } catch (error) {
    console.error("Error al obtener el informe:", error);
    res.status(500).json({ error: "No se pudo obtener el informe solicitado." });
  }
});

// Crear un nuevo informe
app.post("/api/reports", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
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
    } = req.body;

    const resolvedAuthorId = req.user?.userId || authorId;

    if (!period || !submissionDate || !summary || !resolvedAuthorId) {
      return res
        .status(400)
        .json({ error: "Faltan datos obligatorios para crear el informe." });
    }

    let resolvedType = type as string | undefined;
    let resolvedScopeDbValue = reportScope
      ? reportScopeMap[reportScope as string]
      : undefined;
    let resolvedNumber = number as string | undefined;
    let resolvedVersion = 1;
    let previousReportConnect:
      | { connect: { id: string } }
      | undefined = undefined;

    if (previousReportId) {
      const previousReport = await prisma.report.findUnique({
        where: { id: previousReportId },
      });

      if (!previousReport) {
        return res
          .status(404)
          .json({ error: "El informe anterior no fue encontrado." });
      }

      resolvedType = previousReport.type;
      resolvedScopeDbValue = previousReport.reportScope;
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

      if (!resolvedScopeDbValue) {
        const mappedScope = reportScopeMap[reportScope as string];
        if (!mappedScope) {
          return res.status(400).json({
            error: `El valor de reportScope '${reportScope}' no es válido.`,
          });
        }
        resolvedScopeDbValue = mappedScope;
      }
    }

    if (!Array.isArray(attachments)) {
      return res.status(400).json({
        error:
          "El formato de los adjuntos no es válido. Debe ser un arreglo de objetos { id }.",
      });
    }

    const newReport = await prisma.report.create({
      data: {
        type: resolvedType!,
        reportScope: resolvedScopeDbValue!,
        number: resolvedNumber!,
        version: resolvedVersion,
        previousReport: previousReportConnect,
        period,
        submissionDate: new Date(submissionDate),
        summary,
        status: "DRAFT",
        author: { connect: { id: resolvedAuthorId } },
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

    const formattedReport = formatReportRecord(newReport);

    const versionHistory = await prisma.report.findMany({
      where: { number: newReport.number },
      select: {
        id: true,
        version: true,
        status: true,
        submissionDate: true,
        createdAt: true,
      } as const,
      orderBy: { version: "desc" },
    });

    formattedReport.versions = versionHistory.map(mapReportVersionSummary);

    res.status(201).json(formattedReport);
  } catch (error) {
    console.error("Error al crear el informe:", error);
    if ((error as any).code === "P2002") {
      // Error de número único duplicado
      return res
        .status(409)
        .json({ error: "Ya existe un informe con este número y versión." });
    }
    res.status(500).json({ error: "No se pudo crear el informe." });
  }
});

// Actualizar un informe (principalmente estado)
app.put("/api/reports/:id", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
  try {
    const { id } = req.params;
    const { status, summary, requiredSignatories = [] } = req.body; // Campos que permitimos actualizar

    const prismaStatus = reportStatusMap[status] || undefined;
    if (!prismaStatus || !Object.values(ReportStatus).includes(prismaStatus)) {
      return res.status(400).json({ error: "Estado inválido proporcionado." });
    }

    const updateData: any = {
      status: prismaStatus,
      summary, // Permite actualizar el resumen si viene
      requiredSignatoriesJson: JSON.stringify(
        requiredSignatories.map((u: any) => u.id)
      ), // Actualiza firmantes requeridos
    };

    const updatedReport = await prisma.report.update({
      where: { id: id },
      data: updateData,
      include: {
        // Devolvemos el informe completo actualizado
        author: true,
        attachments: true,
        signatures: { include: { signer: true } },
      },
    });

    // Formatear respuesta
    const formattedReport = formatReportRecord(updatedReport);

    const versionHistory = await prisma.report.findMany({
      where: { number: updatedReport.number },
      select: {
        id: true,
        version: true,
        status: true,
        submissionDate: true,
        createdAt: true,
      } as const,
      orderBy: { version: "desc" },
    });

    formattedReport.versions = versionHistory.map(mapReportVersionSummary);

    res.json(formattedReport);
  } catch (error) {
    console.error("Error al actualizar el informe:", error);
    if ((error as any).code === "P2025") {
      return res.status(404).json({ error: "El informe no fue encontrado." });
    }
    res.status(500).json({ error: "No se pudo actualizar el informe." });
  }
});

// Añadir una firma a un informe
app.post("/api/reports/:id/signatures", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
  try {
    const { id } = req.params;
    const { signerId, password } = req.body; // Recibimos el ID del firmante y su contraseña

    if (!signerId || !password) {
      return res
        .status(400)
        .json({ error: "Se requiere ID del firmante y contraseña." });
    }

    // 1. Verificar contraseña del firmante
    const signer = await prisma.user.findUnique({ where: { id: signerId } });
    if (!signer) {
      return res.status(404).json({ error: "Usuario firmante no encontrado." });
    }
    const passwordMatch = await bcrypt.compare(password, signer.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: "Contraseña incorrecta." });
    }

    // 2. Verificar que el informe exista
    const report = await prisma.report.findUnique({ where: { id } });
    if (!report) {
      return res.status(404).json({ error: "Informe no encontrado." });
    }

    // 3. Añadir la firma (evita duplicados si ya firmó)
    const existingSignature = await prisma.signature.findFirst({
      where: { reportId: id, signerId: signerId },
    });

    if (existingSignature) {
      const currentReport = await prisma.report.findUnique({
        where: { id },
        include: {
          author: true,
          attachments: true,
          signatures: { include: { signer: true } },
        },
      });

      if (!currentReport) {
        return res
          .status(404)
          .json({ error: "Informe no encontrado tras validar firma." });
      }

      const formattedReport = formatReportRecord(currentReport);

      const versionHistory = await prisma.report.findMany({
        where: { number: currentReport.number },
        select: {
          id: true,
          version: true,
          status: true,
          submissionDate: true,
          createdAt: true,
        },
        orderBy: { version: "desc" },
      });

      formattedReport.versions = versionHistory.map(mapReportVersionSummary);

      return res.json(formattedReport);
    }

    await prisma.signature.create({
      data: {
        signer: { connect: { id: signerId } },
        report: { connect: { id: id } },
      },
    });

    // 4. (Opcional) Lógica para cambiar el estado a 'APROBADO' si todos firman
    // Necesitarías leer 'requiredSignatoriesJson', parsearlo,
    // contar las firmas actuales y comparar. Si coinciden, actualiza el estado.
    // const requiredIds = JSON.parse(report.requiredSignatoriesJson || '[]');
    // const currentSignatures = await prisma.signature.count({ where: { reportId: id } });
    // let finalStatus = report.status;
    // if (requiredIds.length > 0 && currentSignatures + 1 >= requiredIds.length && report.status === 'SUBMITTED') {
    //     finalStatus = ReportStatus.APPROVED;
    //     await prisma.report.update({ where: { id }, data: { status: finalStatus } });
    // }
    // Por ahora, no cambiaremos el estado automáticamente al firmar.

    // 5. Devolver el informe actualizado con la nueva firma
    const updatedReport = await prisma.report.findUnique({
      where: { id },
      include: {
        author: true,
        attachments: true,
        signatures: { include: { signer: true } },
      },
    });

    if (!updatedReport) {
      return res
        .status(404)
        .json({ error: "Informe no encontrado tras añadir la firma." });
    }

    const formattedReport = formatReportRecord(updatedReport);

    const versionHistory = await prisma.report.findMany({
      where: { number: updatedReport.number },
      select: {
        id: true,
        version: true,
        status: true,
        submissionDate: true,
        createdAt: true,
      } as const,
      orderBy: { version: "desc" },
    });

    formattedReport.versions = versionHistory.map(mapReportVersionSummary);

    res.status(201).json(formattedReport);
  } catch (error) {
    console.error("Error al añadir la firma al informe:", error);
    res.status(500).json({ error: "No se pudo añadir la firma." });
  }
});

app.post(
  "/api/reports/:id/generate-weekly-excel",
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const baseUrl =
        process.env.SERVER_PUBLIC_URL || `http://localhost:${port}`;

      const result = await generateWeeklyReportExcel({
        prisma,
        reportId: id,
        uploadsDir,
        baseUrl,
      });

      const updatedReport = await prisma.report.findUnique({
        where: { id },
        include: {
          author: true,
          attachments: true,
          signatures: { include: { signer: true } },
        },
      });

      if (!updatedReport) {
        return res
          .status(404)
          .json({ error: "Informe no encontrado tras generar el Excel." });
      }

      const formattedReport = formatReportRecord(updatedReport);
      const versionHistory = await prisma.report.findMany({
        where: { number: updatedReport.number },
        select: {
          id: true,
          version: true,
          status: true,
          submissionDate: true,
          createdAt: true,
        },
        orderBy: { version: "desc" },
      });
      formattedReport.versions = versionHistory.map(mapReportVersionSummary);

      res.json({
        report: formattedReport,
        attachment: buildAttachmentResponse(result.attachment),
      });
    } catch (error) {
      console.error(
        "Error al generar el Excel del informe semanal:",
        error
      );
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

// --- RUTAS PARA AVANCE FOTOGRÁFICO ---

// Obtener todos los puntos de control con sus fotos
app.get("/api/control-points", async (req, res) => {
  try {
    const points = await prisma.controlPoint.findMany({
      orderBy: { createdAt: "asc" },
      include: {
        photos: {
          // Incluye las fotos asociadas
          orderBy: { date: "asc" }, // Ordena las fotos por fecha
          include: {
            author: true, // Incluye quién tomó la foto
          },
        },
      },
    });
    res.json(points);
  } catch (error) {
    console.error("Error al obtener los puntos de control:", error);
    res
      .status(500)
      .json({ error: "No se pudieron obtener los puntos de control." });
  }
});

// Crear un nuevo punto de control
app.post("/api/control-points", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
  try {
    const { name, description, location } = req.body;

    if (!name) {
      return res
        .status(400)
        .json({ error: "El nombre del punto de control es obligatorio." });
    }

    const newPoint = await prisma.controlPoint.create({
      data: { name, description, location },
      include: { photos: { include: { author: true } } }, // Devuelve el punto nuevo (vacío de fotos)
    });
    res.status(201).json(newPoint);
  } catch (error) {
    console.error("Error al crear el punto de control:", error);
    res.status(500).json({ error: "No se pudo crear el punto de control." });
  }
});

// Añadir una foto a un punto de control existente
app.post("/api/control-points/:id/photos", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
  try {
    const { id } = req.params; // ID del ControlPoint
    // Recibe el ID del Attachment y las notas
    const { notes, authorId, attachmentId } = req.body;
    const resolvedAuthorId = req.user?.userId || authorId;

    if (!resolvedAuthorId || !attachmentId) {
      return res
        .status(400)
        .json({ error: "Faltan datos del autor o del archivo adjunto." });
    }

    // Verifica que el punto de control exista (opcional pero bueno)
    const controlPointExists = await prisma.controlPoint.findUnique({
      where: { id },
    });
    if (!controlPointExists) {
      return res.status(404).json({ error: "Punto de control no encontrado." });
    }

    // Busca el Attachment para obtener su URL
    const attachment = await prisma.attachment.findUnique({
      where: { id: attachmentId },
    });
    if (!attachment) {
      return res.status(404).json({ error: "Archivo adjunto no encontrado." });
    }

    // Crea la PhotoEntry
    const newPhoto = await prisma.photoEntry.create({
      data: {
        notes,
        url: attachment.url, // <-- ¡AÑADE ESTA LÍNEA! Pasa la URL del attachment
        author: { connect: { id: resolvedAuthorId } },
        controlPoint: { connect: { id: id } },
        attachment: { connect: { id: attachmentId } },
      },
      include: {
        author: true,
        attachment: true, // Incluye el attachment en la respuesta
      },
    });

    // Formatea la respuesta para incluir la URL directamente si el frontend la necesita así
    const formattedPhoto = {
      ...newPhoto,
      url: newPhoto.attachment?.url || newPhoto.url, // Asegura que la URL esté disponible
    };

    res.status(201).json(formattedPhoto);
  } catch (error) {
    console.error("Error al añadir la foto:", error);
    if ((error as any).code === "P2025") {
      return res.status(404).json({
        error:
          "El autor, punto de control o archivo adjunto no fueron encontrados.",
      });
    }
    res.status(500).json({ error: "No se pudo añadir la foto." });
  }
});

app.get("/api/project-tasks", async (req, res) => {
  console.log("!!! RUTA /api/project-tasks ALCANZADA !!!"); // <-- Log súper temprano
  console.log("--> GET /api/project-tasks received");
  console.log("--> GET /api/project-tasks received"); // <-- Log 1: Petición recibida
  try {
    console.log("   Querying database for tasks..."); // <-- Log 2: Antes de la consulta
    const tasks = await prisma.projectTask.findMany({
      orderBy: { outlineLevel: "asc" },
    });
    console.log(`   Found ${tasks.length} tasks in database.`); // <-- Log 3: Después de la consulta

    // Formatear fechas a ISO string antes de enviar
    const formattedTasks = tasks.map((task: ProjectTask) => ({
      ...task,
      startDate: task.startDate.toISOString(),
      endDate: task.endDate.toISOString(),
      children: [],
      dependencies: task.dependencies ? JSON.parse(task.dependencies) : [],
    }));
    // ---------------------------------------------
    console.log("   Tasks formatted for response.");

    res.json(formattedTasks);
    console.log("<-- GET /api/project-tasks response sent successfully.");
  } catch (error) {
    console.error("!!! ERROR in GET /api/project-tasks:", error);
    res
      .status(500)
      .json({ error: "No se pudieron obtener las tareas del proyecto." });
  }
});

app.post("/api/project-tasks/import", authMiddleware, requireEditor, async (req: AuthRequest, res) => {
  try {
    let incomingTasks: any[] | undefined;
    if (Array.isArray((req.body as any)?.tasks)) {
      incomingTasks = (req.body as any).tasks;
    } else if (typeof (req.body as any)?.xml === "string") {
      const parsed = await validateCronogramaXml((req.body as any).xml);
      incomingTasks = parsed;
    }

    if (!Array.isArray(incomingTasks)) {
      return res.status(400).json({ error: "Formato inválido. Envía tareas normalizadas o XML válido." });
    }

    const MAX_NAME_LENGTH = Number(process.env.CRON_XML_MAX_NAME_LENGTH || 512);

    const sanitizedTasks = incomingTasks.map((task: any, index: number) => {
      const id = typeof task?.id === "string" && task.id.trim().length > 0 ? task.id.trim() : randomUUID();
      const name = typeof task?.name === "string" && task.name.trim().length > 0 ? task.name.trim() : `Tarea ${index + 1}`;
      let safeName = name;
      if (name.length > MAX_NAME_LENGTH) {
        safeName = name.slice(0, MAX_NAME_LENGTH);
        console.warn(`Truncating task name "${name}" to ${MAX_NAME_LENGTH} characters during import.`);
      }

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

      const progressValue = Math.max(0, Math.min(100, parseInt(`${task?.progress ?? 0}`, 10) || 0));
      const durationValue = Math.max(1, parseInt(`${task?.duration ?? 1}`, 10) || 1);
      const outlineLevelValue = Math.max(1, parseInt(`${task?.outlineLevel ?? 1}`, 10) || 1);
      const isSummaryValue =
        task?.isSummary === true ||
        task?.isSummary === 1 ||
        (typeof task?.isSummary === "string" && task.isSummary.toLowerCase() === "true");

      const dependencyArray = Array.isArray(task?.dependencies)
        ? task.dependencies.map((dep: any) => `${dep}`.trim()).filter((dep: string) => dep.length > 0)
        : [];

      return {
        id,
        taskId: id,
        name: safeName,
        startDate: parsedStart,
        endDate: parsedEnd,
        progress: progressValue,
        duration: durationValue,
        isSummary: isSummaryValue,
        outlineLevel: outlineLevelValue,
        dependencies: dependencyArray.length ? JSON.stringify(dependencyArray) : null,
      };
    });

    await prisma.$transaction(async (tx) => {
      await tx.projectTask.deleteMany();
      if (sanitizedTasks.length) {
        await tx.projectTask.createMany({ data: sanitizedTasks });
      }
    });

    const updatedTasks = await prisma.projectTask.findMany({ orderBy: { outlineLevel: "asc" } });
    const formattedTasks = updatedTasks.map((task) => ({
      ...task,
      startDate: task.startDate.toISOString(),
      endDate: task.endDate.toISOString(),
      dependencies: task.dependencies ? JSON.parse(task.dependencies) : [],
      children: [],
    }));

    res.status(201).json(formattedTasks);
  } catch (error) {
    console.error("Error al importar tareas del cronograma:", error);
    if (error instanceof CronogramaValidationError) {
      return res.status(400).json({ error: error.message });
    }
    res.status(500).json({ error: "No se pudo importar el cronograma." });
  }
});

app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});
import mime from "mime-types";

app.post(
  "/api/reports/:id/export-pdf",
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const baseUrl =
        process.env.SERVER_PUBLIC_URL || `http://localhost:${port}`;

      const result = await generateReportPdf({
        prisma,
        reportId: id,
        uploadsDir,
        baseUrl,
      });

      const updatedReport = await prisma.report.findUnique({
        where: { id },
        include: {
          author: true,
          attachments: true,
          signatures: { include: { signer: true } },
        },
      });

      if (!updatedReport) {
        return res
          .status(404)
          .json({ error: "Informe no encontrado tras generar el PDF." });
      }

      const formattedReport = formatReportRecord(updatedReport);
      const versionHistory = await prisma.report.findMany({
        where: { number: updatedReport.number },
        select: {
          id: true,
          version: true,
          status: true,
          submissionDate: true,
          createdAt: true,
        } as const,
        orderBy: { version: "desc" },
      });
      formattedReport.versions = versionHistory.map(mapReportVersionSummary);

      res.json({
        report: formattedReport,
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
