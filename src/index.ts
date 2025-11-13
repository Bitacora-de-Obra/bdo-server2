import express, {
  CookieOptions,
  NextFunction,
  Request,
  Response,
} from "express";
import cors, { CorsOptions } from "cors";
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
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cron from "node-cron";
import swaggerUi from "swagger-ui-express";
import path from "path";
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
import fsPromises from "fs/promises";
import { sha256 } from "./utils/hash";
import { JsonValue } from "./types/json";

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
    return res.status(401).json({ error: "Usuario no autenticado." });
  }

  if (req.user.appRole === "viewer") {
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

const createStorageKey = (folder: string, originalName: string) => {
  const ext = path.extname(originalName);
  const baseName = sanitizeFileName(path.basename(originalName, ext)) || "file";
  const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
  const normalizedFolder = folder
    .replace(/[^a-zA-Z0-9/_-]/g, "")
    .replace(/\/+$/, "");
  return path.posix.join(normalizedFolder, `${uniqueSuffix}-${baseName}${ext}`);
};

const persistUploadedFile = async (
  file: Express.Multer.File,
  folder: string
) => {
  const storage = getStorage();
  const key = createStorageKey(folder, file.originalname);
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
  const relativePath = `/api/attachments/${attachment.id}/download`;
  const publicUrl = resolveServerPublicUrl();
  const downloadUrl = `${publicUrl}${relativePath}`;
  return {
    ...attachment,
    url: downloadUrl,
    downloadUrl,
    downloadPath: relativePath,
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

const loadUserSignatureBuffer = async (
  userSignature: any
): Promise<Buffer> => {
  const storage = getStorage();
  const candidates = [
    userSignature.storagePath,
    resolveStorageKeyFromUrl(userSignature.url),
  ].filter((value): value is string => Boolean(value));

  for (const candidate of candidates) {
    try {
      return await storage.read(candidate);
    } catch (error) {
      console.warn("No se pudo leer la firma desde storage.", {
        candidate,
        error,
      });
    }
  }

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
    requiredSignatories: requiredSigners,
    signatureTasks: formattedSignatureTasks,
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
  origin(origin, callback) {
    // Permitir requests sin origen (ej. curl) y orígenes registrados
    if (!origin || allowedOrigins.includes(origin.replace(/\/+$/, ""))) {
      callback(null, true);
    } else {
      callback(new Error(`Origin ${origin} not allowed by CORS`));
    }
  },
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  exposedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
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

app.use(cors(corsOptions));

app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);

app.use("/api/auth/login", loginRateLimiter);
app.use("/api/auth/refresh", refreshRateLimiter);

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
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// Middleware global para debug - captura TODAS las peticiones
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
    ];

    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(
        new Error(
          "Tipo de archivo no permitido. Solo se permiten imágenes (JPG, PNG, GIF, WEBP) y PDFs."
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
      console.error("Error durante la migración:", error);
      res.status(500).json({
        error: "Error durante la migración de URLs",
        details: error instanceof Error ? error.message : "Error desconocido",
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
      console.error("Error corrigiendo migraciones:", error);
      res.status(500).json({
        error: "Error corrigiendo migraciones de base de datos",
        details: error instanceof Error ? error.message : "Error desconocido",
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

app.get(
  "/api/project-details",
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const project = await prisma.project.findFirst({
        include: {
          keyPersonnel: true,
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
      const modifications = await prisma.contractModification.findMany({
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
      const { number, type, date, value, days, justification, attachmentId } =
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

      const newModification = await prisma.contractModification.create({
        data: {
          number,
          type: prismaType,
          date: new Date(date),
          value: parsedValue,
          days: parsedDays,
          justification,
          attachment: attachmentId
            ? { connect: { id: attachmentId } }
            : undefined,
        },
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
app.get("/api/actas", async (_req, res) => {
  try {
    const actas = await prisma.acta.findMany({
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

    const newActa = await prisma.acta.create({
      data: {
        number,
        title,
        date: new Date(date),
        area: prismaArea,
        status: prismaStatus,
        summary,
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
    const entries = await prisma.logEntry.findMany({
      orderBy: { createdAt: "desc" },
      include: {
        author: true,
        attachments: true,
        comments: { include: { author: true }, orderBy: { timestamp: "asc" } },
        signatures: { include: { signer: true } },
        signatureTasks: { include: { signer: true }, orderBy: { assignedAt: "asc" } },
        assignees: true,
        history: { include: { user: true }, orderBy: { timestamp: "desc" } },
      },
    });

    const formattedEntries = entries.map((entry) => ({
      ...formatLogEntry(entry),
      attachments: (entry.attachments || []).map(buildAttachmentResponse),
    }));

    res.json(formattedEntries);
  } catch (error) {
    console.error("Error al obtener anotaciones:", error);
    res.status(500).json({ error: "No se pudieron obtener las anotaciones." });
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
  async (req: AuthRequest, res) => {
    console.log("=== INICIO POST /api/log-entries ===");
    console.log("DEBUG: Método:", req.method);
    console.log("DEBUG: URL:", req.url);
    console.log("DEBUG: Headers content-type:", req.headers["content-type"]);
    try {
      const userId = req.user?.userId;
      console.log("DEBUG: User ID:", userId);
      if (!userId) {
        return res.status(401).json({ error: "Usuario no autenticado." });
      }

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

      if (!title || !description || !type) {
        return res.status(400).json({
          error: "Título, descripción y tipo son obligatorios.",
        });
      }

      if (!projectId || typeof projectId !== "string") {
        return res
          .status(400)
          .json({ error: "El identificador del proyecto es obligatorio." });
      }

      const prismaType = entryTypeMap[type] || entryTypeMap["Anotación"];
      const prismaStatus =
        entryStatusMap[status] ||
        entryStatusMap[entryStatusReverseMap[status] || "Abierta"] ||
        "OPEN";

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
            "log-entries",
            `${Date.now()}-${file.originalname}`
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

      const logEntry = await prisma.logEntry.create({
        data: {
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
          author: { connect: { id: userId } },
          project: { connect: { id: projectId } },
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

      // Crear tareas de firma para los firmantes requeridos
      console.log("DEBUG: ===== CREACIÓN DE TAREAS DE FIRMA =====");
      console.log("DEBUG: requiredSignerIds extraídos:", requiredSignerIds);
      console.log("DEBUG: userId (autor):", userId);
      console.log("DEBUG: uniqueSignerIds (incluyendo autor):", uniqueSignerIds);
      console.log("DEBUG: Cantidad de firmantes:", uniqueSignerIds.length);
      
      if (uniqueSignerIds.length > 0) {
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
              },
            });
            createdTasks.push(task.id);
            console.log("DEBUG: ✓ Tarea de firma creada exitosamente:", {
              taskId: task.id,
              signerId: signerId,
              logEntryId: logEntry.id,
            });
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
        include: {
          author: true,
          attachments: true,
          comments: {
            include: { author: true },
            orderBy: { timestamp: "asc" },
          },
          signatures: { include: { signer: true } },
          signatureTasks: { include: { signer: true }, orderBy: { assignedAt: "asc" } },
          assignees: true,
          history: {
            include: { user: true },
            orderBy: { timestamp: "desc" },
          },
        },
      });

      if (!entryWithRelations) {
        throw new Error("No se pudo recuperar la anotación recién creada.");
      }

      const formattedEntry = formatLogEntry(entryWithRelations);
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
      console.log("DEBUG: Resumen de firmas:", formattedEntry.signatureSummary);
      console.log("DEBUG: ===== FIN RESPUESTA =====");
      console.log("=== FIN POST /api/log-entries ===");
      res.status(201).json(formattedEntry);
    } catch (error) {
      console.error("Error al crear anotación:", error);
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === "P2002" &&
        Array.isArray((error.meta as any)?.target) &&
        ((error.meta as any).target as string[]).includes(
          "LogEntry_projectId_entryDate_key"
        )
      ) {
        return res.status(409).json({
          error:
            "Ya existe una bitácora registrada para este proyecto en la fecha seleccionada.",
        });
      }
      res.status(500).json({ error: "No se pudo crear la anotación." });
    }
  }
);

app.get(
  "/api/log-entries/:id",
  authMiddleware,
  async (req: AuthRequest, res) => {
    try {
      const { id } = req.params;
      const entry = await prisma.logEntry.findUnique({
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
          assignees: true,
          history: { include: { user: true }, orderBy: { timestamp: "desc" } },
        },
      });

      if (!entry) {
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

      try {
        const { id } = req.params;
        const { content, authorId } = req.body ?? {};

        if (!content || typeof content !== "string" || !content.trim()) {
          return res.status(400).json({
            error: "El contenido del comentario es obligatorio.",
          });
        }

        const logEntry = await prisma.logEntry.findUnique({ where: { id } });
        if (!logEntry) {
          return res
            .status(404)
            .json({ error: "Anotación no encontrada." });
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
            const stored = await persistUploadedFile(
              file,
              "log-entry-comments"
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
    });
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

      const passwordMatches = await bcrypt.compare(password, signer.password);
      if (!passwordMatches) {
        return res.status(401).json({
          error: "Contraseña incorrecta.",
          code: "INVALID_SIGNATURE_PASSWORD",
        });
      }

      const entry = await prisma.logEntry.findUnique({
        where: { id },
        include: {
          signatureTasks: { include: { signer: true } },
          attachments: true,
        },
      });

      if (!entry) {
        return res.status(404).json({ error: "Anotación no encontrada." });
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

      await prisma.signature.create({
        data: {
          signer: { connect: { id: signerId } },
          logEntry: { connect: { id } },
          signedAt: new Date(),
        },
      });

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
              fileName: { contains: "firmado" },
            },
            orderBy: { createdAt: "desc" },
          });

          // Si no hay PDFs firmados, buscar el original
          if (!basePdf) {
            basePdf = await prisma.attachment.findFirst({
              where: {
                logEntryId: id,
                type: "application/pdf",
                fileName: { not: { contains: "firmado" } },
              },
              orderBy: { createdAt: "asc" },
            });
          }

          // Si aún no hay PDF, buscar cualquier PDF
          if (!basePdf) {
            basePdf = await prisma.attachment.findFirst({
              where: {
                logEntryId: id,
                type: "application/pdf",
              },
              orderBy: { createdAt: "desc" },
            });
          }

          // Si no hay PDF, generar uno automáticamente antes de firmar
          if (!basePdf) {
            console.log("No hay PDF existente, generando uno automáticamente...");
            try {
              const baseUrl =
                process.env.SERVER_PUBLIC_URL || `http://localhost:${port}`;
              await generateLogEntryPdf({
                prisma,
                logEntryId: id,
                uploadsDir: process.env.UPLOADS_DIR || "./uploads",
                baseUrl,
              });

              // Buscar el PDF recién generado
              basePdf = await prisma.attachment.findFirst({
                where: {
                  logEntryId: id,
                  type: "application/pdf",
                },
                orderBy: { createdAt: "desc" },
              });

              if (basePdf) {
                console.log(
                  `PDF generado automáticamente: ${basePdf.fileName}`
                );
              }
            } catch (pdfError) {
              console.warn(
                "No se pudo generar PDF automáticamente:",
                pdfError
              );
            }
          }

          if (basePdf) {
            console.log(
              `Aplicando firma manuscrita al PDF: ${basePdf.fileName} (ID: ${basePdf.id})`
            );

            // Cargar buffers en paralelo
            const [originalBuffer, signatureBuffer] = await Promise.all([
              loadAttachmentBuffer(basePdf),
              loadUserSignatureBuffer(userSignature),
            ]);

            // Obtener tareas de firma ordenadas para calcular posición
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
            let signerIndex = orderedTasks.findIndex(
              (t: any) => t.signer?.id === signerId
            );
            if (signerIndex < 0) signerIndex = 0;

            const MARGIN = 48;
            const BOX_HEIGHT = 110;
            const GAP = 16;
            const LINE_Y = 72;
            const LINE_X = 70;
            const yPos = MARGIN + signerIndex * (BOX_HEIGHT + GAP) + LINE_Y;

            const signedBuffer = await applySignatureToPdf({
              originalPdf: originalBuffer,
              signature: {
                buffer: signatureBuffer,
                mimeType: userSignature.mimeType || "image/png",
              },
              position: {
                page: 1,
                x: LINE_X,
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
            const parsedFileName = path.parse(
              basePdf.fileName || "documento.pdf"
            );
            const signedFileName = `${parsedFileName.name}-firmado-${Date.now()}.pdf`;
            const signedKey = createStorageKey(
              "log-entry-signatures",
              signedFileName
            );
            await storage.save({ path: signedKey, content: signedBuffer });
            const signedUrl = storage.getPublicUrl(signedKey);

            // Crear nuevo adjunto firmado
            await prisma.attachment.create({
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
              `PDF firmado creado exitosamente: ${signedFileName}`
            );
          } else {
            console.warn(
              "No se pudo encontrar o generar un PDF base para aplicar la firma."
            );
          }
        } catch (pdfError) {
          console.warn(
            "La firma manuscrita no pudo aplicarse al PDF, pero la firma quedó registrada.",
            pdfError
          );
        }
      }

      await prisma.logEntrySignatureTask.update({
        where: { id: myTask.id },
        data: { status: "SIGNED", signedAt: new Date() },
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
          assignees: true,
          history: { include: { user: true }, orderBy: { timestamp: "desc" } },
        },
      });

      if (!updated) {
        return res
          .status(404)
          .json({ error: "Anotación no encontrada tras firmar." });
      }

      res.json(formatLogEntry(updated));
    } catch (error) {
      console.error("Error al firmar anotación:", error);
      res.status(500).json({ error: "No se pudo firmar la anotación." });
    }
  }
);

// --- RUTAS PARA COMUNICACIONES ---
app.get("/api/communications", async (_req, res) => {
  try {
    const communications = await prisma.communication.findMany({
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

    const newComm = await prisma.communication.create({
      data: {
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

      const current = await prisma.communication.findUnique({
        where: { id },
        select: { assigneeId: true },
      });

      if (!current) {
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
      prisma.project.findFirst({ include: { keyPersonnel: true } }),
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
          dueDate: { gte: new Date() },
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
        .map((comm) => {
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
        .map((acta) => {
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
        .map((acta) => {
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
        .map((report) => {
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
        .map((drawing) => {
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
        .map((point) => {
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
        .map((commitment) => {
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
        .map((entry) => {
          const author = entry.author?.fullName || "No especificado";
          const type = entryTypeReverseMap[entry.type] || entry.type;
          const status = entryStatusReverseMap[entry.status] || entry.status;
          const assignees =
            entry.assignees?.map((a) => a.fullName).join(", ") ||
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
        return res
          .status(400)
          .json({ error: "No se recibió ningún archivo válido." });
      }

      const existing = await prisma.userSignature.findUnique({
        where: { userId },
      });

      const storage = getStorage();
      const key = createStorageKey(
        `user-signatures/${userId}`,
        file.originalname
      );
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
          console.warn(
            "No se pudo eliminar la firma anterior del almacenamiento.",
            { error }
          );
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
      versions: (drawing.versions || []).map((version: any) => ({
        ...version,
        createdAt:
          version.createdAt instanceof Date
            ? version.createdAt.toISOString()
            : version.createdAt,
      })),
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
      versions: (drawing.versions || []).map((version: any) => ({
        ...version,
        createdAt:
          version.createdAt instanceof Date
            ? version.createdAt.toISOString()
            : version.createdAt,
      })),
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

      const stored = await persistUploadedFile(file, "attachments");

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
app.get("/api/project-tasks", async (_req, res) => {
  try {
    const tasks = await prisma.projectTask.findMany({
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

app.get("/api/control-points", async (_req, res) => {
  try {
    const points = await prisma.controlPoint.findMany({
      orderBy: { createdAt: "asc" },
      include: {
        photos: {
          orderBy: { date: "asc" },
          include: { author: true, attachment: true },
        },
      },
    });

    const formatted = points.map((point) => ({
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

app.get("/api/work-actas", async (_req, res) => {
  try {
    const actas = await prisma.workActa.findMany({
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

      const newActa = await prisma.workActa.create({
        data: {
          number,
          period,
          date: new Date(date),
          status: prismaStatus,
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
    const where: Prisma.ReportWhereInput = {};

    if (type) where.type = String(type);
    if (scope && reportScopeMap[String(scope)]) {
      where.reportScope = reportScopeMap[String(scope)];
    }

    const reports = await prisma.report.findMany({
      where,
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

      const newReport = await prisma.report.create({
        data: {
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

      const report = await prisma.report.findUnique({ where: { id } });
      if (!report) {
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

      const result = await generateWeeklyReportExcel({
        prisma,
        reportId: id,
        uploadsDir,
        baseUrl,
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

      const result = await generateReportPdf({
        prisma,
        reportId: id,
        uploadsDir,
        baseUrl,
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

      const result = await generateLogEntryPdf({
        prisma,
        logEntryId: id,
        uploadsDir: process.env.UPLOADS_DIR || "./uploads",
        baseUrl,
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
app.get("/api/cost-actas", async (_req, res) => {
  try {
    const actas = await prisma.costActa.findMany({
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

    res.json({
      ...acta,
      status:
        Object.keys(costActaStatusMap).find(
          (key) => costActaStatusMap[key] === acta.status
        ) || acta.status,
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

      const newActa = await prisma.costActa.create({
        data: {
          number,
          period,
          submissionDate: new Date(submissionDate),
          billedAmount: Number(billedAmount),
          totalContractValue: Number(totalContractValue),
          relatedProgress,
          status: CostActaStatus.SUBMITTED,
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
      const { status, relatedProgress } = req.body ?? {};

      const prismaStatus = costActaStatusMap[status] || undefined;
      if (
        !prismaStatus ||
        !Object.values(CostActaStatus).includes(prismaStatus)
      ) {
        return res.status(400).json({ error: "Estado inválido proporcionado." });
      }

      const updateData: Prisma.CostActaUpdateInput = {
        status: prismaStatus,
        relatedProgress,
      };

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

      const newObservation = await prisma.observation.create({
        data: {
          text,
          author: { connect: { id: resolvedAuthorId } },
          costActa: { connect: { id } },
        },
        include: { author: true },
      });

      res.status(201).json(newObservation);
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

      const newPoint = await prisma.controlPoint.create({
        data: { name, description, location },
        include: {
          photos: { include: { author: true }, orderBy: { date: "asc" } },
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

      const pointExists = await prisma.controlPoint.findUnique({
        where: { id },
      });
      if (!pointExists) {
        return res.status(404).json({ error: "Punto de control no encontrado." });
      }

      const attachment = await prisma.attachment.findUnique({
        where: { id: attachmentId },
      });
      if (!attachment) {
        return res.status(404).json({ error: "Archivo adjunto no encontrado." });
      }

      const newPhoto = await prisma.photoEntry.create({
        data: {
          notes,
          url: attachment.url,
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
          dependencies: dependencyArray.length
            ? JSON.stringify(dependencyArray)
            : null,
        };
      });

      await prisma.$transaction(async (tx) => {
        await tx.projectTask.deleteMany();
        if (sanitizedTasks.length) {
          await tx.projectTask.createMany({ data: sanitizedTasks });
        }
      });

      const updatedTasks = await prisma.projectTask.findMany({
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
  async (_req: AuthRequest, res) => {
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

    const user = await prisma.user.findUnique({
      where: { email },
    });

    console.log("User found:", user ? "yes" : "no");

    if (!user) {
      return res.status(401).json({ error: "Credenciales inválidas." });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    console.log("Password valid:", isPasswordValid ? "yes" : "no");

    if (!isPasswordValid) {
      return res.status(401).json({ error: "Credenciales inválidas." });
    }

    if (user.status !== "active") {
      return res
        .status(403)
        .json({ error: "La cuenta de usuario está inactiva." });
    }

    // Crear tokens de acceso y refresh
    const accessToken = createAccessToken(user.id, user.tokenVersion);
    const refreshToken = createRefreshToken(user.id, user.tokenVersion);

    console.log("Tokens created successfully");

    // Actualizar último login
    await prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() },
    });

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
        avatarUrl: true,
        status: true,
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

app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});
