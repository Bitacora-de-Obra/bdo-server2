import express, {
  CookieOptions,
  NextFunction,
  Request,
  Response,
} from "express";
import cors from "cors";
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
// El middleware de autenticación ya está importado arriba
const app = express();
const prisma = new PrismaClient();
const port = 4001;
const isProduction = process.env.NODE_ENV === "production";

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

const buildAttachmentResponse = (attachment: any) => ({
  ...attachment,
  downloadUrl: `http://localhost:${port}/api/attachments/${attachment.id}/download`,
});

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
    signatureSummary: {
      total: totalSignatureTasks,
      signed: signedSignatureTasks.length,
      pending: pendingSignatureTasks.length,
      completed: totalSignatureTasks > 0 && pendingSignatureTasks.length === 0,
    },
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

app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "http://localhost:3001",
      "http://localhost:5173",
    ], // Permite puertos de React y Vite
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
        return res
          .status(400)
          .json({
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
            return res
              .status(409)
              .json({
                error: "El documento ya fue completamente firmado.",
                code: "DOCUMENT_LOCKED",
              });
          }
          const task = logEntry.signatureTasks.find(
            (t: any) => t.signerId === userId
          );
          if (!task) {
            return res
              .status(403)
              .json({
                error: "No tienes tarea de firma asignada en esta anotación.",
              });
          }
          if (task.status === "SIGNED") {
            return res
              .status(409)
              .json({
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
app.post("/api/admin/migrate-urls-to-r2", authMiddleware, requireAdmin, async (req: AuthRequest, res) => {
  try {
    const storage = getStorage();
    
    // Solo ejecutar si estamos usando Cloudflare R2
    if (process.env.STORAGE_DRIVER !== 'cloudflare') {
      return res.status(400).json({ 
        error: "Esta migración solo funciona cuando STORAGE_DRIVER=cloudflare" 
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
          { url: { contains: "/uploads/" } }
        ]
      }
    });

    console.log(`Encontrados ${localAttachments.length} archivos con URLs locales`);

    let migratedCount = 0;
    let errorCount = 0;

    for (const attachment of localAttachments) {
      try {
        // Extraer el storage path desde la URL local
        let storagePath = attachment.storagePath;
        
        if (!storagePath && attachment.url) {
          // Intentar extraer el path desde la URL
          const urlPath = attachment.url.replace(/^.*\/uploads\//, '');
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
              storagePath: storagePath
            }
          });

          console.log(`✅ Migrado: ${attachment.fileName} -> ${newUrl}`);
          migratedCount++;
        } else {
          console.log(`⚠️  No se pudo determinar storagePath para: ${attachment.fileName}`);
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
        url: { contains: "localhost" }
      }
    });

    for (const signature of localSignatures) {
      try {
        if (signature.storagePath) {
          const newUrl = storage.getPublicUrl(signature.storagePath);
          await prisma.userSignature.update({
            where: { id: signature.id },
            data: { url: newUrl }
          });
          console.log(`✅ Firma migrada: ${signature.fileName} -> ${newUrl}`);
          migratedCount++;
        }
      } catch (error) {
        console.error(`❌ Error migrando firma ${signature.fileName}:`, error);
        errorCount++;
      }
    }

    res.json({
      success: true,
      message: `Migración completada. ${migratedCount} archivos migrados, ${errorCount} errores.`,
      migrated: migratedCount,
      errors: errorCount,
      totalProcessed: localAttachments.length + localSignatures.length
    });

  } catch (error) {
    console.error("Error durante la migración:", error);
    res.status(500).json({ 
      error: "Error durante la migración de URLs",
      details: error instanceof Error ? error.message : "Error desconocido"
    });
  }
});

// Database migration fix endpoint - SOLO PARA EMERGENCIAS
app.post("/api/admin/fix-migrations", authMiddleware, requireAdmin, async (req: AuthRequest, res) => {
  try {
    console.log("🔧 Iniciando corrección de migraciones...");
    
    // Verificar que estemos en producción
    if (process.env.NODE_ENV !== 'production') {
      return res.status(400).json({ 
        error: "Este endpoint solo se debe usar en producción" 
      });
    }

    // Ejecutar comando para resolver migraciones fallidas
    const { exec } = require('child_process');
    const util = require('util');
    const execAsync = util.promisify(exec);

    try {
      // Primero, marcar la migración fallida como resuelta
      console.log("Marcando migración fallida como resuelta...");
      await execAsync('npx prisma migrate resolve --applied 20250325100000_add_report_versions');
      
      // Luego, aplicar las migraciones pendientes
      console.log("Aplicando migraciones pendientes...");
      await execAsync('npx prisma migrate deploy');
      
      console.log("✅ Migraciones corregidas exitosamente");
      
      res.json({
        success: true,
        message: "Migraciones de base de datos corregidas exitosamente",
        timestamp: new Date().toISOString()
      });

    } catch (migrationError) {
      console.error("Error en migración:", migrationError);
      
      // Si falla, intentar solo deploy
      try {
        console.log("Intentando solo deploy...");
        await execAsync('npx prisma migrate deploy --accept-data-loss');
        
        res.json({
          success: true,
          message: "Migraciones aplicadas con data loss acceptance",
          warning: "Se usó --accept-data-loss",
          timestamp: new Date().toISOString()
        });
      } catch (deployError) {
        throw deployError;
      }
    }

  } catch (error) {
    console.error("Error corrigiendo migraciones:", error);
    res.status(500).json({ 
      error: "Error corrigiendo migraciones de base de datos",
      details: error instanceof Error ? error.message : "Error desconocido"
    });
  }
});

// Health check endpoint
app.get("/", (req, res) => {
  res.json({ 
    status: "OK", 
    message: "BDO Server API is running",
    timestamp: new Date().toISOString(),
    version: "1.0.0"
  });
});

app.get("/health", (req, res) => {
  res.json({ 
    status: "healthy", 
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    storage: process.env.STORAGE_DRIVER || 'local'
  });
});

app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});
