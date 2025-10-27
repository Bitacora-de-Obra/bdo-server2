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
import { validateCronogramaXml, CronogramaValidationError } from "./utils/xmlValidator";
import { logger } from "./logger";
import fsPromises from "fs/promises";

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
  modificationTypeMap,
  roleMap,
} from "./utils/enum-maps";
import { getStorage } from "./storage";
import {
  sendEmailVerificationEmail,
  sendPasswordResetEmail,
  sendCommitmentReminderEmail,
  isEmailServiceConfigured,
} from "./services/email";
// El middleware de autenticación ya está importado arriba
const app = express();
const prisma = new PrismaClient();
const port = 4001;
const isProduction = process.env.NODE_ENV === "production";

// --- INICIO: Configuración de IA (Chatbot) ---
// --- INICIO: Configuración de IA (OpenAI) ---
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

const buildAttachmentResponse = (attachment: any) => ({
  ...attachment,
  downloadUrl: `http://localhost:${port}/api/attachments/${attachment.id}/download`,
});

const formatLogEntry = (entry: any) => ({
  ...entry,
  type: entryTypeReverseMap[entry.type] || entry.type,
  status: entryStatusReverseMap[entry.status] || entry.status,
  comments: (entry.comments || []).map((comment: any) => ({
    ...comment,
    timestamp: comment.timestamp instanceof Date ? comment.timestamp.toISOString() : comment.timestamp,
  })),
  attachments: (entry.attachments || []).map(buildAttachmentResponse),
  signatures: (entry.signatures || []).map((signature: any) => ({
    ...signature,
    signedAt: signature.signedAt instanceof Date ? signature.signedAt.toISOString() : signature.signedAt,
  })),
  assignees: entry.assignees || [],
  history: (entry.history || []).map((change: any) => ({
    id: change.id,
    fieldName: change.fieldName,
    oldValue: change.oldValue,
    newValue: change.newValue,
    timestamp: change.timestamp instanceof Date ? change.timestamp.toISOString() : change.timestamp,
    user: change.user
      ? {
          id: change.user.id,
          fullName: change.user.fullName,
          avatarUrl: change.user.avatarUrl,
          email: change.user.email,
          appRole: change.user.appRole,
          projectRole: change.user.projectRole,
        }
      : {
          id: 'system',
          fullName: 'Sistema',
          avatarUrl: '',
          email: '',
          appRole: 'viewer',
          projectRole: 'ADMIN',
        },
  })),
});

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
    notes: communication.notes,
    status: communicationStatusReverseMap[communication.status] || communication.status,
    uploader: communication.uploader || null,
    parentId: communication.parentId || null,
    attachments: (communication.attachments || []).map(buildAttachmentResponse),
    statusHistory: (communication.statusHistory || []).map((history: any) => ({
      ...history,
      status: communicationStatusReverseMap[history.status] || history.status,
      timestamp: history.timestamp instanceof Date ? history.timestamp.toISOString() : history.timestamp,
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

const mapReportVersionSummary = (report: any) => ({
  id: report.id,
  version: report.version,
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


// Ruta de ping para verificar que el servidor está funcionando
app.get("/api/ping", (req, res) => {
  console.log("!!! PING RECIBIDO !!!");
  res.json({ message: "pong" });
});

// --- INICIO: Endpoint del Chatbot ---
// --- INICIO: Endpoint del Chatbot (Versión OpenAI) ---
app.post("/api/chatbot/query", authMiddleware, async (req: AuthRequest, res) => {
  const { query } = req.body;
  const userId = req.user?.userId;

  if (!query) {
    return res.status(400).json({ error: "No se proporcionó una consulta (query)." });
  }
  if (!userId) {
    return res.status(401).json({ error: "Usuario no autenticado." });
  }

  try {
    const [project, contractModifications, ultimaAnotacion] = await Promise.all([
      prisma.project.findFirst({
        include: { keyPersonnel: true },
      }),
      prisma.contractModification.findMany({
        orderBy: { date: "desc" },
      }),
      prisma.logEntry.findFirst({
        orderBy: { createdAt: "desc" },
        include: { author: { select: { fullName: true } } },
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

    const contextoSecciones: string[] = [];

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

      contextoSecciones.push(
        `Resumen del proyecto:\n${projectSummary.join("\n")}`
      );

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
        contextoSecciones.push(
          `Modificaciones contractuales recientes (máx. 5):\n${modificationsSummary}`
        );
      }
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

      contextoSecciones.push(
        `Última anotación registrada en la bitácora:\n${ultimaAnotacionResumen}`
      );
    }

    const contexto =
      contextoSecciones.join("\n\n") ||
      "No se encontró información contextual relevante en la base de datos.";

    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      temperature: 0.2,
      messages: [
        {
          role: "system",
          content:
            "Eres el asistente virtual de la Bitácora de Obra. Usa únicamente la información del contexto proporcionado. Si los datos no están en el contexto, indica con claridad que no cuentas con esa información. Responde siempre en español y en un máximo de 4 frases.",
        },
        {
          role: "user",
          content: `Contexto disponible:
${contexto}

---

Pregunta del usuario:
${query}`,
        },
      ],
    });

    const botResponse =
      completion.choices?.[0]?.message?.content?.trim() ||
      "No pude generar una respuesta.";

    res.json({ response: botResponse });

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


// --- Endpoint para subir un único archivo ---
app.post("/api/upload", async (req, res) => {
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
app.post("/api/contract-modifications", authMiddleware, async (req: AuthRequest, res) => {
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
      uploaderId,
      attachments = [],
    } = req.body;
    const prismaDeliveryMethod = deliveryMethodMap[deliveryMethod] || "SYSTEM";
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
        uploader: { connect: { id: uploaderId } },
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
        attachments: true,
        statusHistory: { include: { user: true }, orderBy: { timestamp: "asc" } },
      },
    });
    const formattedComm = formatCommunication(newComm);
    formattedComm.attachments = (newComm.attachments || []).map(buildAttachmentResponse);
    res.status(201).json(formattedComm);
  } catch (error) {
    console.error("Error al crear la comunicación:", error);
    res.status(500).json({ error: "No se pudo crear la comunicación." });
  }
});

app.put("/api/communications/:id/status", authMiddleware, async (req: AuthRequest, res) => {
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

app.post("/api/drawings", async (req, res) => {
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

app.post("/api/drawings/:id/versions", async (req, res) => {
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

app.post("/api/drawings/:id/comments", async (req, res) => {
  try {
    const { id } = req.params;
    const { content, authorId } = req.body;
    if (!content || !authorId) {
      return res
        .status(400)
        .json({ error: "El contenido y el autor son obligatorios." });
    }
    const newComment = await prisma.comment.create({
      data: {
        content,
        author: { connect: { id: authorId } },
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

app.put("/api/actas/:id", authMiddleware, async (req: AuthRequest, res) => {
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

app.put("/api/actas/:actaId/commitments/:commitmentId", authMiddleware, async (req: AuthRequest, res) => {
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

app.post("/api/actas/:actaId/commitments/:commitmentId/reminder", authMiddleware, async (req: AuthRequest, res) => {
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

app.post("/api/actas/:id/signatures", authMiddleware, async (req: AuthRequest, res) => {
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
        comments: { include: { author: true }, orderBy: { timestamp: "asc" } },
        signatures: { include: { signer: true } },
        assignees: true,
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
        comments: { include: { author: true }, orderBy: { timestamp: "asc" } },
        signatures: { include: { signer: true } },
        assignees: true,
        history: { include: { user: true }, orderBy: { timestamp: "desc" } },
      },
    });
    // Formatear enums antes de enviar
    const formattedEntries = entries.map((entry) => ({
      ...entry,
      type:
        Object.keys(entryTypeMap).find(
          (key) => entryTypeMap[key] === entry.type
        ) || entry.type,
      status:
        Object.keys(entryStatusMap).find(
          (key) => entryStatusMap[key] === entry.status
        ) || entry.status,
    }));
    res.json(formattedEntries);
  } catch (error) {
    console.error("Error al obtener las anotaciones:", error);
    res.status(500).json({ error: "No se pudieron obtener las anotaciones." });
  }
});

app.post("/api/log-entries", authMiddleware, (req: AuthRequest, res) => {
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

    // Procesar assignees
    let assignees = [];
    if (formData.assignees) {
      // Si es un string, intentar parsearlo
      if (typeof formData.assignees === 'string' && formData.assignees.startsWith('[')) {
        try {
          assignees = JSON.parse(formData.assignees);
        } catch (e) {
          console.warn('Error parsing assignees array:', e);
          assignees = [];
        }
      } 
      // Si es un objeto o array
      else if (typeof formData.assignees === 'object') {
        assignees = Array.isArray(formData.assignees) ? formData.assignees : [formData.assignees];
      }
    }

    // Extraer IDs de assignees
    const assigneeIds = assignees.map((a: { id: string } | string) => typeof a === 'object' ? a.id : a);

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
            size: file.size,
            type: file.mimetype,
          },
        });
        attachments.push(attachment);
      } catch (e) {
        console.error('Error creating attachment:', e);
      }
    }

    // Validar fechas
    const startDate = new Date(formData.activityStartDate);
    const endDate = new Date(formData.activityEndDate);
    
    if (isNaN(startDate.getTime())) {
      return res.status(400).json({ error: "La fecha de inicio no es válida." });
    }
    if (isNaN(endDate.getTime())) {
      return res.status(400).json({ error: "La fecha de fin no es válida." });
    }
    if (endDate < startDate) {
      return res.status(400).json({ error: "La fecha de fin debe ser posterior a la fecha de inicio." });
    }

    // Validar assignees
    if (!Array.isArray(assignees)) {
      return res.status(400).json({ error: "El formato de los asignados no es válido." });
    }

    // Validar attachments
    if (!Array.isArray(attachments)) {
      return res.status(400).json({ error: "El formato de los adjuntos no es válido." });
    }

    // Mapear tipos enumerados
    const prismaType = entryTypeMap[formData.type] || "GENERAL";
    const prismaStatus = entryStatusMap[formData.status] || "DRAFT";

      // Crear la entrada
    const newEntry = await prisma.logEntry.create({
        data: {
          title: formData.title.trim(),
          description: formData.description?.trim() || "",
          type: prismaType,
          subject: formData.subject?.trim() || "",
          location: formData.location?.trim() || "",
          activityStartDate: new Date(formData.activityStartDate),
          activityEndDate: new Date(formData.activityEndDate),
          isConfidential: isConfidentialValue,
          status: prismaStatus,
          author: { connect: { id: formData.authorId } },
          project: { connect: { id: formData.projectId } },
          assignees: {
            connect: assigneeIds.map((id: string) => ({ id })),
          },
          attachments: {
            connect: attachments.map(att => ({ id: att.id })),
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

    await recordLogEntryChanges(newEntry.id, req.user?.userId || formData.authorId, creationChanges);

    const entryWithHistory = await prisma.logEntry.findUnique({
      where: { id: newEntry.id },
      include: {
        author: true,
        attachments: true,
        comments: { include: { author: true }, orderBy: { timestamp: "asc" } },
        signatures: { include: { signer: true } },
        assignees: true,
        history: { include: { user: true }, orderBy: { timestamp: "desc" } },
      },
    });

    res.status(201).json(formatLogEntry(entryWithHistory));
  } catch (error: any) {
    console.error("Error al crear la anotación:", error);

    // Manejar errores específicos
    if (error.code === 'P2002') {
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

app.put("/api/log-entries/:id", authMiddleware, async (req: AuthRequest, res) => {
  try {
    const { id } = req.params;
    const existingEntry = await prisma.logEntry.findUnique({
      where: { id },
      include: {
        attachments: true,
        assignees: true,
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
      isConfidential,
      status,
      assignees = [],
      attachments = [],
    } = req.body;
    const prismaType = entryTypeMap[type] || "GENERAL";
    const prismaStatus = entryStatusMap[status] || "DRAFT";
    const updatedEntry = await prisma.logEntry.update({
      where: { id: id },
      data: {
        title,
        description,
        type: prismaType,
        subject,
        location,
        activityStartDate: new Date(activityStartDate),
        activityEndDate: new Date(activityEndDate),
        isConfidential,
        status: prismaStatus,
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
      },
      include: {
        author: true,
        attachments: true,
        comments: { include: { author: true }, orderBy: { timestamp: "asc" } },
        signatures: { include: { signer: true } },
        assignees: true,
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
    if (activityStartDate !== undefined) {
      const oldValue = formatDate(existingEntry.activityStartDate);
      const newValue = formatDate(updatedEntry.activityStartDate);
      if (oldValue !== newValue) {
        changes.push({ fieldName: 'Fecha Inicio Actividad', oldValue, newValue });
      }
    }
    if (activityEndDate !== undefined) {
      const oldValue = formatDate(existingEntry.activityEndDate);
      const newValue = formatDate(updatedEntry.activityEndDate);
      if (oldValue !== newValue) {
        changes.push({ fieldName: 'Fecha Fin Actividad', oldValue, newValue });
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
        history: { include: { user: true }, orderBy: { timestamp: "desc" } },
      },
    });

    res.json(formatLogEntry(refreshedEntry));
  } catch (error) {
    console.error("Error al actualizar la anotación:", error);
    res.status(500).json({ error: "No se pudo actualizar la anotación." });
  }
});

app.delete("/api/log-entries/:id", authMiddleware, async (req: AuthRequest, res) => {
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

app.post("/api/log-entries/:id/comments", authMiddleware, async (req: AuthRequest, res) => {
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

    const newComment = await prisma.comment.create({
      data: {
        content,
        author: { connect: { id: authorId } },
        logEntry: { connect: { id } },
      },
      include: { author: true },
    });

    res.status(201).json(newComment);
  } catch (error) {
    console.error("Error al crear comentario de bitácora:", error);
    res.status(500).json({ error: "No se pudo crear el comentario." });
  }
});

app.post("/api/log-entries/:id/signatures", authMiddleware, async (req: AuthRequest, res) => {
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
      return res.status(401).json({ error: "Contraseña incorrecta." });
    }

    const entryExists = await prisma.logEntry.findUnique({ where: { id } });
    if (!entryExists) {
      return res.status(404).json({ error: "Anotación no encontrada." });
    }

    const existingSignature = await prisma.signature.findFirst({
      where: { logEntryId: id, signerId },
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
          logEntry: { connect: { id } },
        },
      });
    }

    const updatedEntry = await prisma.logEntry.findUnique({
      where: { id },
      include: {
        author: true,
        attachments: true,
        comments: { include: { author: true }, orderBy: { timestamp: "asc" } },
        signatures: { include: { signer: true } },
        assignees: true,
      },
    });

    if (!updatedEntry) {
      return res.status(404).json({ error: "Anotación no encontrada tras firmar." });
    }

    const formattedEntry = {
      ...updatedEntry,
      type: entryTypeReverseMap[updatedEntry.type] || updatedEntry.type,
      status: entryStatusReverseMap[updatedEntry.status] || updatedEntry.status,
    };

    res.json(formattedEntry);
  } catch (error) {
    console.error("Error al firmar anotación:", error);
    res.status(500).json({ error: "No se pudo firmar la anotación." });
  }
});

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

app.post("/api/work-actas", authMiddleware, async (req: AuthRequest, res) => {
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

app.put("/api/work-actas/:id", authMiddleware, async (req: AuthRequest, res) => {
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
app.post("/api/cost-actas", async (req, res) => {
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

app.put("/api/cost-actas/:id", async (req, res) => {
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
app.post("/api/cost-actas/:id/observations", async (req, res) => {
  try {
    const { id } = req.params;
    const { text, authorId } = req.body;

    if (!text || !authorId) {
      return res.status(400).json({
        error: "El texto y el autor son obligatorios para la observación.",
      });
    }

    const newObservation = await prisma.observation.create({
      data: {
        text,
        author: { connect: { id: authorId } },
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
      },
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
app.post("/api/reports", async (req, res) => {
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

    if (!period || !submissionDate || !summary || !authorId) {
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
        author: { connect: { id: authorId } },
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
      },
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
app.put("/api/reports/:id", async (req, res) => {
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
      },
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
app.post("/api/reports/:id/signatures", async (req, res) => {
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
      },
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
app.post("/api/control-points", async (req, res) => {
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
app.post("/api/control-points/:id/photos", async (req, res) => {
  try {
    const { id } = req.params; // ID del ControlPoint
    // Recibe el ID del Attachment y las notas
    const { notes, authorId, attachmentId } = req.body;

    if (!authorId || !attachmentId) {
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
        author: { connect: { id: authorId } },
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

app.post("/api/project-tasks/import", authMiddleware, async (req: AuthRequest, res) => {
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
        },
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
