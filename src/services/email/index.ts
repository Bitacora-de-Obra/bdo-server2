import nodemailer from "nodemailer";
import { logger } from "../../logger";
import {
  isResendConfigured,
  sendEmailWithResend,
} from "./resendClient";
import {
  getEmailBaseTemplate,
  getEmailButton,
  getEmailInfoBox,
} from "./templates";

interface SendEmailOptions {
  to: string;
  subject: string;
  html: string;
  text: string;
  cc?: string | string[];
  bcc?: string | string[];
}

interface SendVerificationParams {
  to: string;
  token: string;
  fullName?: string | null;
}

interface SendResetParams extends SendVerificationParams {}

interface CommitmentReminder {
  id: string;
  description: string;
  dueDate: Date;
  actaNumber?: string | null;
  actaTitle?: string | null;
  daysUntilDue: number;
}

interface SendCommitmentReminderParams {
  to: string;
  recipientName?: string | null;
  commitments: CommitmentReminder[];
  timezone?: string;
  daysAhead?: number;
  cc?: string[];
  bcc?: string[];
}

interface SendCommunicationAssignmentParams {
  to: string;
  recipientName?: string | null;
  assignerName?: string | null;
  communication: {
    radicado: string;
    subject: string;
    sentDate?: Date | string | null;
    dueDate?: Date | string | null;
    responseDueDate?: Date | string | null;
  };
}

interface SendSignatureAssignmentParams {
  to: string;
  recipientName?: string | null;
  assignerName?: string | null;
  logEntry: {
    id: string;
    folioNumber: number;
    title: string;
    entryDate?: Date | string | null;
  };
}

const smtpHost = process.env.SMTP_HOST;
const smtpPort = Number(process.env.SMTP_PORT || 587);
const smtpSecure = process.env.SMTP_SECURE === "true";
const smtpUser = process.env.SMTP_USER;
const smtpPass = process.env.SMTP_PASS;
const defaultFrom =
  process.env.EMAIL_FROM || smtpUser || "no-reply@bitacora-digital.local";
const useResend = isResendConfigured();

let transporterRef: nodemailer.Transporter | null = null;

export const isEmailServiceConfigured = () => Boolean(smtpHost);

export const getEmailConfigurationSummary = () => ({
  configured: isEmailServiceConfigured(),
  host: smtpHost || null,
  port: smtpPort,
  secure: smtpSecure,
  defaultFrom,
  auth: smtpUser
    ? {
        user: smtpUser,
        hasPassword: Boolean(smtpPass),
      }
    : null,
  overrides: {
    emailVerificationUrl: Boolean(process.env.EMAIL_VERIFICATION_URL),
    passwordResetUrl: Boolean(process.env.PASSWORD_RESET_URL),
    commitmentReminderCc: Boolean(process.env.COMMITMENT_REMINDER_CC),
    commitmentReminderBcc: Boolean(process.env.COMMITMENT_REMINDER_BCC),
  },
});

const getTransporter = () => {
  if (!isEmailServiceConfigured()) {
    return null;
  }

  if (!transporterRef) {
    transporterRef = nodemailer.createTransport({
      host: smtpHost,
      port: smtpPort,
      secure: smtpSecure,
      auth: smtpUser
        ? {
            user: smtpUser,
            pass: smtpPass || "",
          }
        : undefined,
    });
  }

  return transporterRef;
};

const getAppBaseUrl = () => {
  const explicit =
    process.env.APP_BASE_URL || process.env.FRONTEND_URL || process.env.BASE_URL;
  if (explicit) {
    return explicit.replace(/\/$/, "");
  }
  const port = process.env.PORT || "4001";
  return `http://localhost:${port}`;
};

const buildLinkFromTemplate = (
  template: string | undefined,
  token: string,
  fallbackPath: string
) => {
  const baseTemplate =
    template ||
    `${getAppBaseUrl()}${fallbackPath}${
      fallbackPath.includes("?") ? "&" : "?"
    }token={{token}}`;

  return baseTemplate.replace("{{token}}", encodeURIComponent(token));
};

const sendEmail = async ({
  to,
  subject,
  html,
  text,
  cc,
  bcc,
}: SendEmailOptions): Promise<boolean> => {
  if (useResend) {
    try {
      await sendEmailWithResend({
        to,
        subject,
        html,
        text,
        cc,
        bcc,
      });
      logger.debug("Correo enviado vía Resend", { to, subject });
      return true;
    } catch (error) {
      logger.error("Fallo envío con Resend. Se intentará SMTP.", {
        error: error instanceof Error ? error.message : String(error),
        to,
        subject,
      });
      // Continua a SMTP fallback
    }
  }

  const transporter = getTransporter();

  if (!transporter) {
    logger.warn("SMTP no configurado; se omite el envío de correo.", {
      to,
      subject,
    });
    logger.info("Contenido del correo omitido (modo desarrollo):", {
      to,
      subject,
      text,
    });
    return false;
  }

  try {
    await transporter.sendMail({
      from: defaultFrom,
      to,
      subject,
      html,
      text,
      cc,
      bcc,
    });
    return true;
  } catch (error) {
    logger.error("No se pudo enviar el correo electrónico.", {
      to,
      subject,
      error,
    });
    throw error;
  }
};

export const sendEmailVerificationEmail = async ({
  to,
  token,
  fullName,
}: SendVerificationParams) => {
  const verificationUrl = buildLinkFromTemplate(
    process.env.EMAIL_VERIFICATION_URL,
    token,
    "/auth/verify-email"
  );

  const displayName = fullName || "Usuario";

  const subject = "Verifica tu correo electrónico";
  const text = [
    `Hola ${displayName},`,
    "",
    "Hemos recibido una solicitud para verificar tu cuenta. Completa el proceso haciendo clic en el siguiente enlace:",
    verificationUrl,
    "",
    "Si no solicitaste esta verificación, puedes ignorar este mensaje.",
  ].join("\n");

  const content = `
    <h1>Verifica tu correo electrónico</h1>
    <p>Hola <strong>${displayName}</strong>,</p>
    <p>Hemos recibido una solicitud para verificar tu cuenta en Bitácora Digital de Obra. Para completar el proceso, haz clic en el siguiente botón:</p>
    ${getEmailButton("Verificar correo electrónico", verificationUrl)}
    <p>O copia y pega este enlace en tu navegador:</p>
    <p style="word-break: break-all; color: #0D47A1;">${verificationUrl}</p>
    ${getEmailInfoBox("Si no solicitaste esta verificación, puedes ignorar este mensaje de forma segura.", "warning")}
  `;
  const html = getEmailBaseTemplate(content);

  await sendEmail({ to, subject, html, text });
};

export const sendPasswordResetEmail = async ({
  to,
  token,
  fullName,
}: SendResetParams) => {
  const resetUrl = buildLinkFromTemplate(
    process.env.PASSWORD_RESET_URL,
    token,
    "/auth/reset-password"
  );

  const displayName = fullName || "Usuario";

  const subject = "Restablece tu contraseña";
  const text = [
    `Hola ${displayName},`,
    "",
    "Recibimos una solicitud para restablecer tu contraseña. Si fuiste tú, utiliza el enlace a continuación:",
    resetUrl,
    "",
    "Si no solicitaste este cambio, ignora este correo.",
  ].join("\n");

  const content = `
    <h1>Restablece tu contraseña</h1>
    <p>Hola <strong>${displayName}</strong>,</p>
    <p>Recibimos una solicitud para restablecer la contraseña de tu cuenta en Bitácora Digital de Obra.</p>
    <p>Si fuiste tú quien solicitó este cambio, haz clic en el siguiente botón para crear una nueva contraseña:</p>
    ${getEmailButton("Restablecer contraseña", resetUrl)}
    <p>O copia y pega este enlace en tu navegador:</p>
    <p style="word-break: break-all; color: #0D47A1;">${resetUrl}</p>
    ${getEmailInfoBox("Este enlace expirará en 1 hora por seguridad. Si no solicitaste este cambio, ignora este correo de forma segura.", "warning")}
  `;
  const html = getEmailBaseTemplate(content);

  await sendEmail({ to, subject, html, text });
};

const formatDateLabel = (value?: Date | string | null) => {
  if (!value) {
    return null;
  }
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    return null;
  }
  return date.toLocaleDateString("es-CO", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });
};

const parseAddressList = (value?: string | null) =>
  value
    ?.split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0) ?? [];

const formatCommitmentDate = (
  date: Date,
  timezone?: string,
  locale = "es-CO"
) => {
  try {
    const formatter = new Intl.DateTimeFormat(locale, {
      year: "numeric",
      month: "long",
      day: "numeric",
      timeZone: timezone,
    });
    return formatter.format(date);
  } catch (_error) {
    return date.toISOString().split("T")[0];
  }
};

export const sendCommitmentReminderEmail = async ({
  to,
  recipientName,
  commitments,
  timezone,
  daysAhead,
  cc,
  bcc,
}: SendCommitmentReminderParams) => {
  if (!commitments.length) {
    return;
  }

  const ccList = cc ?? parseAddressList(process.env.COMMITMENT_REMINDER_CC);
  const bccList =
    bcc ?? parseAddressList(process.env.COMMITMENT_REMINDER_BCC);

  const displayName = recipientName || "equipo del proyecto";
  const summaryLine =
    commitments.length === 1
      ? "Tienes un compromiso próximo a vencer."
      : `Tienes ${commitments.length} compromisos próximos a vencer.`;

  const subject =
    process.env.COMMITMENT_REMINDER_SUBJECT ||
    `Recordatorio de compromisos próximos (${commitments.length})`;

  const introDays =
    typeof daysAhead === "number"
      ? ` durante los próximos ${daysAhead} día${
          daysAhead === 1 ? "" : "s"
        }`
      : "";

  const textLines: string[] = [
    `Hola ${displayName},`,
    "",
    `${summaryLine}${introDays}.`,
    "",
  ];

  const htmlItems: string[] = [];

  commitments.forEach((commitment) => {
    const titleParts = [
      commitment.actaNumber ? `Acta ${commitment.actaNumber}` : null,
      commitment.actaTitle || null,
    ].filter(Boolean);
    const dueDateFormatted = formatCommitmentDate(
      commitment.dueDate,
      timezone
    );
    const daysInfo =
      commitment.daysUntilDue < 0
        ? "Vencido"
        : commitment.daysUntilDue === 0
        ? "Vence hoy"
        : `Vence en ${commitment.daysUntilDue} día${
            commitment.daysUntilDue === 1 ? "" : "s"
          }`;

    textLines.push(
      `- ${commitment.description} · ${titleParts.join(" · ")} · Fecha límite: ${dueDateFormatted} (${daysInfo})`
    );

    htmlItems.push(
      `<li><strong>${commitment.description}</strong><br/><span>${titleParts.join(
        " · "
      )}</span><br/><span>Fecha límite: ${dueDateFormatted} (${daysInfo})</span></li>`
    );
  });

  textLines.push(
    "",
    "Por favor ingresa a Bitácora Digital para actualizar el estado de estos compromisos.",
    "",
    "Gracias."
  );

  const content = `
    <h1>Recordatorio de Compromisos</h1>
    <p>Hola <strong>${displayName}</strong>,</p>
    <p>${summaryLine}${introDays}:</p>
    <ul style="list-style: none; padding: 0;">
      ${htmlItems.map(item => `<li style="background-color: #f9fafb; padding: 16px; margin: 12px 0; border-radius: 6px; border-left: 4px solid #0D47A1;">${item}</li>`).join("")}
    </ul>
    <p>Por favor ingresa a Bitácora Digital para actualizar el estado de estos compromisos.</p>
    ${getEmailButton("Ver Mis Pendientes", `${getAppBaseUrl()}#/pending_tasks`)}
    <p>Gracias por tu atención.</p>
  `;
  const html = getEmailBaseTemplate(content);

  await sendEmail({
    to,
    subject,
    html,
    text: textLines.join("\n"),
    cc: ccList.length ? ccList : undefined,
    bcc: bccList.length ? bccList : undefined,
  });
};

export const verifyEmailTransporter = async () => {
  const transporter = getTransporter();
  if (!transporter) {
    throw new Error(
      "El servicio de correo no está configurado. Define las variables SMTP_HOST, SMTP_PORT, SMTP_USER/PASS."
    );
  }

  try {
    await transporter.verify();
    return true;
  } catch (error) {
    logger.error("Error al verificar el transporte SMTP.", { error });
    throw error;
  }
};

export const sendTestEmail = async (to: string, initiatedBy?: string) => {
  if (!to) {
    throw new Error("Debes indicar un correo de destino para la prueba.");
  }

  if (!isEmailServiceConfigured()) {
    throw new Error(
      "El servicio de correo no está configurado. Configura SMTP_HOST para habilitarlo."
    );
  }

  const subject = "Bitácora Digital · Correo de prueba";
  const intro = initiatedBy
    ? `Este mensaje fue solicitado por ${initiatedBy}.`
    : "Este mensaje fue generado desde la herramienta de diagnóstico.";

  const content = `
    <h1>Correo de Prueba</h1>
    <p>Hola,</p>
    <p>${intro}</p>
    ${getEmailInfoBox(`El envío confirma que la configuración SMTP de Bitácora Digital está operativa.<br/><br/><strong>Fecha y hora:</strong> ${new Date().toLocaleString("es-CO", {
      timeZone: process.env.REMINDER_TIMEZONE || "America/Bogota",
    })}`, "info")}
    <p>Si tú no solicitaste esta prueba, puedes ignorar este correo de forma segura.</p>
  `;
  const html = getEmailBaseTemplate(content);

  const text = [
    "Hola,",
    intro,
    "El envío confirma que la configuración SMTP de Bitácora Digital está operativa.",
    `Fecha y hora: ${new Date().toLocaleString("es-CO", {
      timeZone: process.env.REMINDER_TIMEZONE || "America/Bogota",
    })}`,
    "",
    "Si tú no solicitaste esta prueba, puedes ignorar este correo.",
  ].join("\n");

  const sent = await sendEmail({ to, subject, html, text });

  if (!sent) {
    throw new Error(
      "El correo de prueba no se envió porque el servicio está en modo 'desactivado' (sin SMTP_HOST)."
    );
  }

  return true;
};

export const sendCommunicationAssignmentEmail = async ({
  to,
  recipientName,
  assignerName,
  communication,
}: SendCommunicationAssignmentParams) => {
  const displayRecipient = recipientName || "equipo";
  const assignerDisplay = assignerName || "un miembro del equipo";
  const dueDateLabel = formatDateLabel(communication.responseDueDate ?? communication.dueDate);
  const sentDateLabel = formatDateLabel(communication.sentDate);
  const baseUrl = getAppBaseUrl();
  const communicationsLink = `${baseUrl}#/pending_tasks`;

  const subject = `Nueva comunicación asignada · Radicado ${communication.radicado}`;

  const textLines = [
    `Hola ${displayRecipient},`,
    "",
    `${assignerDisplay} te asignó el seguimiento de la comunicación con radicado ${communication.radicado}.`,
    `Asunto: ${communication.subject}`,
  ];

  if (sentDateLabel) {
    textLines.push(`Fecha de envío: ${sentDateLabel}`);
  }

  if (dueDateLabel) {
    textLines.push(`Fecha límite para respuesta: ${dueDateLabel}`);
  } else {
    textLines.push(
      "Esta comunicación no tiene una fecha límite registrada. Revisa los detalles para acordar plazos."
    );
  }

  textLines.push(
    "",
    `Ingresa a la Bitácora Digital y consulta la sección "Mis Pendientes" o "Comunicaciones Oficiales" para registrar el avance:`,
    communicationsLink,
    "",
    "Gracias."
  );

  const content = `
    <h1>Nueva Comunicación Asignada</h1>
    <p>Hola <strong>${displayRecipient}</strong>,</p>
    <p>${assignerDisplay} te asignó el seguimiento de una comunicación oficial.</p>
    ${getEmailInfoBox(`
      <strong>Radicado:</strong> ${communication.radicado}<br/>
      <strong>Asunto:</strong> ${communication.subject}<br/>
      ${sentDateLabel ? `<strong>Fecha de envío:</strong> ${sentDateLabel}<br/>` : ""}
      ${dueDateLabel ? `<strong>Fecha límite para respuesta:</strong> ${dueDateLabel}` : "<strong>Fecha límite:</strong> No registrada"}
    `, "info")}
    <p>Ingresa a la Bitácora Digital para gestionar esta comunicación:</p>
    ${getEmailButton("Ver Comunicación", communicationsLink)}
    <p>Gracias.</p>
  `;
  const html = getEmailBaseTemplate(content);

  await sendEmail({
    to,
    subject,
    html,
    text: textLines.join("\n"),
  });
};

export const sendSignatureAssignmentEmail = async ({
  to,
  recipientName,
  assignerName,
  logEntry,
}: SendSignatureAssignmentParams) => {
  const displayRecipient = recipientName || "equipo";
  const assignerDisplay = assignerName || "un miembro del equipo";
  const entryDateLabel = formatDateLabel(logEntry.entryDate);
  const baseUrl = getAppBaseUrl();
  const logEntryLink = `${baseUrl}#/log-entries/${logEntry.id}`;

  const subject = `Nueva bitácora asignada para firma · Folio #${logEntry.folioNumber}`;

  const textLines = [
    `Hola ${displayRecipient},`,
    "",
    `${assignerDisplay} te asignó una bitácora para su revisión y firma.`,
    "",
    `Folio: #${logEntry.folioNumber}`,
    `Título: ${logEntry.title}`,
  ];

  if (entryDateLabel) {
    textLines.push(`Fecha de la bitácora: ${entryDateLabel}`);
  }

  textLines.push(
    "",
    `Ingresa a la Bitácora Digital para revisar y firmar la bitácora:`,
    logEntryLink,
    "",
    "Gracias."
  );

  const content = `
    <h1>Bitácora Asignada para Firma</h1>
    <p>Hola <strong>${displayRecipient}</strong>,</p>
    <p>${assignerDisplay} te asignó una bitácora para su revisión y firma.</p>
    ${getEmailInfoBox(`
      <strong>Folio:</strong> #${logEntry.folioNumber}<br/>
      <strong>Título:</strong> ${logEntry.title}<br/>
      ${entryDateLabel ? `<strong>Fecha de la bitácora:</strong> ${entryDateLabel}` : ""}
    `, "info")}
    <p>Ingresa a la Bitácora Digital para revisar y firmar la bitácora:</p>
    ${getEmailButton("Revisar y Firmar Bitácora", logEntryLink)}
    <p>Gracias.</p>
  `;
  const html = getEmailBaseTemplate(content);

  await sendEmail({
    to,
    subject,
    html,
    text: textLines.join("\n"),
  });
};

interface SendSecurityAlertEmailParams {
  to: string[];
  event: {
    type: string;
    severity: string;
    timestamp: Date;
    ipAddress?: string;
    userId?: string;
    email?: string;
    path?: string;
    method?: string;
    details?: Record<string, any>;
  };
}

export const sendSecurityAlertEmail = async ({
  to,
  event,
}: SendSecurityAlertEmailParams) => {
  if (!to.length) {
    return;
  }

  const eventDate = new Date(event.timestamp);
  const timezone = process.env.REMINDER_TIMEZONE || "America/Bogota";
  const formattedDate = eventDate.toLocaleString("es-CO", { timeZone: timezone });

  const subject = `[Alerta de Seguridad · ${event.severity.toUpperCase()}] ${event.type}`;

  const detailLines = [
    `Tipo: ${event.type}`,
    `Severidad: ${event.severity}`,
    `Fecha/Hora: ${formattedDate}`,
    `IP: ${event.ipAddress || "desconocida"}`,
    `Usuario: ${event.userId || "N/A"}`,
    `Correo asociado: ${event.email || "N/A"}`,
    `Ruta: ${event.path || "N/A"}`,
    `Método: ${event.method || "N/A"}`,
  ];

  if (event.details && Object.keys(event.details).length > 0) {
    detailLines.push("", "Detalles adicionales:", JSON.stringify(event.details, null, 2));
  }

  const severityColor = event.severity === 'critical' ? '#C62828' : event.severity === 'high' ? '#F9A825' : '#0D47A1';
  const content = `
    <h1 style="color: ${severityColor};">Alerta de Seguridad</h1>
    <p>Se ha detectado un evento de seguridad que requiere tu atención:</p>
    ${getEmailInfoBox(`
      <strong>Tipo:</strong> ${event.type}<br/>
      <strong>Severidad:</strong> <span style="color: ${severityColor}; font-weight: 600;">${event.severity.toUpperCase()}</span><br/>
      <strong>Fecha/Hora:</strong> ${formattedDate} (${timezone})<br/>
      <strong>IP:</strong> ${event.ipAddress || "desconocida"}<br/>
      <strong>Usuario:</strong> ${event.userId || "N/A"}<br/>
      <strong>Correo asociado:</strong> ${event.email || "N/A"}<br/>
      <strong>Ruta:</strong> ${event.path || "N/A"} (${event.method || "N/A"})
    `, event.severity === 'critical' || event.severity === 'high' ? 'warning' : 'info')}
    ${
      event.details && Object.keys(event.details).length
        ? `<div style="background-color: #f9fafb; padding: 16px; margin: 24px 0; border-radius: 6px; border: 1px solid #e5e7eb;">
            <strong>Detalles adicionales:</strong>
            <pre style="background: #ffffff; padding: 12px; border-radius: 4px; overflow-x: auto; font-size: 12px; margin: 8px 0 0 0;">${JSON.stringify(
              event.details,
              null,
              2
            )}</pre>
          </div>`
        : ""
    }
    <p>Este mensaje se generó automáticamente. Revisa el panel de monitoreo para obtener más contexto.</p>
  `;
  const html = getEmailBaseTemplate(content);

  await sendEmail({
    to: to.join(","),
    subject,
    html,
    text: detailLines.join("\n"),
  });
};
