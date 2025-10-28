import nodemailer from "nodemailer";
import { logger } from "../../logger";

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

const smtpHost = process.env.SMTP_HOST;
const smtpPort = Number(process.env.SMTP_PORT || 587);
const smtpSecure = process.env.SMTP_SECURE === "true";
const smtpUser = process.env.SMTP_USER;
const smtpPass = process.env.SMTP_PASS;
const defaultFrom =
  process.env.EMAIL_FROM || smtpUser || "no-reply@bitacora-digital.local";

let transporterRef: nodemailer.Transporter | null = null;

export const isEmailServiceConfigured = () => Boolean(smtpHost);

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

  const html = `
    <p>Hola ${displayName},</p>
    <p>Hemos recibido una solicitud para verificar tu cuenta. Completa el proceso haciendo clic en el siguiente enlace:</p>
    <p><a href="${verificationUrl}" target="_blank" rel="noopener noreferrer">Verificar correo</a></p>
    <p>Si no solicitaste esta verificación, puedes ignorar este mensaje.</p>
  `;

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

  const html = `
    <p>Hola ${displayName},</p>
    <p>Recibimos una solicitud para restablecer tu contraseña. Si fuiste tú, utiliza el enlace a continuación:</p>
    <p><a href="${resetUrl}" target="_blank" rel="noopener noreferrer">Restablecer contraseña</a></p>
    <p>Si no solicitaste este cambio, ignora este correo.</p>
  `;

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

  const html = `
    <p>Hola ${displayName},</p>
    <p>${summaryLine}${introDays}:</p>
    <ul>
      ${htmlItems.join("")}
    </ul>
    <p>Ingresa a Bitácora Digital para actualizar el estado de estos compromisos.</p>
    <p>Gracias.</p>
  `;

  await sendEmail({
    to,
    subject,
    html,
    text: textLines.join("\n"),
    cc: ccList.length ? ccList : undefined,
    bcc: bccList.length ? bccList : undefined,
  });
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

  const html = `
    <p>Hola ${displayRecipient},</p>
    <p>${assignerDisplay} te asignó el seguimiento de la comunicación con radicado <strong>${communication.radicado}</strong>.</p>
    <ul>
      <li><strong>Asunto:</strong> ${communication.subject}</li>
      ${
        sentDateLabel
          ? `<li><strong>Fecha de envío:</strong> ${sentDateLabel}</li>`
          : ""
      }
      ${
        dueDateLabel
          ? `<li><strong>Fecha límite para respuesta:</strong> ${dueDateLabel}</li>`
          : "<li><strong>Fecha límite:</strong> No registrada</li>"
      }
    </ul>
    <p>Ingresa a la Bitácora Digital para gestionar la comunicación:</p>
    <p><a href="${communicationsLink}" target="_blank" rel="noopener noreferrer">${communicationsLink}</a></p>
    <p>Gracias.</p>
  `;

  await sendEmail({
    to,
    subject,
    html,
    text: textLines.join("\n"),
  });
};
