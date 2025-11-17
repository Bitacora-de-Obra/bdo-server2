import { logger } from "../../logger";

const RESEND_API_URL = "https://api.resend.com/emails";

const resendApiKey = process.env.RESEND_API_KEY;
const resendFrom = process.env.RESEND_FROM;
const resendMode = process.env.RESEND_MODE || "live";

interface ResendEmailPayload {
  to: string | string[];
  subject: string;
  html?: string;
  text?: string;
  cc?: string | string[];
  bcc?: string | string[];
  replyTo?: string;
}

export const isResendConfigured = (): boolean => Boolean(resendApiKey && resendFrom);

export const sendEmailWithResend = async (
  payload: ResendEmailPayload
): Promise<boolean> => {
  if (!isResendConfigured()) {
    throw new Error("Resend no está configurado.");
  }

  const body = {
    ...payload,
    from: resendFrom!,
    to: Array.isArray(payload.to) ? payload.to : [payload.to],
    cc: payload.cc
      ? Array.isArray(payload.cc)
        ? payload.cc
        : [payload.cc]
      : undefined,
    bcc: payload.bcc
      ? Array.isArray(payload.bcc)
        ? payload.bcc
        : [payload.bcc]
      : undefined,
    text: payload.text,
    html: payload.html,
    reply_to: payload.replyTo,
    ...(resendMode === "test" ? { test_mode: true } : {}),
  };

  const response = await fetch(RESEND_API_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${resendApiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    logger.error("Resend falló al enviar correo", {
      status: response.status,
      error: errorBody,
    });
    throw new Error(`Resend respondió ${response.status}`);
  }

  return true;
};

