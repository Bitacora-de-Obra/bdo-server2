import type { Request } from "express";

const getHeaderValue = (value?: string | string[] | null): string | null => {
  if (!value) return null;
  if (Array.isArray(value)) {
    return value.length ? value[0] : null;
  }
  return value;
};

/**
 * Construye la URL base (protocolo + host) a partir de un request,
 * priorizando Origin para respetar el subdominio con el que el usuario accedió.
 */
export const getRequestBaseUrl = (req: Request): string | null => {
  const parseUrl = (value: string) => {
    try {
      const url = new URL(value);
      return `${url.protocol}//${url.host}`.replace(/\/$/, "");
    } catch {
      return value.replace(/\/$/, "");
    }
  };

  const origin = getHeaderValue(req.headers.origin);
  if (origin) {
    return parseUrl(origin);
  }

  const referer = getHeaderValue(req.headers.referer);
  if (referer) {
    return parseUrl(referer);
  }

  const forwardedProto = getHeaderValue(req.headers["x-forwarded-proto"]);
  const forwardedHost = getHeaderValue(req.headers["x-forwarded-host"]);
  const host = forwardedHost || getHeaderValue(req.headers.host);

  if (host) {
    const protocol = forwardedProto || req.protocol || "https";
    return `${protocol}://${host}`.replace(/\/$/, "");
  }

  return null;
};

