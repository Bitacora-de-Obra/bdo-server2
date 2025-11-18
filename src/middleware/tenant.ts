/**
 * Middleware para detectar y validar el tenant desde el subdominio
 */

import { Request, Response, NextFunction } from "express";
import { PrismaClient } from "@prisma/client";
import { logger } from "../logger";

const prisma = new PrismaClient();

// Extender el tipo Request para incluir tenant
declare global {
  namespace Express {
    interface Request {
      tenant?: {
        id: string;
        subdomain: string;
        name: string;
        domain: string;
        isActive: boolean;
      };
    }
  }
}

/**
 * Extrae el subdominio del hostname
 * Ejemplos:
 *   "mutis.bdigitales.com" -> "mutis"
 *   "www.bdigitales.com" -> null
 *   "localhost:3000" -> null
 */
function extractSubdomain(hostname: string | undefined): string | null {
  if (!hostname) return null;

  // Remover puerto si existe
  const host = hostname.split(":")[0];

  // Dividir por puntos
  const parts = host.split(".");

  // Si tiene al menos 3 partes (subdomain.domain.tld), extraer el subdominio
  if (parts.length >= 3) {
    return parts[0]; // Primer elemento es el subdominio
  }

  // Si tiene 2 partes y no es "www", podría ser un subdominio
  // Pero por seguridad, solo aceptamos subdominios explícitos
  return null;
}

/**
 * Middleware para detectar el tenant desde el subdominio
 * Agrega req.tenant al request si se encuentra un tenant válido
 */
export async function detectTenantMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    // Obtener el hostname del request
    const host = Array.isArray(req.headers.host) 
      ? req.headers.host[0] 
      : req.headers.host || "";
    const forwardedHost = Array.isArray(req.headers["x-forwarded-host"])
      ? req.headers["x-forwarded-host"][0]
      : req.headers["x-forwarded-host"] || "";
    const origin = Array.isArray(req.headers.origin)
      ? req.headers.origin[0]
      : req.headers.origin || "";
    
    const hostname = host || forwardedHost;
    
    // Intentar extraer subdominio del host o origin
    const subdomain = extractSubdomain(hostname) || extractSubdomain(origin);

    if (!subdomain) {
      // Si no hay subdominio, no es un request multi-tenant
      // Permitir continuar sin tenant (para desarrollo local o requests sin subdominio)
      logger.debug("No se detectó subdominio, continuando sin tenant", {
        host,
        origin,
      });
      return next();
    }

    // Buscar tenant por subdomain
    // Nota: Prisma Client se generará después de aplicar la migración
    // Por ahora usamos $queryRaw como fallback
    const tenant = await prisma.$queryRawUnsafe<Array<{
      id: string;
      subdomain: string;
      name: string;
      domain: string;
      isActive: boolean;
    }>>(
      `SELECT id, subdomain, name, domain, isActive FROM Tenant WHERE subdomain = ? LIMIT 1`,
      subdomain
    ).then(results => results[0] || null);

    if (!tenant) {
      logger.warn("Tenant no encontrado", { subdomain, host, origin });
      res.status(404).json({
        error: "Tenant no encontrado",
        message: `El subdominio "${subdomain}" no está registrado.`,
      });
      return;
    }

    if (!tenant.isActive) {
      logger.warn("Tenant inactivo", { subdomain, tenantId: tenant.id });
      res.status(403).json({
        error: "Tenant inactivo",
        message: `El tenant "${tenant.name}" está inactivo.`,
      });
      return;
    }

    // Agregar tenant al request
    req.tenant = {
      id: tenant.id,
      subdomain: tenant.subdomain,
      name: tenant.name,
      domain: tenant.domain,
      isActive: tenant.isActive,
    };

    logger.debug("Tenant detectado", {
      tenantId: tenant.id,
      subdomain: tenant.subdomain,
      name: tenant.name,
    });

    next();
  } catch (error) {
    logger.error("Error al detectar tenant", { error });
    res.status(500).json({
      error: "Error interno del servidor",
      message: "No se pudo detectar el tenant.",
    });
  }
}

/**
 * Middleware que requiere que el request tenga un tenant
 * Útil para endpoints que siempre requieren multi-tenancy
 */
export function requireTenantMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  if (!req.tenant) {
    res.status(400).json({
      error: "Tenant requerido",
      message: "Este endpoint requiere un tenant válido.",
    });
    return;
  }
  next();
}

