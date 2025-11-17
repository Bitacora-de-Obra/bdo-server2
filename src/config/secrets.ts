import fs from "fs";
import path from "path";
import crypto from "crypto";
import { logger } from "../logger";

type SecretSource = "env" | "file" | "fallback";

interface ResolveSecretOptions {
  envVar: string;
  fileEnvVar?: string;
  fallbackEnvVar?: string;
  minLength?: number;
  displayName: string;
  required?: boolean;
}

interface SecretResolution {
  value: string;
  source: SecretSource;
  details?: string;
}

const MIN_SECRET_LENGTH = 32;

const weakSecretPatterns = [/^your-secret/i, /^your-refresh/i, /^changeme/i];

const normalize = (value: string) => value.trim();

const readSecretFile = (location: string, displayName: string): string => {
  try {
    const filePath = path.resolve(location);
    const fileContents = fs.readFileSync(filePath, "utf-8");
    return normalize(fileContents);
  } catch (error) {
    throw new Error(
      `[Secrets] No se pudo leer el archivo "${location}" para ${displayName}: ${
        (error as Error).message
      }`
    );
  }
};

const validateSecret = (value: string, displayName: string, minLength: number) => {
  if (!value || value.length < minLength) {
    throw new Error(
      `[Secrets] ${displayName} debe tener al menos ${minLength} caracteres.`
    );
  }

  if (weakSecretPatterns.some((pattern) => pattern.test(value))) {
    throw new Error(
      `[Secrets] ${displayName} parece ser un valor de ejemplo o débil. Genera un secreto seguro.`
    );
  }

  // Verificar entropía aproximada
  const uniqueChars = new Set(value.split("")).size;
  if (uniqueChars < Math.min(16, value.length / 2)) {
    logger.warn(
      `[Secrets] ${displayName} parece tener baja entropía (${uniqueChars} caracteres únicos). Considera regenerarlo.`
    );
  }
};

const resolveSecret = ({
  envVar,
  fileEnvVar,
  fallbackEnvVar,
  minLength = MIN_SECRET_LENGTH,
  displayName,
  required = true,
}: ResolveSecretOptions): SecretResolution => {
  const readAndValidate = (value: string, source: SecretSource, details?: string) => {
    const normalized = normalize(value);
    validateSecret(normalized, displayName, minLength);
    return { value: normalized, source, details };
  };

  if (fileEnvVar) {
    const filePath = process.env[fileEnvVar];
    if (filePath) {
      const fileValue = readSecretFile(filePath, displayName);
      return readAndValidate(fileValue, "file", filePath);
    }
  }

  const directValue = process.env[envVar];
  if (directValue) {
    return readAndValidate(directValue, "env", envVar);
  }

  if (fallbackEnvVar) {
    const fallbackValue = process.env[fallbackEnvVar];
    if (fallbackValue) {
      logger.warn(
        `[Secrets] ${displayName} está usando el fallback ${fallbackEnvVar}. Define ${envVar} para separarlos.`
      );
      return readAndValidate(fallbackValue, "fallback", fallbackEnvVar);
    }
  }

  if (!required) {
    return {
      value: "",
      source: "env",
    };
  }

  throw new Error(
    `[Secrets] Falta ${displayName}. Configura ${
      fileEnvVar ? `${envVar} o ${fileEnvVar}` : envVar
    }${fallbackEnvVar ? ` (fallback: ${fallbackEnvVar})` : ""}.`
  );
};

const jwtAccess = resolveSecret({
  envVar: "JWT_ACCESS_SECRET",
  fileEnvVar: "JWT_ACCESS_SECRET_FILE",
  fallbackEnvVar: "JWT_SECRET",
  displayName: "JWT Access Secret",
});

const jwtRefresh = resolveSecret({
  envVar: "JWT_REFRESH_SECRET",
  fileEnvVar: "JWT_REFRESH_SECRET_FILE",
  fallbackEnvVar: "JWT_SECRET",
  displayName: "JWT Refresh Secret",
});

const legacyJwt = resolveSecret({
  envVar: "JWT_SECRET",
  fileEnvVar: "JWT_SECRET_FILE",
  displayName: "JWT (legacy) Secret",
  required: false,
});

export const secrets = {
  jwt: {
    access: jwtAccess.value,
    refresh: jwtRefresh.value,
    legacy: legacyJwt.value || jwtAccess.value,
  },
};

export const secretDiagnostics = {
  jwt: {
    access: { source: jwtAccess.source, details: jwtAccess.details },
    refresh: { source: jwtRefresh.source, details: jwtRefresh.details },
    legacy: { source: legacyJwt.source, details: legacyJwt.details },
  },
};

export const generateSecret = (size = 64): string =>
  crypto.randomBytes(size).toString("base64");

