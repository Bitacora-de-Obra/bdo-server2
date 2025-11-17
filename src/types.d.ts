declare module "mime-types";
declare module "helmet";
declare module "express-rate-limit";
declare module "node-cron";
declare module "swagger-ui-express";
declare module "xml2js";

declare global {
  namespace NodeJS {
    interface ProcessEnv {
      NODE_ENV?: "development" | "production" | "test";
      DATABASE_URL?: string;
      OPENAI_API_KEY?: string;
      TRUST_PROXY?: "true" | "false";
      COOKIE_SECURE?: "true" | "false";
      COOKIE_SAMESITE?: "lax" | "strict" | "none" | string;
      COOKIE_DOMAIN?: string;
      LOGIN_RATE_LIMIT_WINDOW_MS?: string;
      LOGIN_RATE_LIMIT_MAX?: string;
      REFRESH_RATE_LIMIT_WINDOW_MS?: string;
      REFRESH_RATE_LIMIT_MAX?: string;
      EMAIL_VERIFICATION_TOKEN_TTL_HOURS?: string;
      PASSWORD_RESET_TOKEN_TTL_MINUTES?: string;
      COMMITMENT_REMINDER_CRON?: string;
      REMINDER_TIMEZONE?: string;
      COMMITMENT_REMINDER_DAYS_AHEAD?: string;
      UPLOADS_DIR?: string;
      STORAGE_DRIVER?: "local" | "s3" | "cloudflare" | "r2" | string;
      STORAGE_PUBLIC_URL?: string;

      // Cloudflare R2
      CLOUDFLARE_ACCOUNT_ID?: string;
      CLOUDFLARE_R2_BUCKET?: string;
      CLOUDFLARE_R2_ACCESS_KEY_ID?: string;
      CLOUDFLARE_R2_SECRET_ACCESS_KEY?: string;
      CLOUDFLARE_R2_PUBLIC_URL?: string;

      SERVER_PUBLIC_URL?: string;
      CRON_XML_MAX_NAME_LENGTH?: string;
      JWT_SECRET?: string;
      JWT_REFRESH_SECRET?: string;
      JWT_ACCESS_SECRET?: string;
      JWT_SECRET_FILE?: string;
      JWT_ACCESS_SECRET_FILE?: string;
      JWT_REFRESH_SECRET_FILE?: string;
    }
  }
}
