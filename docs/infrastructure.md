# Infraestructura y despliegue

## Entornos y variables

- Archivos de ejemplo: `.env.example` (dev) y `.env.production.example`.
- Variables clave:
  - `STORAGE_DRIVER`: `local` o `s3`.
  - `FRONTEND_URL`: para CORS.
  - `SERVER_PUBLIC_URL`: base absoluta para generar enlaces de descargas (`/uploads`).
  - `LOG_*`, `COMMITMENT_REMINDER_*`, `ENABLE_SWAGGER`.
  - `COMMITMENT_REMINDER_CC`, `COMMITMENT_REMINDER_BCC`, `COMMITMENT_REMINDER_SUBJECT`: personalización de los correos de recordatorio.
  - `SMTP_*`, `EMAIL_FROM`: credenciales SMTP para correos de verificación y restablecimiento.
  - `APP_BASE_URL`, `EMAIL_VERIFICATION_URL`, `PASSWORD_RESET_URL`: base y plantillas de enlaces enviados por correo.
  - `EMAIL_VERIFICATION_TOKEN_TTL_HOURS`, `PASSWORD_RESET_TOKEN_TTL_MINUTES`: vigencia de tokens.
- Usa `cp .env.example .env` en dev y ajusta según ambiente.

## Storage de adjuntos

- Abstracción en `src/storage/index.ts` permite elegir entre almacenamiento local (`UPLOADS_DIR`) y S3.
- Para usar S3 configurer variables `S3_BUCKET`, `S3_REGION`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_ENDPOINT`, `S3_FORCE_PATH_STYLE`.
- Cuando la dependencia `@aws-sdk/client-s3` esté disponible, `s3StorageProvider` se encargará de subir/borrar archivos.

## Despliegue (scripts sugeridos)

- Añadir scripts en package.json:
  - `"start": "node dist/index.js"` tras compilar con `tsc`.
  - `"build": "tsc"`.
- Preparar Dockerfile (pendiente) con multi-stage build: compilar TypeScript y copiar artefactos a imagen Node.js runtime.
- CI (GitHub Actions) ya ejecuta lint/build/tests; añadir job de deployment cuando haya infra.

## Backups de Base de Datos

- Para MySQL, se recomienda usar `mysqldump`:
  ```bash
  mysqldump -h ${DB_HOST} -u ${DB_USER} -p${DB_PASSWORD} bitacora_db > backup-$(date +%F).sql
  ```
- Programar cron en el servidor (ej. `/etc/cron.d/bitacora-backups`) para ejecutar el dump diario y subirlo a almacenamiento seguro (S3/Drive).
- Mantener al menos 7 días de rotación; verificar restauraciones periódicamente.

## Tareas pendientes

- Instalación de `@aws-sdk/client-s3` (bloqueado sin acceso a npm).
- Dockerfile y scripts de despliegue automatizado.
- Integración con servicio de backups (S3 Glacier, RDS snapshots, etc.) y monitoreo.
