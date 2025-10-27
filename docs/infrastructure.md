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
- Para usar S3 configura **todas** las variables (`S3_BUCKET`, `S3_REGION`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_ENDPOINT`, `S3_FORCE_PATH_STYLE`). Si falta `S3_BUCKET`, el servicio vuelve automáticamente al driver local.
- Define `STORAGE_PUBLIC_URL`/`SERVER_PUBLIC_URL` con el dominio público que servirá los adjuntos (CDN, bucket web, etc.) y aplica las políticas CORS/Headers necesarias en ese frontal (por ejemplo, limitar `Access-Control-Allow-Origin` a tus dominios).
- Cuando la dependencia `@aws-sdk/client-s3` esté disponible, `s3StorageProvider` se encargará de subir/borrar archivos garantizando claves saneadas.

## Despliegue (scripts sugeridos)

- Añadir scripts en package.json:
  - `"start": "node dist/index.js"` tras compilar con `tsc`.
  - `"build": "tsc"`.
- Dockerfile multi-stage disponible en `bdo-server/Dockerfile` (compila TypeScript y conserva artefactos mínimos).
- Entrypoint `scripts/entrypoint.sh` ejecuta `prisma migrate deploy` y opcionalmente `prisma db seed` (`PRISMA_RUN_SEED=true`) antes de arrancar el proceso.
- CI/CD: usa `.github/workflows/deploy.yml` como base. La pipeline construye el frontend (`npm run build` en `bdo-appd`), compila backend (`npm run build` tras `npm ci` y `prisma generate`), construye/push de imagen Docker (configurable con `REGISTRY`, `IMAGE_NAME`), ejecuta `prisma migrate deploy` / `prisma db seed` y permite un paso final (`DEPLOY_COMMAND`) para orquestar el despliegue.

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
