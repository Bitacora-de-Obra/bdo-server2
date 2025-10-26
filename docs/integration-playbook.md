# Integraciones y Automatización

## 1. Recordatorios programados

- El job diario se programa con `node-cron` en `src/index.ts` (`scheduleDailyCommitmentReminder`).
- Configurable vía variables:
  - `COMMITMENT_REMINDER_CRON` (por defecto `0 6 * * *`).
  - `COMMITMENT_REMINDER_DAYS_AHEAD` (por defecto 2 días).
  - `REMINDER_TIMEZONE` (por defecto `America/Bogota`).
- Actualmente registra en consola los compromisos próximos; sustituye el `console.log` por integración SMTP o servicio externo cuando tengas credenciales.

## 2. Importación de cronograma XML

- El endpoint `POST /api/project-tasks/import` acepta `tasks` ya normalizadas **o** un campo `xml` con el cronograma completo.
- La utilidad `validateCronogramaXml` (src/utils/xmlValidator.ts) valida que existan fechas y nombres, levantando `CronogramaValidationError` si el formato no es compatible.
- Para soportar nombres largos, se amplió la columna `ProjectTask.name` a 512 caracteres (`prisma/migrations/20251026133000_extend_project_task_columns`).

## 3. Exportación de PDF

- Ruta `POST /api/reports/:id/export-pdf` devuelve un stub en `/uploads/generated`. Está listo para reemplazar la lógica por tu generador (puedes usar `pdfkit` o `puppeteer`).

## 4. Documentación de la API

- Especificación inicial en `openapi/openapi.json`.
- Swagger UI disponible en `http://localhost:4001/api/docs`; la ruta `http://localhost:4001/api/docs/json` entrega el JSON.
- Ejecuta `npm run generate-docs` (definir script si se desea) para copiar la especificación al root antes de desplegar.

## Variables adicionales

- `CRON_XML_MAX_NAME_LENGTH`: ajusta máximo de caracteres para nombres de tareas (default 512).
- `LOGIN_RATE_LIMIT_*`, `REFRESH_RATE_LIMIT_*`: controlan los límites de autenticación.

Mantén este documento en sincronía conforme se implementen notificaciones reales (SMTP, Slack, etc.) y se amplíe la especificación OpenAPI.
