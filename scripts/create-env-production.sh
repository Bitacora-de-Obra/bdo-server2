#!/bin/bash

# Script para crear archivo .env.production desde template
# Uso: ./scripts/create-env-production.sh

cat > .env.production.example << 'EOF'
# ============================================
# CONFIGURACIÓN DE PRODUCCIÓN
# Bitácora Digital de Obra
# ============================================
# 
# INSTRUCCIONES:
# 1. Copia este archivo a .env en tu servidor de producción
# 2. Reemplaza todos los valores de ejemplo con valores reales
# 3. NUNCA commitees el archivo .env real al repositorio
#
# ============================================

# ENTORNO
NODE_ENV=production

# BASE DE DATOS
DATABASE_URL=mysql://usuario:contraseña@tu-servidor-db:3306/bitacora_prod

# SECRETOS JWT (CRÍTICO - GENERAR NUEVOS con: npm run secrets:generate)
JWT_ACCESS_SECRET=tu_secreto_access_minimo_32_caracteres_aqui
JWT_REFRESH_SECRET=tu_secreto_refresh_minimo_32_caracteres_aqui
JWT_SECRET=tu_secreto_legacy_minimo_32_caracteres_aqui

# URLs Y CORS
FRONTEND_URL=https://bitacora.tu-dominio.com
SERVER_PUBLIC_URL=https://api.tu-dominio.com

# COOKIES Y SEGURIDAD
COOKIE_SECURE=true
COOKIE_SAMESITE=strict
COOKIE_DOMAIN=.tu-dominio.com
TRUST_PROXY=true

# ALMACENAMIENTO - Cloudflare R2 (Recomendado)
STORAGE_DRIVER=cloudflare
CLOUDFLARE_ACCOUNT_ID=tu_account_id
CLOUDFLARE_R2_BUCKET=bitacora-archivos
CLOUDFLARE_R2_ACCESS_KEY_ID=tu_access_key
CLOUDFLARE_R2_SECRET_ACCESS_KEY=tu_secret_key
CLOUDFLARE_R2_PUBLIC_URL=https://archivos.tu-dominio.com

# EMAIL - Resend (Recomendado)
RESEND_API_KEY=re_xxxxxxxxxxxxxxxxxxxxxx
RESEND_FROM="Bitácora Digital <no-reply@tu-dominio.com>"
RESEND_MODE=live

# EMAIL - SMTP (Fallback)
# SMTP_HOST=smtp.gmail.com
# SMTP_PORT=587
# SMTP_SECURE=false
# SMTP_USER=tu-email@gmail.com
# SMTP_PASS=tu-contraseña-de-aplicacion
# EMAIL_FROM=Bitácora Digital <no-reply@tu-dominio.com>

# SEGURIDAD
SECURITY_ALERT_EMAILS=seguridad@tu-dominio.com,admin@tu-dominio.com
SECURITY_CLEANUP_CRON=0 2 * * *
SECURITY_EVENTS_MAX_AGE_DAYS=30

# RATE LIMITING
API_RATE_LIMIT_WINDOW_MS=900000
API_RATE_LIMIT_MAX=100
LOGIN_RATE_LIMIT_WINDOW_MS=900000
LOGIN_RATE_LIMIT_MAX=5

# TIMEOUTS
REQUEST_TIMEOUT_MS=30000

# OPENAI (Opcional - Para Chatbot)
# OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxx

# LOGGING
LOG_LEVEL=info

# RECORDATORIOS
COMMITMENT_REMINDER_CRON=0 6 * * *
REMINDER_TIMEZONE=America/Bogota
COMMITMENT_REMINDER_DAYS_AHEAD=2
EOF

echo "✅ Archivo .env.production.example creado"
echo "📝 Ahora puedes copiarlo y configurarlo:"
echo "   cp .env.production.example .env"
echo "   nano .env  # Editar con tus valores reales"



