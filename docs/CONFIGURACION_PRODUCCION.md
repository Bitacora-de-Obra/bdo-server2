# 🔧 Guía de Configuración de Producción

**Fecha:** Noviembre 2025

---

## 📋 Resumen

Esta guía te ayudará a configurar el servidor de producción paso a paso, asegurando que todas las variables de entorno estén correctamente configuradas.

---

## 🚀 Paso 1: Preparar el Entorno

### 1.1 Clonar el Repositorio
```bash
git clone https://github.com/Bitacora-de-Obra/bdo-server2.git
cd bdo-server2
git checkout main  # o la rama de producción
```

### 1.2 Instalar Dependencias
```bash
npm install
npx prisma generate
```

---

## 🔐 Paso 2: Generar Secretos JWT

### 2.1 Generar Secretos
```bash
npm run secrets:generate
```

Esto generará secretos aleatorios seguros. **Copia los valores generados.**

### 2.2 Configurar Secretos

**Opción A: Variables de Entorno (Desarrollo/Staging)**
```bash
JWT_ACCESS_SECRET=tu_secreto_generado_aqui
JWT_REFRESH_SECRET=otro_secreto_generado_aqui
JWT_SECRET=tercer_secreto_generado_aqui
```

**Opción B: Archivos de Secretos (Producción - Recomendado)**
```bash
# Crear archivos de secretos
echo "tu_secreto_access" > /run/secrets/jwt_access
echo "tu_secreto_refresh" > /run/secrets/jwt_refresh
echo "tu_secreto_legacy" > /run/secrets/jwt_legacy

# Configurar permisos
chmod 600 /run/secrets/jwt_*
chown app:app /run/secrets/jwt_*

# Configurar variables
JWT_ACCESS_SECRET_FILE=/run/secrets/jwt_access
JWT_REFRESH_SECRET_FILE=/run/secrets/jwt_refresh
JWT_SECRET_FILE=/run/secrets/jwt_legacy
```

---

## 📝 Paso 3: Configurar Variables de Entorno

### 3.1 Copiar Archivo de Ejemplo
```bash
cp .env.production.example .env
```

### 3.2 Editar Variables Críticas

Abre `.env` y configura:

#### Base de Datos
```env
DATABASE_URL=mysql://usuario:contraseña@servidor:3306/bitacora_prod
```

#### URLs
```env
FRONTEND_URL=https://bitacora.tu-dominio.com
SERVER_PUBLIC_URL=https://api.tu-dominio.com
```

#### Cookies (CRÍTICO en producción)
```env
COOKIE_SECURE=true
COOKIE_SAMESITE=strict
COOKIE_DOMAIN=.tu-dominio.com
TRUST_PROXY=true
```

#### Email - Resend (Recomendado)
```env
RESEND_API_KEY=re_xxxxxxxxxxxxxxxxxxxxxx
RESEND_FROM="Bitácora Digital <no-reply@tu-dominio.com>"
RESEND_MODE=live
```

O SMTP (Fallback):
```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=tu-email@gmail.com
SMTP_PASS=tu-contraseña-de-aplicacion
EMAIL_FROM=Bitácora Digital <no-reply@tu-dominio.com>
```

#### Storage - Cloudflare R2 (Recomendado)
```env
STORAGE_DRIVER=cloudflare
CLOUDFLARE_ACCOUNT_ID=tu_account_id
CLOUDFLARE_R2_BUCKET=bitacora-archivos
CLOUDFLARE_R2_ACCESS_KEY_ID=tu_access_key
CLOUDFLARE_R2_SECRET_ACCESS_KEY=tu_secret_key
CLOUDFLARE_R2_PUBLIC_URL=https://archivos.tu-dominio.com
```

#### Seguridad
```env
SECURITY_ALERT_EMAILS=seguridad@tu-dominio.com,admin@tu-dominio.com
NODE_ENV=production
```

---

## 🗄️ Paso 4: Configurar Base de Datos

### 4.1 Crear Base de Datos
```sql
CREATE DATABASE bitacora_prod CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'bitacora_user'@'%' IDENTIFIED BY 'contraseña_segura';
GRANT ALL PRIVILEGES ON bitacora_prod.* TO 'bitacora_user'@'%';
FLUSH PRIVILEGES;
```

### 4.2 Ejecutar Migraciones
```bash
npx prisma migrate deploy
```

### 4.3 (Opcional) Ejecutar Seed
```bash
PRISMA_RUN_SEED=true npm start
```

**Nota:** Solo ejecuta seed si es una base de datos nueva.

---

## 📦 Paso 5: Configurar Storage

### Opción A: Cloudflare R2 (Recomendado)

1. Crear bucket en Cloudflare R2
2. Generar Access Key y Secret
3. Configurar variables en `.env`:
   ```env
   STORAGE_DRIVER=cloudflare
   CLOUDFLARE_R2_BUCKET=bitacora-archivos
   CLOUDFLARE_R2_ACCESS_KEY_ID=tu_access_key
   CLOUDFLARE_R2_SECRET_ACCESS_KEY=tu_secret_key
   CLOUDFLARE_R2_PUBLIC_URL=https://archivos.tu-dominio.com
   ```

### Opción B: Local (Solo para testing)

```env
STORAGE_DRIVER=local
UPLOADS_DIR=./uploads
```

**Asegúrate de crear el directorio:**
```bash
mkdir -p uploads
chmod 755 uploads
```

---

## 📧 Paso 6: Configurar Email

### Opción A: Resend (Recomendado)

1. Crear cuenta en [Resend.com](https://resend.com)
2. Verificar dominio
3. Generar API Key
4. Configurar en `.env`:
   ```env
   RESEND_API_KEY=re_xxxxxxxxxxxxxxxxxxxxxx
   RESEND_FROM="Bitácora Digital <no-reply@tu-dominio.com>"
   RESEND_MODE=live
   ```

### Opción B: SMTP (Gmail, SendGrid, etc.)

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=tu-email@gmail.com
SMTP_PASS=tu-contraseña-de-aplicacion
EMAIL_FROM=Bitácora Digital <no-reply@tu-dominio.com>
```

**Probar envío de email:**
```bash
# El sistema probará automáticamente al iniciar
# O puedes usar el endpoint de prueba si está disponible
```

---

## ✅ Paso 7: Validar Configuración

### 7.1 Validar Variables de Entorno
```bash
npm run validate:env
```

Este script verificará:
- ✅ Todas las variables críticas están configuradas
- ✅ Secretos tienen longitud adecuada
- ✅ URLs son válidas
- ✅ Configuración de seguridad es correcta

### 7.2 Pre-Despliegue Completo
```bash
npm run pre-deploy
```

Esto ejecutará:
1. Validación de variables
2. Verificación de TypeScript
3. Generación de Prisma Client
4. Verificación de migraciones
5. Build del proyecto

---

## 🚀 Paso 8: Build y Despliegue

### 8.1 Build del Proyecto
```bash
npm run build
```

### 8.2 Iniciar Servidor
```bash
npm start
```

O con PM2 (recomendado para producción):
```bash
pm2 start dist/index.js --name bitacora-api
pm2 save
pm2 startup
```

---

## 🔍 Paso 9: Verificar que Todo Funciona

### 9.1 Health Check
```bash
curl https://api.tu-dominio.com/api/health
```

Debería retornar:
```json
{
  "status": "ok",
  "timestamp": "2025-11-17T..."
}
```

### 9.2 Probar Login
```bash
curl -X POST https://api.tu-dominio.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.com","password":"contraseña"}'
```

### 9.3 Verificar Logs
```bash
# Si usas PM2
pm2 logs bitacora-api

# O verificar logs del sistema
tail -f logs/app.log
```

---

## 🔒 Paso 10: Configurar SSL/HTTPS

### Opción A: Cloudflare (Recomendado)
1. Agregar dominio a Cloudflare
2. Configurar DNS
3. Activar SSL/TLS (Full o Full Strict)

### Opción B: Let's Encrypt
```bash
# Instalar Certbot
sudo apt-get install certbot

# Obtener certificado
sudo certbot --nginx -d api.tu-dominio.com

# Renovación automática
sudo certbot renew --dry-run
```

### Opción C: Nginx como Reverse Proxy
```nginx
server {
    listen 80;
    server_name api.tu-dominio.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.tu-dominio.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:4001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

---

## 📊 Paso 11: Monitoreo y Alertas

### 11.1 Configurar Alertas de Seguridad
```env
SECURITY_ALERT_EMAILS=seguridad@tu-dominio.com,admin@tu-dominio.com
```

### 11.2 Monitoreo Externo (Recomendado)
- **UptimeRobot**: Monitoreo de uptime
- **Pingdom**: Monitoreo de disponibilidad
- **Datadog/New Relic**: Monitoreo de recursos

### 11.3 Logs
```bash
# Ver logs de seguridad
tail -f logs/security.log

# Ver logs de aplicación
tail -f logs/app.log
```

---

## 🔄 Paso 12: Backups

### 12.1 Backup de Base de Datos
```bash
# Script de backup diario
#!/bin/bash
DATE=$(date +%Y%m%d)
mysqldump -h $DB_HOST -u $DB_USER -p$DB_PASSWORD bitacora_prod > /backups/backup-$DATE.sql
```

### 12.2 Configurar Cron
```bash
# Agregar a crontab
0 2 * * * /path/to/backup-script.sh
```

### 12.3 Backup de Archivos
Si usas storage local, hacer backup del directorio `uploads/`:
```bash
tar -czf backups/uploads-$DATE.tar.gz uploads/
```

---

## ✅ Checklist Final

Antes de considerar producción lista:

- [ ] ✅ Todas las variables de entorno configuradas
- [ ] ✅ Secretos JWT generados y configurados
- [ ] ✅ Base de datos creada y migraciones ejecutadas
- [ ] ✅ Storage configurado (R2/S3)
- [ ] ✅ Email configurado (Resend/SMTP)
- [ ] ✅ SSL/HTTPS configurado
- [ ] ✅ `npm run validate:env` pasa sin errores
- [ ] ✅ `npm run pre-deploy` pasa sin errores
- [ ] ✅ Health check funciona
- [ ] ✅ Login funciona
- [ ] ✅ Monitoreo configurado
- [ ] ✅ Backups configurados
- [ ] ✅ Logs funcionando

---

## 🆘 Troubleshooting

### Error: "JWT_ACCESS_SECRET debe tener al menos 32 caracteres"
**Solución:** Genera nuevos secretos con `npm run secrets:generate`

### Error: "DATABASE_URL no está configurada"
**Solución:** Verifica que `DATABASE_URL` esté en `.env`

### Error: "Cannot connect to database"
**Solución:** 
- Verifica credenciales
- Verifica que el servidor de BD esté accesible
- Verifica firewall/security groups

### Emails no se envían
**Solución:**
- Verifica configuración de Resend/SMTP
- Revisa logs para errores específicos
- Prueba con `RESEND_MODE=test` primero

---

## 📚 Recursos Adicionales

- `PRODUCTION_CHECKLIST.md` - Checklist completo de producción
- `SECURITY_IMPROVEMENTS.md` - Mejoras de seguridad implementadas
- `SAFE_MERGE_GUIDE.md` - Guía para merge seguro a producción

---

**Última actualización:** Noviembre 2025

