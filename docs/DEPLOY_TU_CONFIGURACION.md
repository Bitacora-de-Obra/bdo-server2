# 🚀 Guía de Despliegue - Tu Configuración Actual

**Basado en tu configuración existente**

---

## ✅ Lo que Ya Tienes Configurado

### Cloudflare R2 (Storage) ✅
```env
STORAGE_DRIVER=cloudflare
CLOUDFLARE_ACCOUNT_ID=f5a8cb8424c5d6a19d528a252365d348
CLOUDFLARE_R2_BUCKET=bitacora-files
CLOUDFLARE_R2_ACCESS_KEY_ID=d96e6b751a5081660efb14ce12b06a35
CLOUDFLARE_R2_SECRET_ACCESS_KEY=*** (configurado)
CLOUDFLARE_R2_PUBLIC_URL= (pendiente configurar)
```

### Base de Datos ✅
- `DATABASE_URL` configurado

### JWT Secrets ✅
- `JWT_ACCESS_SECRET` configurado
- `JWT_REFRESH_SECRET` configurado
- `JWT_SECRET` configurado

### Email (SMTP) ✅
- `SMTP_HOST=smtp.gmail.com`
- `SMTP_PORT=587`
- `SMTP_SECURE=false`

### URLs ✅
- `FRONTEND_URL` configurado
- `SERVER_PUBLIC_URL` configurado

---

## ⚠️ Ajustes Necesarios para Producción

### Variables que Deben Cambiar en Producción:

```env
# Cambiar de development a production
NODE_ENV=production

# Cambiar a true en producción
COOKIE_SECURE=true
COOKIE_SAMESITE=strict
TRUST_PROXY=true

# Configurar URL pública de R2 (si quieres servir archivos directamente)
CLOUDFLARE_R2_PUBLIC_URL=https://archivos.tu-dominio.com
```

---

## 🚀 Despliegue por Plataforma

### Railway

**Variables a Configurar en Railway Dashboard:**

1. **Copia todas las variables de tu `.env` actual**
2. **Ajusta estas para producción:**
   ```env
   NODE_ENV=production
   COOKIE_SECURE=true
   COOKIE_SAMESITE=strict
   TRUST_PROXY=true
   ```

3. **Si Railway genera DATABASE_URL automáticamente:**
   - Railway creará un servicio MySQL/PostgreSQL
   - Te dará `DATABASE_URL` automáticamente
   - Reemplaza el que tienes con el de Railway

**Pasos:**
1. Railway Dashboard → New Project
2. Deploy from GitHub → Selecciona `bdo-server`
3. Add MySQL/PostgreSQL (si no tienes uno externo)
4. Variables → Agrega todas las de tu `.env` (ajustando las de producción)
5. Deploy automático

---

### Render

**Ya tienes `.env.render.production`** ✅

**Variables a Configurar en Render:**

1. **Render Dashboard → Service → Environment**
2. **Importa desde `.env.render.production` o agrega manualmente:**
   - Todas las variables de Cloudflare R2
   - Todas las variables JWT
   - `DATABASE_URL` (o crea PostgreSQL en Render)
   - Ajusta para producción:
     ```env
     NODE_ENV=production
     COOKIE_SECURE=true
     COOKIE_SAMESITE=strict
     TRUST_PROXY=true
     ```

**Pasos:**
1. Render Dashboard → New → Web Service
2. Conecta GitHub → `bdo-server`
3. Build: `npm install && npx prisma generate && npm run build`
4. Start: `npm start`
5. Agrega PostgreSQL (si no tienes externo)
6. Environment → Agrega todas las variables

---

### Vercel

**Variables a Configurar en Vercel:**

1. **Vercel Dashboard → Project → Settings → Environment Variables**
2. **Agrega todas las variables de tu `.env`:**
   - Cloudflare R2 (todas)
   - JWT Secrets (todas)
   - Database URL
   - URLs (FRONTEND_URL, SERVER_PUBLIC_URL)
   - SMTP (todas)
   - **Ajusta para producción:**
     ```env
     NODE_ENV=production
     COOKIE_SECURE=true
     COOKIE_SAMESITE=strict
     TRUST_PROXY=true
     ```

**Pasos:**
1. Vercel Dashboard → Add New Project
2. Conecta GitHub → `bdo-server`
3. Framework: Other
4. Root Directory: `bdo-server`
5. Build: `npm install && npx prisma generate && npm run build`
6. Output: `dist`
7. Environment Variables → Agrega todas

---

## 📋 Checklist de Variables por Plataforma

### Todas las Plataformas Necesitan:

- [x] `DATABASE_URL` (ya configurado)
- [x] `JWT_ACCESS_SECRET` (ya configurado)
- [x] `JWT_REFRESH_SECRET` (ya configurado)
- [x] `JWT_SECRET` (ya configurado)
- [x] `FRONTEND_URL` (ya configurado)
- [x] `SERVER_PUBLIC_URL` (ya configurado)
- [x] Cloudflare R2 (todas las variables) (ya configurado)
- [x] SMTP (ya configurado)
- [ ] `NODE_ENV=production` (cambiar en producción)
- [ ] `COOKIE_SECURE=true` (cambiar en producción)
- [ ] `COOKIE_SAMESITE=strict` (cambiar en producción)
- [ ] `TRUST_PROXY=true` (cambiar en producción)
- [ ] `CLOUDFLARE_R2_PUBLIC_URL` (opcional, para servir archivos directamente)

---

## 🔧 Configuración de Cloudflare R2 Public URL

Si quieres servir archivos directamente desde R2:

1. **Cloudflare Dashboard → R2 → bitacora-files**
2. **Settings → Public Access**
3. **Enable Public Access**
4. **Configurar dominio personalizado** (opcional)
5. **Obtener URL pública** y configurar:
   ```env
   CLOUDFLARE_R2_PUBLIC_URL=https://pub-xxxxx.r2.dev
   ```

---

## ✅ Resumen

**Ya tienes configurado:**
- ✅ Cloudflare R2 completo
- ✅ Base de datos
- ✅ JWT Secrets
- ✅ SMTP
- ✅ URLs

**Solo necesitas:**
1. Copiar estas variables a cada plataforma
2. Ajustar `NODE_ENV`, `COOKIE_*`, `TRUST_PROXY` para producción
3. Configurar `CLOUDFLARE_R2_PUBLIC_URL` (opcional)

**¿En qué plataforma quieres desplegar primero?** Railway, Render, o Vercel?

