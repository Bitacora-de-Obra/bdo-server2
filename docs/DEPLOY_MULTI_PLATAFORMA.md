# 🚀 Guía de Despliegue Multi-Plataforma

**Fecha:** Noviembre 2025

Esta guía te ayudará a desplegar la Bitácora Digital de Obra en múltiples plataformas: Vercel, Railway, Cloudflare Workers, y Render.

---

## 📋 Tabla de Contenidos

1. [Vercel](#vercel)
2. [Railway](#railway)
3. [Cloudflare Workers](#cloudflare-workers)
4. [Render](#render)
5. [Configuración de Variables de Entorno](#configuración-de-variables-de-entorno)
6. [Base de Datos](#base-de-datos)
7. [Storage](#storage)

---

## 🟢 Vercel

### Requisitos Previos
- Cuenta en [Vercel](https://vercel.com)
- Repositorio en GitHub

### Pasos de Despliegue

1. **Instalar Vercel CLI** (opcional):
```bash
npm i -g vercel
```

2. **Conectar Repositorio**:
   - Ve a [Vercel Dashboard](https://vercel.com/dashboard)
   - Click en "Add New Project"
   - Conecta tu repositorio de GitHub
   - Selecciona el directorio `bdo-server`

3. **Configuración del Proyecto**:
   - **Framework Preset:** Other
   - **Root Directory:** `bdo-server`
   - **Build Command:** `npm install && npx prisma generate && npm run build`
   - **Output Directory:** `dist`
   - **Install Command:** `npm install`

4. **Variables de Entorno**:
   - Ve a Settings → Environment Variables
   - Agrega todas las variables de `.env.production.example`
   - **Importante:** Configura `DATABASE_URL`, `JWT_*_SECRET`, etc.

5. **Desplegar**:
   - Vercel desplegará automáticamente en cada push a `main`
   - O manualmente: `vercel --prod`

### Configuración Especial

**Para Prisma en Vercel:**
```bash
# En Build Command, agregar:
npm install && npx prisma generate && npm run build && npx prisma migrate deploy
```

**Nota:** Vercel tiene límites de tiempo de ejecución. Para operaciones largas, considera usar funciones serverless separadas.

---

## 🚂 Railway

### Requisitos Previos
- Cuenta en [Railway](https://railway.app)
- Repositorio en GitHub

### Pasos de Despliegue

1. **Conectar Repositorio**:
   - Ve a [Railway Dashboard](https://railway.app/dashboard)
   - Click en "New Project"
   - Selecciona "Deploy from GitHub repo"
   - Selecciona tu repositorio y el directorio `bdo-server`

2. **Configuración Automática**:
   - Railway detectará automáticamente `railway.json`
   - Configurará el build y start commands

3. **Base de Datos**:
   - En Railway, agrega un servicio MySQL/PostgreSQL
   - Railway generará automáticamente `DATABASE_URL`
   - Conecta el servicio a tu aplicación

4. **Variables de Entorno**:
   - Ve a Variables tab
   - Agrega todas las variables necesarias
   - Railway puede generar algunas automáticamente

5. **Desplegar**:
   - Railway desplegará automáticamente en cada push
   - O manualmente desde el dashboard

### Configuración Especial

**Para Prisma en Railway:**
```bash
# Railway ejecutará automáticamente:
# - npm install
# - npx prisma generate
# - npm run build
# Luego en start: npm start (que ejecuta migrate deploy)
```

**Health Check:**
Railway verificará automáticamente `/health`

---

## ☁️ Cloudflare Workers

### Requisitos Previos
- Cuenta en [Cloudflare](https://cloudflare.com)
- Wrangler CLI instalado

### Pasos de Despliegue

1. **Instalar Wrangler**:
```bash
npm install -g wrangler
wrangler login
```

2. **Configurar Proyecto**:
   - El archivo `wrangler.toml` ya está configurado
   - Ajusta `routes` con tu dominio

3. **Variables de Entorno**:
```bash
# Configurar secrets en Cloudflare
wrangler secret put DATABASE_URL
wrangler secret put JWT_ACCESS_SECRET
wrangler secret put JWT_REFRESH_SECRET
# ... etc para todas las variables sensibles
```

4. **Desplegar**:
```bash
npm run build
wrangler deploy
```

### Limitaciones de Cloudflare Workers

⚠️ **Importante:** Cloudflare Workers tiene limitaciones:
- Tiempo máximo de ejecución: 30 segundos (gratis) / 15 minutos (paid)
- No puede usar Prisma directamente (necesita adaptación)
- Recomendado solo para APIs simples o endpoints específicos

**Alternativa:** Usar Cloudflare Pages con Functions para el frontend y otro servicio para el backend.

---

## 🎨 Render

### Requisitos Previos
- Cuenta en [Render](https://render.com)
- Repositorio en GitHub

### Pasos de Despliegue

1. **Conectar Repositorio**:
   - Ve a [Render Dashboard](https://dashboard.render.com)
   - Click en "New" → "Web Service"
   - Conecta tu repositorio de GitHub
   - Selecciona el directorio `bdo-server`

2. **Configuración del Servicio**:
   - **Name:** `bdo-server`
   - **Environment:** `Node`
   - **Build Command:** `npm install && npx prisma generate && npm run build`
   - **Start Command:** `npm start`
   - **Plan:** Starter (o el que prefieras)

3. **Base de Datos**:
   - En Render, crea un servicio PostgreSQL o MySQL
   - Render generará automáticamente `DATABASE_URL`
   - Conecta el servicio a tu aplicación

4. **Variables de Entorno**:
   - Ve a Environment tab
   - Agrega todas las variables necesarias
   - Render puede sincronizar desde `.env` si lo configuras

5. **Health Check**:
   - Render verificará automáticamente `/health`
   - Configurado en `render.yaml`

6. **Desplegar**:
   - Render desplegará automáticamente en cada push a `main`
   - O manualmente desde el dashboard

### Configuración Especial

**Auto-Deploy:**
Render puede auto-desplegar desde `render.yaml` si está en la raíz del repo.

**Health Check:**
Render verificará `/health` cada minuto para determinar si el servicio está saludable.

---

## 🔐 Configuración de Variables de Entorno

### Variables Críticas para Todas las Plataformas

```env
# Base de Datos
DATABASE_URL=mysql://usuario:contraseña@host:puerto/database

# JWT Secrets (generar con: npm run secrets:generate)
JWT_ACCESS_SECRET=tu_secreto_minimo_32_caracteres
JWT_REFRESH_SECRET=otro_secreto_minimo_32_caracteres
JWT_SECRET=tercer_secreto_minimo_32_caracteres

# URLs
FRONTEND_URL=https://tu-frontend.vercel.app
SERVER_PUBLIC_URL=https://tu-backend.railway.app

# Cookies (CRÍTICO en producción)
COOKIE_SECURE=true
COOKIE_SAMESITE=strict
TRUST_PROXY=true

# Storage
STORAGE_DRIVER=cloudflare
CLOUDFLARE_R2_BUCKET=tu-bucket
CLOUDFLARE_R2_ACCESS_KEY_ID=tu_key
CLOUDFLARE_R2_SECRET_ACCESS_KEY=tu_secret

# Email
RESEND_API_KEY=re_xxxxxxxxxxxxx
RESEND_FROM="Bitácora Digital <no-reply@tu-dominio.com>"
RESEND_MODE=live

# Seguridad
SECURITY_ALERT_EMAILS=admin@tu-dominio.com
NODE_ENV=production
```

### Cómo Configurar en Cada Plataforma

#### Vercel
1. Dashboard → Project → Settings → Environment Variables
2. Agrega cada variable
3. Selecciona los ambientes (Production, Preview, Development)

#### Railway
1. Dashboard → Project → Variables tab
2. Agrega cada variable
3. Railway puede sincronizar desde archivos `.env`

#### Cloudflare
```bash
# Usar wrangler secret para variables sensibles
wrangler secret put DATABASE_URL
wrangler secret put JWT_ACCESS_SECRET

# O configurar en dashboard: Workers & Pages → Settings → Variables
```

#### Render
1. Dashboard → Service → Environment
2. Agrega cada variable
3. Puedes importar desde archivo `.env`

---

## 🗄️ Base de Datos

### Opciones Recomendadas por Plataforma

#### Railway
- ✅ **Recomendado:** Railway PostgreSQL/MySQL
- Integración nativa
- `DATABASE_URL` generado automáticamente

#### Render
- ✅ **Recomendado:** Render PostgreSQL
- Integración nativa
- `DATABASE_URL` generado automáticamente

#### Vercel
- ⚠️ **Recomendado:** Servicio externo (PlanetScale, Supabase, Railway DB)
- Vercel no ofrece base de datos nativa
- Configurar `DATABASE_URL` manualmente

#### Cloudflare
- ⚠️ **Recomendado:** Servicio externo (PlanetScale, Supabase)
- Cloudflare Workers no puede usar Prisma directamente
- Considerar usar D1 (SQLite) o servicio externo

### Migraciones

**En todas las plataformas, ejecutar migraciones:**

```bash
# Opción 1: En el build command
npm install && npx prisma generate && npm run build && npx prisma migrate deploy

# Opción 2: En el start command (ya configurado en package.json)
# npm start ejecuta force-migration-fix.js que hace migrate deploy
```

---

## 📦 Storage

### Cloudflare R2 (Recomendado para Todas)

1. **Crear Bucket en Cloudflare:**
   - Dashboard → R2 → Create Bucket
   - Nombre: `bitacora-archivos`

2. **Generar Access Keys:**
   - R2 → Manage R2 API Tokens
   - Create API Token
   - Copia `Access Key ID` y `Secret Access Key`

3. **Configurar Variables:**
```env
STORAGE_DRIVER=cloudflare
CLOUDFLARE_ACCOUNT_ID=tu_account_id
CLOUDFLARE_R2_BUCKET=bitacora-archivos
CLOUDFLARE_R2_ACCESS_KEY_ID=tu_access_key
CLOUDFLARE_R2_SECRET_ACCESS_KEY=tu_secret_key
CLOUDFLARE_R2_PUBLIC_URL=https://archivos.tu-dominio.com
```

4. **Configurar Dominio Público (Opcional):**
   - R2 → Bucket → Settings → Public Access
   - Configurar dominio personalizado

---

## ✅ Checklist de Despliegue

### Antes de Desplegar

- [ ] ✅ Variables de entorno configuradas en la plataforma
- [ ] ✅ Base de datos creada y accesible
- [ ] ✅ `DATABASE_URL` configurado correctamente
- [ ] ✅ Secretos JWT generados y configurados
- [ ] ✅ Storage configurado (R2/S3)
- [ ] ✅ Email configurado (Resend/SMTP)
- [ ] ✅ URLs configuradas (FRONTEND_URL, SERVER_PUBLIC_URL)
- [ ] ✅ Build local funciona (`npm run build`)
- [ ] ✅ Pre-deploy pasa (`npm run pre-deploy`)

### Después de Desplegar

- [ ] ✅ Health check funciona (`/health`)
- [ ] ✅ Login funciona
- [ ] ✅ Base de datos conectada
- [ ] ✅ Migraciones aplicadas
- [ ] ✅ Storage funciona (subir archivo de prueba)
- [ ] ✅ Email funciona (enviar email de prueba)
- [ ] ✅ Logs sin errores críticos

---

## 🔄 CI/CD Automático

### GitHub Actions (Recomendado)

Crea `.github/workflows/deploy.yml`:

```yaml
name: Deploy

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '20'
      - run: npm install
      - run: npx prisma generate
      - run: npm run build
      # Desplegar a cada plataforma según necesites
```

---

## 📚 Recursos Adicionales

- [Vercel Docs](https://vercel.com/docs)
- [Railway Docs](https://docs.railway.app)
- [Cloudflare Workers Docs](https://developers.cloudflare.com/workers/)
- [Render Docs](https://render.com/docs)

---

## 🆘 Troubleshooting

### Error: "Cannot find module '@prisma/client'"
**Solución:** Agregar `npx prisma generate` al build command

### Error: "Database connection failed"
**Solución:** Verificar `DATABASE_URL` y que la BD sea accesible desde la plataforma

### Error: "JWT secret too short"
**Solución:** Generar nuevos secretos con `npm run secrets:generate`

### Error: "Storage driver not found"
**Solución:** Verificar que `STORAGE_DRIVER` esté configurado y las credenciales sean correctas

---

**Última actualización:** Noviembre 2025


