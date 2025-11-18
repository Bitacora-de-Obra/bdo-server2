# ⚡ Despliegue Rápido - Guía Resumida

**Para desplegar rápidamente en cada plataforma**

---

## 🟢 Vercel (Frontend + Backend API)

### Backend
1. **Conectar repo en Vercel Dashboard**
2. **Configurar:**
   - Root: `bdo-server`
   - Build: `npm install && npx prisma generate && npm run build`
   - Output: `dist`
3. **Variables:** Agregar todas de `.env.production.example`
4. **Listo:** Auto-deploy en cada push

### Frontend
1. **Conectar repo en Vercel Dashboard**
2. **Configurar:**
   - Root: `bdo-appd`
   - Build: `npm install && npm run build`
   - Output: `dist`
3. **Variables:** `VITE_API_URL=https://tu-backend.vercel.app`
4. **Listo:** Auto-deploy en cada push

---

## 🚂 Railway (Backend Recomendado)

1. **New Project → Deploy from GitHub**
2. **Seleccionar:** `bdo-server`
3. **Agregar MySQL/PostgreSQL** (Railway lo conecta automáticamente)
4. **Variables:** Agregar todas de `.env.production.example`
5. **Listo:** Auto-deploy en cada push

**Ventajas:**
- ✅ Base de datos integrada
- ✅ Variables automáticas
- ✅ Logs en tiempo real

---

## 🎨 Render (Backend Alternativo)

1. **New → Web Service**
2. **Conectar GitHub repo**
3. **Configurar:**
   - Build: `npm install && npx prisma generate && npm run build`
   - Start: `npm start`
4. **Agregar PostgreSQL** (Render lo conecta)
5. **Variables:** Agregar todas
6. **Listo:** Auto-deploy en cada push

---

## ☁️ Cloudflare (Storage + Workers)

### R2 Storage (Archivos)
1. **Dashboard → R2 → Create Bucket**
2. **Generar API Token**
3. **Configurar variables:**
   ```env
   STORAGE_DRIVER=cloudflare
   CLOUDFLARE_R2_BUCKET=bitacora-archivos
   CLOUDFLARE_R2_ACCESS_KEY_ID=xxx
   CLOUDFLARE_R2_SECRET_ACCESS_KEY=xxx
   ```

### Workers (Opcional - API Simple)
⚠️ **Nota:** Workers tiene limitaciones con Prisma. Mejor usar Railway/Render para backend completo.

---

## 📋 Variables Mínimas Requeridas

```env
# Base de Datos
DATABASE_URL=mysql://...

# JWT (generar con: npm run secrets:generate)
JWT_ACCESS_SECRET=...
JWT_REFRESH_SECRET=...
JWT_SECRET=...

# URLs
FRONTEND_URL=https://...
SERVER_PUBLIC_URL=https://...

# Cookies
COOKIE_SECURE=true
COOKIE_SAMESITE=strict
TRUST_PROXY=true

# Storage (Cloudflare R2)
STORAGE_DRIVER=cloudflare
CLOUDFLARE_R2_BUCKET=...
CLOUDFLARE_R2_ACCESS_KEY_ID=...
CLOUDFLARE_R2_SECRET_ACCESS_KEY=...

# Email
RESEND_API_KEY=...
RESEND_FROM=...
RESEND_MODE=live

# Seguridad
SECURITY_ALERT_EMAILS=...
NODE_ENV=production
```

---

## ✅ Checklist Rápido

- [ ] Repo conectado en la plataforma
- [ ] Build command configurado
- [ ] Base de datos creada y conectada
- [ ] Variables de entorno agregadas
- [ ] Health check funciona (`/health`)
- [ ] Login funciona
- [ ] Storage funciona

---

## 🚀 Recomendación de Arquitectura

**Opción 1 (Recomendada):**
- **Backend:** Railway o Render
- **Frontend:** Vercel
- **Storage:** Cloudflare R2
- **Base de Datos:** Integrada en Railway/Render

**Opción 2:**
- **Backend:** Vercel (serverless)
- **Frontend:** Vercel
- **Storage:** Cloudflare R2
- **Base de Datos:** PlanetScale o Supabase

---

**Para detalles completos, ver:** `DEPLOY_MULTI_PLATAFORMA.md`



