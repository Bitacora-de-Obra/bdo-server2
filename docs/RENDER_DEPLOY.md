# 🚀 Despliegue en Render - Guía Rápida

**Tu aplicación está en:** `https://bdo-server2.onrender.com`

---

## ✅ Push Completado

Los cambios ya están en `features` y Render debería estar desplegando automáticamente.

---

## ⚠️ IMPORTANTE: Actualizar Variables de Entorno

**Antes de que funcione correctamente, debes actualizar estas variables en Render:**

### 1. Ve a Render Dashboard
- Render Dashboard → `bdo-server2` → Environment

### 2. Actualiza/Crea estas variables:

#### JWT_ACCESS_SECRET (NUEVA - Crítica)
```
mneCvQOvHlm/UJfjk1H6I3NpU5ZULyU5q769/4iHXYN5WmFZRMt/pZWlPMRLea4A
```

#### JWT_REFRESH_SECRET (Actualizar)
```
4SCxZa8KYHGR/qLXPGCLJfHEgd4EMfydWlssdVE/8lwhwkaIEFDVh5czzyAnW3t1
```

#### JWT_SECRET (Actualizar)
```
1PspQAXvmfnXKThuwzhX8qHhoUD5AeFsROEdCN8kHe8xfvk64KWVIWppsIXUm+OC
```

#### NODE_ENV (Cambiar)
```
production
```
(Actualmente está en `development`)

---

## 🔍 Verificar Despliegue

### 1. Ver Estado en Render
- Render Dashboard → `bdo-server2`
- Verifica que el deploy esté en progreso o completado

### 2. Verificar Health Check
```bash
curl https://bdo-server2.onrender.com/health
```

Debería responder:
```json
{
  "status": "healthy",
  "uptime": ...,
  "memory": {...},
  "storage": "cloudflare"
}
```

### 3. Verificar Logs
- Render Dashboard → `bdo-server2` → Logs
- Busca errores relacionados con JWT o variables de entorno

---

## 🔄 Si Render No Auto-Despliega

### Verificar Configuración de Auto-Deploy

1. **Render Dashboard → `bdo-server2` → Settings**
2. **Verifica:**
   - Branch: Debe estar en `features` o `main` (según tu configuración)
   - Auto-Deploy: Debe estar activado
   - Build Command: `npm install && npx prisma generate && npm run build`
   - Start Command: `npm start`

### Forzar Deploy Manual

Si no auto-despliega:
1. Render Dashboard → `bdo-server2`
2. Click en "Manual Deploy"
3. Selecciona la rama `features`
4. Click en "Deploy"

---

## 📋 Checklist Post-Deploy

Después de que Render despliegue:

- [ ] Health check funciona (`/health`)
- [ ] Variables de entorno actualizadas (JWT secrets, NODE_ENV)
- [ ] Logs sin errores críticos
- [ ] Base de datos conectada
- [ ] Storage (Cloudflare R2) funciona
- [ ] Email (SMTP) funciona

---

## 🆘 Troubleshooting

### Error: "JWT secret too short"
**Solución:** Actualiza los JWT secrets en Render con los valores generados

### Error: "Cannot connect to database"
**Solución:** Verifica que `DATABASE_URL` esté correcto en Render

### Error: "Storage driver not found"
**Solución:** Verifica que `STORAGE_DRIVER=cloudflare` y todas las variables de Cloudflare R2 estén configuradas

### Deploy no inicia
**Solución:** 
1. Verifica que la rama esté correcta en Settings
2. Verifica que el build command sea correcto
3. Intenta deploy manual

---

**Estado:** ✅ Push completado - Render debería estar desplegando

