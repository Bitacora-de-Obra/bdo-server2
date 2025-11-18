# 🔧 Solución al Error de CORS

## ❌ Error Detectado

```
Error: Origin https://bdigitales.com not allowed by CORS
```

---

## 🔍 Causa

El dominio `https://bdigitales.com` no está en la lista de orígenes permitidos en CORS.

---

## ✅ Solución

### Opción 1: Agregar a CORS_ALLOWED_ORIGINS (Recomendado)

En Render Dashboard → `bdo-server2` → Environment:

**Agrega o actualiza la variable:**
```env
CORS_ALLOWED_ORIGINS=https://bdigitales.com,https://bdo-client.vercel.app,http://localhost:5173,http://localhost:3000
```

**O si ya existe, agrega el dominio:**
```env
CORS_ALLOWED_ORIGINS=http://localhost:5173,http://localhost:3000,https://bdo-client.vercel.app,https://bdigitales.com
```

### Opción 2: Actualizar FRONTEND_URL

Si `https://bdigitales.com` es tu dominio principal de producción:

**En Render Dashboard → Environment:**
```env
FRONTEND_URL=https://bdigitales.com
```

El código automáticamente agregará `FRONTEND_URL` a los orígenes permitidos.

### Opción 3: Actualizar APP_BASE_URL

Si tienes `APP_BASE_URL` configurado:

```env
APP_BASE_URL=https://bdigitales.com
```

---

## 📋 Pasos en Render

1. **Render Dashboard → `bdo-server2` → Environment**
2. **Busca `CORS_ALLOWED_ORIGINS`**:
   - Si existe: Agrega `,https://bdigitales.com` al final
   - Si no existe: Crea nueva variable con: `https://bdigitales.com,https://bdo-client.vercel.app`
3. **O actualiza `FRONTEND_URL`** a `https://bdigitales.com`
4. **Guarda y redeploya**

---

## 🔄 Después de Actualizar

1. **Redeploy en Render** (automático o manual)
2. **Verificar que el error desaparece:**
   ```bash
   curl -H "Origin: https://bdigitales.com" \
        -H "Access-Control-Request-Method: GET" \
        -X OPTIONS \
        https://bdo-server2.onrender.com/api/health
   ```

3. **Verificar en los logs** que no aparezca el error de CORS

---

## ✅ Configuración Recomendada

Para producción, deberías tener:

```env
FRONTEND_URL=https://bdigitales.com
CORS_ALLOWED_ORIGINS=https://bdigitales.com,https://bdo-client.vercel.app
```

Esto permitirá:
- ✅ `https://bdigitales.com` (dominio principal)
- ✅ `https://bdo-client.vercel.app` (Vercel - si lo usas)
- ✅ Localhost (para desarrollo local)

---

## 🎯 Resumen

**Problema:** `https://bdigitales.com` no está en la lista de orígenes permitidos

**Solución:** Agregar el dominio a `CORS_ALLOWED_ORIGINS` o actualizar `FRONTEND_URL` en Render

**Impacto:** ⚠️ **SÍ te afecta** - El frontend no podrá hacer requests al backend hasta que se corrija

**Urgencia:** 🔴 **Alta** - Debe corregirse antes de que los usuarios usen la aplicación



