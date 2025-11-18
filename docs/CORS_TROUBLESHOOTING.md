# 🔧 Troubleshooting CORS - Error Persistente

## ❌ Problema

Aunque `CORS_ALLOWED_ORIGINS` incluye `https://bdigitales.com`, el error persiste:
```
Error: Origin https://bdigitales.com not allowed by CORS
```

---

## 🔍 Posibles Causas

### 1. Espacios en CORS_ALLOWED_ORIGINS ⚠️

**Problema:** Si tienes espacios después de las comas, los orígenes no se normalizan correctamente.

**Ejemplo problemático:**
```env
CORS_ALLOWED_ORIGINS=https://bdigitales.com, https://bdo-client.vercel.app
#                                    ↑ espacio aquí causa problemas
```

**Solución:** Quita TODOS los espacios:
```env
CORS_ALLOWED_ORIGINS=https://bdigitales.com,https://bdo-client.vercel.app,http://localhost:5173,http://localhost:3000
```

### 2. Render No Ha Redeployado ⚠️

**Problema:** Cambiaste las variables pero Render no ha redeployado.

**Solución:**
1. Render Dashboard → `bdo-server2` → Manual Deploy
2. O espera a que auto-deploy (puede tardar unos minutos)

### 3. Caché del Navegador ⚠️

**Problema:** El navegador puede estar cacheando el error de CORS.

**Solución:**
- Limpia caché del navegador
- Prueba en modo incógnito
- Hard refresh: `Ctrl+Shift+R` (Windows) o `Cmd+Shift+R` (Mac)

---

## ✅ Solución Paso a Paso

### Paso 1: Verificar CORS_ALLOWED_ORIGINS en Render

1. **Render Dashboard → `bdo-server2` → Environment**
2. **Busca `CORS_ALLOWED_ORIGINS`**
3. **Asegúrate de que NO tenga espacios después de las comas:**

**❌ Incorrecto:**
```
https://bdigitales.com, https://bdo-client.vercel.app
```

**✅ Correcto:**
```
https://bdigitales.com,https://bdo-client.vercel.app,http://localhost:5173,http://localhost:3000
```

### Paso 2: Verificar FRONTEND_URL

Asegúrate de que esté configurado:
```env
FRONTEND_URL=https://bdigitales.com
```

### Paso 3: Forzar Redeploy

1. **Render Dashboard → `bdo-server2`**
2. **Click en "Manual Deploy"**
3. **Selecciona la rama `features`**
4. **Click en "Deploy"**

### Paso 4: Verificar Logs

Después del deploy, revisa los logs:
- Deberías ver logs de inicio sin errores de CORS
- Si el error persiste, los logs ahora mostrarán qué orígenes están permitidos

---

## 🔍 Debugging Mejorado

El código ahora registra en los logs cuando se bloquea un origen:
```json
{
  "origin": "https://bdigitales.com",
  "normalizedOrigin": "https://bdigitales.com",
  "allowedOrigins": ["https://bdigitales.com", ...]
}
```

**Revisa los logs en Render para ver:**
- Qué origen está llegando
- Cómo se normaliza
- Qué orígenes están en la lista permitida

---

## ✅ Verificación Final

Después de corregir y redeployar:

```bash
# Probar desde el navegador
# Abre la consola del navegador en https://bdigitales.com
# Intenta hacer login o cualquier request
# No debería aparecer error de CORS
```

O desde terminal:
```bash
curl -H "Origin: https://bdigitales.com" \
     -H "Access-Control-Request-Method: GET" \
     -X OPTIONS \
     https://bdo-server2.onrender.com/api/health
```

Debería retornar headers de CORS sin error.

---

## 🎯 Resumen

**Cambios hechos:**
- ✅ Código mejorado para normalizar orígenes correctamente
- ✅ Logs mejorados para debugging

**Lo que debes hacer:**
1. ✅ Verificar que `CORS_ALLOWED_ORIGINS` NO tenga espacios
2. ✅ Verificar que `FRONTEND_URL=https://bdigitales.com`
3. ✅ Forzar redeploy en Render
4. ✅ Verificar logs después del deploy

**El código ya está pusheado y Render debería estar desplegando automáticamente.**



