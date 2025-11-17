# 🚀 Cómo Activar Cloudflare R2 en Render (Producción)

## ⚠️ Importante

Los cambios en tu `.env` local **NO afectan** el servidor en producción. Debes actualizar las variables de entorno directamente en Render.

---

## 📋 Pasos para Activar Cloudflare R2 en Render

### Paso 1: Ir al Dashboard de Render

1. Ve a [Render Dashboard](https://dashboard.render.com)
2. Busca tu servicio `bdo-server2`
3. Haz clic en el servicio

### Paso 2: Ir a Environment Variables

1. En el menú lateral, haz clic en **"Environment"**
2. Verás todas las variables de entorno actuales

### Paso 3: Agregar/Actualizar Variables S3

Necesitas agregar o actualizar estas variables:

#### 1. Cambiar STORAGE_DRIVER
- Busca `STORAGE_DRIVER` (si existe)
- Si existe: Cambia el valor de `local` a `s3`
- Si NO existe: Haz clic en **"Add Environment Variable"** y agrega:
  ```
  Key: STORAGE_DRIVER
  Value: s3
  ```

#### 2. Agregar Variables S3

Agrega estas variables (haz clic en **"Add Environment Variable"** para cada una):

```
Key: S3_BUCKET
Value: bitacora-files
```

```
Key: S3_REGION
Value: auto
```

```
Key: S3_ACCESS_KEY_ID
Value: d96e6b751a5081660efb14ce12b06a35
```

```
Key: S3_SECRET_ACCESS_KEY
Value: 9e22c8ccf1559982db9dc233e77a0e3bc5e35a07b2ce3540ff002177fbeb5c24
```

```
Key: S3_ENDPOINT
Value: https://f5a8cb8424c5d6a19d528a252365d348.r2.cloudflarestorage.com
```

```
Key: S3_FORCE_PATH_STYLE
Value: false
```

#### 3. (Opcional) Agregar STORAGE_PUBLIC_URL

Si tienes una URL pública configurada en Cloudflare R2:

```
Key: STORAGE_PUBLIC_URL
Value: https://pub-e07f0269fa994f659a210ce23fc46290.r2.dev
```

O déjala vacía si quieres usar el endpoint por defecto.

### Paso 4: Guardar y Redeployar

1. Haz clic en **"Save Changes"** (Render guarda automáticamente)
2. Render **automáticamente redeployará** el servicio cuando detecte cambios en variables de entorno
3. Espera a que termine el redeploy (puede tomar 2-5 minutos)

### Paso 5: Verificar que Funciona

1. Ve a los **Logs** del servicio en Render
2. Busca este mensaje:
   ```
   Storage driver configurado { driver: 's3' }
   ```
3. Si ves ese mensaje, ¡Cloudflare R2 está activo! ✅

---

## 🔍 Verificación Adicional

### Probar Subiendo un Archivo

1. Ve a tu aplicación: `https://bdigitales.com`
2. Sube un archivo (PDF, imagen, etc.)
3. Verifica en **Cloudflare R2 Dashboard**:
   - Ve a [Cloudflare Dashboard](https://dash.cloudflare.com)
   - R2 → `bitacora-files` bucket
   - Deberías ver el archivo que subiste

### Verificar la URL del Archivo

Después de subir un archivo, la URL debería apuntar a Cloudflare R2, no a `/uploads/`.

---

## 📝 Resumen de Variables a Agregar en Render

| Variable | Valor |
|----------|-------|
| `STORAGE_DRIVER` | `s3` |
| `S3_BUCKET` | `bitacora-files` |
| `S3_REGION` | `auto` |
| `S3_ACCESS_KEY_ID` | `d96e6b751a5081660efb14ce12b06a35` |
| `S3_SECRET_ACCESS_KEY` | `9e22c8ccf1559982db9dc233e77a0e3bc5e35a07b2ce3540ff002177fbeb5c24` |
| `S3_ENDPOINT` | `https://f5a8cb8424c5d6a19d528a252365d348.r2.cloudflarestorage.com` |
| `S3_FORCE_PATH_STYLE` | `false` |
| `STORAGE_PUBLIC_URL` | (opcional) `https://pub-e07f0269fa994f659a210ce23fc46290.r2.dev` |

---

## ⚠️ Notas Importantes

- ✅ Los **nuevos archivos** se guardarán automáticamente en Cloudflare R2
- ⚠️ Los **archivos existentes** que están guardados localmente NO se migrarán automáticamente
- 🔄 Render redeployará automáticamente cuando guardes las variables
- 📋 Las variables `CLOUDFLARE_*` que ya tienes se pueden mantener como referencia, pero no se usan (el código usa `S3_*`)

---

## 🆘 Si Algo Sale Mal

### Si el servidor no inicia:

1. Revisa los **Logs** en Render
2. Busca errores relacionados con S3 o Cloudflare
3. Verifica que todas las variables estén correctamente escritas (sin espacios extra)

### Si los archivos no se suben:

1. Verifica que `STORAGE_DRIVER=s3` esté configurado
2. Verifica que todas las variables `S3_*` estén configuradas
3. Revisa los logs del servidor para ver errores específicos

### Rollback (Volver a Local):

Si necesitas volver a almacenamiento local temporalmente:

1. En Render, cambia `STORAGE_DRIVER` de `s3` a `local`
2. Guarda y espera el redeploy

---

## ✅ Checklist

- [ ] Agregar `STORAGE_DRIVER=s3` en Render
- [ ] Agregar todas las variables `S3_*` en Render
- [ ] Guardar cambios en Render
- [ ] Esperar redeploy automático
- [ ] Verificar en logs: `Storage driver configurado { driver: 's3' }`
- [ ] Probar subiendo un archivo
- [ ] Verificar en Cloudflare R2 Dashboard que el archivo aparece

---

¡Listo! Una vez que completes estos pasos, Cloudflare R2 estará activo en producción. 🎉


