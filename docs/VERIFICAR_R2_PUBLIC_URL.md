# Verificar URLs Públicas de Cloudflare R2

## Problema
Las imágenes no se visualizan en la app aunque están guardadas en Cloudflare R2.

## Verificación

### 1. Verificar que el dominio público esté configurado en Cloudflare

El dominio público de R2 (`https://pub-e07f0269fa994f659a210ce23fc46290.r2.dev`) necesita estar configurado en Cloudflare:

1. Ve a Cloudflare Dashboard → R2 → `bitacora-files`
2. Ve a la pestaña "Settings" → "Public Access"
3. Verifica que el dominio público esté habilitado
4. Si no está habilitado, haz clic en "Allow Access" o configura un Custom Domain

### 2. Verificar formato de URLs

Las URLs deberían tener este formato:
```
https://pub-e07f0269fa994f659a210ce23fc46290.r2.dev/log-entries/1763421648557-396349032-1763421648557-Gemini_Generated_Image_3240313240313240.png
```

### 3. Verificar CORS en Cloudflare R2

Si las imágenes no se cargan, puede ser un problema de CORS:

1. Ve a Cloudflare Dashboard → R2 → `bitacora-files`
2. Ve a "Settings" → "CORS Policy"
3. Agrega esta configuración CORS:

```json
[
  {
    "AllowedOrigins": [
      "https://bdigitales.com",
      "https://bdo-client.vercel.app",
      "http://localhost:5173",
      "http://localhost:3000"
    ],
    "AllowedMethods": ["GET", "HEAD"],
    "AllowedHeaders": ["*"],
    "ExposeHeaders": ["ETag"],
    "MaxAgeSeconds": 3600
  }
]
```

### 4. Probar URL directamente

Prueba acceder directamente a una URL de imagen en el navegador:
```
https://pub-e07f0269fa994f659a210ce23fc46290.r2.dev/log-entries/[nombre-archivo].png
```

Si no carga, el problema está en la configuración del dominio público de R2.

### 5. Verificar en el código

El código genera URLs así:
```typescript
const publicUrl = storage.getPublicUrl(attachment.storagePath);
// Resultado: https://pub-e07f0269fa994f659a210ce23fc46290.r2.dev/log-entries/archivo.png
```

Verifica que `attachment.storagePath` tenga el formato correcto (ej: `log-entries/archivo.png`).


