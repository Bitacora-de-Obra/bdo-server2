# Solución: Imágenes no se visualizan en la app

## Problema
Las imágenes están guardadas en Cloudflare R2 pero no se visualizan en la aplicación.

## Causas Posibles

### 1. Dominio Público no habilitado en Cloudflare R2
El dominio público `https://pub-e07f0269fa994f659a210ce23fc46290.r2.dev` necesita estar habilitado.

**Solución:**
1. Ve a Cloudflare Dashboard → R2 → `bitacora-files`
2. Ve a "Settings" → "Public Access" o "Custom Domains"
3. Verifica que el dominio público esté habilitado
4. Si no está, haz clic en "Allow Access" o configura un Custom Domain

### 2. Problema de CORS
Si el dominio público está habilitado pero las imágenes no cargan, puede ser CORS.

**Solución:**
1. Ve a Cloudflare Dashboard → R2 → `bitacora-files`
2. Ve a "Settings" → "CORS Policy"
3. Agrega esta configuración:

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

### 3. URLs antiguas en la base de datos
Los attachments existentes pueden tener URLs antiguas que apuntan al servidor en lugar de R2.

**Solución:**
Ejecuta el script para actualizar las URLs:

```bash
cd bdo-server
# Configura CLOUDFLARE_R2_PUBLIC_URL en el .env o en Render
CLOUDFLARE_R2_PUBLIC_URL=https://pub-e07f0269fa994f659a210ce23fc46290.r2.dev node scripts/update-attachment-urls-r2.js
```

### 4. Verificar que las URLs se generen correctamente
El código ya está generando las URLs correctas usando `storage.getPublicUrl()`, pero verifica:

1. Que `CLOUDFLARE_R2_PUBLIC_URL` esté configurado en Render
2. Que `STORAGE_DRIVER=r2` esté configurado
3. Que los attachments tengan `storagePath` configurado

## Verificación

### Probar URL directamente
Abre en el navegador una URL de imagen:
```
https://pub-e07f0269fa994f659a210ce23fc46290.r2.dev/log-entries/[nombre-archivo].png
```

Si no carga, el problema está en la configuración del dominio público de R2.

### Verificar en Render
1. Ve a Render Dashboard → `bdo-server2` → Environment
2. Verifica que `CLOUDFLARE_R2_PUBLIC_URL` esté configurado
3. Reinicia el servicio después de configurar

## Estado del Código

✅ **Ya corregido:**
- PDF carga imágenes desde R2
- Endpoints de visualización/descarga usan R2
- `buildAttachmentResponse` genera URLs públicas de R2
- Firmas se suben y cargan desde R2

⚠️ **Pendiente:**
- Verificar que el dominio público esté habilitado en Cloudflare
- Configurar CORS si es necesario
- Actualizar URLs de attachments existentes si tienen URLs antiguas


