# Cómo Habilitar el Dominio Público en Cloudflare R2

## Pasos para Habilitar el Dominio Público

### Opción 1: Desde el Dashboard del Bucket

1. **Ve al Dashboard de Cloudflare**
   - https://dash.cloudflare.com

2. **Navega a R2**
   - En el menú lateral, busca "Storage & databases" → "R2 object storage"
   - O busca directamente "R2" en el menú

3. **Selecciona tu bucket**
   - Haz clic en `bitacora-files` (no en "Overview")

4. **Ve a Settings**
   - En la parte superior del bucket, busca la pestaña "Settings"
   - O busca "Public Access" o "Custom Domains" en el menú del bucket

5. **Habilita Public Access**
   - Busca la sección "Public Access" o "Public Domain"
   - Deberías ver el dominio: `pub-e07f0269fa994f659a210ce23fc46290.r2.dev`
   - Si está deshabilitado, haz clic en "Allow Public Access" o "Enable"

### Opción 2: Desde la Configuración del Bucket

1. **En el bucket `bitacora-files`**
2. **Busca "Settings" o "Configuration"**
3. **Busca "Public Access" o "Custom Domains"**
4. **Habilita el acceso público**

### Opción 3: Si no encuentras la opción

Puede que Cloudflare haya cambiado la ubicación. Busca:

- **"Public Access"** en cualquier menú del bucket
- **"Custom Domains"** en Settings
- **"Public Domain"** en la configuración
- **"Allow Public Access"** como botón o toggle

## Verificar que está Habilitado

Una vez habilitado, deberías poder acceder directamente a:
```
https://pub-e07f0269fa994f659a210ce23fc46290.r2.dev/log-entries/[nombre-archivo].png
```

Si puedes acceder a esa URL en el navegador, el dominio público está habilitado.

## Configurar CORS (Importante)

Después de habilitar el dominio público, configura CORS:

1. **En el bucket `bitacora-files`**
2. **Ve a "Settings" → "CORS Policy"**
3. **Agrega esta configuración:**

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

## Nota

Si no encuentras la opción de "Public Access", puede ser que:
- Tu cuenta de Cloudflare no tenga esa funcionalidad habilitada
- Necesites usar un Custom Domain en su lugar
- La interfaz haya cambiado

En ese caso, contacta con el soporte de Cloudflare o revisa la documentación más reciente.

