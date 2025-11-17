# Cómo Activar Cloudflare R2 para Almacenamiento de Documentos

## Estado Actual

❌ **Cloudflare R2 NO está activo actualmente**

- `STORAGE_DRIVER=local` → Los documentos se guardan localmente
- Variables de Cloudflare configuradas pero no se están usando

## Cómo Activar Cloudflare R2

Cloudflare R2 es compatible con la API de S3, así que podemos usar el driver S3 con las variables de Cloudflare.

### Paso 1: Mapear Variables de Cloudflare a S3

El código actual espera variables `S3_*`, pero tienes variables `CLOUDFLARE_*`. Necesitas agregar estas variables a tu `.env`:

```env
# Cambiar el driver a s3
STORAGE_DRIVER=s3

# Mapear variables de Cloudflare a S3
S3_BUCKET=bitacora-files
S3_REGION=auto
S3_ACCESS_KEY_ID=d96e6b751a5081660efb14ce12b06a35
S3_SECRET_ACCESS_KEY=9e22c8ccf1559982db9dc233e77a0e3bc5e35a07b2ce3540ff002177fbeb5c24
S3_ENDPOINT=https://f5a8cb8424c5d6a19d528a252365d348.r2.cloudflarestorage.com
S3_FORCE_PATH_STYLE=false

# URL pública para acceder a los archivos (opcional)
STORAGE_PUBLIC_URL=https://pub-xxxxx.r2.dev
# O usar el endpoint directamente
# STORAGE_PUBLIC_URL=https://f5a8cb8424c5d6a19d528a252365d348.r2.cloudflarestorage.com/bitacora-files
```

### Paso 2: Verificar que @aws-sdk/client-s3 esté instalado

```bash
cd bdo-server
npm list @aws-sdk/client-s3
```

Si no está instalado:
```bash
npm install @aws-sdk/client-s3
```

### Paso 3: Reiniciar el servidor

Después de cambiar las variables de entorno, reinicia el servidor para que tome los cambios.

### Paso 4: Verificar que funciona

1. Sube un documento (PDF, imagen, etc.) desde la aplicación
2. Verifica en Cloudflare R2 Dashboard que el archivo se subió
3. Verifica que la URL del archivo apunta a Cloudflare R2

## Nota Importante

- Los archivos que ya están guardados localmente NO se migrarán automáticamente
- Solo los nuevos archivos se guardarán en Cloudflare R2
- Si quieres migrar archivos existentes, necesitarás un script de migración

## Variables Necesarias

| Variable | Valor | Descripción |
|----------|-------|-------------|
| `STORAGE_DRIVER` | `s3` | Driver de almacenamiento |
| `S3_BUCKET` | `bitacora-files` | Nombre del bucket en Cloudflare R2 |
| `S3_REGION` | `auto` | Región para Cloudflare R2 |
| `S3_ACCESS_KEY_ID` | (tu access key) | Access Key ID de Cloudflare R2 |
| `S3_SECRET_ACCESS_KEY` | (tu secret) | Secret Access Key de Cloudflare R2 |
| `S3_ENDPOINT` | `https://[ACCOUNT_ID].r2.cloudflarestorage.com` | Endpoint de Cloudflare R2 |
| `S3_FORCE_PATH_STYLE` | `false` | Estilo de path para Cloudflare R2 |
| `STORAGE_PUBLIC_URL` | (opcional) | URL pública para acceder a los archivos |

