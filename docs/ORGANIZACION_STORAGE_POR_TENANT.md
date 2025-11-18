# Organización de Archivos en Cloudflare R2 por Tenant

## Problema Actual

Actualmente, los archivos se organizan así en R2:
```
attachments/2024/11/1234567890-file.pdf
puntos-fijos/controlPointId/2024/11/1234567890-photo.jpg
informes/2024/11/report.pdf
```

**Problema**: No hay diferenciación por tenant. Todos los clientes comparten el mismo espacio.

## Solución: Incluir tenantId en las Rutas

### Estructura Recomendada

```
tenants/{tenantId}/attachments/2024/11/1234567890-file.pdf
tenants/{tenantId}/puntos-fijos/controlPointId/2024/11/1234567890-photo.jpg
tenants/{tenantId}/informes/2024/11/report.pdf
```

O usando el subdomain (más legible):

```
tenants/{subdomain}/attachments/2024/11/1234567890-file.pdf
tenants/{subdomain}/puntos-fijos/controlPointId/2024/11/1234567890-photo.jpg
tenants/{subdomain}/informes/2024/11/report.pdf
```

## Implementación

### Opción 1: Modificar `createStorageKey` (Recomendado)

```typescript
// src/index.ts
const createStorageKey = (
  seccion: string,
  originalName: string,
  subfolder?: string,
  tenantId?: string  // Nuevo parámetro
) => {
  const now = new Date();
  const year = now.getFullYear().toString();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  
  const ext = path.extname(originalName);
  const baseName = sanitizeFileName(path.basename(originalName, ext)) || "file";
  const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
  
  // Normalizar sección
  const normalizedSeccion = seccion
    .replace(/[^a-zA-Z0-9_-]/g, "")
    .toLowerCase();
  
  // Normalizar subfolder si existe
  const normalizedSubfolder = subfolder
    ? subfolder.replace(/[^a-zA-Z0-9_-]/g, "").toLowerCase()
    : undefined;
  
  // Construir path con tenant
  const pathParts: string[] = [];
  
  // Agregar prefijo de tenant si existe
  if (tenantId) {
    pathParts.push('tenants', tenantId);
  }
  
  pathParts.push(normalizedSeccion);
  
  if (normalizedSubfolder) {
    pathParts.push(normalizedSubfolder);
  }
  
  pathParts.push(year, month, `${uniqueSuffix}-${baseName}${ext}`);
  
  return path.posix.join(...pathParts);
};
```

### Opción 2: Helper Function para Obtener tenantId

```typescript
// src/utils/storage.ts
import { Request } from 'express';

export function getTenantIdFromRequest(req: Request): string | undefined {
  return (req as any).tenant?.id;
}

export function getTenantSubdomainFromRequest(req: Request): string | undefined {
  return (req as any).tenant?.subdomain;
}

// Uso en createStorageKey
const createStorageKey = (
  seccion: string,
  originalName: string,
  subfolder?: string,
  req?: Request  // Pasar el request para obtener tenant
) => {
  const tenantId = req ? getTenantIdFromRequest(req) : undefined;
  // ... resto del código
};
```

### Opción 3: Middleware para Agregar tenantId a Request

Ya tienes `detectTenantMiddleware` que agrega `req.tenant`. Puedes usarlo directamente:

```typescript
// En cualquier endpoint de upload
app.post('/api/attachments', multerUpload.single('file'), async (req, res) => {
  const tenantId = (req as any).tenant?.id;
  
  const key = createStorageKey(
    'attachments',
    req.file.originalname,
    undefined,
    tenantId  // Pasar tenantId
  );
  
  await storage.save({ path: key, content: req.file.buffer });
  // ...
});
```

## Ejemplo Completo: Modificar Endpoint de Upload

### Antes (sin tenant):

```typescript
app.post('/api/attachments', multerUpload.single('file'), async (req, res) => {
  const key = createStorageKey('attachments', req.file.originalname);
  await storage.save({ path: key, content: req.file.buffer });
  // ...
});
```

### Después (con tenant):

```typescript
app.post('/api/attachments', multerUpload.single('file'), async (req, res) => {
  const tenantId = (req as any).tenant?.id;
  
  const key = createStorageKey(
    'attachments',
    req.file.originalname,
    undefined,
    tenantId
  );
  
  await storage.save({ path: key, content: req.file.buffer });
  // ...
});
```

## Migración de Archivos Existentes

Si ya tienes archivos en R2 sin el prefijo de tenant, puedes migrarlos:

### Script de Migración

```typescript
// scripts/migrate-storage-to-tenants.js
const { PrismaClient } = require('@prisma/client');
const { S3Client, ListObjectsV2Command, CopyObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const prisma = new PrismaClient();

const s3Client = new S3Client({
  endpoint: process.env.S3_ENDPOINT,
  region: process.env.S3_REGION,
  credentials: {
    accessKeyId: process.env.S3_ACCESS_KEY_ID,
    secretAccessKey: process.env.S3_SECRET_ACCESS_KEY,
  },
});

async function migrateStorage() {
  const bucket = process.env.S3_BUCKET;
  const tenant = await prisma.$queryRawUnsafe(`
    SELECT id, subdomain FROM Tenant WHERE subdomain = 'mutis' LIMIT 1
  `);
  
  if (!tenant || tenant.length === 0) {
    console.log('Tenant no encontrado');
    return;
  }
  
  const tenantId = tenant[0].id;
  
  // Listar todos los objetos en el bucket
  let continuationToken;
  do {
    const command = new ListObjectsV2Command({
      Bucket: bucket,
      ContinuationToken: continuationToken,
    });
    
    const response = await s3Client.send(command);
    
    for (const object of response.Contents || []) {
      const oldKey = object.Key;
      
      // Saltar si ya tiene el prefijo de tenant
      if (oldKey.startsWith(`tenants/${tenantId}/`)) {
        continue;
      }
      
      // Crear nueva clave con prefijo de tenant
      const newKey = `tenants/${tenantId}/${oldKey}`;
      
      console.log(`Migrando: ${oldKey} -> ${newKey}`);
      
      // Copiar a nueva ubicación
      await s3Client.send(new CopyObjectCommand({
        Bucket: bucket,
        CopySource: `${bucket}/${oldKey}`,
        Key: newKey,
      }));
      
      // Eliminar original (opcional, comentar si quieres mantener backup)
      // await s3Client.send(new DeleteObjectCommand({
      //   Bucket: bucket,
      //   Key: oldKey,
      // }));
    }
    
    continuationToken = response.NextContinuationToken;
  } while (continuationToken);
  
  console.log('Migración completada');
}

migrateStorage()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error('Error:', error);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
```

## Actualizar Referencias en Base de Datos

Después de migrar los archivos, actualiza las rutas en la base de datos:

```sql
-- Actualizar storagePath en Attachment
UPDATE Attachment 
SET storagePath = CONCAT('tenants/', tenantId, '/', SUBSTRING(storagePath, 1))
WHERE storagePath NOT LIKE 'tenants/%'
AND tenantId IS NOT NULL;

-- Actualizar storagePath en PhotoEntry (puntos fijos)
UPDATE PhotoEntry
SET storagePath = CONCAT('tenants/', 
  (SELECT tenantId FROM ControlPoint WHERE ControlPoint.id = PhotoEntry.controlPointId), 
  '/', 
  SUBSTRING(storagePath, 1))
WHERE storagePath NOT LIKE 'tenants/%';
```

## Ventajas de Esta Organización

### ✅ Aislamiento Completo
- Cada cliente tiene su propia "carpeta" en R2
- Fácil identificar qué archivos pertenecen a quién
- No hay riesgo de colisiones de nombres

### ✅ Facilidad de Backup
- Puedes hacer backup de un tenant específico:
  ```bash
  # Backup solo de mutis
  aws s3 sync s3://bucket/tenants/mutis/ ./backup/mutis/
  ```

### ✅ Facilidad de Eliminación
- Si un cliente se va, puedes eliminar toda su carpeta:
  ```bash
  aws s3 rm s3://bucket/tenants/cliente-eliminado/ --recursive
  ```

### ✅ Análisis de Uso
- Fácil ver cuánto espacio usa cada cliente:
  ```bash
  aws s3 ls s3://bucket/tenants/mutis/ --recursive --summarize
  ```

## Consideraciones

### Compatibilidad con Archivos Existentes

Si tienes archivos sin el prefijo de tenant, puedes:

1. **Opción A**: Migrar todos los archivos existentes (recomendado)
2. **Opción B**: Mantener compatibilidad hacia atrás:
   ```typescript
   async function readFile(storagePath: string, tenantId?: string) {
     // Intentar con prefijo de tenant primero
     if (tenantId) {
       const tenantPath = `tenants/${tenantId}/${storagePath}`;
       try {
         return await storage.read(tenantPath);
       } catch {
         // Si falla, intentar sin prefijo (archivos antiguos)
       }
     }
     return await storage.read(storagePath);
   }
   ```

### URLs Públicas

Las URLs públicas también cambiarán:

**Antes:**
```
https://r2.bdigitales.com/attachments/2024/11/file.pdf
```

**Después:**
```
https://r2.bdigitales.com/tenants/mutis/attachments/2024/11/file.pdf
```

Asegúrate de actualizar las URLs en la base de datos o usar `storage.getPublicUrl()` que maneja esto automáticamente.

## Implementación Gradual

1. **Fase 1**: Modificar `createStorageKey` para aceptar `tenantId`
2. **Fase 2**: Actualizar todos los endpoints de upload para pasar `tenantId`
3. **Fase 3**: Migrar archivos existentes (opcional)
4. **Fase 4**: Actualizar rutas en base de datos (opcional)

## Ejemplo de Estructura Final

```
tenants/
  ├── mutis/
  │   ├── attachments/
  │   │   └── 2024/
  │   │       └── 11/
  │   │           └── 1234567890-file.pdf
  │   ├── puntos-fijos/
  │   │   └── controlPointId1/
  │   │       └── 2024/
  │   │           └── 11/
  │   │               └── 1234567890-photo.jpg
  │   └── informes/
  │       └── 2024/
  │           └── 11/
  │               └── report.pdf
  └── cliente2/
      ├── attachments/
      └── ...
```

