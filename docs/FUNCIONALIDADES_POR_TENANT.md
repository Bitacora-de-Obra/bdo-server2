# Funcionalidades Diferentes por Cliente (Tenant)

## Resumen

Cuando un cliente necesita funcionalidades diferentes a otros clientes, hay varias estrategias que puedes usar. Esta guía explica las opciones desde la más simple hasta la más compleja.

## Estrategia 1: Feature Flags por Tenant (Recomendado)

### Concepto

Agregar una columna o tabla de configuración que active/desactive features específicas por tenant.

### Implementación

#### Opción A: Columna JSON en Tenant

```prisma
model Tenant {
  id        String   @id @default(uuid())
  subdomain String   @unique
  name      String
  domain    String
  isActive  Boolean  @default(true)
  
  // Configuración de features
  features  Json?    // { "enableChat": true, "enableReports": false, ... }
  
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}
```

#### Opción B: Tabla de Configuración Separada

```prisma
model Tenant {
  id        String   @id @default(uuid())
  subdomain String   @unique
  name      String
  domain    String
  isActive  Boolean  @default(true)
  
  config    TenantConfig?
  
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}

model TenantConfig {
  id        String   @id @default(uuid())
  tenantId  String   @unique
  tenant    Tenant   @relation(fields: [tenantId], references: [id], onDelete: Cascade)
  
  // Feature flags
  enableChat        Boolean @default(true)
  enableReports     Boolean @default(true)
  enableDrawings    Boolean @default(false)
  enableControlPoints Boolean @default(true)
  
  // Configuraciones específicas
  maxFileSize       Int     @default(10485760) // 10MB
  allowedFileTypes  String  @default("pdf,doc,docx,jpg,png")
  customBranding    Json?   // { logo: "...", colors: {...} }
  
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}
```

### Uso en el Código

```typescript
// En cualquier endpoint o componente
async function someEndpoint(req: Request, res: Response) {
  const tenant = (req as any).tenant;
  
  // Obtener configuración del tenant
  const config = await prisma.tenantConfig.findUnique({
    where: { tenantId: tenant.id }
  });
  
  // Verificar feature flag
  if (!config?.enableChat) {
    return res.status(403).json({ 
      error: "Chat no está habilitado para este tenant" 
    });
  }
  
  // Continuar con la lógica...
}
```

### Helper Function

```typescript
// src/utils/tenantFeatures.ts
export async function hasFeature(
  tenantId: string,
  feature: string
): Promise<boolean> {
  const config = await prisma.tenantConfig.findUnique({
    where: { tenantId }
  });
  
  if (!config) return false;
  
  // Feature flags booleanos
  return (config as any)[feature] === true;
}

// Uso:
if (await hasFeature(tenant.id, 'enableChat')) {
  // Mostrar chat
}
```

## Estrategia 2: Configuración por Tenant

### Concepto

Similar a feature flags, pero para configuraciones más complejas (valores, límites, personalizaciones).

### Ejemplo de Uso

```typescript
// Verificar límite de archivos
const config = await getTenantConfig(tenant.id);
if (fileSize > config.maxFileSize) {
  return res.status(400).json({ 
    error: `El archivo excede el tamaño máximo de ${config.maxFileSize} bytes` 
  });
}

// Personalización de branding
const branding = config.customBranding;
res.render('template', {
  logo: branding?.logo || defaultLogo,
  primaryColor: branding?.colors?.primary || '#000000'
});
```

## Estrategia 3: Condicionales en el Código

### Concepto

Usar condicionales basados en el `tenantId` o `subdomain` para comportamientos diferentes.

### Ejemplo

```typescript
// En un endpoint
app.post('/api/something', async (req, res) => {
  const tenant = (req as any).tenant;
  
  if (tenant.subdomain === 'cliente2') {
    // Lógica específica para cliente2
    return handleCliente2Logic(req, res);
  } else {
    // Lógica estándar
    return handleStandardLogic(req, res);
  }
});
```

### ⚠️ Advertencia

Esta estrategia puede volverse difícil de mantener si hay muchos clientes con lógicas diferentes. Úsala solo para casos muy específicos.

## Estrategia 4: Middleware de Configuración

### Concepto

Cargar la configuración del tenant al inicio de cada request y hacerla disponible.

### Implementación

```typescript
// src/middleware/tenantConfig.ts
export async function loadTenantConfigMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const tenant = (req as any).tenant;
  
  if (tenant) {
    const config = await prisma.tenantConfig.findUnique({
      where: { tenantId: tenant.id }
    });
    
    (req as any).tenantConfig = config || getDefaultConfig();
  }
  
  next();
}

// En index.ts
app.use(detectTenantMiddleware);
app.use(loadTenantConfigMiddleware); // Después de detectTenantMiddleware

// Uso en endpoints
app.get('/api/something', (req, res) => {
  const config = (req as any).tenantConfig;
  
  if (!config.enableFeatureX) {
    return res.status(403).json({ error: 'Feature no disponible' });
  }
  
  // ...
});
```

## Estrategia 5: Frontend - Feature Flags

### Concepto

También puedes controlar features en el frontend basándote en el tenant.

### Implementación

```typescript
// En el frontend
const tenantConfig = await fetch('/api/tenant/config').then(r => r.json());

if (tenantConfig.enableChat) {
  // Renderizar componente de chat
  return <ChatComponent />;
}

// O usando un hook
function useFeature(feature: string) {
  const { tenantConfig } = useTenant();
  return tenantConfig?.[feature] === true;
}

// Uso
function MyComponent() {
  const hasChat = useFeature('enableChat');
  
  return (
    <div>
      {hasChat && <ChatComponent />}
    </div>
  );
}
```

## Ejemplo Completo: Chat por Tenant

### 1. Agregar al Schema

```prisma
model TenantConfig {
  id        String   @id @default(uuid())
  tenantId  String   @unique
  tenant    Tenant   @relation(fields: [tenantId], references: [id])
  
  enableChat Boolean @default(false)
  
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}
```

### 2. Crear Configuración para un Tenant

```typescript
// scripts/enable-chat-for-tenant.js
const tenant = await prisma.tenant.findUnique({
  where: { subdomain: 'cliente2' }
});

await prisma.tenantConfig.upsert({
  where: { tenantId: tenant.id },
  create: {
    tenantId: tenant.id,
    enableChat: true
  },
  update: {
    enableChat: true
  }
});
```

### 3. Usar en el Backend

```typescript
app.get('/api/chat/session', authMiddleware, async (req, res) => {
  const tenant = (req as any).tenant;
  const config = await prisma.tenantConfig.findUnique({
    where: { tenantId: tenant.id }
  });
  
  if (!config?.enableChat) {
    return res.status(403).json({ 
      error: 'Chat no está habilitado para este tenant' 
    });
  }
  
  // Continuar con la lógica del chat...
});
```

### 4. Usar en el Frontend

```typescript
// Obtener configuración al cargar la app
const config = await apiFetch('/api/tenant/config');

// Renderizar condicionalmente
{config.enableChat && <ChatWidget />}
```

## Recomendaciones

### ✅ Usa Feature Flags cuando:
- Necesitas activar/desactivar features completas
- Las diferencias son binarias (sí/no)
- Quieres mantener un solo código base

### ✅ Usa Configuración cuando:
- Necesitas valores personalizados (límites, colores, textos)
- Las diferencias son de grado, no de tipo
- Quieres permitir auto-configuración

### ⚠️ Evita Condicionales Hardcodeados cuando:
- Hay más de 2-3 clientes con lógicas diferentes
- Las diferencias son complejas
- Necesitas cambiar comportamientos sin deploy

## Migración Gradual

Si ya tienes código con lógica específica por cliente, puedes migrar gradualmente:

1. **Fase 1**: Agregar tabla `TenantConfig` con valores por defecto
2. **Fase 2**: Mover condicionales hardcodeados a feature flags
3. **Fase 3**: Permitir configuración desde UI/admin

## Ejemplo de Script de Migración

```typescript
// scripts/migrate-to-tenant-config.js
async function migrate() {
  const tenants = await prisma.tenant.findMany();
  
  for (const tenant of tenants) {
    // Valores por defecto
    const defaultConfig = {
      enableChat: tenant.subdomain === 'mutis', // Solo mutis tiene chat
      enableReports: true,
      maxFileSize: 10485760
    };
    
    await prisma.tenantConfig.upsert({
      where: { tenantId: tenant.id },
      create: {
        tenantId: tenant.id,
        ...defaultConfig
      },
      update: defaultConfig
    });
  }
}
```

