# Cómo Agregar un Nuevo Cliente (Tenant)

## Resumen

Con la arquitectura multi-tenant implementada, **NO necesitas clonar el repositorio ni crear nuevos servidores**. Todo se maneja desde el mismo código base y servidor.

## Pasos para Agregar un Nuevo Cliente

### 1. Crear el Tenant en la Base de Datos

Ejecuta este script o SQL para crear el nuevo tenant:

```sql
INSERT INTO Tenant (id, subdomain, name, domain, isActive, createdAt, updatedAt)
VALUES (
  UUID(),
  'nuevocliente',                    -- Subdominio (ej: nuevocliente.bdigitales.com)
  'Proyecto Nuevo Cliente',          -- Nombre del proyecto
  'nuevocliente.bdigitales.com',     -- Dominio completo
  true,                               -- Activo
  NOW(),
  NOW()
);
```

O usa el script de Node.js:

```javascript
// scripts/create-tenant.js
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function createTenant() {
  const tenant = await prisma.$executeRawUnsafe(`
    INSERT INTO Tenant (id, subdomain, name, domain, isActive, createdAt, updatedAt)
    VALUES (
      UUID(),
      ?,
      ?,
      ?,
      true,
      NOW(),
      NOW()
    )
  `, 'nuevocliente', 'Proyecto Nuevo Cliente', 'nuevocliente.bdigitales.com');
  
  console.log('Tenant creado:', tenant);
}

createTenant();
```

### 2. Configurar DNS

#### En tu proveedor de DNS (ej: Cloudflare, GoDaddy):

1. Agregar un registro CNAME:
   - **Nombre**: `nuevocliente`
   - **Tipo**: CNAME
   - **Valor**: `cname.vercel-dns.com` (o el dominio de tu servidor)

#### En Vercel (para el frontend):

1. Ve a tu proyecto en Vercel
2. Settings → Domains
3. Agregar dominio: `nuevocliente.bdigitales.com`
4. Verificar que el DNS esté configurado correctamente

### 3. Crear Usuarios para el Nuevo Tenant

Los usuarios deben crearse con el `tenantId` del nuevo cliente:

```sql
-- Primero obtener el tenantId
SELECT id FROM Tenant WHERE subdomain = 'nuevocliente';

-- Luego crear usuarios con ese tenantId
INSERT INTO User (id, email, password, fullName, tenantId, ...)
VALUES (
  UUID(),
  'admin@nuevocliente.com',
  '$2b$10$...',  -- Hash de la contraseña
  'Admin Nuevo Cliente',
  'TENANT_ID_AQUI',  -- ID del tenant creado
  ...
);
```

O usa el script existente modificado:

```javascript
// scripts/createAdmin.js (modificado para incluir tenantId)
const tenantId = 'TENANT_ID_DEL_NUEVO_CLIENTE';
// ... resto del código
```

### 4. Verificar que Todo Funcione

1. Accede a `https://nuevocliente.bdigitales.com`
2. El middleware debería detectar el tenant automáticamente
3. Intenta iniciar sesión con un usuario del nuevo tenant
4. Verifica que los datos estén aislados (no deberías ver datos de otros clientes)

## Arquitectura Multi-Tenant

### Lo que Comparten Todos los Clientes:

- ✅ **Código base**: Mismo repositorio
- ✅ **Servidor backend**: Mismo servidor (bdo-server2.onrender.com)
- ✅ **Base de datos**: Misma base de datos MySQL
- ✅ **Frontend**: Mismo código desplegado en Vercel

### Lo que es Único por Cliente:

- 🔒 **Subdominio**: `mutis.bdigitales.com`, `nuevocliente.bdigitales.com`, etc.
- 🔒 **Datos**: Aislados por `tenantId` en todas las tablas
- 🔒 **Usuarios**: Cada cliente tiene sus propios usuarios
- 🔒 **Proyectos**: Cada cliente tiene sus propios proyectos

## Ventajas

1. **Escalabilidad**: Fácil agregar nuevos clientes
2. **Costos**: Un solo servidor y base de datos
3. **Mantenimiento**: Un solo deploy actualiza todos los clientes
4. **Seguridad**: Aislamiento completo de datos por `tenantId`

## Consideraciones

1. **Rendimiento**: Monitorear el uso de recursos si hay muchos clientes
2. **Personalización**: Si un cliente necesita features muy específicas, considerar flags de feature
3. **Backups**: Todos los datos están en una sola base de datos, hacer backups regulares

## Scripts Útiles

- `scripts/create-tenant.js`: Crear un nuevo tenant
- `scripts/createAdmin.js`: Crear usuario admin (modificar para incluir tenantId)
- `scripts/test-multi-tenant.js`: Verificar que el multi-tenancy funciona correctamente

