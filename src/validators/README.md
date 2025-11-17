# Sistema de Validación con Zod

Este directorio contiene los schemas de validación usando Zod para validar los datos de entrada de la API.

## Uso Básico

### 1. Crear un Schema

```typescript
// src/validators/exampleSchemas.ts
import { z } from 'zod';
import { commonSchemas } from '../middleware/validation';

export const createExampleSchema = z.object({
  body: z.object({
    name: z.string().min(1, 'El nombre es obligatorio'),
    email: commonSchemas.email,
    age: z.number().int().positive().optional(),
  }),
  params: z.object({
    id: commonSchemas.uuid,
  }),
});
```

### 2. Aplicar Validación a un Endpoint

```typescript
import { validate } from './middleware/validation';
import { createExampleSchema } from './validators/exampleSchemas';

app.post(
  '/api/examples/:id',
  authMiddleware,
  validate(createExampleSchema),
  async (req: AuthRequest, res) => {
    // req.body y req.params ya están validados y tipados
    const { name, email } = req.body;
    const { id } = req.params;
    // ...
  }
);
```

## Validación con Multipart/Form-Data

Para endpoints que usan `multipart/form-data` (con multer), la validación debe aplicarse **después** de que multer procese los archivos:

```typescript
app.post(
  '/api/log-entries',
  authMiddleware,
  upload.array('attachments', 10),
  validate(createLogEntrySchema), // Validación después de multer
  async (req: AuthRequest, res) => {
    // req.body ya está validado
    // req.files contiene los archivos procesados por multer
  }
);
```

## Schemas Comunes

El archivo `middleware/validation.ts` exporta `commonSchemas` con validaciones reutilizables:

- `uuid`: Validación de UUID
- `email`: Validación de email
- `date`: Validación de fecha ISO
- `positiveNumber`: Número positivo
- `nonEmptyString`: String no vacío
- `boolean`: Boolean (acepta string "true"/"false")

## Manejo de Errores

Si la validación falla, el middleware automáticamente responde con:

```json
{
  "error": "Error de validación",
  "code": "VALIDATION_ERROR",
  "details": [
    {
      "path": "email",
      "message": "Email inválido"
    }
  ]
}
```

## Próximos Pasos

1. Crear schemas para todos los endpoints críticos
2. Validar tipos de archivos en multipart
3. Agregar validaciones personalizadas (ej: formato de fecha específico)
4. Validar permisos granulares (usuario puede acceder al recurso)


