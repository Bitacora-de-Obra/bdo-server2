# Guía de datos y migraciones

## 1. Migración para tareas del cronograma

Se añadió la migración `20251026133000_extend_project_task_columns` que amplía `ProjectTask.name` a 512 caracteres y guarda `dependencies` como `LONGTEXT`. Ejecuta:

```bash
npx prisma migrate deploy
```

Esto elimina los errores `P2000` cuando los nombres provienen de archivos XML extensos.

## 2. Importación de cronograma

El endpoint `POST /api/project-tasks/import` ahora corta cualquier nombre por encima de 512 caracteres y registra un aviso en el servidor. Asegúrate de:

1. Ejecutar `npm run dev` con la variable `DEBUG_IMPORT=1` si quieres ver logs detallados.
2. Validar el XML antes de subirlo; los campos de fecha deben venir en ISO (`YYYY-MM-DD`).
3. Mantener las dependencias como identificadores simples (el backend normaliza el array).

## 3. Datos de arranque

El seed `prisma/seed.ts` crea:

- Proyecto principal (Ampliación Av. Ciudad de Cali).
- Usuarios base (incluye admin y cuentas de demostración).
- Ítems contractuales y tareas iniciales.
- Configuración global (`AppSetting`) con valores sensatos.

Para ejecutar el seed en un entorno limpio:

```bash
npx prisma db push --skip-generate
npm run seed   # si tienes definido el script prisma seed
```

o manualmente:

```bash
node --loader ts-node/esm prisma/seed.ts
```

## 4. Variables de entorno relevantes

- `CRON_XML_MAX_NAME_LENGTH` (opcional): sobrescribe el límite de 512 caracteres si se necesita.
- `DATABASE_URL`: apunta a la instancia MySQL con permisos de migración.

Mantén esta guía actualizada al agregar nuevas migraciones o fuentes de datos.
