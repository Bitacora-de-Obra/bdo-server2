# Actualizar Build Command en Render

## Problema
Render está ejecutando el comando directo sin el flag `--accept-data-loss`, causando que el deploy falle.

## Solución

### Opción 1: Usar el script actualizado (RECOMENDADO)

1. Ve al dashboard de Render: https://dashboard.render.com
2. Selecciona el servicio `bdo-server`
3. Ve a "Settings" → "Build & Deploy"
4. En "Build Command", cambia a:
   ```
   bash scripts/render-build-direct.sh
   ```
5. Guarda los cambios

### Opción 2: Actualizar el comando directo

Si prefieres mantener el comando directo, cambia el "Build Command" a:
```
npm install && npx prisma db push --accept-data-loss && npx prisma generate && npm run build
```

## Verificación

Después de actualizar, el próximo deploy debería:
- ✅ Instalar dependencias
- ✅ Hacer push del schema con --accept-data-loss
- ✅ Generar Prisma Client
- ✅ Compilar TypeScript
- ✅ Completar exitosamente

