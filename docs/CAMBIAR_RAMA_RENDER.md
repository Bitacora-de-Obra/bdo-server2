# 🔄 Cómo Cambiar la Rama en Render

## Opción 1: Cambiar en el Dashboard de Render (Recomendado)

1. **Ve al Dashboard de Render**
   - https://dashboard.render.com
   - Selecciona tu servicio `bdo-server2`

2. **Ve a Settings**
   - Click en "Settings" en el menú lateral

3. **Busca "Build & Deploy"**
   - Scroll hasta la sección "Build & Deploy"

4. **Cambia la Branch**
   - En "Branch", cambia de `features` a `fix/render-build-types`
   - Click en "Save Changes"

5. **Trigger Manual Deploy**
   - Ve a la pestaña "Events" o "Manual Deploy"
   - Click en "Manual Deploy"
   - Render comenzará a deployar desde la nueva rama

## Opción 2: Actualizar render.yaml (Alternativa)

Si prefieres mantener la configuración en el código, puedes actualizar `render.yaml`:

```yaml
services:
  - type: web
    name: bdo-server
    env: node
    plan: starter
    buildCommand: bash scripts/render-build.sh
    startCommand: npm start
    # Agregar esto:
    branch: fix/render-build-types  # Cambiar aquí
    envVars:
      - key: NODE_ENV
        value: production
      - key: PORT
        value: 4001
    healthCheckPath: /health
    autoDeploy: true
```

**Nota:** Render puede no leer `render.yaml` automáticamente si ya tienes el servicio configurado. Es mejor cambiar desde el dashboard.

## ⚠️ Importante

- **Después de probar**, recuerda cambiar la rama de vuelta a `features` en Render
- O haz merge de `fix/render-build-types` a `features` cuando todo funcione

## 🔄 Volver a features

Cuando quieras volver a deployar desde `features`:

1. Dashboard → Settings → Build & Deploy
2. Cambia Branch de `fix/render-build-types` a `features`
3. Save Changes
4. Manual Deploy

