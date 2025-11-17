# 🔍 Verificación de Configuración de Render

## ⚠️ Si el build aún falla después de los fixes

Verifica estas configuraciones en el dashboard de Render:

### 1. **Environment Variables**

Asegúrate de que estas variables estén configuradas:

```env
NODE_ENV=production
PORT=4001
DATABASE_URL=...
# ... otras variables
```

**Importante:** `NODE_ENV=production` está bien para el runtime, pero el script de build lo maneja temporalmente.

### 2. **Build Command**

En el dashboard de Render, verifica que el **Build Command** sea:
```bash
bash scripts/render-build.sh
```

### 3. **Node Version**

Verifica que Render esté usando Node.js 20.x. Puedes agregar esto al `render.yaml`:

```yaml
services:
  - type: web
    name: bdo-server
    env: node
    plan: starter
    buildCommand: bash scripts/render-build.sh
    startCommand: npm start
    # Agregar esto:
    dockerfilePath: ./Dockerfile  # Si usas Docker
    # O especificar versión de Node:
    # nodeVersion: 20
```

### 4. **Clear Build Cache**

En el dashboard de Render:
1. Ve a tu servicio `bdo-server2`
2. Click en "Settings"
3. Scroll hasta "Clear build cache"
4. Click en "Clear build cache"
5. Haz un nuevo deploy

### 5. **Alternative: Mover tipos a dependencies**

Si nada funciona, como último recurso, mueve los tipos a `dependencies`:

```json
{
  "dependencies": {
    "@types/jsonwebtoken": "^9.0.5",
    "@types/bcryptjs": "^2.4.6",
    "@types/nodemailer": "^7.0.3",
    "@types/pdfkit": "^0.13.6",
    "@types/multer": "^1.4.11"
  },
  "devDependencies": {
    // ... otros devDependencies sin los tipos
  }
}
```

Esto aumentará el tamaño del bundle pero garantiza que los tipos estén disponibles.

### 6. **Verificar Logs**

Revisa los logs de Render para ver:
- Si `npm install --include=dev` se está ejecutando
- Si los tipos se están instalando
- Si hay errores específicos durante la instalación

