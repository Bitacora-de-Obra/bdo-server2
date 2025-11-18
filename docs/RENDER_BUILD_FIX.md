# 🔧 Fix para Build de Render - Errores de TypeScript

## ❌ Problema

El build en Render falla con errores de TypeScript indicando que los tipos no se encuentran:
- `Could not find a declaration file for module 'jsonwebtoken'`
- `Could not find a declaration file for module 'bcryptjs'`
- `Could not find a declaration file for module 'nodemailer'`
- `Could not find a declaration file for module 'pdfkit'`

## 🔍 Causa

Render configura `NODE_ENV=production` por defecto, lo que hace que `npm ci` y `npm install` **NO instalen `devDependencies`** por defecto. Los tipos de TypeScript (`@types/*`) están en `devDependencies`, por lo que no se instalan.

## ✅ Solución

El script `scripts/render-build.sh` ahora:

1. **Guarda el NODE_ENV original** (production en Render)
2. **Temporalmente cambia a `NODE_ENV=development`** solo para instalar dependencias
3. **Usa `npm install --include=dev`** para forzar la instalación de devDependencies
4. **Verifica que los tipos estén instalados** antes de continuar
5. **Restaura NODE_ENV original** para el resto del build

## 📋 Verificación

El script verifica que estos tipos estén instalados:
- `@types/jsonwebtoken`
- `@types/bcryptjs`
- `@types/nodemailer`
- `@types/pdfkit`
- `@types/multer`

## 🚀 Próximos Pasos

Si el build aún falla después de este fix:

1. **Verifica los logs de Render** para ver si los tipos se están instalando
2. **Revisa si hay errores de Prisma Client** - puede que la migración de `SecurityEventLog` no se haya aplicado
3. **Verifica que el schema de Prisma** tenga todos los modelos necesarios

## 🔄 Alternativa: Mover tipos a dependencies

Si el problema persiste, una solución alternativa es mover los tipos de `devDependencies` a `dependencies`:

```json
{
  "dependencies": {
    "@types/jsonwebtoken": "^9.0.5",
    "@types/bcryptjs": "^2.4.6",
    "@types/nodemailer": "^7.0.3",
    "@types/pdfkit": "^0.13.6",
    "@types/multer": "^1.4.11"
  }
}
```

**Nota:** Esto aumentará el tamaño del bundle de producción, pero garantiza que los tipos estén disponibles durante el build.



