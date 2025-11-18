# 🌿 Estrategia de Ramas Git - Bitácora Digital

**Fecha:** Noviembre 2025

---

## 📋 Estructura de Ramas Propuesta

### Opción 1: GitFlow Simplificado (Recomendada) ✅

```
main (producción)
  ↑
features (desarrollo/integración)
  ↑
feature/* (features individuales)
```

**Flujo:**
1. Desarrollo en `feature/*`
2. Merge a `features` para integración
3. Merge a `main` cuando está listo para producción
4. `main` siempre desplegable

**Ventajas:**
- ✅ Simple y claro
- ✅ `main` siempre estable
- ✅ Fácil de seguir

---

### Opción 2: Con Rama Explícita de Producción

```
production (producción - solo merge desde main)
  ↑
main (staging/pre-producción)
  ↑
features (desarrollo/integración)
  ↑
feature/* (features individuales)
```

**Flujo:**
1. Desarrollo en `feature/*`
2. Merge a `features` para integración
3. Merge a `main` para staging/testing
4. Merge a `production` cuando está listo para producción real

**Ventajas:**
- ✅ Separación clara entre staging y producción
- ✅ Permite testing en `main` antes de producción
- ✅ `production` solo se actualiza cuando está 100% listo

**Desventajas:**
- ⚠️ Más complejo
- ⚠️ Requiere mantener dos ramas principales sincronizadas

---

## 🎯 Recomendación

**Recomiendo la Opción 1 (GitFlow Simplificado)** porque:

1. **Ya tienen la estructura**: `main` y `features` existen
2. **Más simple**: Menos ramas = menos confusión
3. **Estándar de la industria**: Patrón común y bien entendido
4. **Suficiente para el proyecto**: No necesitan la complejidad adicional

**Estructura final:**
- `main` = **Producción** (siempre estable, desplegable)
- `features` = **Desarrollo** (integración de features)
- `feature/*` = **Features individuales**

---

## 📝 Flujo de Trabajo Propuesto

### Para Desarrollo Normal:
```bash
# 1. Crear feature branch desde features
git checkout features
git pull origin features
git checkout -b feature/nueva-funcionalidad

# 2. Desarrollar y commitear
git add .
git commit -m "feat: nueva funcionalidad"
git push origin feature/nueva-funcionalidad

# 3. Merge a features (después de revisión)
git checkout features
git merge feature/nueva-funcionalidad
git push origin features
```

### Para Ir a Producción:
```bash
# 1. Asegurar que features está estable
git checkout features
npm run validate:env
npm run pre-deploy

# 2. Merge a main
git checkout main
git pull origin main
git merge features
git push origin main

# 3. Tag de release (opcional)
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

---

## 🚀 Para el Primer Despliegue a Producción

### Paso 1: Consolidar Features en `features`
```bash
# En bdo-server
git checkout features
git merge feature/security-improvements
git merge feature/security-monitoring-persistence
git merge feature/secret-hardening
git merge feature/email-resend
git merge feature/security-updates
git push origin features

# En bdo-appd
git checkout features
git merge feature/offline-mode
git merge feature/camera-photo-capture
git merge feature/comment-mentions
git push origin features
```

### Paso 2: Validar en `features`
```bash
# Validar que todo funciona
npm run validate:env
npm run pre-deploy
npm run build
npm start  # Probar localmente
```

### Paso 3: Merge a `main` (Producción)
```bash
git checkout main
git pull origin main
git merge features
git push origin main

# Tag de release
git tag -a v1.0.0 -m "Primera versión de producción"
git push origin v1.0.0
```

---

## 🔒 Protección de Ramas (Recomendado)

En GitHub, configurar protección para `main`:
- ✅ Requerir Pull Request para merge
- ✅ Requerir revisión de código
- ✅ Requerir que los checks pasen (`validate:env`, `pre-deploy`)
- ✅ No permitir force push
- ✅ Requerir que esté actualizada con `features`

---

## 📊 Estado Actual vs Propuesta

### Estado Actual:
- `main` - Rama principal (probablemente producción)
- `features` - Integración de features
- `feature/*` - Features individuales
- `develop` - Existe pero no se usa mucho

### Propuesta:
- **`main`** = Producción (siempre estable)
- **`features`** = Desarrollo/Integración
- **`feature/*`** = Features individuales
- **`develop`** = Eliminar o usar como alternativa a `features`

---

## ✅ Checklist para Producción

Antes de mergear `features` → `main`:

- [ ] Todas las features están mergeadas en `features`
- [ ] `npm run validate:env` pasa sin errores
- [ ] `npm run pre-deploy` pasa sin errores
- [ ] Tests pasan (si existen)
- [ ] Build funciona correctamente
- [ ] Documentación actualizada
- [ ] Variables de entorno configuradas
- [ ] Migraciones listas para ejecutar

---

## 🎯 Conclusión

**Recomendación final:** Usar `main` como producción directamente.

**Razones:**
1. Ya tienen la estructura correcta
2. Es más simple y mantenible
3. `main` es el estándar para producción
4. No necesitan la complejidad de una rama `production` separada

**Si en el futuro necesitan más control:**
- Pueden usar tags para versiones específicas
- Pueden crear `production` más adelante si es necesario
- Pueden usar `main` como staging y crear `production` después

---

**¿Quieres que implementemos esta estrategia ahora?**



