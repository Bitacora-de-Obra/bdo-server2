# 🛡️ Guía Segura para Merge a Producción

**Objetivo:** Hacer merge a producción de forma segura, con puntos de retorno en cada paso.

---

## 🔒 Principios de Seguridad

1. **Nunca perder código**: Git guarda todo el historial
2. **Backups antes de cambios grandes**: Crear ramas de backup
3. **Probar antes de mergear**: Validar en `features` primero
4. **Puntos de retorno**: Tags y ramas de backup en cada paso
5. **Reversión fácil**: Saber cómo volver atrás si algo falla

---

## 📋 Plan Seguro Paso a Paso

### Paso 0: Crear Backup Completo (ANTES DE TODO) ✅

```bash
# En bdo-server
cd bdo-server
git checkout features
git pull origin features
./scripts/create-backup-branch.sh pre-produccion-merge

# En bdo-appd
cd bdo-appd
git checkout features
git pull origin features
./scripts/create-backup-branch.sh pre-produccion-merge
```

**¿Por qué?** Si algo sale mal, puedes volver a este punto exacto.

---

### Paso 1: Validar en `features` Primero

```bash
# Validar que features está estable
cd bdo-server
git checkout features
git pull origin features

# Validar variables de entorno
npm run validate:env

# Pre-despliegue completo
npm run pre-deploy

# Si todo pasa, features está listo ✅
```

**Si algo falla aquí:** No pasa nada, solo arregla en `features` y vuelve a probar.

---

### Paso 2: Crear Tag de Backup de `main`

```bash
# Antes de tocar main, crear un tag de backup
cd bdo-server
git checkout main
git pull origin main
git tag backup-main-$(date +%Y%m%d-%H%M%S)
git push origin --tags

# Hacer lo mismo en bdo-appd
cd ../bdo-appd
git checkout main
git pull origin main
git tag backup-main-$(date +%Y%m%d-%H%M%S)
git push origin --tags
```

**¿Por qué?** Si algo sale mal con `main`, puedes volver al tag:
```bash
git checkout backup-main-20251117-120000
git checkout -b main-restored
```

---

### Paso 3: Merge a `main` (Con Cuidado)

```bash
# Merge features → main
cd bdo-server
git checkout main
git pull origin main

# Merge sin fast-forward para tener un commit de merge explícito
git merge --no-ff features -m "Merge features → main: Preparación para producción"

# Si hay conflictos, resuélvelos aquí
# Si no hay conflictos, continúa

# NO hacer push todavía - primero validar
```

---

### Paso 4: Validar `main` Después del Merge

```bash
# Validar que main funciona después del merge
npm run validate:env
npm run pre-deploy
npm run build

# Si todo pasa, hacer push
git push origin main
```

**Si algo falla aquí:** Puedes revertir el merge:
```bash
git reset --hard HEAD~1  # Deshace el último commit (el merge)
# O volver al tag de backup
git reset --hard backup-main-20251117-120000
```

---

### Paso 5: Crear Tag de Release

```bash
# Si todo está bien, crear tag de release
git tag -a v1.0.0 -m "Release v1.0.0 - Primera versión de producción"
git push origin v1.0.0
```

---

## 🔄 Cómo Volver Atrás (Si Algo Sale Mal)

### Opción 1: Revertir el Último Commit (Merge)
```bash
# Si acabas de hacer merge y quieres deshacerlo
git reset --hard HEAD~1
git push origin main --force  # ⚠️ Solo si es necesario
```

### Opción 2: Volver a un Tag de Backup
```bash
# Ver todos los tags
git tag -l

# Volver a un tag específico
git checkout backup-main-20251117-120000
git checkout -b main-restored

# O resetear main a ese tag
git checkout main
git reset --hard backup-main-20251117-120000
git push origin main --force  # ⚠️ Solo si es necesario
```

### Opción 3: Volver a una Rama de Backup
```bash
# Ver ramas de backup
git branch -a | grep backup

# Volver a una rama de backup
git checkout backup/features-pre-produccion-merge-20251117-120000

# Crear nueva rama desde ahí
git checkout -b main-restored
```

### Opción 4: Revertir un Commit Específico (Sin Perder Historial)
```bash
# Ver historial
git log --oneline

# Revertir un commit específico (crea un nuevo commit que deshace los cambios)
git revert <commit-hash>
git push origin main
```

---

## 🛡️ Protecciones Adicionales

### 1. Configurar Protección de Rama en GitHub

En GitHub → Settings → Branches → Add rule para `main`:
- ✅ Require pull request before merging
- ✅ Require status checks to pass
- ✅ Require branches to be up to date
- ✅ Do not allow force pushes
- ✅ Do not allow deletions

**Esto previene cambios accidentales en `main`.**

### 2. Usar Pull Requests (Recomendado)

En lugar de merge directo, crear PR:
```bash
# Crear PR desde features → main
# GitHub te mostrará los cambios antes de mergear
# Puedes revisar, probar, y luego mergear con un click
```

**Ventajas:**
- ✅ Revisión de código antes de mergear
- ✅ CI/CD puede validar antes
- ✅ Historial claro de quién aprobó qué
- ✅ Fácil de revertir si es necesario

---

## 📊 Checklist de Seguridad

Antes de hacer merge a `main`:

- [ ] ✅ Backup de `features` creado
- [ ] ✅ Tag de backup de `main` creado
- [ ] ✅ `features` validado y funcionando
- [ ] ✅ Sin conflictos pendientes
- [ ] ✅ Tests pasan (si existen)
- [ ] ✅ Build funciona
- [ ] ✅ Variables de entorno validadas
- [ ] ✅ Documentación actualizada

Después del merge:

- [ ] ✅ `main` validado después del merge
- [ ] ✅ Build funciona en `main`
- [ ] ✅ Tag de release creado
- [ ] ✅ Push a `main` exitoso

---

## 🚨 Plan de Emergencia

Si algo sale mal después del merge:

1. **NO ENTRAR EN PÁNICO** - Git guarda todo
2. Identificar el problema
3. Decidir la solución:
   - Revertir el merge (si es reciente)
   - Volver a un tag de backup
   - Hacer un hotfix en `main`
4. Documentar qué pasó y por qué
5. Aprender y mejorar el proceso

---

## 💡 Recomendación Final

**Para el primer merge a producción, usa Pull Requests:**

1. Crear PR desde `features` → `main`
2. Revisar todos los cambios
3. Validar que todo funciona
4. Mergear el PR
5. Crear tag de release

**Esto es más seguro que merge directo porque:**
- ✅ Tienes una revisión visual de todos los cambios
- ✅ Puedes cancelar el PR si ves algo raro
- ✅ GitHub guarda un historial completo
- ✅ Es más fácil revertir si es necesario

---

## ✅ Conclusión

**Git es seguro:** Todo está guardado en el historial. Siempre puedes volver atrás.

**Backups son tu amigo:** Tags y ramas de backup te dan puntos de retorno.

**Probar primero:** Validar en `features` antes de tocar `main`.

**Pull Requests:** La forma más segura de hacer merge a producción.

---

**¿Quieres que te guíe paso a paso en el primer merge? Puedo ayudarte a hacerlo de forma segura.**

