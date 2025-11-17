# 🔐 Cómo Corregir los Secretos JWT

## Problema Detectado

Los secretos JWT actuales no cumplen con los requisitos de seguridad:
- ❌ Deben tener al menos 32 caracteres
- ❌ No pueden ser valores de ejemplo

## Solución

### Paso 1: Generar Nuevos Secretos

Ejecuta:
```bash
npm run secrets:generate
```

Esto generará secretos aleatorios seguros en Base64 y Hex.

### Paso 2: Actualizar tu archivo .env

Copia los valores generados y actualiza tu `.env`:

```env
# Usa los valores generados (Base64 o Hex, ambos funcionan)
JWT_ACCESS_SECRET=tu_secreto_generado_aqui_minimo_32_caracteres
JWT_REFRESH_SECRET=otro_secreto_generado_aqui_minimo_32_caracteres
JWT_SECRET=tercer_secreto_generado_aqui_minimo_32_caracteres
```

**Importante:**
- Cada secreto debe ser diferente
- Mínimo 32 caracteres
- Usa los valores generados, no valores de ejemplo

### Paso 3: Validar Nuevamente

```bash
npm run validate:env
```

Ahora debería pasar sin errores críticos.

---

## Nota sobre Advertencias

Las advertencias son normales en desarrollo:
- ⚠️ `NODE_ENV=development` - Cambiar a `production` solo en producción
- ⚠️ `FRONTEND_URL=localhost` - Cambiar al dominio real en producción
- ⚠️ `SECURITY_ALERT_EMAILS` - Opcional, configurar en producción

Estas advertencias NO bloquean el desarrollo, solo son recordatorios para producción.


