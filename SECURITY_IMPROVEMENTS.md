# Mejoras de Seguridad Implementadas

## Cambios Realizados

### 1. ✅ Middleware de Debug Removido en Producción
- El middleware de debug que exponía información sensible ahora solo se ejecuta en desarrollo
- En producción, no se loguean detalles de peticiones HTTP

### 2. ✅ Separación de Secretos JWT
- Los tokens de acceso y refresh ahora pueden usar secretos diferentes
- Variables de entorno soportadas:
  - `JWT_SECRET` (fallback para ambos)
  - `JWT_ACCESS_SECRET` (para access tokens)
  - `JWT_REFRESH_SECRET` (para refresh tokens)

**Recomendación:** En producción, usar secretos diferentes para mayor seguridad.

### 3. ✅ Manejo de Errores Mejorado
- Stack traces ocultos en producción
- Mensajes de error genéricos para clientes
- Logging completo en servidor usando `logger`
- Middleware global de manejo de errores implementado

### 4. ✅ Rate Limiting Global
- Rate limiting aplicado a todas las rutas API
- Configurable via variables de entorno:
  - `API_RATE_LIMIT_WINDOW_MS` (default: 15 minutos)
  - `API_RATE_LIMIT_MAX` (default: 100 requests)
- Excluye rutas de autenticación (que tienen su propio limiter)

### 5. ✅ Logging Mejorado
- Uso consistente de `logger` en lugar de `console.error`
- Información sensible no se expone en logs de producción
- Stack traces solo en desarrollo

## Variables de Entorno Nuevas/Opcionales

```env
# JWT Secrets (opcional - JWT_SECRET sigue funcionando como fallback)
JWT_ACCESS_SECRET=tu_secreto_para_access_tokens
JWT_REFRESH_SECRET=tu_secreto_para_refresh_tokens
# Alternativa: leer desde archivos montados
JWT_SECRET_FILE=/run/secrets/jwt_legacy
JWT_ACCESS_SECRET_FILE=/run/secrets/jwt_access
JWT_REFRESH_SECRET_FILE=/run/secrets/jwt_refresh
# Genera nuevos valores ejecutando: npm run secrets:generate

# Rate Limiting Global
API_RATE_LIMIT_WINDOW_MS=900000  # 15 minutos en milisegundos
API_RATE_LIMIT_MAX=100           # Máximo de requests por ventana

# Monitoreo de Seguridad
SECURITY_CLEANUP_CRON=0 2 * * *  # Cron para limpieza (default: diario a las 2 AM)
SECURITY_EVENTS_MAX_AGE_DAYS=30  # Días a mantener eventos (default: 30)

# Request Timeout
REQUEST_TIMEOUT_MS=30000  # Timeout en milisegundos (default: 30000 = 30 segundos)

# Alertas de Seguridad (opcional)
SECURITY_ALERT_EMAILS=seguridad@empresa.com,devops@empresa.com

# Proveedor de Correo (Resend opcional)
RESEND_API_KEY=re_xxxxxxxxxxxxxxxxxxxxxx
RESEND_FROM="Bitácora Digital <no-reply@tu-dominio.com>"
RESEND_MODE=test   # o 'live'
```

### 6. ✅ Protección CSRF
- Implementado patrón "Double Submit Cookie" para protección CSRF
- Tokens CSRF generados automáticamente en requests GET
- Verificación de tokens en requests modificadores (POST, PUT, PATCH, DELETE)
- Compatible con APIs REST que usan JWT (no bloquea si no hay cookie CSRF)
- Rutas públicas excluidas de verificación CSRF
- Timing-safe comparison para prevenir timing attacks

### 7. ✅ Sistema de Monitoreo de Seguridad
- **Registro de eventos de seguridad**: Sistema completo de monitoreo implementado
- **Tipos de eventos registrados**:
  - `LOGIN_FAILED` / `LOGIN_SUCCESS` / `LOGIN_BLOCKED`
  - `ACCESS_DENIED` / `UNAUTHORIZED_ACCESS_ATTEMPT`
  - `RATE_LIMIT_EXCEEDED`
  - `CSRF_TOKEN_INVALID`
  - `FILE_UPLOAD_REJECTED`
  - `TOKEN_INVALID` / `TOKEN_EXPIRED`
  - `PASSWORD_CHANGE`
  - `SUSPICIOUS_ACTIVITY`
- **Detección automática de patrones**:
  - Detección de ataques de fuerza bruta (5 intentos fallidos en 15 minutos)
  - Detección de actividad sospechosa (10 eventos en 1 hora)
  - Alertas automáticas para eventos críticos y de alta severidad
- **Registro en middlewares de permisos**:
  - `requireAdmin`: Registra eventos cuando se deniega acceso de administrador
  - `requireEditor`: Registra eventos cuando se deniega acceso de editor
  - `requireLogEntryAccess`: Registra eventos cuando se deniega acceso a recursos
- **Endpoints de administración**:
  - `GET /api/admin/security/events`: Obtener eventos filtrados
  - `GET /api/admin/security/stats`: Obtener estadísticas de seguridad
- **Limpieza automática**: Tarea programada (cron) para limpiar eventos antiguos
  - Configurable via `SECURITY_CLEANUP_CRON` (default: "0 2 * * *" - diario a las 2 AM)
  - `SECURITY_EVENTS_MAX_AGE_DAYS` (default: 30 días)
- **Almacenamiento**: In-memory (en producción, considerar Redis o base de datos)
  - Máximo 10,000 eventos en memoria
  - Limpieza automática de eventos antiguos

### 8. ✅ Account Lockout (Bloqueo de Cuentas)
- **Protección contra fuerza bruta**: Bloqueo automático de cuentas después de 5 intentos fallidos de login
- **Duración del bloqueo**: 15 minutos (configurable)
- **Ventana de tiempo**: Los intentos se cuentan en una ventana de 15 minutos
- **Limpieza automática**: Los intentos fallidos se limpian después de un login exitoso
- **Mensajes informativos**: El usuario recibe información sobre cuántos intentos le quedan y cuándo se desbloqueará la cuenta
- **Integración con monitoreo**: Los bloqueos se registran como eventos de seguridad de alta severidad

### 9. ✅ Headers de Seguridad Mejorados (Helmet)
- **Content Security Policy (CSP)**: Política estricta para prevenir XSS y ataques de inyección
- **HTTP Strict Transport Security (HSTS)**: Fuerza conexiones HTTPS con max-age de 1 año
- **X-Frame-Options**: Previene clickjacking (deny)
- **X-Content-Type-Options**: Previene MIME type sniffing (noSniff)
- **X-XSS-Protection**: Habilita filtro XSS del navegador
- **Referrer Policy**: Controla qué información de referrer se envía (strict-origin-when-cross-origin)
- **Permitted Cross-Domain Policies**: Deshabilitado para mayor seguridad

### 10. ✅ Validación de Fortaleza de Contraseñas
- **Requisitos mínimos**:
  - Mínimo 8 caracteres
  - Al menos una letra mayúscula
  - Al menos una letra minúscula
  - Al menos un número
  - Al menos un carácter especial (!@#$%^&*()_+-=[]{}|;:,.<>?)
- **Evaluación de fortaleza**: Clasifica contraseñas como weak, medium o strong
- **Mensajes detallados**: Retorna lista de errores específicos cuando la contraseña no cumple requisitos
- **Compatibilidad**: Respeta la configuración de `requireStrongPassword` en AppSettings

### 11. ✅ Request Timeout
- **Timeout global**: 30 segundos por defecto (configurable via `REQUEST_TIMEOUT_MS`)
- **Prevención de requests colgados**: Termina automáticamente requests que tardan demasiado
- **Respuesta apropiada**: Retorna error 408 (Request Timeout) con mensaje claro
- **Limpieza automática**: Limpia el timeout cuando la respuesta se envía correctamente

### 12. ✅ Límites de Tamaño de Body Más Estrictos
- **Límite global JSON**: Reducido de 10MB a 2MB
- **Protección contra DoS**: Previene ataques de denegación de servicio mediante requests grandes
- **Nota**: Endpoints específicos que necesitan archivos grandes (como uploads) usan multer con límites separados

### 13. ✅ Gestión de Secretos Reforzada
- **Gestor centralizado (`src/config/secrets.ts`)**: Todas las claves sensibles se cargan desde un único módulo con validaciones de entropía y longitud (`>=32` caracteres).
- **Soporte para archivos seguros**: Cada secreto acepta una variante `_FILE` (por ejemplo `JWT_ACCESS_SECRET_FILE`) para apuntar a archivos montados por el sistema operativo o un Vault.
- **Fallback controlado**: Si `JWT_ACCESS_SECRET` no existe, se usa `JWT_SECRET` pero se deja registro en logs para facilitar la separación en producción.
- **Script de rotación**: `npm run secrets:generate` produce cadenas Base64/Hex aleatorias listas para actualizar en el gestor de secretos.
- **Tip de operación**: los archivos apuntados por las variables `_FILE` se leen solo al arrancar la app; basta con reemplazarlos y reiniciar el proceso para completar una rotación.

### 14. ✅ Monitoreo Persistente y Alertas
- **Persistencia en base de datos**: Los eventos se guardan en la tabla `SecurityEventLog`, lo que permite auditoría histórica, visualización en dashboards y análisis post-mortem.
- **Endpoints consolidados**: `GET /api/admin/security/events` y `GET /api/admin/security/stats` ahora consultan la información persistida para que los datos sobrevivan reinicios.
- **Retención automática**: El cron configurado con `SECURITY_CLEANUP_CRON` elimina tanto la caché en memoria como los registros antiguos en la base de datos.
- **Alertas inmediatas**: Si defines `SECURITY_ALERT_EMAILS` y hay SMTP configurado, los eventos `high`/`critical` disparan un correo con los detalles clave.

### 15. ✅ Proveedor de Correo Moderno (Resend opcional)
- **Resend como transporte primario**: Si defines `RESEND_API_KEY` y `RESEND_FROM`, todos los correos se envían mediante la API de Resend (con `SMTP_HOST` como fallback automático si falla o no está configurado).
- **Modo de pruebas**: Con `RESEND_MODE=test` puedes validar en ambientes de QA sin enviar correos reales (aprovechamos el “Test Mode” descrito por Resend).
- **Configuración sencilla**: Solo requiere la API key (`re_xxx`) y la dirección `from`. Se mantiene compatibilidad con Gmail/SMTP para entornos que aún no estén migrados.

## Próximos Pasos Recomendados

1. ✅ **Validación de Entrada Centralizada**: Implementado con Zod
2. ✅ **Permisos Granulares**: Implementado para log entries
3. ✅ **Validación de Archivos Mejorada**: Implementado con magic bytes
4. ✅ **CSRF Protection**: Implementado con Double Submit Cookie pattern
5. ✅ **Monitoreo**: Sistema completo de monitoreo y alertas implementado
6. ✅ **Account Lockout**: Implementado con bloqueo temporal después de intentos fallidos
7. ✅ **Headers de Seguridad**: Helmet configurado con CSP, HSTS y otros headers
8. ✅ **Validación de Contraseñas**: Validación robusta de fortaleza de contraseñas
9. ✅ **Request Timeout**: Timeout global para prevenir requests colgados
10. ✅ **Límites de Body**: Límites más estrictos para prevenir DoS
11. ✅ **Gestión de Secretos**: Validación, archivos seguros y script de rotación
12. ✅ **Monitoreo Persistente**: Eventos guardados en DB y alertas opcionales por correo
13. ✅ **Proveedor de Correo Moderno**: Resend como opción para mejorar la entregabilidad
14. **Integración con sistemas externos**: Considerar integración con:
    - Sistemas de SIEM (Security Information and Event Management)
    - Notificaciones por email a administradores
    - Integración con Slack/Discord para alertas en tiempo real
    - Almacenamiento persistente en base de datos o Redis para eventos históricos

## Testing

Para probar las mejoras:

1. Verificar que en producción no se exponen stack traces
2. Verificar que el rate limiting funciona correctamente
3. Verificar que los logs no contienen información sensible
4. Probar con secretos JWT separados
5. **Probar sistema de monitoreo**:
   - Intentar acceder a endpoints de admin sin permisos → Verificar evento `ACCESS_DENIED`
   - Intentar login con credenciales incorrectas → Verificar evento `LOGIN_FAILED`
   - Exceder rate limit → Verificar evento `RATE_LIMIT_EXCEEDED`
   - Cambiar contraseña → Verificar evento `PASSWORD_CHANGE`
   - Consultar eventos: `GET /api/admin/security/events`
   - Consultar estadísticas: `GET /api/admin/security/stats`
6. **Probar Account Lockout**:
   - Intentar login con contraseña incorrecta 5 veces → Verificar que la cuenta se bloquea
   - Intentar login con cuenta bloqueada → Verificar mensaje de bloqueo con tiempo restante
   - Esperar 15 minutos o hacer login exitoso → Verificar que el bloqueo se limpia
7. **Probar validación de contraseñas**:
   - Intentar cambiar contraseña con contraseña débil → Verificar mensajes de error detallados
   - Cambiar contraseña con contraseña fuerte → Verificar que se acepta
8. **Probar headers de seguridad**:
   - Verificar que las respuestas incluyen headers CSP, HSTS, X-Frame-Options, etc.
   - Usar herramientas como SecurityHeaders.com para verificar la configuración
9. **Probar request timeout**:
   - Crear un endpoint de prueba que tarde más de 30 segundos → Verificar que retorna 408

## Notas

- Los cambios son retrocompatibles: si no se configuran los nuevos secretos, se usa `JWT_SECRET`
- El middleware de debug sigue disponible en desarrollo para facilitar debugging
- El rate limiting global puede ajustarse según las necesidades del proyecto

