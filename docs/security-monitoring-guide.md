# Guía del Sistema de Monitoreo de Seguridad

## 📍 Ubicación del Sistema

El sistema de monitoreo de seguridad está implementado en:

- **Servicio principal**: `bdo-server/src/services/securityMonitoring.ts`
- **Endpoints API**: `bdo-server/src/index.ts` (líneas ~2427-2471)
- **Integración**: Se registra automáticamente en middlewares y puntos críticos

## 🔍 ¿Qué hace?

El sistema registra y monitorea eventos de seguridad en tiempo real:

### Tipos de Eventos Registrados

1. **Autenticación**:
   - `LOGIN_FAILED` - Intentos de login fallidos
   - `LOGIN_SUCCESS` - Logins exitosos
   - `LOGIN_BLOCKED` - Detección de ataques de fuerza bruta
   - `TOKEN_INVALID` - Tokens inválidos
   - `TOKEN_EXPIRED` - Tokens expirados

2. **Autorización**:
   - `ACCESS_DENIED` - Acceso denegado a recursos
   - `UNAUTHORIZED_ACCESS_ATTEMPT` - Intentos de acceso no autorizado

3. **Protección**:
   - `RATE_LIMIT_EXCEEDED` - Exceso de rate limiting
   - `CSRF_TOKEN_INVALID` - Tokens CSRF inválidos
   - `FILE_UPLOAD_REJECTED` - Archivos rechazados

4. **Actividad**:
   - `PASSWORD_CHANGE` - Cambios de contraseña
   - `SUSPICIOUS_ACTIVITY` - Actividad sospechosa detectada

## 🚀 Cómo Usar los Endpoints

### 1. Obtener Eventos de Seguridad

**Endpoint**: `GET /api/admin/security/events`

**Autenticación**: Requiere token de administrador

**Parámetros de consulta (opcionales)**:
- `type` - Tipo de evento (ej: `LOGIN_FAILED`, `ACCESS_DENIED`)
- `severity` - Severidad (`low`, `medium`, `high`, `critical`)
- `ipAddress` - Filtrar por IP
- `userId` - Filtrar por ID de usuario
- `startDate` - Fecha de inicio (ISO 8601)
- `endDate` - Fecha de fin (ISO 8601)
- `limit` - Límite de resultados (default: 100)

**Ejemplo de uso**:

```bash
# Obtener todos los eventos
curl -X GET "http://localhost:4001/api/admin/security/events" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"

# Filtrar por tipo
curl -X GET "http://localhost:4001/api/admin/security/events?type=LOGIN_FAILED&limit=50" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"

# Filtrar por severidad y fecha
curl -X GET "http://localhost:4001/api/admin/security/events?severity=high&startDate=2025-01-01T00:00:00Z" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"

# Filtrar por IP sospechosa
curl -X GET "http://localhost:4001/api/admin/security/events?ipAddress=192.168.1.100" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

**Respuesta**:
```json
{
  "events": [
    {
      "type": "LOGIN_FAILED",
      "severity": "medium",
      "timestamp": "2025-01-17T01:00:00.000Z",
      "ipAddress": "192.168.1.100",
      "userAgent": "Mozilla/5.0...",
      "email": "usuario@example.com",
      "path": "/api/auth/login",
      "method": "POST",
      "details": {
        "reason": "Invalid credentials"
      },
      "metadata": {
        "origin": "http://localhost:3000",
        "referer": "http://localhost:3000/login"
      }
    }
  ],
  "count": 1,
  "filters": {
    "type": "LOGIN_FAILED",
    "limit": 100
  }
}
```

### 2. Obtener Estadísticas de Seguridad

**Endpoint**: `GET /api/admin/security/stats`

**Autenticación**: Requiere token de administrador

**Ejemplo de uso**:

```bash
curl -X GET "http://localhost:4001/api/admin/security/stats" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

**Respuesta**:
```json
{
  "totalEvents": 1250,
  "eventsByType": {
    "LOGIN_FAILED": 45,
    "LOGIN_SUCCESS": 320,
    "ACCESS_DENIED": 12,
    "RATE_LIMIT_EXCEEDED": 3,
    "CSRF_TOKEN_INVALID": 2,
    "PASSWORD_CHANGE": 8
  },
  "eventsBySeverity": {
    "low": 350,
    "medium": 45,
    "high": 12,
    "critical": 0
  },
  "topIPs": [
    { "ip": "192.168.1.100", "count": 25 },
    { "ip": "10.0.0.50", "count": 18 }
  ],
  "recentCriticalEvents": 0
}
```

## 🔔 Detección Automática

El sistema detecta automáticamente:

### 1. Ataques de Fuerza Bruta
- **Umbral**: 5 intentos fallidos en 15 minutos
- **Acción**: Genera evento `LOGIN_BLOCKED` con severidad `high`
- **IP bloqueada**: Se registra para monitoreo

### 2. Actividad Sospechosa
- **Umbral**: 10 eventos sospechosos en 1 hora desde la misma IP
- **Eventos considerados**: `ACCESS_DENIED`, `CSRF_TOKEN_INVALID`, `FILE_UPLOAD_REJECTED`, `UNAUTHORIZED_ACCESS_ATTEMPT`
- **Acción**: Genera evento `SUSPICIOUS_ACTIVITY` con severidad `high`

### 3. Alertas Automáticas
- Los eventos con severidad `critical` o `high` se registran automáticamente en los logs
- Se puede integrar con sistemas externos (email, Slack, SIEM)

## 📊 Dónde se Registran los Eventos

Los eventos se registran automáticamente en:

1. **Middleware de Autenticación** (`middleware/auth.ts`):
   - Tokens expirados/inválidos
   - Usuarios inactivos

2. **Middleware de Permisos** (`middleware/resourcePermissions.ts`):
   - Acceso denegado a recursos
   - Intentos de acceso no autorizado

3. **Rate Limiting** (`index.ts`):
   - Exceso de requests

4. **CSRF Protection** (`middleware/csrf.ts`):
   - Tokens CSRF inválidos

5. **Validación de Archivos** (`middleware/fileValidationMiddleware.ts`):
   - Archivos rechazados

6. **Endpoints de Autenticación** (`index.ts`):
   - Logins fallidos/exitosos
   - Cambios de contraseña

7. **Middlewares de Permisos** (`index.ts`):
   - `requireAdmin` - Acceso denegado de admin
   - `requireEditor` - Acceso denegado de editor

## ⚙️ Configuración

### Variables de Entorno

```env
# Limpieza automática de eventos
SECURITY_CLEANUP_CRON=0 2 * * *  # Diario a las 2 AM (formato cron)
SECURITY_EVENTS_MAX_AGE_DAYS=30  # Mantener eventos por 30 días
```

### Límites

- **Máximo de eventos en memoria**: 10,000
- **Limpieza automática**: Diaria (configurable)
- **Detección de fuerza bruta**: 5 intentos / 15 minutos
- **Detección de actividad sospechosa**: 10 eventos / 1 hora

## 🔄 Limpieza Automática

El sistema ejecuta una tarea programada (cron) que:
- Limpia eventos más antiguos que `SECURITY_EVENTS_MAX_AGE_DAYS`
- Se ejecuta diariamente a las 2 AM (configurable)
- Registra en logs cuando se completa

## 📝 Ejemplo de Integración en Frontend

```typescript
// Obtener eventos de seguridad
async function getSecurityEvents(filters?: {
  type?: string;
  severity?: string;
  limit?: number;
}) {
  const params = new URLSearchParams();
  if (filters?.type) params.append('type', filters.type);
  if (filters?.severity) params.append('severity', filters.severity);
  if (filters?.limit) params.append('limit', filters.limit.toString());

  const response = await fetch(
    `/api/admin/security/events?${params.toString()}`,
    {
      headers: {
        'Authorization': `Bearer ${adminToken}`
      }
    }
  );

  return response.json();
}

// Obtener estadísticas
async function getSecurityStats() {
  const response = await fetch('/api/admin/security/stats', {
    headers: {
      'Authorization': `Bearer ${adminToken}`
    }
  });

  return response.json();
}
```

## 🎯 Casos de Uso

1. **Monitoreo de Intentos de Hackeo**:
   - Filtrar eventos `LOGIN_FAILED` por IP
   - Identificar patrones de fuerza bruta

2. **Auditoría de Accesos**:
   - Revisar eventos `ACCESS_DENIED` para identificar intentos de acceso no autorizado

3. **Análisis de Tráfico**:
   - Ver `topIPs` para identificar IPs con más actividad
   - Analizar eventos por severidad

4. **Cumplimiento**:
   - Exportar eventos para auditorías
   - Rastrear cambios de contraseña

## ⚠️ Notas Importantes

- **Almacenamiento**: Actualmente en memoria (se pierde al reiniciar)
- **Producción**: Considerar migrar a Redis o base de datos para persistencia
- **Privacidad**: Los eventos contienen información sensible (IPs, user agents)
- **Rendimiento**: El sistema está optimizado para hasta 10,000 eventos

## 🔮 Mejoras Futuras

- [ ] Persistencia en base de datos
- ] Integración con sistemas SIEM
- ] Notificaciones por email/Slack
- ] Dashboard de visualización
- ] Exportación de reportes


