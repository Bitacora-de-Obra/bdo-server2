# Sistema de Control de Costos del Chatbot

## 📋 Descripción

El sistema de control de costos del chatbot permite monitorear y limitar el uso de la API de OpenAI para evitar gastos excesivos. Incluye límites diarios y mensuales, alertas progresivas y estadísticas detalladas de uso.

## 🛠️ Características

### Límites Configurables
- **Límite diario**: $5 USD por día
- **Límite mensual**: $50 USD por mes
- **Límite por consulta**: $0.50 USD por consulta
- **Máximo de consultas**: 100 por día, 1000 por mes

### Modelos Soportados
- `gpt-3.5-turbo`: $0.002 por 1K tokens
- `gpt-4-turbo`: $0.01 por 1K tokens
- `gpt-4-vision-preview`: $0.01 por 1K tokens
- `gpt-4o`: $0.005 por 1K tokens
- `gpt-4o-mini`: $0.00015 por 1K tokens

### Alertas Progresivas
- **80% del límite diario**: Advertencia
- **90% del límite diario**: Advertencia crítica
- **95% del límite diario**: Alerta crítica
- **100% del límite diario**: Bloqueo

## 🔧 API Endpoints

### 1. Consulta del Chatbot
```
POST /api/chatbot/query
```

**Request:**
```json
{
  "query": "¿Cuál es el estado actual del proyecto?"
}
```

**Response:**
```json
{
  "response": "Respuesta del chatbot...",
  "model": "gpt-3.5-turbo",
  "cost": 0.002,
  "alert": {
    "type": "WARNING",
    "message": "Has usado el 80% de tu límite diario",
    "remaining": 1.0
  }
}
```

### 2. Estadísticas de Uso
```
GET /api/chatbot/usage
```

**Response:**
```json
{
  "daily": {
    "cost": 2.50,
    "queries": 25,
    "tokens": 15000,
    "limit": 5.00,
    "remaining": 2.50,
    "percentage": 50.0
  },
  "monthly": {
    "cost": 15.75,
    "queries": 150,
    "tokens": 90000,
    "limit": 50.00,
    "remaining": 34.25,
    "percentage": 31.5,
    "projected": 25.00
  },
  "recentHistory": [...],
  "modelStats": [...],
  "efficiency": {
    "avgCostPerQuery": 0.105,
    "avgTokensPerQuery": 600
  }
}
```

### 3. Historial de Uso
```
GET /api/chatbot/history?days=30&limit=100
```

### 4. Alertas de Costo
```
GET /api/chatbot/alerts
```

## 🗄️ Base de Datos

### Tabla: ChatbotUsage
```sql
CREATE TABLE ChatbotUsage (
  id VARCHAR(36) PRIMARY KEY,
  userId VARCHAR(36) NOT NULL,
  date DATE NOT NULL,
  queryCount INT DEFAULT 0,
  cost DECIMAL(10,4) DEFAULT 0.00,
  model VARCHAR(50),
  tokensUsed INT DEFAULT 0,
  createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY unique_user_date (userId, date),
  INDEX idx_user (userId),
  INDEX idx_date (date)
);
```

## ⚙️ Configuración

### Variables de Entorno
```env
OPENAI_API_KEY=tu_clave_de_openai
DATABASE_URL=mysql://usuario:password@localhost:3306/database
```

### Límites Personalizables
Los límites se pueden modificar en `src/utils/costControl.ts`:

```typescript
export const COST_LIMITS = {
  daily: 5.00,           // $5 USD por día
  monthly: 50.00,        // $50 USD por mes
  perQuery: 0.50,        // $0.50 USD por consulta
  maxQueriesPerDay: 100, // Máximo 100 consultas por día
  maxQueriesPerMonth: 1000, // Máximo 1000 consultas por mes
};
```

## 🚀 Uso

### 1. Consulta Básica
```javascript
const response = await fetch('/api/chatbot/query', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + token
  },
  body: JSON.stringify({
    query: '¿Cuál es el estado del proyecto?'
  })
});

const data = await response.json();
console.log(data.response); // Respuesta del chatbot
console.log(data.cost);     // Costo de la consulta
```

### 2. Verificar Estadísticas
```javascript
const stats = await fetch('/api/chatbot/usage', {
  headers: {
    'Authorization': 'Bearer ' + token
  }
});

const data = await stats.json();
console.log(`Costo diario: $${data.daily.cost}/${data.daily.limit}`);
console.log(`Consultas restantes: ${data.daily.remaining}`);
```

## 🔍 Monitoreo

### Logs del Sistema
El sistema registra automáticamente:
- Consultas procesadas
- Costos por consulta
- Modelos utilizados
- Tokens consumidos
- Alertas generadas

### Dashboard de Usuario
Los usuarios pueden ver:
- Uso actual (diario/semanal/mensual)
- Historial de consultas
- Estadísticas por modelo
- Proyecciones de costo
- Alertas activas

## 🛡️ Seguridad

### Validaciones
- Verificación de límites antes de procesar
- Validación de tokens de autenticación
- Sanitización de consultas
- Rate limiting por usuario

### Prevención de Abuso
- Límites estrictos por consulta
- Bloqueo automático al exceder límites
- Monitoreo de patrones de uso
- Alertas en tiempo real

## 📊 Análisis de Costos

### Métricas Disponibles
- Costo promedio por consulta
- Tokens promedio por consulta
- Distribución de uso por modelo
- Patrones de uso temporal
- Eficiencia de costos

### Reportes
- Uso diario/semanal/mensual
- Tendencias de costo
- Análisis de modelos más utilizados
- Proyecciones de gasto

## 🔧 Mantenimiento

### Limpieza de Datos
```sql
-- Eliminar datos antiguos (más de 1 año)
DELETE FROM ChatbotUsage WHERE date < DATE_SUB(NOW(), INTERVAL 1 YEAR);
```

### Optimización
- Índices en userId y date
- Particionado por fecha (opcional)
- Archivo de datos históricos

## 🚨 Solución de Problemas

### Error: Límite Excedido
```json
{
  "error": "Límite de uso excedido",
  "reason": "Límite diario de costo alcanzado",
  "type": "USAGE_LIMIT_EXCEEDED"
}
```

### Error: Modelo No Disponible
```json
{
  "error": "Modelo no disponible",
  "reason": "Modelo gpt-4 no disponible para consultas simples",
  "suggestion": "Usa gpt-3.5-turbo para consultas básicas"
}
```

## 📈 Mejoras Futuras

### Funcionalidades Planificadas
- Límites por proyecto
- Planes de suscripción
- Análisis predictivo
- Integración con facturación
- Dashboard administrativo
- Notificaciones por email
- API de webhooks

### Optimizaciones
- Cache de respuestas frecuentes
- Compresión de contexto
- Modelos híbridos
- Análisis de sentimientos
- Clasificación automática de consultas
