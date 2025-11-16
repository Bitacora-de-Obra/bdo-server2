# Auditoría de Seguridad - Bitácora Digital

**Fecha:** Enero 2025  
**Versión analizada:** feature/log-entry-workflow

## Resumen Ejecutivo

La aplicación implementa **buenas prácticas de seguridad básicas**, pero hay **áreas críticas que requieren atención inmediata** antes de un despliegue en producción.

### Calificación General: ⚠️ **6.5/10** (Requiere mejoras)

---

## ✅ Aspectos Positivos

### 1. **Autenticación y Autorización**
- ✅ JWT con tokens de acceso (15 min) y refresh (7 días)
- ✅ Sistema de `tokenVersion` para invalidar tokens
- ✅ Middleware de autenticación robusto
- ✅ Validación de estado de usuario (active/inactive)
- ✅ Rate limiting en login y refresh tokens
- ✅ Contraseñas hasheadas con bcrypt

### 2. **Protección de Rutas**
- ✅ Middleware `requireAdmin` y `requireEditor`
- ✅ Validación de permisos basada en `appRole` y `projectRole`
- ✅ Protección de endpoints sensibles

### 3. **Configuración de Seguridad**
- ✅ Helmet configurado (headers de seguridad)
- ✅ CORS configurado con whitelist de orígenes
- ✅ Cookies httpOnly y secure en producción
- ✅ Rate limiting implementado

### 4. **Validación de Archivos**
- ✅ Multer configurado con límites de tamaño (10MB)
- ✅ Filtrado de tipos MIME permitidos
- ✅ Validación de extensiones de archivo

### 5. **ORM Seguro**
- ✅ Uso de Prisma ORM (protección contra SQL injection)
- ✅ No se encontraron queries SQL crudas sin sanitizar

---

## ⚠️ Vulnerabilidades y Áreas de Mejora

### 🔴 **CRÍTICAS** (Resolver antes de producción)

#### 1. **Exposición de Información Sensible en Logs**
**Riesgo:** ALTO  
**Ubicación:** `bdo-server/src/index.ts` líneas 1561-1574

```typescript
// Middleware global de debug que expone información
app.use((req, res, next) => {
  if (req.method === "POST") {
    console.log("🌐 GLOBAL MIDDLEWARE: Petición POST detectada");
    console.log("🌐 GLOBAL MIDDLEWARE: Path:", req.path);
    // ... más logs
  }
  next();
});
```

**Problema:**
- Logs de debug en producción pueden exponer rutas, headers, y datos sensibles
- No hay diferenciación entre entorno de desarrollo y producción

**Recomendación:**
```typescript
if (!isProduction) {
  app.use((req, res, next) => {
    // Solo en desarrollo
  });
}
```

#### 2. **Manejo de Errores Expone Stack Traces**
**Riesgo:** MEDIO-ALTO  
**Ubicación:** Múltiples endpoints

**Problema:**
- Errores pueden exponer información de la estructura interna
- Stack traces en respuestas pueden revelar rutas de archivos y estructura del código

**Recomendación:**
```typescript
// En lugar de:
catch (error) {
  console.error(error);
  res.status(500).json({ error: error.message }); // ❌ Expone detalles
}

// Usar:
catch (error) {
  logger.error('Error interno', { error, userId: req.user?.userId });
  res.status(500).json({ 
    error: 'Error interno del servidor',
    code: 'INTERNAL_ERROR' 
  }); // ✅ Mensaje genérico
}
```

#### 3. **Validación de Entrada Insuficiente**
**Riesgo:** MEDIO  
**Ubicación:** Múltiples endpoints POST/PUT

**Problema:**
- No hay validación centralizada de esquemas (Zod, Joi, etc.)
- Validación manual inconsistente
- Posible inyección de datos maliciosos en campos JSON

**Ejemplo problemático:**
```typescript
// Línea 4123 - Parsing JSON sin validación
const value = typeof req.body[field] === "string" 
  ? JSON.parse(req.body[field]) 
  : req.body[field];
```

**Recomendación:**
- Implementar validación con Zod o Joi
- Validar todos los inputs antes de procesarlos
- Sanitizar strings antes de almacenar

#### 4. **Falta de Validación de Permisos Granulares**
**Riesgo:** MEDIO  
**Ubicación:** Endpoints de actualización

**Problema:**
- Algunos endpoints verifican `appRole` pero no verifican si el usuario tiene permiso sobre el recurso específico
- Un usuario podría modificar recursos de otros proyectos si conoce el ID

**Ejemplo:**
```typescript
// Verificar que el usuario pertenece al proyecto antes de permitir edición
const logEntry = await prisma.logEntry.findUnique({
  where: { id },
  include: { project: { include: { members: true } } }
});

if (!logEntry.project.members.some(m => m.id === req.user.userId)) {
  return res.status(403).json({ error: 'No autorizado' });
}
```

#### 5. **Mismo Secreto para Access y Refresh Tokens**
**Riesgo:** MEDIO  
**Ubicación:** `bdo-server/src/middleware/auth.ts` línea 35

```typescript
export const createRefreshToken = (userId: string, tokenVersion: number): string => {
  return jwt.sign(
    { userId, tokenVersion },
    process.env.JWT_SECRET!, // ⚠️ Mismo secreto
    { expiresIn: '7d' }
  );
};
```

**Recomendación:**
- Usar `JWT_REFRESH_SECRET` separado para refresh tokens
- Mayor seguridad en caso de compromiso de un tipo de token

---

### 🟡 **IMPORTANTES** (Resolver pronto)

#### 6. **Falta de Rate Limiting Global**
**Riesgo:** MEDIO  
**Problema:**
- Solo hay rate limiting en login y refresh
- Endpoints sensibles (crear usuarios, exportar datos) no tienen protección

**Recomendación:**
```typescript
const apiRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // 100 requests por ventana
});

app.use('/api/', apiRateLimiter);
```

#### 7. **Validación de Archivos Puede Mejorarse**
**Riesgo:** MEDIO  
**Ubicación:** `bdo-server/src/index.ts` líneas 1577-1636

**Problema:**
- Validación solo por MIME type (puede ser falsificado)
- No hay validación de contenido real del archivo (magic bytes)
- No hay escaneo de malware

**Recomendación:**
- Validar magic bytes además de MIME type
- Considerar escaneo de virus para archivos subidos
- Renombrar archivos con UUIDs para evitar path traversal

#### 8. **Falta de CSRF Protection**
**Riesgo:** MEDIO  
**Problema:**
- No hay protección explícita contra CSRF
- Aunque se usa JWT en headers, las cookies de refresh token son vulnerables

**Recomendación:**
- Implementar tokens CSRF para operaciones críticas
- O usar SameSite=Strict en cookies (ya configurado, pero verificar)

#### 9. **Exposición de IDs de Usuario en URLs**
**Riesgo:** BAJO-MEDIO  
**Problema:**
- IDs de usuario (UUIDs) expuestos en URLs y respuestas
- Puede facilitar enumeración de usuarios

**Recomendación:**
- Considerar usar IDs opacos o hasheados para recursos públicos
- O al menos no exponer IDs en logs de acceso

#### 10. **Falta de Validación de Tamaño de Request Body**
**Riesgo:** BAJO  
**Problema:**
- `express.json({ limit: "10mb" })` es alto para algunos endpoints
- No hay límites diferenciados por endpoint

**Recomendación:**
- Reducir límite global a 1-2MB
- Aumentar solo para endpoints que realmente necesitan archivos grandes

---

### 🟢 **MEJORAS RECOMENDADAS**

#### 11. **Logging Mejorado**
- Implementar logger estructurado (Winston, Pino)
- No loguear información sensible (passwords, tokens)
- Diferentes niveles de log por entorno

#### 12. **Monitoreo y Alertas**
- Implementar monitoreo de intentos de acceso fallidos
- Alertas por actividad sospechosa
- Logging de auditoría más completo

#### 13. **Headers de Seguridad Adicionales**
```typescript
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      // ... más directivas
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
  },
}));
```

#### 14. **Validación de Email y Sanitización**
- Validar formato de email con regex robusto
- Sanitizar HTML en campos de texto (si se permite HTML)
- Protección XSS en campos de texto libre

#### 15. **Secrets Management**
- Verificar que `.env` no esté en el repositorio
- Usar variables de entorno en producción
- Rotar secretos periódicamente

---

## 📋 Checklist de Seguridad Pre-Producción

### Autenticación y Autorización
- [x] JWT implementado correctamente
- [x] Refresh tokens con httpOnly cookies
- [x] Rate limiting en login
- [ ] Separar secretos de access y refresh tokens
- [ ] Implementar 2FA (opcional pero recomendado)

### Validación y Sanitización
- [ ] Implementar validación centralizada (Zod/Joi)
- [ ] Sanitizar todos los inputs de usuario
- [ ] Validar permisos granulares por recurso
- [ ] Validar magic bytes de archivos

### Protección de Datos
- [ ] Encriptar datos sensibles en reposo (si aplica)
- [ ] Implementar backup encriptado
- [ ] Verificar que passwords nunca se loguean
- [ ] Ocultar stack traces en producción

### Configuración
- [ ] Remover logs de debug de producción
- [ ] Configurar CORS restrictivo
- [ ] Verificar que .env no esté en git
- [ ] Configurar HTTPS obligatorio
- [ ] Implementar rate limiting global

### Monitoreo
- [ ] Implementar logging estructurado
- [ ] Configurar alertas de seguridad
- [ ] Auditoría de accesos a recursos sensibles
- [ ] Monitoreo de intentos de acceso fallidos

---

## 🔧 Implementación Prioritaria

### Prioridad 1 (Antes de producción)
1. Remover middleware de debug
2. Mejorar manejo de errores (ocultar stack traces)
3. Implementar validación de entrada centralizada
4. Separar secretos de JWT

### Prioridad 2 (Primeras semanas)
5. Rate limiting global
6. Validación de permisos granulares
7. Mejorar validación de archivos
8. Logging estructurado

### Prioridad 3 (Mejoras continuas)
9. CSRF protection
10. Monitoreo y alertas
11. Headers de seguridad adicionales
12. Rotación de secretos

---

## 📚 Recursos

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [Express Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)

---

**Nota:** Esta auditoría es una evaluación inicial. Se recomienda una auditoría de seguridad profesional antes del despliegue en producción con datos reales.

