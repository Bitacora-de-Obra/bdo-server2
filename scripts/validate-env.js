#!/usr/bin/env node

/**
 * Script de validación de variables de entorno
 * Verifica que todas las variables críticas estén configuradas antes de producción
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Colores para output
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
};

const log = {
  success: (msg) => console.log(`${colors.green}✓${colors.reset} ${msg}`),
  error: (msg) => console.log(`${colors.red}✗${colors.reset} ${msg}`),
  warning: (msg) => console.log(`${colors.yellow}⚠${colors.reset} ${msg}`),
  info: (msg) => console.log(`${colors.blue}ℹ${colors.reset} ${msg}`),
  section: (msg) => console.log(`\n${colors.cyan}${msg}${colors.reset}`),
};

// Cargar variables de entorno
require('dotenv').config();

const errors = [];
const warnings = [];

// Validar que un secreto tenga longitud mínima
const validateSecretLength = (value, name, minLength = 32) => {
  if (!value || value.length < minLength) {
    errors.push(`${name} debe tener al menos ${minLength} caracteres`);
    return false;
  }
  return true;
};

// Validar que no sea un valor de ejemplo
const validateNotExample = (value, name, examples = []) => {
  const lowerValue = value.toLowerCase();
  if (examples.some(ex => lowerValue.includes(ex.toLowerCase()))) {
    errors.push(`${name} parece ser un valor de ejemplo. Debe ser un valor real.`);
    return false;
  }
  return true;
};

// Validar URL
const validateUrl = (value, name) => {
  try {
    new URL(value);
    return true;
  } catch {
    errors.push(`${name} debe ser una URL válida`);
    return false;
  }
};

// Validar email
const validateEmail = (value, name) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(value)) {
    errors.push(`${name} debe ser un email válido`);
    return false;
  }
  return true;
};

// Validar que un archivo exista
const validateFileExists = (filePath, name) => {
  if (!filePath) return false;
  const fullPath = path.resolve(filePath);
  if (!fs.existsSync(fullPath)) {
    errors.push(`${name} apunta a un archivo que no existe: ${filePath}`);
    return false;
  }
  return true;
};

log.section('🔍 Validación de Variables de Entorno');

// 1. NODE_ENV
log.section('1. Entorno de Ejecución');
if (process.env.NODE_ENV === 'production') {
  log.success('NODE_ENV está configurado como production');
} else if (process.env.NODE_ENV === 'development') {
  warnings.push('NODE_ENV está en development. Asegúrate de cambiarlo a production en producción.');
  log.warning('NODE_ENV está en development');
} else {
  warnings.push('NODE_ENV no está configurado. Se asumirá development.');
  log.warning('NODE_ENV no está configurado');
}

// 2. Base de Datos
log.section('2. Base de Datos');
if (process.env.DATABASE_URL) {
  if (process.env.DATABASE_URL.includes('localhost') || process.env.DATABASE_URL.includes('127.0.0.1')) {
    warnings.push('DATABASE_URL apunta a localhost. En producción debe apuntar a un servidor remoto.');
    log.warning('DATABASE_URL apunta a localhost');
  } else {
    log.success('DATABASE_URL está configurado');
  }
} else {
  errors.push('DATABASE_URL es requerida');
  log.error('DATABASE_URL no está configurada');
}

// 3. Secretos JWT
log.section('3. Secretos JWT');
const jwtAccessSecret = process.env.JWT_ACCESS_SECRET || 
  (process.env.JWT_ACCESS_SECRET_FILE ? 
    (validateFileExists(process.env.JWT_ACCESS_SECRET_FILE, 'JWT_ACCESS_SECRET_FILE') ? 
      fs.readFileSync(path.resolve(process.env.JWT_ACCESS_SECRET_FILE), 'utf-8').trim() : null) : 
    process.env.JWT_SECRET);

const jwtRefreshSecret = process.env.JWT_REFRESH_SECRET || 
  (process.env.JWT_REFRESH_SECRET_FILE ? 
    (validateFileExists(process.env.JWT_REFRESH_SECRET_FILE, 'JWT_REFRESH_SECRET_FILE') ? 
      fs.readFileSync(path.resolve(process.env.JWT_REFRESH_SECRET_FILE), 'utf-8').trim() : null) : 
    process.env.JWT_SECRET);

if (jwtAccessSecret) {
  validateSecretLength(jwtAccessSecret, 'JWT_ACCESS_SECRET', 32);
  validateNotExample(jwtAccessSecret, 'JWT_ACCESS_SECRET', ['your-secret', 'changeme', 'secret']);
  if (jwtAccessSecret.length >= 32) {
    log.success('JWT_ACCESS_SECRET está configurado');
  }
} else {
  errors.push('JWT_ACCESS_SECRET o JWT_SECRET es requerido');
  log.error('JWT_ACCESS_SECRET no está configurado');
}

if (jwtRefreshSecret) {
  validateSecretLength(jwtRefreshSecret, 'JWT_REFRESH_SECRET', 32);
  validateNotExample(jwtRefreshSecret, 'JWT_REFRESH_SECRET', ['your-secret', 'changeme', 'secret']);
  if (jwtRefreshSecret.length >= 32) {
    log.success('JWT_REFRESH_SECRET está configurado');
  }
} else {
  errors.push('JWT_REFRESH_SECRET o JWT_SECRET es requerido');
  log.error('JWT_REFRESH_SECRET no está configurado');
}

if (process.env.JWT_ACCESS_SECRET && process.env.JWT_REFRESH_SECRET && 
    process.env.JWT_ACCESS_SECRET === process.env.JWT_REFRESH_SECRET) {
  warnings.push('JWT_ACCESS_SECRET y JWT_REFRESH_SECRET son iguales. Se recomienda usar secretos diferentes.');
  log.warning('JWT_ACCESS_SECRET y JWT_REFRESH_SECRET son iguales');
}

// 4. Storage
log.section('4. Almacenamiento de Archivos');
const storageDriver = process.env.STORAGE_DRIVER || 'local';

if (storageDriver === 's3' || storageDriver === 'cloudflare' || storageDriver === 'r2') {
  if (storageDriver === 'cloudflare' || storageDriver === 'r2') {
    if (process.env.CLOUDFLARE_R2_BUCKET) {
      log.success('CLOUDFLARE_R2_BUCKET está configurado');
    } else {
      errors.push('CLOUDFLARE_R2_BUCKET es requerido cuando STORAGE_DRIVER es cloudflare/r2');
      log.error('CLOUDFLARE_R2_BUCKET no está configurado');
    }
    
    if (process.env.CLOUDFLARE_R2_ACCESS_KEY_ID && process.env.CLOUDFLARE_R2_SECRET_ACCESS_KEY) {
      log.success('Credenciales de Cloudflare R2 están configuradas');
    } else {
      errors.push('CLOUDFLARE_R2_ACCESS_KEY_ID y CLOUDFLARE_R2_SECRET_ACCESS_KEY son requeridos');
      log.error('Credenciales de Cloudflare R2 no están configuradas');
    }
  } else if (storageDriver === 's3') {
    if (process.env.S3_BUCKET) {
      log.success('S3_BUCKET está configurado');
    } else {
      errors.push('S3_BUCKET es requerido cuando STORAGE_DRIVER es s3');
      log.error('S3_BUCKET no está configurado');
    }
  }
} else {
  // Local storage
  const uploadsDir = process.env.UPLOADS_DIR || './uploads';
  if (fs.existsSync(uploadsDir)) {
    log.success(`Almacenamiento local configurado en: ${uploadsDir}`);
  } else {
    warnings.push(`UPLOADS_DIR (${uploadsDir}) no existe. Se creará automáticamente.`);
    log.warning(`UPLOADS_DIR no existe: ${uploadsDir}`);
  }
}

// 5. Email
log.section('5. Configuración de Email');
const hasResend = !!(process.env.RESEND_API_KEY && process.env.RESEND_FROM);
const hasSMTP = !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);

if (hasResend) {
  log.success('Resend está configurado');
  if (process.env.RESEND_MODE === 'test') {
    warnings.push('RESEND_MODE está en "test". Cambia a "live" en producción.');
    log.warning('RESEND_MODE está en test');
  }
  if (process.env.RESEND_FROM) {
    validateEmail(process.env.RESEND_FROM.match(/<(.+)>/)?.[1] || process.env.RESEND_FROM, 'RESEND_FROM');
  }
} else if (hasSMTP) {
  log.success('SMTP está configurado (fallback)');
  if (process.env.EMAIL_FROM) {
    validateEmail(process.env.EMAIL_FROM, 'EMAIL_FROM');
  }
} else {
  warnings.push('Ni Resend ni SMTP están configurados. Los emails no funcionarán.');
  log.warning('Configuración de email no encontrada');
}

// 6. CORS y URLs
log.section('6. URLs y CORS');
if (process.env.FRONTEND_URL) {
  validateUrl(process.env.FRONTEND_URL, 'FRONTEND_URL');
  if (process.env.FRONTEND_URL.includes('localhost') || process.env.FRONTEND_URL.includes('127.0.0.1')) {
    warnings.push('FRONTEND_URL apunta a localhost. En producción debe apuntar al dominio real.');
    log.warning('FRONTEND_URL apunta a localhost');
  } else {
    log.success('FRONTEND_URL está configurado');
  }
} else {
  warnings.push('FRONTEND_URL no está configurado. CORS puede no funcionar correctamente.');
  log.warning('FRONTEND_URL no está configurado');
}

if (process.env.SERVER_PUBLIC_URL) {
  validateUrl(process.env.SERVER_PUBLIC_URL, 'SERVER_PUBLIC_URL');
  log.success('SERVER_PUBLIC_URL está configurado');
} else {
  warnings.push('SERVER_PUBLIC_URL no está configurado. Los enlaces de descarga pueden no funcionar.');
  log.warning('SERVER_PUBLIC_URL no está configurado');
}

// 7. Seguridad
log.section('7. Configuración de Seguridad');
if (process.env.NODE_ENV === 'production') {
  if (process.env.COOKIE_SECURE !== 'true') {
    warnings.push('COOKIE_SECURE debería ser "true" en producción para cookies seguras.');
    log.warning('COOKIE_SECURE no está en "true"');
  } else {
    log.success('COOKIE_SECURE está configurado correctamente');
  }
}

if (process.env.SECURITY_ALERT_EMAILS) {
  const emails = process.env.SECURITY_ALERT_EMAILS.split(',').map(e => e.trim());
  emails.forEach(email => validateEmail(email, 'SECURITY_ALERT_EMAILS'));
  log.success('SECURITY_ALERT_EMAILS está configurado');
} else {
  warnings.push('SECURITY_ALERT_EMAILS no está configurado. Las alertas de seguridad no se enviarán por email.');
  log.warning('SECURITY_ALERT_EMAILS no está configurado');
}

// 8. Opcionales pero recomendados
log.section('8. Configuración Opcional (Recomendada)');
if (!process.env.OPENAI_API_KEY) {
  warnings.push('OPENAI_API_KEY no está configurado. El chatbot no funcionará.');
  log.warning('OPENAI_API_KEY no está configurado');
} else {
  log.success('OPENAI_API_KEY está configurado');
}

// Resumen
log.section('📊 Resumen de Validación');

console.log(`\n${colors.cyan}Resultados:${colors.reset}`);
console.log(`  ${colors.green}✓${colors.reset} Configuraciones correctas`);
console.log(`  ${colors.yellow}⚠${colors.reset} Advertencias: ${warnings.length}`);
console.log(`  ${colors.red}✗${colors.reset} Errores: ${errors.length}\n`);

if (warnings.length > 0) {
  console.log(`${colors.yellow}Advertencias:${colors.reset}`);
  warnings.forEach(w => console.log(`  ⚠ ${w}`));
  console.log();
}

if (errors.length > 0) {
  console.log(`${colors.red}Errores críticos:${colors.reset}`);
  errors.forEach(e => console.log(`  ✗ ${e}`));
  console.log();
  console.log(`${colors.red}❌ La validación falló. Corrige los errores antes de continuar.${colors.reset}\n`);
  process.exit(1);
} else if (warnings.length > 0) {
  console.log(`${colors.yellow}⚠️  La validación pasó con advertencias. Revisa las advertencias antes de producción.${colors.reset}\n`);
  process.exit(0);
} else {
  console.log(`${colors.green}✅ Todas las validaciones pasaron correctamente.${colors.reset}\n`);
  process.exit(0);
}

