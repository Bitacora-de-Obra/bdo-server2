#!/usr/bin/env node

/**
 * Script de pre-despliegue
 * Ejecuta todas las validaciones necesarias antes de desplegar a producción
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

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

let hasErrors = false;

const runCommand = (command, description) => {
  try {
    log.info(`Ejecutando: ${description}...`);
    execSync(command, { stdio: 'inherit', cwd: __dirname + '/..' });
    log.success(`${description} completado`);
    return true;
  } catch (error) {
    log.error(`${description} falló`);
    hasErrors = true;
    return false;
  }
};

log.section('🚀 Pre-Despliegue - Validaciones');

// 1. Verificar que estamos en el directorio correcto
if (!fs.existsSync(path.join(__dirname, '../package.json'))) {
  log.error('No se encontró package.json. Ejecuta este script desde la raíz del proyecto.');
  process.exit(1);
}

// 2. Verificar que node_modules existe
if (!fs.existsSync(path.join(__dirname, '../node_modules'))) {
  log.warning('node_modules no existe. Instalando dependencias...');
  runCommand('npm install', 'Instalación de dependencias');
}

// 3. Validar variables de entorno
log.section('1. Validación de Variables de Entorno');
runCommand('node scripts/validate-env.js', 'Validación de variables de entorno');

// 4. Verificar TypeScript
log.section('2. Verificación de TypeScript');
runCommand('npm run typecheck', 'Verificación de tipos TypeScript');

// 5. Generar Prisma Client
log.section('3. Generación de Prisma Client');
runCommand('npx prisma generate', 'Generación de Prisma Client');

// 6. Verificar migraciones pendientes
log.section('4. Verificación de Migraciones');
try {
  log.info('Verificando migraciones pendientes...');
  const output = execSync('npx prisma migrate status', { 
    encoding: 'utf-8',
    cwd: __dirname + '/..'
  });
  
  if (output.includes('Database schema is up to date')) {
    log.success('Todas las migraciones están aplicadas');
  } else if (output.includes('Following migration(s) have not yet been applied')) {
    log.warning('Hay migraciones pendientes. Ejecuta "npx prisma migrate deploy" en producción.');
  } else {
    log.warning('No se pudo verificar el estado de las migraciones');
  }
} catch (error) {
  log.warning('No se pudo verificar migraciones (puede ser normal si la BD no está disponible)');
}

// 7. Build del proyecto
log.section('5. Build del Proyecto');
runCommand('npm run build', 'Compilación del proyecto');

// 8. Verificar que dist existe
if (fs.existsSync(path.join(__dirname, '../dist'))) {
  log.success('Build completado - directorio dist existe');
} else {
  log.error('Build falló - directorio dist no existe');
  hasErrors = true;
}

// Resumen final
log.section('📊 Resumen de Pre-Despliegue');

if (hasErrors) {
  console.log(`\n${colors.red}❌ El pre-despliegue falló. Corrige los errores antes de continuar.${colors.reset}\n`);
  process.exit(1);
} else {
  console.log(`\n${colors.green}✅ Pre-despliegue completado exitosamente.${colors.reset}`);
  console.log(`\n${colors.cyan}Próximos pasos:${colors.reset}`);
  console.log('  1. Revisa las advertencias (si las hay)');
  console.log('  2. Ejecuta las migraciones en producción: npx prisma migrate deploy');
  console.log('  3. Inicia el servidor: npm start');
  console.log('  4. Verifica el health check: curl http://localhost:4001/api/health\n');
  process.exit(0);
}


