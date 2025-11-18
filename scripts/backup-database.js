/**
 * Script para hacer backup de la base de datos de producción
 * 
 * Uso:
 *   node scripts/backup-database.js
 * 
 * Requiere:
 *   - DATABASE_URL en .env o como variable de entorno
 *   - mysqldump instalado (o usar Prisma para exportar)
 */

const { PrismaClient } = require('@prisma/client');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const prisma = new PrismaClient();

// Parsear DATABASE_URL para obtener credenciales
function parseDatabaseUrl(url) {
  // Formato: mysql://user:password@host:port/database
  const match = url.match(/mysql:\/\/([^:]+):([^@]+)@([^:]+):(\d+)\/(.+)/);
  if (!match) {
    throw new Error('DATABASE_URL no tiene el formato esperado');
  }
  
  return {
    user: match[1],
    password: match[2],
    host: match[3],
    port: match[4],
    database: match[5],
  };
}

async function backupWithPrisma() {
  console.log('📦 Creando backup usando Prisma...\n');
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('T')[0] + '_' + 
                    new Date().toISOString().replace(/[:.]/g, '-').split('T')[1].split('.')[0];
  const backupDir = path.join(__dirname, '../backups');
  const backupFile = path.join(backupDir, `backup_${timestamp}.json`);
  
  // Crear directorio de backups si no existe
  if (!fs.existsSync(backupDir)) {
    fs.mkdirSync(backupDir, { recursive: true });
  }
  
  try {
    // Obtener todas las tablas principales
    console.log('📊 Exportando datos...\n');
    
    const backup = {
      timestamp: new Date().toISOString(),
      version: '1.0',
      tables: {},
    };
    
    // Exportar datos de cada tabla principal
    const tables = [
      'User',
      'Project',
      'LogEntry',
      'ControlPoint',
      'Communication',
      'ContractModification',
      'Acta',
      'CostActa',
      'WorkActa',
      'Report',
      'ProjectTask',
      'Attachment',
      'Comment',
      'Signature',
      'PhotoEntry',
      'KeyPersonnel',
      'CorredorVialElement',
      'ContractItem',
      'Drawing',
      'WeeklyReport',
      'Commitment',
      'Observation',
      'Notification',
      'UserSignature',
      'DocumentSignatureLog',
      'LogEntryHistory',
      'LogEntrySignatureTask',
      'LogEntryReviewTask',
      'CommunicationStatusHistory',
      'WorkActaItem',
      'ContractItemExecution',
      'DrawingVersion',
      'EmailVerificationToken',
      'PasswordResetToken',
      'AuditLog',
      'ChatbotUsage',
      'ChatbotInteraction',
    ];
    
    for (const table of tables) {
      try {
        const model = prisma[table.toLowerCase()];
        if (model) {
          const data = await model.findMany();
          backup.tables[table] = data;
          console.log(`  ✅ ${table}: ${data.length} registros`);
        } else {
          // Intentar con findMany directamente
          const data = await prisma.$queryRawUnsafe(`SELECT * FROM ${table}`);
          backup.tables[table] = data;
          console.log(`  ✅ ${table}: ${data.length} registros`);
        }
      } catch (error) {
        console.warn(`  ⚠️  ${table}: Error al exportar - ${error.message}`);
        backup.tables[table] = { error: error.message };
      }
    }
    
    // Guardar backup
    fs.writeFileSync(backupFile, JSON.stringify(backup, null, 2));
    
    const fileSize = (fs.statSync(backupFile).size / 1024 / 1024).toFixed(2);
    console.log(`\n✅ Backup creado exitosamente:`);
    console.log(`   Archivo: ${backupFile}`);
    console.log(`   Tamaño: ${fileSize} MB`);
    console.log(`   Timestamp: ${backup.timestamp}`);
    
    return backupFile;
  } catch (error) {
    console.error('❌ Error al crear backup:', error);
    throw error;
  }
}

async function backupWithMysqldump() {
  console.log('📦 Creando backup usando mysqldump...\n');
  
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) {
    throw new Error('DATABASE_URL no está configurado');
  }
  
  const dbConfig = parseDatabaseUrl(dbUrl);
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('T')[0] + '_' + 
                    new Date().toISOString().replace(/[:.]/g, '-').split('T')[1].split('.')[0];
  const backupDir = path.join(__dirname, '../backups');
  const backupFile = path.join(backupDir, `backup_${timestamp}.sql`);
  
  // Crear directorio de backups si no existe
  if (!fs.existsSync(backupDir)) {
    fs.mkdirSync(backupDir, { recursive: true });
  }
  
  try {
    // Construir comando mysqldump
    const dumpCommand = `mysqldump -h ${dbConfig.host} -P ${dbConfig.port} -u ${dbConfig.user} -p${dbConfig.password} ${dbConfig.database} > ${backupFile}`;
    
    console.log(`📊 Ejecutando mysqldump...`);
    console.log(`   Host: ${dbConfig.host}`);
    console.log(`   Database: ${dbConfig.database}\n`);
    
    execSync(dumpCommand, { stdio: 'inherit' });
    
    const fileSize = (fs.statSync(backupFile).size / 1024 / 1024).toFixed(2);
    console.log(`\n✅ Backup SQL creado exitosamente:`);
    console.log(`   Archivo: ${backupFile}`);
    console.log(`   Tamaño: ${fileSize} MB`);
    
    return backupFile;
  } catch (error) {
    console.error('❌ Error al crear backup con mysqldump:', error.message);
    console.log('\n💡 Intentando con método alternativo (Prisma)...\n');
    return await backupWithPrisma();
  }
}

async function main() {
  console.log('🔐 BACKUP DE BASE DE DATOS DE PRODUCCIÓN\n');
  console.log('⚠️  ADVERTENCIA: Este script accederá a la base de datos de producción.');
  console.log('   Asegúrate de tener las credenciales correctas.\n');
  
  try {
    // Intentar primero con mysqldump (más rápido y completo)
    let backupFile;
    try {
      backupFile = await backupWithMysqldump();
    } catch (error) {
      console.log('\n💡 mysqldump no disponible, usando método Prisma...\n');
      backupFile = await backupWithPrisma();
    }
    
    console.log('\n✅ Backup completado exitosamente!');
    console.log(`\n📁 Ubicación del backup: ${backupFile}`);
    console.log('\n💡 Guarda este archivo en un lugar seguro antes de continuar con los cambios.');
    
  } catch (error) {
    console.error('\n❌ Error fatal al crear backup:', error);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

// Ejecutar
main();

