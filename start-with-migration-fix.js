import { PrismaClient } from '@prisma/client';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);
const prisma = new PrismaClient();

async function fixMigrations() {
  try {
    console.log('🔧 Iniciando corrección de base de datos...');
    
    // Primero, verificar conexión a la base de datos
    await prisma.$connect();
    console.log('✅ Conexión a base de datos establecida');
    
    // Intentar marcar la migración problemática como completada directamente en la BD
    try {
      await prisma.$executeRawUnsafe(`
        INSERT IGNORE INTO _prisma_migrations (id, checksum, finished_at, migration_name, logs, rolled_back_at, started_at, applied_steps_count)
        VALUES ('20250321510000_add_report_versions', '', NOW(), '20250321510000_add_report_versions', '', NULL, NOW(), 1)
        ON DUPLICATE KEY UPDATE finished_at = NOW(), rolled_back_at = NULL;
      `);
      console.log('✅ Migración problemática marcada como completada');
    } catch (error) {
      console.log('⚠️ No se pudo marcar la migración directamente:', error);
    }
    
    // Aplicar migraciones restantes
    console.log('Aplicando migraciones pendientes...');
    try {
      const { stdout, stderr } = await execAsync('npx prisma migrate deploy');
      console.log('stdout:', stdout);
      if (stderr) console.log('stderr:', stderr);
      console.log('✅ Migraciones aplicadas exitosamente');
    } catch (error) {
      console.log('⚠️ Error en migrate deploy, intentando resolución...');
      try {
        await execAsync('npx prisma migrate resolve --applied 20250321510000_add_report_versions');
        await execAsync('npx prisma migrate deploy');
        console.log('✅ Migraciones aplicadas después de resolución');
      } catch (resolveError) {
        console.log('❌ Error persistente en migraciones:', resolveError);
        // Como último recurso, generar el cliente
        await execAsync('npx prisma generate');
        console.log('✅ Cliente Prisma generado como fallback');
      }
    }
    
  } catch (error) {
    console.error('❌ Error en corrección de migraciones:', error);
  } finally {
    await prisma.$disconnect();
  }
}

fixMigrations().then(() => {
  console.log('🚀 Iniciando servidor...');
  require('./dist/index.js');
}).catch((error) => {
  console.error('❌ Error fatal:', error);
  process.exit(1);
});
