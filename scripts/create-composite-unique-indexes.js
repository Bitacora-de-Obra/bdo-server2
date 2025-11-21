/**
 * Script para crear índices únicos compuestos sin eliminar los existentes
 * Esto evita el error de AUTO_INCREMENT que requiere estar en una clave
 */

const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function createCompositeUniqueIndexes() {
  console.log('🔄 Creando índices únicos compuestos...\n');

  const indexes = [
    {
      table: 'Acta',
      name: 'Acta_number_tenantId_key',
      columns: ['number', 'tenantId'],
      description: 'Acta: [number, tenantId]'
    },
    {
      table: 'Communication',
      name: 'Communication_radicado_tenantId_key',
      columns: ['radicado', 'tenantId'],
      description: 'Communication: [radicado, tenantId]'
    },
    {
      table: 'ContractModification',
      name: 'ContractModification_number_tenantId_key',
      columns: ['number', 'tenantId'],
      description: 'ContractModification: [number, tenantId]'
    },
    {
      table: 'CostActa',
      name: 'CostActa_number_tenantId_key',
      columns: ['number', 'tenantId'],
      description: 'CostActa: [number, tenantId]'
    },
    {
      table: 'LogEntry',
      name: 'LogEntry_folioNumber_tenantId_key',
      columns: ['folioNumber', 'tenantId'],
      description: 'LogEntry: [folioNumber, tenantId]',
      skipIfExists: true // No eliminar el índice único simple de folioNumber
    },
    {
      table: 'Project',
      name: 'Project_contractId_tenantId_key',
      columns: ['contractId', 'tenantId'],
      description: 'Project: [contractId, tenantId]'
    },
    {
      table: 'ProjectTask',
      name: 'ProjectTask_taskId_tenantId_key',
      columns: ['taskId', 'tenantId'],
      description: 'ProjectTask: [taskId, tenantId]'
    },
    {
      table: 'Report',
      name: 'Report_number_version_tenantId_key',
      columns: ['number', 'version', 'tenantId'],
      description: 'Report: [number, version, tenantId]'
    },
    {
      table: 'User',
      name: 'User_email_tenantId_key',
      columns: ['email', 'tenantId'],
      description: 'User: [email, tenantId]'
    },
    {
      table: 'WorkActa',
      name: 'WorkActa_number_tenantId_key',
      columns: ['number', 'tenantId'],
      description: 'WorkActa: [number, tenantId]'
    },
  ];

  for (const idx of indexes) {
    try {
      // Verificar si el índice ya existe
      const existing = await prisma.$queryRawUnsafe(`
        SELECT COUNT(*) as count
        FROM information_schema.TABLE_CONSTRAINTS
        WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = ?
        AND CONSTRAINT_NAME = ?
        AND CONSTRAINT_TYPE = 'UNIQUE'
      `, idx.table, idx.name);

      if (existing[0].count > 0) {
        console.log(`✅ ${idx.description}: Ya existe`);
        continue;
      }

      // Verificar que no hay duplicados que violen la unicidad
      const columnList = idx.columns.map(c => `\`${c}\``).join(', ');
      const whereClause = idx.columns.map(c => `\`${c}\` IS NOT NULL`).join(' AND ');
      
      const duplicates = await prisma.$queryRawUnsafe(`
        SELECT ${columnList}, COUNT(*) as count
        FROM \`${idx.table}\`
        WHERE ${whereClause}
        GROUP BY ${columnList}
        HAVING count > 1
      `);

      if (duplicates.length > 0) {
        console.log(`⚠️  ${idx.description}: Se encontraron duplicados, saltando...`);
        console.log(`   Duplicados:`, duplicates);
        continue;
      }

      // Crear el índice único compuesto
      const columnsSql = idx.columns.map(c => `\`${c}\``).join(', ');
      await prisma.$executeRawUnsafe(`
        CREATE UNIQUE INDEX \`${idx.name}\` ON \`${idx.table}\` (${columnsSql})
      `);

      console.log(`✅ ${idx.description}: Creado`);
    } catch (error) {
      if (error.message.includes('Duplicate key') || error.message.includes('already exists')) {
        console.log(`✅ ${idx.description}: Ya existe (detectado por error)`);
      } else {
        console.error(`❌ ${idx.description}: Error -`, error.message);
        // Continuar con los siguientes índices
      }
    }
  }

  console.log('\n✅ Proceso completado');
}

createCompositeUniqueIndexes()
  .then(() => {
    console.log('\n🎉 Índices únicos compuestos creados exitosamente');
    process.exit(0);
  })
  .catch((error) => {
    console.error('\n❌ Error:', error);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

