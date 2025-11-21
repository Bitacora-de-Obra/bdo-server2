/**
 * Script completo para crear Tenant y aplicar migración multi-tenant
 * Incluye creación de tabla Tenant, tenant 'mutis', y asignación de tenantId
 */

const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function main() {
  console.log('🔄 INICIANDO MIGRACIÓN COMPLETA A MULTI-TENANT\n');
  console.log('⚠️  Este script modificará la base de datos.');
  console.log('   Asegúrate de tener un backup antes de continuar.\n');

  try {
    // Paso 1: Crear tabla Tenant si no existe
    console.log('📋 Paso 1: Creando tabla Tenant...');
    try {
      await prisma.$executeRawUnsafe(`
        CREATE TABLE IF NOT EXISTS \`Tenant\` (
          \`id\` VARCHAR(191) NOT NULL,
          \`subdomain\` VARCHAR(191) NOT NULL,
          \`name\` VARCHAR(191) NOT NULL,
          \`domain\` VARCHAR(191) NOT NULL,
          \`isActive\` BOOLEAN NOT NULL DEFAULT true,
          \`createdAt\` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
          \`updatedAt\` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
          PRIMARY KEY (\`id\`),
          UNIQUE KEY \`Tenant_subdomain_key\` (\`subdomain\`),
          KEY \`Tenant_subdomain_idx\` (\`subdomain\`),
          KEY \`Tenant_isActive_idx\` (\`isActive\`)
        ) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
      `);
      console.log('   ✅ Tabla Tenant creada o ya existe\n');
    } catch (error) {
      if (error.message.includes('already exists') || error.message.includes('Duplicate')) {
        console.log('   ✅ Tabla Tenant ya existe\n');
      } else {
        throw error;
      }
    }

    // Paso 2: Crear tenant 'mutis' si no existe
    console.log('📋 Paso 2: Verificando/Creando tenant "mutis"...');
    let tenantResult = await prisma.$queryRawUnsafe(`
      SELECT id, subdomain, name FROM Tenant WHERE subdomain = 'mutis' LIMIT 1
    `);

    let tenantId;
    if (!tenantResult || tenantResult.length === 0) {
      const newTenantId = await prisma.$queryRawUnsafe(`
        SELECT UUID() as id
      `);
      tenantId = newTenantId[0].id;
      
      await prisma.$executeRawUnsafe(`
        INSERT INTO Tenant (id, subdomain, name, domain, isActive, createdAt, updatedAt)
        VALUES (?, 'mutis', 'Proyecto Mutis', 'mutis.bdigitales.com', true, NOW(), NOW())
      `, tenantId);
      console.log(`   ✅ Tenant "mutis" creado (ID: ${tenantId})\n`);
    } else {
      tenantId = tenantResult[0].id;
      console.log(`   ✅ Tenant "mutis" ya existe (ID: ${tenantId})\n`);
    }

    // Paso 3: Agregar tenantId como NULL a todas las tablas que lo necesitan
    console.log('📋 Paso 3: Agregando columna tenantId a las tablas...\n');
    
    const tables = [
      'User', 'Project', 'LogEntry', 'ControlPoint', 'Communication',
      'ContractModification', 'Acta', 'CostActa', 'WorkActa', 'Report',
      'ProjectTask', 'Drawing', 'SecurityEventLog'
    ];

    for (const table of tables) {
      try {
        await prisma.$executeRawUnsafe(`
          ALTER TABLE \`${table}\` ADD COLUMN \`tenantId\` VARCHAR(191) NULL
        `);
        console.log(`   ✅ Columna tenantId agregada a ${table}`);
      } catch (error) {
        if (error.message.includes('Duplicate column') || error.message.includes('already exists')) {
          console.log(`   ⚠️  Columna tenantId ya existe en ${table}`);
        } else {
          console.error(`   ❌ Error en ${table}:`, error.message);
        }
      }
    }

    // Paso 4: Asignar tenantId a todos los registros existentes
    console.log('\n📋 Paso 4: Asignando tenantId a registros existentes...\n');
    
    for (const table of tables) {
      try {
        const result = await prisma.$executeRawUnsafe(`
          UPDATE \`${table}\` SET tenantId = ? WHERE tenantId IS NULL
        `, tenantId);
        console.log(`   ✅ ${table}: ${result} registros actualizados`);
      } catch (error) {
        console.error(`   ❌ Error actualizando ${table}:`, error.message);
      }
    }

    // Paso 5: Crear índices y foreign keys
    console.log('\n📋 Paso 5: Creando índices y foreign keys...\n');
    
    for (const table of tables) {
      try {
        // Crear índice (MySQL no soporta IF NOT EXISTS, así que usamos try/catch)
        try {
          await prisma.$executeRawUnsafe(`
            CREATE INDEX \`${table}_tenantId_idx\` ON \`${table}\`(\`tenantId\`)
          `);
        } catch (error) {
          if (error.message.includes('Duplicate key') || error.message.includes('already exists')) {
            // Índice ya existe, continuar
          } else {
            throw error;
          }
        }
        
        // Crear foreign key (excepto para SecurityEventLog que es opcional)
        if (table !== 'SecurityEventLog') {
          try {
            await prisma.$executeRawUnsafe(`
              ALTER TABLE \`${table}\` 
              ADD CONSTRAINT \`${table}_tenantId_fkey\` 
              FOREIGN KEY (\`tenantId\`) REFERENCES \`Tenant\`(\`id\`) 
              ON DELETE RESTRICT ON UPDATE CASCADE
            `);
            console.log(`   ✅ Índice y FK creados para ${table}`);
          } catch (error) {
            if (error.message.includes('Duplicate key') || error.message.includes('already exists')) {
              console.log(`   ⚠️  FK ya existe para ${table}`);
            } else {
              throw error;
            }
          }
        } else {
          // SecurityEventLog tiene FK opcional (SET NULL)
          try {
            await prisma.$executeRawUnsafe(`
              ALTER TABLE \`SecurityEventLog\` 
              ADD CONSTRAINT \`SecurityEventLog_tenantId_fkey\` 
              FOREIGN KEY (\`tenantId\`) REFERENCES \`Tenant\`(\`id\`) 
              ON DELETE SET NULL ON UPDATE CASCADE
            `);
            console.log(`   ✅ Índice y FK creados para SecurityEventLog`);
          } catch (error) {
            if (error.message.includes('Duplicate key') || error.message.includes('already exists')) {
              console.log(`   ⚠️  FK ya existe para SecurityEventLog`);
            } else {
              throw error;
            }
          }
        }
      } catch (error) {
        if (error.message.includes('Duplicate key') || error.message.includes('already exists')) {
          console.log(`   ⚠️  Índice ya existe para ${table}`);
        } else {
          console.error(`   ❌ Error creando índices para ${table}:`, error.message);
        }
      }
    }

    // Paso 6: Hacer tenantId obligatorio (excepto SecurityEventLog)
    console.log('\n📋 Paso 6: Haciendo tenantId obligatorio...\n');
    
    for (const table of tables) {
      if (table === 'SecurityEventLog') continue; // SecurityEventLog mantiene tenantId opcional
      
      try {
        await prisma.$executeRawUnsafe(`
          ALTER TABLE \`${table}\` MODIFY COLUMN \`tenantId\` VARCHAR(191) NOT NULL
        `);
        console.log(`   ✅ tenantId ahora es obligatorio en ${table}`);
      } catch (error) {
        console.error(`   ❌ Error haciendo tenantId obligatorio en ${table}:`, error.message);
      }
    }

    // Paso 7: Actualizar índices únicos compuestos (para Drawing)
    console.log('\n📋 Paso 7: Actualizando índices únicos...\n');
    
    try {
      // Eliminar índice único antiguo de Drawing.code si existe
      const indexExists = await prisma.$queryRawUnsafe(`
        SELECT COUNT(*) as count 
        FROM information_schema.table_constraints 
        WHERE table_schema = DATABASE() 
        AND table_name = 'Drawing' 
        AND constraint_name = 'Drawing_code_key'
      `);
      
      if (indexExists[0].count > 0) {
        await prisma.$executeRawUnsafe(`
          ALTER TABLE \`Drawing\` DROP INDEX \`Drawing_code_key\`
        `);
        console.log('   ✅ Índice único antiguo de Drawing.code eliminado');
      }
      
      // Crear índice único compuesto
      try {
        await prisma.$executeRawUnsafe(`
          CREATE UNIQUE INDEX \`Drawing_code_tenantId_key\` 
          ON \`Drawing\`(\`code\`, \`tenantId\`)
        `);
      } catch (error) {
        if (error.message.includes('Duplicate key') || error.message.includes('already exists')) {
          console.log('   ⚠️  Índice único compuesto ya existe');
        } else {
          throw error;
        }
      }
      console.log('   ✅ Índice único compuesto creado para Drawing (code, tenantId)');
    } catch (error) {
      if (error.message.includes('Duplicate key') || error.message.includes('already exists')) {
        console.log('   ⚠️  Índice único compuesto ya existe');
      } else {
        console.error('   ❌ Error actualizando índices únicos:', error.message);
      }
    }

    console.log('\n✅ MIGRACIÓN COMPLETADA EXITOSAMENTE!\n');
    console.log('📋 Próximos pasos:');
    console.log('   1. Ejecutar: npx prisma generate');
    console.log('   2. Verificar que el código compila: npm run build');
    console.log('   3. Probar la aplicación\n');

  } catch (error) {
    console.error('\n❌ Error durante la migración:');
    console.error(error);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

main();

