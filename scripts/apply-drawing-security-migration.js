/**
 * Script para aplicar la migración de tenantId a Drawing y SecurityEventLog
 * 
 * Este script:
 * 1. Verifica que existe un tenant (crea 'mutis' si no existe)
 * 2. Aplica la migración SQL de forma segura
 * 3. Verifica que los cambios se aplicaron correctamente
 */

const { PrismaClient } = require('@prisma/client');
const fs = require('fs');
const path = require('path');

const prisma = new PrismaClient();

async function main() {
  console.log('🔄 Iniciando migración de tenantId a Drawing y SecurityEventLog...\n');

  try {
    // 1. Verificar o crear tenant 'mutis'
    console.log('1️⃣ Verificando tenant "mutis"...');
    let tenant = await prisma.$queryRawUnsafe(`
      SELECT id, subdomain, name FROM Tenant WHERE subdomain = 'mutis' LIMIT 1
    `);

    if (!tenant || tenant.length === 0) {
      console.log('   ⚠️  Tenant "mutis" no existe. Creándolo...');
      const newTenant = await prisma.$executeRawUnsafe(`
        INSERT INTO Tenant (id, subdomain, name, domain, isActive, createdAt, updatedAt)
        VALUES (UUID(), 'mutis', 'Proyecto Mutis', 'mutis.bdigitales.com', true, NOW(), NOW())
      `);
      tenant = await prisma.$queryRawUnsafe(`
        SELECT id, subdomain, name FROM Tenant WHERE subdomain = 'mutis' LIMIT 1
      `);
      console.log('   ✅ Tenant "mutis" creado');
    } else {
      console.log('   ✅ Tenant "mutis" existe');
    }

    const tenantId = tenant[0].id;
    console.log(`   📋 Tenant ID: ${tenantId}\n`);

    // 2. Leer el archivo de migración SQL
    const migrationPath = path.join(
      __dirname,
      '../prisma/migrations/20251118220644_add_tenant_to_drawing_and_security_event_log/migration.sql'
    );

    if (!fs.existsSync(migrationPath)) {
      throw new Error(`No se encontró el archivo de migración: ${migrationPath}`);
    }

    const migrationSQL = fs.readFileSync(migrationPath, 'utf-8');
    console.log('2️⃣ Leyendo archivo de migración SQL...\n');

    // 3. Dividir el SQL en statements individuales
    const statements = migrationSQL
      .split(';')
      .map(s => s.trim())
      .filter(s => s.length > 0 && !s.startsWith('--'));

    // 4. Reemplazar la referencia al tenant en los UPDATE statements
    const processedStatements = statements.map(statement => {
      // Reemplazar la subquery del tenant con el tenantId real
      return statement.replace(
        /\(SELECT `id` FROM `Tenant` WHERE `subdomain` = 'mutis' LIMIT 1\)/g,
        `'${tenantId}'`
      );
    });

    // 5. Ejecutar cada statement
    console.log('3️⃣ Aplicando cambios a la base de datos...\n');
    for (let i = 0; i < processedStatements.length; i++) {
      const statement = processedStatements[i];
      if (statement.trim().length === 0) continue;

      try {
        // Para statements que usan PREPARE/EXECUTE, necesitamos ejecutarlos de forma especial
        if (statement.includes('PREPARE') || statement.includes('EXECUTE')) {
          // Ejecutar el bloque completo de PREPARE/EXECUTE
          const fullBlock = statements.slice(i).join(';').split('DEALLOCATE')[0] + 'DEALLOCATE PREPARE stmt;';
          await prisma.$executeRawUnsafe(fullBlock);
          // Saltar los statements que ya procesamos
          i += fullBlock.split(';').length - 1;
          console.log(`   ✅ Ejecutado: Eliminación de índice único antiguo`);
        } else {
          await prisma.$executeRawUnsafe(statement);
          if (statement.includes('ADD COLUMN')) {
            console.log(`   ✅ Agregada columna tenantId`);
          } else if (statement.includes('CREATE INDEX')) {
            console.log(`   ✅ Creado índice`);
          } else if (statement.includes('ADD CONSTRAINT')) {
            console.log(`   ✅ Agregada foreign key`);
          } else if (statement.includes('UPDATE')) {
            console.log(`   ✅ Asignado tenantId a registros existentes`);
          } else if (statement.includes('MODIFY COLUMN')) {
            console.log(`   ✅ tenantId ahora es obligatorio en Drawing`);
          } else if (statement.includes('CREATE UNIQUE INDEX')) {
            console.log(`   ✅ Creado índice único compuesto`);
          }
        }
      } catch (error) {
        // Si el error es que la columna ya existe o el índice ya existe, continuar
        if (
          error.message.includes('Duplicate column name') ||
          error.message.includes('Duplicate key name') ||
          error.message.includes('already exists')
        ) {
          console.log(`   ⚠️  Ya existe: ${statement.substring(0, 50)}...`);
        } else {
          throw error;
        }
      }
    }

    // 6. Verificar que los cambios se aplicaron
    console.log('\n4️⃣ Verificando cambios...\n');
    
    const drawingHasTenantId = await prisma.$queryRawUnsafe(`
      SELECT COUNT(*) as count 
      FROM information_schema.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE() 
      AND TABLE_NAME = 'Drawing' 
      AND COLUMN_NAME = 'tenantId'
    `);
    
    const securityHasTenantId = await prisma.$queryRawUnsafe(`
      SELECT COUNT(*) as count 
      FROM information_schema.COLUMNS 
      WHERE TABLE_SCHEMA = DATABASE() 
      AND TABLE_NAME = 'SecurityEventLog' 
      AND COLUMN_NAME = 'tenantId'
    `);

    if (drawingHasTenantId[0].count > 0 && securityHasTenantId[0].count > 0) {
      console.log('   ✅ Columna tenantId existe en Drawing');
      console.log('   ✅ Columna tenantId existe en SecurityEventLog');
    } else {
      throw new Error('Las columnas no se crearon correctamente');
    }

    // Verificar que los registros existentes tienen tenantId
    const drawingsWithoutTenant = await prisma.$queryRawUnsafe(`
      SELECT COUNT(*) as count FROM Drawing WHERE tenantId IS NULL
    `);
    
    if (drawingsWithoutTenant[0].count > 0) {
      console.log(`   ⚠️  Advertencia: ${drawingsWithoutTenant[0].count} drawings sin tenantId`);
    } else {
      console.log('   ✅ Todos los drawings tienen tenantId asignado');
    }

    console.log('\n✅ Migración completada exitosamente!\n');
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

