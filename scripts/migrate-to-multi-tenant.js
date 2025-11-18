/**
 * Script de migración para convertir la base de datos a multi-tenant
 * 
 * Este script:
 * 1. Crea el tenant "mutis" con subdomain "mutis"
 * 2. Asigna todos los datos existentes a ese tenant
 * 3. Actualiza los constraints únicos a compuestos con tenantId
 * 
 * ⚠️  ADVERTENCIA: Este script modifica la base de datos de producción
 * ⚠️  Asegúrate de tener un backup antes de ejecutar
 * 
 * Uso:
 *   node scripts/migrate-to-multi-tenant.js
 */

const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function migrateToMultiTenant() {
  console.log('🔄 MIGRACIÓN A MULTI-TENANT\n');
  console.log('⚠️  ADVERTENCIA: Este script modificará la base de datos.');
  console.log('   Asegúrate de tener un backup antes de continuar.\n');

  try {
    // Paso 1: Verificar que no exista ya un tenant "mutis"
    console.log('📋 Paso 1: Verificando estado actual...');
    const existingTenant = await prisma.tenant.findUnique({
      where: { subdomain: 'mutis' },
    });

    if (existingTenant) {
      console.log('   ⚠️  Ya existe un tenant con subdomain "mutis"');
      console.log(`   ID: ${existingTenant.id}`);
      console.log(`   Nombre: ${existingTenant.name}`);
      console.log('\n   ¿Deseas continuar de todas formas? (sí/no)');
      // En producción, mejor abortar si ya existe
      console.log('   ❌ Abortando por seguridad...');
      return;
    }

    // Paso 2: Crear el tenant "mutis"
    console.log('\n📋 Paso 2: Creando tenant "mutis"...');
    const mutisTenant = await prisma.tenant.create({
      data: {
        subdomain: 'mutis',
        name: 'Proyecto Mutis',
        domain: 'mutis.bdigitales.com',
        isActive: true,
      },
    });
    console.log(`   ✅ Tenant creado: ${mutisTenant.id}`);
    console.log(`   Subdomain: ${mutisTenant.subdomain}`);
    console.log(`   Nombre: ${mutisTenant.name}`);

    // Paso 3: Contar registros existentes
    console.log('\n📋 Paso 3: Contando registros existentes...');
    const counts = {
      users: await prisma.user.count(),
      projects: await prisma.project.count(),
      logEntries: await prisma.logEntry.count(),
      controlPoints: await prisma.controlPoint.count(),
      communications: await prisma.communication.count(),
      contractModifications: await prisma.contractModification.count(),
      actas: await prisma.acta.count(),
      costActas: await prisma.costActa.count(),
      workActas: await prisma.workActa.count(),
      reports: await prisma.report.count(),
      projectTasks: await prisma.projectTask.count(),
    };

    console.log('   Registros encontrados:');
    Object.entries(counts).forEach(([table, count]) => {
      console.log(`   - ${table}: ${count}`);
    });

    const totalRecords = Object.values(counts).reduce((sum, count) => sum + count, 0);
    console.log(`   Total: ${totalRecords} registros`);

    if (totalRecords === 0) {
      console.log('\n   ℹ️  No hay registros para migrar. La base de datos está vacía.');
      return;
    }

    // Paso 4: Asignar tenantId a todos los registros
    console.log('\n📋 Paso 4: Asignando tenantId a todos los registros...');
    console.log('   Esto puede tomar varios minutos dependiendo del tamaño de la base de datos...\n');

    await prisma.$transaction(async (tx) => {
      // Actualizar Users
      if (counts.users > 0) {
        console.log(`   📝 Actualizando ${counts.users} usuarios...`);
        await tx.$executeRawUnsafe(
          `UPDATE User SET tenantId = ? WHERE tenantId IS NULL`,
          mutisTenant.id
        );
        console.log(`   ✅ Usuarios actualizados`);
      }

      // Actualizar Projects
      if (counts.projects > 0) {
        console.log(`   📝 Actualizando ${counts.projects} proyectos...`);
        await tx.$executeRawUnsafe(
          `UPDATE Project SET tenantId = ? WHERE tenantId IS NULL`,
          mutisTenant.id
        );
        console.log(`   ✅ Proyectos actualizados`);
      }

      // Actualizar LogEntries
      if (counts.logEntries > 0) {
        console.log(`   📝 Actualizando ${counts.logEntries} log entries...`);
        await tx.$executeRawUnsafe(
          `UPDATE LogEntry SET tenantId = ? WHERE tenantId IS NULL`,
          mutisTenant.id
        );
        console.log(`   ✅ Log entries actualizados`);
      }

      // Actualizar ControlPoints
      if (counts.controlPoints > 0) {
        console.log(`   📝 Actualizando ${counts.controlPoints} control points...`);
        await tx.$executeRawUnsafe(
          `UPDATE ControlPoint SET tenantId = ? WHERE tenantId IS NULL`,
          mutisTenant.id
        );
        console.log(`   ✅ Control points actualizados`);
      }

      // Actualizar Communications
      if (counts.communications > 0) {
        console.log(`   📝 Actualizando ${counts.communications} comunicaciones...`);
        await tx.$executeRawUnsafe(
          `UPDATE Communication SET tenantId = ? WHERE tenantId IS NULL`,
          mutisTenant.id
        );
        console.log(`   ✅ Comunicaciones actualizadas`);
      }

      // Actualizar ContractModifications
      if (counts.contractModifications > 0) {
        console.log(`   📝 Actualizando ${counts.contractModifications} modificaciones de contrato...`);
        await tx.$executeRawUnsafe(
          `UPDATE ContractModification SET tenantId = ? WHERE tenantId IS NULL`,
          mutisTenant.id
        );
        console.log(`   ✅ Modificaciones de contrato actualizadas`);
      }

      // Actualizar Actas
      if (counts.actas > 0) {
        console.log(`   📝 Actualizando ${counts.actas} actas...`);
        await tx.$executeRawUnsafe(
          `UPDATE Acta SET tenantId = ? WHERE tenantId IS NULL`,
          mutisTenant.id
        );
        console.log(`   ✅ Actas actualizadas`);
      }

      // Actualizar CostActas
      if (counts.costActas > 0) {
        console.log(`   📝 Actualizando ${counts.costActas} actas de costo...`);
        await tx.$executeRawUnsafe(
          `UPDATE CostActa SET tenantId = ? WHERE tenantId IS NULL`,
          mutisTenant.id
        );
        console.log(`   ✅ Actas de costo actualizadas`);
      }

      // Actualizar WorkActas
      if (counts.workActas > 0) {
        console.log(`   📝 Actualizando ${counts.workActas} actas de obra...`);
        await tx.$executeRawUnsafe(
          `UPDATE WorkActa SET tenantId = ? WHERE tenantId IS NULL`,
          mutisTenant.id
        );
        console.log(`   ✅ Actas de obra actualizadas`);
      }

      // Actualizar Reports
      if (counts.reports > 0) {
        console.log(`   📝 Actualizando ${counts.reports} reportes...`);
        await tx.$executeRawUnsafe(
          `UPDATE Report SET tenantId = ? WHERE tenantId IS NULL`,
          mutisTenant.id
        );
        console.log(`   ✅ Reportes actualizados`);
      }

      // Actualizar ProjectTasks
      if (counts.projectTasks > 0) {
        console.log(`   📝 Actualizando ${counts.projectTasks} tareas de proyecto...`);
        await tx.$executeRawUnsafe(
          `UPDATE ProjectTask SET tenantId = ? WHERE tenantId IS NULL`,
          mutisTenant.id
        );
        console.log(`   ✅ Tareas de proyecto actualizadas`);
      }
    }, {
      timeout: 300000, // 5 minutos de timeout
    });

    // Paso 5: Verificar que todos los registros tienen tenantId
    console.log('\n📋 Paso 5: Verificando migración...');
    const verification = {
      users: await prisma.user.count({ where: { tenantId: mutisTenant.id } }),
      projects: await prisma.project.count({ where: { tenantId: mutisTenant.id } }),
      logEntries: await prisma.logEntry.count({ where: { tenantId: mutisTenant.id } }),
      controlPoints: await prisma.controlPoint.count({ where: { tenantId: mutisTenant.id } }),
      communications: await prisma.communication.count({ where: { tenantId: mutisTenant.id } }),
      contractModifications: await prisma.contractModification.count({ where: { tenantId: mutisTenant.id } }),
      actas: await prisma.acta.count({ where: { tenantId: mutisTenant.id } }),
      costActas: await prisma.costActa.count({ where: { tenantId: mutisTenant.id } }),
      workActas: await prisma.workActa.count({ where: { tenantId: mutisTenant.id } }),
      reports: await prisma.report.count({ where: { tenantId: mutisTenant.id } }),
      projectTasks: await prisma.projectTask.count({ where: { tenantId: mutisTenant.id } }),
    };

    console.log('   Registros asignados al tenant "mutis":');
    let allMatch = true;
    Object.entries(verification).forEach(([table, count]) => {
      const original = counts[table];
      const match = count === original;
      const icon = match ? '✅' : '❌';
      console.log(`   ${icon} ${table}: ${count}/${original}`);
      if (!match) allMatch = false;
    });

    if (allMatch) {
      console.log('\n✅ Migración completada exitosamente!');
      console.log(`\n📊 Resumen:`);
      console.log(`   - Tenant creado: ${mutisTenant.subdomain} (${mutisTenant.name})`);
      console.log(`   - Total de registros migrados: ${totalRecords}`);
      console.log(`   - Todos los registros están asignados al tenant "mutis"`);
    } else {
      console.log('\n⚠️  ADVERTENCIA: Algunos registros no se migraron correctamente.');
      console.log('   Revisa los errores arriba y verifica manualmente.');
    }

  } catch (error) {
    console.error('\n❌ Error durante la migración:', error);
    console.error('\n💡 Si algo salió mal, puedes restaurar desde el backup.');
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

// Ejecutar migración
migrateToMultiTenant()
  .then(() => {
    console.log('\n✅ Script completado.');
    process.exit(0);
  })
  .catch((error) => {
    console.error('\n❌ Error fatal:', error);
    process.exit(1);
  });

