// Restore all original data (users, project, personnel, etc.)
// This script restores the complete original dataset
// Usage: node scripts/restore-all-data.js

/* eslint-disable no-console */
const { execSync } = require('child_process');
const path = require('path');

async function restoreAllData() {
  console.log('🔄 Restaurando todos los datos originales...\n');
    console.log('📋 Esto incluye:');
    console.log('   1. Usuario admin (admin@admin.com)');
    console.log('   2. Usuarios (IDU, CONTRATISTA, INTERVENTORIA)');
    console.log('   3. Proyecto Mutis (José Celestino Mutis)');
    console.log('   4. Personal clave del proyecto');
    console.log('   5. Ítems contractuales');
    console.log('   6. Actas de obra');
    console.log('   7. Actas de costo');
    console.log('   8. Elementos del corredor vial (CIVs)');
    console.log('   9. CIVs del proyecto\n');

  const scriptsDir = path.join(__dirname);
  
  try {
    // 1. Crear usuario admin
    console.log('👤 1/9 Creando usuario admin...');
    execSync(`node ${path.join(scriptsDir, 'createAdmin.js')}`, {
      stdio: 'inherit',
      cwd: path.join(__dirname, '..'),
    });
    console.log('✅ Usuario admin creado\n');

    // 2. Restaurar usuarios
    console.log('👥 2/9 Restaurando usuarios...');
    execSync(`node ${path.join(scriptsDir, 'restore-all-users.js')}`, {
      stdio: 'inherit',
      cwd: path.join(__dirname, '..'),
    });
    console.log('✅ Usuarios restaurados\n');

    // 3. Crear/actualizar proyecto Mutis
    console.log('📋 3/9 Creando/actualizando Proyecto Mutis...');
    execSync(`node ${path.join(scriptsDir, 'createMutisProject.js')}`, {
      stdio: 'inherit',
      cwd: path.join(__dirname, '..'),
    });
    console.log('✅ Proyecto Mutis configurado\n');

    // 4. Agregar personal clave
    console.log('👤 4/9 Agregando personal clave...');
    execSync(`node ${path.join(scriptsDir, 'addKeyPersonnel.js')}`, {
      stdio: 'inherit',
      cwd: path.join(__dirname, '..'),
    });
    console.log('✅ Personal clave agregado\n');

    // 5. Importar ítems contractuales
    console.log('📊 5/9 Importando ítems contractuales...');
    execSync(`node ${path.join(scriptsDir, 'importContractItems.js')}`, {
      stdio: 'inherit',
      cwd: path.join(__dirname, '..'),
    });
    console.log('✅ Ítems contractuales importados\n');

    // 6. Importar actas de obra
    console.log('📄 6/9 Importando actas de obra...');
    execSync(`node ${path.join(scriptsDir, 'importActasHistory.js')}`, {
      stdio: 'inherit',
      cwd: path.join(__dirname, '..'),
    });
    console.log('✅ Actas de obra importadas\n');

    // 7. Importar actas de costo
    console.log('💰 7/9 Importando actas de costo...');
    execSync(`node ${path.join(scriptsDir, 'importCostActasHistory.js')}`, {
      stdio: 'inherit',
      cwd: path.join(__dirname, '..'),
    });
    console.log('✅ Actas de costo importadas\n');

    // 8. Importar elementos del corredor vial
    console.log('🛣️  8/9 Importando elementos del corredor vial...');
    execSync(`node ${path.join(scriptsDir, 'importCorredorVialElements.js')}`, {
      stdio: 'inherit',
      cwd: path.join(__dirname, '..'),
    });
    console.log('✅ Elementos del corredor vial importados\n');

    // 9. Actualizar CIVs del proyecto
    console.log('📈 9/9 Actualizando CIVs del proyecto...');
    execSync(`node ${path.join(scriptsDir, 'updateProjectCIVs.js')}`, {
      stdio: 'inherit',
      cwd: path.join(__dirname, '..'),
    });
    console.log('✅ CIVs actualizados\n');

    console.log('🎉 ¡Todos los datos originales han sido restaurados!');
    console.log('\n📊 Resumen:');
    console.log('   ✅ Usuarios: ~34 usuarios (IDU, CONTRATISTA, INTERVENTORIA)');
    console.log('   ✅ Proyecto: Mutis (José Celestino Mutis - IDU-2412-2024)');
    console.log('   ✅ Personal clave: Agregado');
    console.log('   ✅ Ítems contractuales: Importados');
    console.log('   ✅ Actas de obra: Importadas');
    console.log('   ✅ Actas de costo: Importadas');
    console.log('   ✅ Elementos del corredor vial: Importados');
    console.log('   ✅ CIVs: Actualizados');
    console.log('\n🔑 Todos los usuarios tienen password: password123');
  } catch (error) {
    console.error('❌ Error durante la restauración:', error.message);
    console.error('\n💡 Algunos scripts pueden fallar si los datos ya existen.');
    console.error('   Esto es normal - los scripts actualizan datos existentes.');
    process.exit(1);
  }
}

restoreAllData();

