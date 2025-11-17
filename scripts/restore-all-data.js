// Restore all original data (users, project, personnel, etc.)
// This script restores the complete original dataset
// Usage: node scripts/restore-all-data.js

/* eslint-disable no-console */
const { execSync } = require('child_process');
const path = require('path');

async function restoreAllData() {
  console.log('🔄 Restaurando todos los datos originales...\n');
    console.log('📋 Esto incluye:');
    console.log('   1. Usuarios (IDU, CONTRATISTA, INTERVENTORIA)');
    console.log('   2. Proyecto Mutis (José Celestino Mutis)');
    console.log('   3. Personal clave del proyecto');
  console.log('   4. Ítems contractuales');
  console.log('   5. Actas de obra');
  console.log('   6. Actas de costo');
  console.log('   7. Otros datos del proyecto\n');

  const scriptsDir = path.join(__dirname);
  
  try {
    // 1. Restaurar usuarios
    console.log('👥 1/7 Restaurando usuarios...');
    execSync(`node ${path.join(scriptsDir, 'restore-all-users.js')}`, {
      stdio: 'inherit',
      cwd: path.join(__dirname, '..'),
    });
    console.log('✅ Usuarios restaurados\n');

    // 2. Crear/actualizar proyecto Mutis
    console.log('📋 2/7 Creando/actualizando Proyecto Mutis...');
    execSync(`node ${path.join(scriptsDir, 'createMutisProject.js')}`, {
      stdio: 'inherit',
      cwd: path.join(__dirname, '..'),
    });
    console.log('✅ Proyecto Mutis configurado\n');

    // 3. Agregar personal clave
    console.log('👤 3/7 Agregando personal clave...');
    execSync(`node ${path.join(scriptsDir, 'addKeyPersonnel.js')}`, {
      stdio: 'inherit',
      cwd: path.join(__dirname, '..'),
    });
    console.log('✅ Personal clave agregado\n');

    // 4. Importar ítems contractuales
    console.log('📊 4/7 Importando ítems contractuales...');
    execSync(`node ${path.join(scriptsDir, 'importContractItems.js')}`, {
      stdio: 'inherit',
      cwd: path.join(__dirname, '..'),
    });
    console.log('✅ Ítems contractuales importados\n');

    // 5. Importar actas de obra
    console.log('📄 5/7 Importando actas de obra...');
    execSync(`node ${path.join(scriptsDir, 'importActasHistory.js')}`, {
      stdio: 'inherit',
      cwd: path.join(__dirname, '..'),
    });
    console.log('✅ Actas de obra importadas\n');

    // 6. Importar actas de costo
    console.log('💰 6/7 Importando actas de costo...');
    execSync(`node ${path.join(scriptsDir, 'importCostActasHistory.js')}`, {
      stdio: 'inherit',
      cwd: path.join(__dirname, '..'),
    });
    console.log('✅ Actas de costo importadas\n');

    // 7. Actualizar CIVs del proyecto
    console.log('📈 7/7 Actualizando CIVs del proyecto...');
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

