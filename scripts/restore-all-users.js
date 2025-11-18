// Restore all original users (IDU, CONTRATISTA, INTERVENTORIA)
// This script runs all user creation scripts to restore the original ~34 users
// Usage: node scripts/restore-all-users.js

/* eslint-disable no-console */
const { execSync } = require('child_process');
const path = require('path');

async function restoreAllUsers() {
  console.log('🔄 Restaurando todos los usuarios originales...\n');
  console.log('📋 Esto incluye:');
  console.log('   - Usuarios de IDU (~11 usuarios)');
  console.log('   - Usuarios de CONTRATISTA (~11 usuarios)');
  console.log('   - Usuarios de INTERVENTORIA (~12 usuarios)');
  console.log('   - Total: ~34 usuarios\n');

  const scriptsDir = path.join(__dirname);
  
  try {
    // 1. Crear usuarios de IDU
    console.log('📦 1/3 Creando usuarios de IDU...');
    execSync(`node ${path.join(scriptsDir, 'createIDUUsers.js')}`, {
      stdio: 'inherit',
      cwd: path.join(__dirname, '..'),
    });
    console.log('✅ Usuarios de IDU creados\n');

    // 2. Crear usuarios de CONTRATISTA
    console.log('📦 2/3 Creando usuarios de CONTRATISTA...');
    execSync(`node ${path.join(scriptsDir, 'createContratistaUsers.js')}`, {
      stdio: 'inherit',
      cwd: path.join(__dirname, '..'),
    });
    console.log('✅ Usuarios de CONTRATISTA creados\n');

    // 3. Crear usuarios de INTERVENTORIA
    console.log('📦 3/3 Creando usuarios de INTERVENTORIA...');
    execSync(`node ${path.join(scriptsDir, 'createInterventoriaUsers.js')}`, {
      stdio: 'inherit',
      cwd: path.join(__dirname, '..'),
    });
    console.log('✅ Usuarios de INTERVENTORIA creados\n');

    console.log('🎉 ¡Todos los usuarios originales han sido restaurados!');
    console.log('\n📊 Resumen:');
    console.log('   - IDU: ~11 usuarios');
    console.log('   - CONTRATISTA: ~11 usuarios');
    console.log('   - INTERVENTORIA: ~12 usuarios');
    console.log('   - Total: ~34 usuarios');
    console.log('\n🔑 Todos los usuarios tienen password: password123');
    console.log('\n💡 Nota: Los usuarios existentes serán actualizados, los nuevos serán creados.');
  } catch (error) {
    console.error('❌ Error durante la restauración:', error.message);
    process.exit(1);
  }
}

restoreAllUsers();



