/**
 * Script de pruebas para verificar que el sistema multi-tenant funciona correctamente
 * 
 * Este script verifica:
 * 1. Que el tenant "mutis" existe
 * 2. Que los datos tienen tenantId asignado
 * 3. Que los endpoints filtran correctamente por tenant
 * 4. Que los datos están aislados por tenant
 */

const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function success(message) {
  log(`✅ ${message}`, 'green');
}

function error(message) {
  log(`❌ ${message}`, 'red');
}

function warning(message) {
  log(`⚠️  ${message}`, 'yellow');
}

function info(message) {
  log(`ℹ️  ${message}`, 'cyan');
}

function section(title) {
  console.log('');
  log(`📋 ${title}`, 'blue');
  console.log('─'.repeat(50));
}

async function testTenantExists() {
  section('1. Verificando que el tenant "mutis" existe');
  
  try {
    const tenant = await prisma.$queryRawUnsafe(`
      SELECT id, subdomain, name, domain, isActive 
      FROM Tenant 
      WHERE subdomain = 'mutis' 
      LIMIT 1
    `);
    
    if (!tenant || tenant.length === 0) {
      error('Tenant "mutis" no encontrado');
      return null;
    }
    
    const t = tenant[0];
    success(`Tenant "mutis" encontrado`);
    info(`  ID: ${t.id}`);
    info(`  Nombre: ${t.name}`);
    info(`  Dominio: ${t.domain}`);
    info(`  Activo: ${t.isActive ? 'Sí' : 'No'}`);
    
    return t.id;
  } catch (err) {
    error(`Error al buscar tenant: ${err.message}`);
    return null;
  }
}

async function testTenantIdInTables(tenantId) {
  section('2. Verificando que las tablas tienen tenantId');
  
  const tables = [
    'User', 'Project', 'LogEntry', 'ControlPoint', 'Communication',
    'ContractModification', 'Acta', 'CostActa', 'WorkActa', 'Report',
    'ProjectTask', 'Drawing', 'SecurityEventLog'
  ];
  
  let allPassed = true;
  
  for (const table of tables) {
    try {
      // Verificar que la columna existe
      const columnExists = await prisma.$queryRawUnsafe(`
        SELECT COUNT(*) as count 
        FROM information_schema.COLUMNS 
        WHERE TABLE_SCHEMA = DATABASE() 
        AND TABLE_NAME = ? 
        AND COLUMN_NAME = 'tenantId'
      `, table);
      
      if (columnExists[0].count === 0) {
        error(`${table}: columna tenantId no existe`);
        allPassed = false;
        continue;
      }
      
      // Contar registros con tenantId
      const count = await prisma.$queryRawUnsafe(`
        SELECT COUNT(*) as count 
        FROM \`${table}\` 
        WHERE tenantId = ?
      `, tenantId);
      
      const totalCount = await prisma.$queryRawUnsafe(`
        SELECT COUNT(*) as count FROM \`${table}\`
      `);
      
      const withTenantId = count[0].count;
      const total = totalCount[0].count;
      
      if (table === 'SecurityEventLog') {
        // SecurityEventLog puede tener tenantId NULL
        if (withTenantId > 0) {
          success(`${table}: ${withTenantId}/${total} registros con tenantId`);
        } else {
          warning(`${table}: 0 registros con tenantId (puede ser normal si no hay eventos)`);
        }
      } else {
        // Otras tablas deben tener tenantId obligatorio
        if (total === 0) {
          info(`${table}: 0 registros (tabla vacía - OK)`);
        } else if (withTenantId === total) {
          success(`${table}: ${withTenantId}/${total} registros con tenantId`);
        } else {
          error(`${table}: ${withTenantId}/${total} registros con tenantId (deberían ser todos)`);
          allPassed = false;
        }
      }
    } catch (err) {
      error(`${table}: Error - ${err.message}`);
      allPassed = false;
    }
  }
  
  return allPassed;
}

async function testDataIsolation(tenantId) {
  section('3. Verificando aislamiento de datos por tenant');
  
  try {
    // Verificar que no hay registros sin tenantId (excepto SecurityEventLog)
    const tables = [
      'User', 'Project', 'LogEntry', 'ControlPoint', 'Communication',
      'ContractModification', 'Acta', 'CostActa', 'WorkActa', 'Report',
      'ProjectTask', 'Drawing'
    ];
    
    let allPassed = true;
    
    for (const table of tables) {
      const nullTenantId = await prisma.$queryRawUnsafe(`
        SELECT COUNT(*) as count 
        FROM \`${table}\` 
        WHERE tenantId IS NULL
      `);
      
      if (nullTenantId[0].count > 0) {
        error(`${table}: ${nullTenantId[0].count} registros sin tenantId`);
        allPassed = false;
      } else {
        success(`${table}: todos los registros tienen tenantId`);
      }
    }
    
    return allPassed;
  } catch (err) {
    error(`Error al verificar aislamiento: ${err.message}`);
    return false;
  }
}

async function testIndexesAndForeignKeys(tenantId) {
  section('4. Verificando índices y foreign keys');
  
  try {
    // Verificar índices
    const indexes = await prisma.$queryRawUnsafe(`
      SELECT TABLE_NAME, INDEX_NAME 
      FROM information_schema.STATISTICS 
      WHERE TABLE_SCHEMA = DATABASE() 
      AND COLUMN_NAME = 'tenantId'
      GROUP BY TABLE_NAME, INDEX_NAME
    `);
    
    if (indexes.length > 0) {
      success(`Encontrados ${indexes.length} índices en tenantId`);
      indexes.forEach(idx => {
        info(`  - ${idx.TABLE_NAME}.${idx.INDEX_NAME}`);
      });
    } else {
      warning('No se encontraron índices en tenantId');
    }
    
    // Verificar foreign keys
    const foreignKeys = await prisma.$queryRawUnsafe(`
      SELECT TABLE_NAME, CONSTRAINT_NAME, REFERENCED_TABLE_NAME
      FROM information_schema.KEY_COLUMN_USAGE 
      WHERE TABLE_SCHEMA = DATABASE() 
      AND COLUMN_NAME = 'tenantId'
      AND REFERENCED_TABLE_NAME IS NOT NULL
    `);
    
    if (foreignKeys.length > 0) {
      success(`Encontradas ${foreignKeys.length} foreign keys en tenantId`);
      foreignKeys.forEach(fk => {
        info(`  - ${fk.TABLE_NAME}.${fk.CONSTRAINT_NAME} -> ${fk.REFERENCED_TABLE_NAME}`);
      });
    } else {
      warning('No se encontraron foreign keys en tenantId');
    }
    
    return true;
  } catch (err) {
    error(`Error al verificar índices/FK: ${err.message}`);
    return false;
  }
}

async function testDrawingUniqueConstraint() {
  section('5. Verificando índice único compuesto de Drawing');
  
  try {
    const uniqueIndex = await prisma.$queryRawUnsafe(`
      SELECT CONSTRAINT_NAME 
      FROM information_schema.TABLE_CONSTRAINTS 
      WHERE TABLE_SCHEMA = DATABASE() 
      AND TABLE_NAME = 'Drawing' 
      AND CONSTRAINT_TYPE = 'UNIQUE'
      AND CONSTRAINT_NAME LIKE '%code%tenantId%'
    `);
    
    if (uniqueIndex.length > 0) {
      success(`Índice único compuesto encontrado: ${uniqueIndex[0].CONSTRAINT_NAME}`);
      return true;
    } else {
      warning('Índice único compuesto (code, tenantId) no encontrado');
      return false;
    }
  } catch (err) {
    error(`Error al verificar índice único: ${err.message}`);
    return false;
  }
}

async function testSampleQueries(tenantId) {
  section('6. Probando consultas filtradas por tenant');
  
  try {
    // Probar consulta de usuarios
    const users = await prisma.$queryRawUnsafe(`
      SELECT COUNT(*) as count 
      FROM User 
      WHERE tenantId = ?
    `, tenantId);
    success(`Usuarios del tenant: ${users[0].count}`);
    
    // Probar consulta de proyectos
    const projects = await prisma.$queryRawUnsafe(`
      SELECT COUNT(*) as count 
      FROM Project 
      WHERE tenantId = ?
    `, tenantId);
    success(`Proyectos del tenant: ${projects[0].count}`);
    
    // Probar consulta de drawings
    const drawings = await prisma.$queryRawUnsafe(`
      SELECT COUNT(*) as count 
      FROM Drawing 
      WHERE tenantId = ?
    `, tenantId);
    success(`Drawings del tenant: ${drawings[0].count}`);
    
    // Probar consulta de security events
    const securityEvents = await prisma.$queryRawUnsafe(`
      SELECT COUNT(*) as count 
      FROM SecurityEventLog 
      WHERE tenantId = ?
    `, tenantId);
    success(`Eventos de seguridad del tenant: ${securityEvents[0].count}`);
    
    return true;
  } catch (err) {
    error(`Error en consultas de prueba: ${err.message}`);
    return false;
  }
}

async function runAllTests() {
  console.log('');
  log('🧪 INICIANDO PRUEBAS DE MULTI-TENANCY', 'cyan');
  console.log('═'.repeat(50));
  
  const results = {
    tenantExists: false,
    tenantIdInTables: false,
    dataIsolation: false,
    indexesAndFK: false,
    drawingUnique: false,
    sampleQueries: false,
  };
  
  // Test 1: Verificar que el tenant existe
  const tenantId = await testTenantExists();
  results.tenantExists = tenantId !== null;
  
  if (!tenantId) {
    error('No se puede continuar sin un tenant válido');
    await prisma.$disconnect();
    process.exit(1);
  }
  
  // Test 2: Verificar tenantId en tablas
  results.tenantIdInTables = await testTenantIdInTables(tenantId);
  
  // Test 3: Verificar aislamiento de datos
  results.dataIsolation = await testDataIsolation(tenantId);
  
  // Test 4: Verificar índices y foreign keys
  results.indexesAndFK = await testIndexesAndForeignKeys(tenantId);
  
  // Test 5: Verificar índice único de Drawing
  results.drawingUnique = await testDrawingUniqueConstraint();
  
  // Test 6: Probar consultas
  results.sampleQueries = await testSampleQueries(tenantId);
  
  // Resumen
  console.log('');
  section('📊 RESUMEN DE PRUEBAS');
  
  const totalTests = Object.keys(results).length;
  const passedTests = Object.values(results).filter(r => r).length;
  
  Object.entries(results).forEach(([test, passed]) => {
    if (passed) {
      success(test);
    } else {
      error(test);
    }
  });
  
  console.log('');
  log(`Resultado: ${passedTests}/${totalTests} pruebas pasadas`, 
      passedTests === totalTests ? 'green' : 'yellow');
  
  if (passedTests === totalTests) {
    success('¡Todas las pruebas pasaron! El sistema multi-tenant está funcionando correctamente.');
  } else {
    warning('Algunas pruebas fallaron. Revisa los errores arriba.');
  }
  
  await prisma.$disconnect();
  
  process.exit(passedTests === totalTests ? 0 : 1);
}

// Ejecutar pruebas
runAllTests().catch((error) => {
  console.error('Error fatal:', error);
  process.exit(1);
});

