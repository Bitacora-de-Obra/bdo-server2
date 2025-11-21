const mysql = require("mysql2/promise");

async function forceMigrationFix() {
  let connection;

  try {
    console.log("🔧 Conectando directamente a la base de datos MySQL...");

    // Extraer detalles de conexión desde DATABASE_URL
    const dbUrl = process.env.DATABASE_URL;
    if (!dbUrl) {
      throw new Error("DATABASE_URL no encontrada");
    }

    // Parse de la URL de conexión
    const url = new URL(dbUrl);
    const connectionConfig = {
      host: url.hostname,
      port: parseInt(url.port) || 3306,
      user: url.username,
      password: url.password,
      database: url.pathname.slice(1), // Remover el '/' inicial
      ssl: {
        rejectUnauthorized: false,
      },
    };

    console.log(
      `Conectando a: ${connectionConfig.host}:${connectionConfig.port}/${connectionConfig.database}`
    );

    connection = await mysql.createConnection(connectionConfig);
    console.log("✅ Conexión establecida");

    // Verificar si la tabla _prisma_migrations existe
    const [tables] = await connection.execute(`
      SELECT TABLE_NAME 
      FROM information_schema.TABLES 
      WHERE TABLE_SCHEMA = DATABASE() 
      AND TABLE_NAME = '_prisma_migrations'
    `);
    
    if (tables.length === 0) {
      console.log("ℹ️  Tabla _prisma_migrations no existe, saltando corrección de migración");
      return;
    }

    // Eliminar completamente la migración problemática
    console.log("🗑️  Eliminando migración problemática...");
    await connection.execute(`
      DELETE FROM _prisma_migrations 
      WHERE migration_name = '20250325100000_add_report_versions' 
      OR id = '20250325100000_add_report_versions'
    `);

    // Verificar estado de migraciones (solo si la tabla existe)
    const [rows] = await connection.execute(`
      SELECT migration_name, finished_at, rolled_back_at 
      FROM _prisma_migrations 
      WHERE rolled_back_at IS NOT NULL OR finished_at IS NULL
      ORDER BY started_at DESC
      LIMIT 10
    `);

    console.log("📋 Estado de migraciones:");
    console.table(rows);

    // Limpiar cualquier migración fallida
    console.log("🧹 Limpiando migraciones fallidas...");
    await connection.execute(`
      DELETE FROM _prisma_migrations 
      WHERE rolled_back_at IS NOT NULL OR finished_at IS NULL
    `);

    console.log("✅ Base de datos limpiada, listo para aplicar migraciones");
  } catch (error) {
    console.error("❌ Error en corrección directa:", error);
    throw error;
  } finally {
    if (connection) {
      await connection.end();
      console.log("🔌 Conexión cerrada");
    }
  }
}

// Ejecutar corrección y luego iniciar servidor
forceMigrationFix()
  .then(async () => {
    console.log("🚀 Aplicando migraciones con Prisma...");
    const { exec } = require("child_process");
    const { promisify } = require("util");
    const execAsync = promisify(exec);

    try {
      // Generar cliente Prisma
      await execAsync("npx prisma generate");
      console.log("✅ Cliente Prisma generado");

      // Aplicar migraciones
      await execAsync("npx prisma migrate deploy");
      console.log("✅ Migraciones aplicadas exitosamente");
    } catch (migrationError) {
      console.log(
        "⚠️ Error en migraciones de Prisma, continuando con el servidor..."
      );
      console.error(migrationError);
    }

    console.log("🎯 Iniciando servidor principal...");
    require("./dist/index.js");
  })
  .catch((error) => {
    console.error("💥 Error fatal en startup:", error);

    // Como último recurso, intentar iniciar el servidor sin migraciones
    console.log("🆘 Intentando iniciar servidor sin migraciones...");
    try {
      require("./dist/index.js");
    } catch (serverError) {
      console.error("💀 No se pudo iniciar el servidor:", serverError);
      process.exit(1);
    }
  });
