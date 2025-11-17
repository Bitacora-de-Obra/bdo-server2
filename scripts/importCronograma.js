// Import cronograma from XML file
// Usage: node scripts/importCronograma.js [path-to-xml-file]
// Example: node scripts/importCronograma.js uploads/cronograma.xml

/* eslint-disable no-console */
const fs = require('fs');
const path = require('path');
const { PrismaClient } = require('@prisma/client');
const { randomUUID } = require('crypto');

const prisma = new PrismaClient();

// Import the XML validator
const { validateCronogramaXml } = require('../src/utils/xmlValidator');

async function importCronograma(xmlFilePath) {
  try {
    console.log('📦 Importando cronograma desde XML...\n');

    // Read XML file
    const fullPath = path.isAbsolute(xmlFilePath)
      ? xmlFilePath
      : path.join(__dirname, '..', xmlFilePath);

    if (!fs.existsSync(fullPath)) {
      console.error(`❌ Archivo no encontrado: ${fullPath}`);
      process.exit(1);
    }

    console.log(`📄 Leyendo archivo: ${fullPath}`);
    const xmlContent = fs.readFileSync(fullPath, 'utf8');

    // Validate and parse XML
    console.log('🔍 Validando y parseando XML...');
    const incomingTasks = await validateCronogramaXml(xmlContent);
    console.log(`✅ Se encontraron ${incomingTasks.length} tareas en el XML\n`);

    // Get project
    const project = await prisma.project.findFirst();
    if (!project) {
      console.error('❌ No se encontró ningún proyecto en la base de datos.');
      console.error('   Por favor, crea el proyecto primero usando: npm run project:create-mutis');
      process.exit(1);
    }

    console.log(`📊 Proyecto encontrado: ${project.name} (${project.contractId})\n`);

    const MAX_NAME_LENGTH = Number(process.env.CRON_XML_MAX_NAME_LENGTH || 512);

    // Sanitize tasks
    const sanitizedTasks = incomingTasks.map((task, index) => {
      const id =
        typeof task?.id === 'string' && task.id.trim().length > 0
          ? task.id.trim()
          : randomUUID();
      const name =
        typeof task?.name === 'string' && task.name.trim().length > 0
          ? task.name.trim()
          : `Tarea ${index + 1}`;
      const safeName =
        name.length > MAX_NAME_LENGTH ? name.slice(0, MAX_NAME_LENGTH) : name;

      const parsedStart = new Date(task?.startDate);
      if (Number.isNaN(parsedStart.getTime())) {
        throw new Error(`La tarea "${safeName}" no tiene una fecha de inicio válida.`);
      }

      const parsedEnd = new Date(task?.endDate || task?.startDate);
      if (Number.isNaN(parsedEnd.getTime())) {
        throw new Error(`La tarea "${safeName}" no tiene una fecha de fin válida.`);
      }
      if (parsedEnd < parsedStart) {
        parsedEnd.setTime(parsedStart.getTime());
      }

      const progressValue = Math.max(
        0,
        Math.min(100, parseInt(`${task?.progress ?? 0}`, 10) || 0)
      );
      const durationValue = Math.max(
        1,
        parseInt(`${task?.duration ?? 1}`, 10) || 1
      );
      const outlineLevelValue = Math.max(
        1,
        parseInt(`${task?.outlineLevel ?? 1}`, 10) || 1
      );
      const isSummaryValue =
        task?.isSummary === true ||
        task?.isSummary === 1 ||
        (typeof task?.isSummary === 'string' && task.isSummary.toLowerCase() === 'true');

      const dependencyArray = Array.isArray(task?.dependencies)
        ? task.dependencies
            .map((dep) => `${dep}`.trim())
            .filter((dep) => dep.length > 0)
        : [];

      return {
        id,
        taskId: id,
        name: safeName,
        startDate: parsedStart,
        endDate: parsedEnd,
        progress: progressValue,
        duration: durationValue,
        isSummary: isSummaryValue,
        outlineLevel: outlineLevelValue,
        dependencies: dependencyArray.length ? JSON.stringify(dependencyArray) : null,
        projectId: project.id,
      };
    });

    // Delete existing tasks and create new ones
    console.log('🗑️  Eliminando tareas existentes...');
    const deleted = await prisma.projectTask.deleteMany({
      where: { projectId: project.id },
    });
    console.log(`   ${deleted.count} tareas eliminadas\n`);

    if (sanitizedTasks.length > 0) {
      console.log(`➕ Creando ${sanitizedTasks.length} tareas...`);
      await prisma.projectTask.createMany({ data: sanitizedTasks });
      console.log('✅ Tareas creadas exitosamente\n');
    }

    // Get final count
    const finalCount = await prisma.projectTask.count({
      where: { projectId: project.id },
    });

    console.log('📈 Resumen:');
    console.log(`   ➕ Tareas creadas: ${sanitizedTasks.length}`);
    console.log(`   📊 Total de tareas en el proyecto: ${finalCount}`);
    console.log('\n✅ Importación completada exitosamente');
  } catch (error) {
    console.error('❌ Error durante la importación:', error.message);
    if (error.stack) {
      console.error(error.stack);
    }
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

// Get XML file path from command line argument
const xmlFilePath = process.argv[2];

if (!xmlFilePath) {
  console.error('❌ Por favor, proporciona la ruta al archivo XML del cronograma.');
  console.error('\nUso:');
  console.error('  node scripts/importCronograma.js <ruta-al-archivo-xml>');
  console.error('\nEjemplo:');
  console.error('  node scripts/importCronograma.js uploads/cronograma.xml');
  process.exit(1);
}

importCronograma(xmlFilePath)
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

