/* eslint-disable no-console */
const { PrismaClient } = require('@prisma/client');
const path = require('path');
const fs = require('fs');

const prisma = new PrismaClient();

async function main() {
  try {
    // Buscar un acta de cobro existente
    const costActa = await prisma.costActa.findFirst({
      include: {
        attachments: true,
        observations: {
          include: { author: true },
        },
      },
    });

    if (!costActa) {
      console.log('⚠️  No se encontró ninguna acta de cobro para probar.');
      return;
    }

    console.log(`\n✓ Acta de cobro encontrada: ${costActa.number}`);
    console.log(`  Descripción: ${costActa.relatedProgress || costActa.period}`);
    console.log(`  Estado: ${costActa.status}`);
    console.log(`  Adjuntos actuales: ${costActa.attachments?.length || 0}`);
    console.log(`  Observaciones actuales: ${costActa.observations?.length || 0}`);

    // Crear un archivo de prueba pequeño
    const testFileName = `test-attachment-${Date.now()}.txt`;
    const testFilePath = path.join(__dirname, '..', 'uploads', testFileName);
    const testContent = `Archivo de prueba creado el ${new Date().toISOString()}\nPara verificar la funcionalidad de adjuntar documentos.`;

    // Crear directorio si no existe
    const uploadsDir = path.join(__dirname, '..', 'uploads');
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir, { recursive: true });
    }

    fs.writeFileSync(testFilePath, testContent);

    console.log(`\n✓ Archivo de prueba creado: ${testFileName}`);

    // Verificar que podemos crear un attachment en la base de datos
    const testAttachment = await prisma.attachment.create({
      data: {
        fileName: testFileName,
        url: `/uploads/${testFileName}`,
        storagePath: testFileName,
        size: fs.statSync(testFilePath).size,
        type: 'text/plain',
        costActa: { connect: { id: costActa.id } },
      },
      include: {
        costActa: true,
      },
    });

    console.log(`\n✓ Attachment creado y vinculado al acta:`);
    console.log(`  ID: ${testAttachment.id}`);
    console.log(`  Nombre: ${testAttachment.fileName}`);
    console.log(`  Vinculado a: ${testAttachment.costActa?.number || 'N/A'}`);

    // Verificar que el acta ahora tiene el attachment
    const updatedActa = await prisma.costActa.findUnique({
      where: { id: costActa.id },
      include: {
        attachments: true,
      },
    });

    console.log(`\n✓ Acta actualizada - Adjuntos: ${updatedActa?.attachments?.length || 0}`);

    // Limpiar el archivo de prueba
    if (fs.existsSync(testFilePath)) {
      fs.unlinkSync(testFilePath);
      console.log(`\n✓ Archivo de prueba eliminado`);
    }

    // Limpiar el attachment de prueba (opcional)
    // await prisma.attachment.delete({ where: { id: testAttachment.id } });
    // console.log(`\n✓ Attachment de prueba eliminado de la base de datos`);

    console.log(`\n✅ Prueba completada exitosamente!`);
    console.log(`\n📝 Nota: El attachment de prueba quedó en la base de datos.`);
    console.log(`   Puedes eliminarlo manualmente si lo deseas: ID ${testAttachment.id}`);

  } catch (error) {
    console.error('\n✗ Error en la prueba:', error);
    process.exit(1);
  }
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });



