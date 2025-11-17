/* eslint-disable no-console */
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function main() {
  // Obtener todas las actas de avance
  const allWorkActas = await prisma.workActa.findMany({
    select: { id: true, number: true },
  });

  console.log(`Total de actas de avance encontradas: ${allWorkActas.length}\n`);

  if (allWorkActas.length === 0) {
    console.log('✅ No hay actas de avance para eliminar.');
    return;
  }

  // Eliminar todas las actas de avance
  let deleted = 0;
  for (const acta of allWorkActas) {
    try {
      // Primero eliminar los items relacionados
      await prisma.workActaItem.deleteMany({
        where: { workActaId: acta.id },
      });
      
      // Luego eliminar el acta
      await prisma.workActa.delete({
        where: { id: acta.id },
      });
      
      deleted++;
      console.log(`✓ Eliminada: ${acta.number}`);
    } catch (error) {
      console.error(`✗ Error al eliminar ${acta.number}:`, error.message);
    }
  }

  console.log(`\n✅ Proceso completado. Se eliminaron ${deleted} actas de avance.`);
  console.log('✅ Ahora puedes crear solo las 7 actas de avance necesarias.');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });


