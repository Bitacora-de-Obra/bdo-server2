/* eslint-disable no-console */
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// Solo estas actas de cobro deben permanecer (las de la última imagen)
const VALID_COST_ACTAS = [
  'COBRO-N.3',
  'COBRO-N.7',
  'COBRO-N.11',
  'COBRO-N.13',
  'COBRO-N.15',
  'COBRO-N.21',
  'COBRO-N.22',
];

async function main() {
  // Obtener todas las actas de costos
  const allCostActas = await prisma.costActa.findMany({
    select: { number: true },
  });

  console.log(`Total de actas de costos encontradas: ${allCostActas.length}`);

  // Filtrar las que NO están en la lista válida
  const actasToDelete = allCostActas.filter(
    (acta) => !VALID_COST_ACTAS.includes(acta.number)
  );

  if (actasToDelete.length === 0) {
    console.log('✅ No hay actas que eliminar. Solo están las 7 actas válidas.');
    return;
  }

  console.log(`\nActas a eliminar (${actasToDelete.length}):`);
  actasToDelete.forEach((acta) => console.log(`  - ${acta.number}`));

  // Eliminar las actas que no están en la lista válida
  for (const acta of actasToDelete) {
    try {
      await prisma.costActa.delete({
        where: { number: acta.number },
      });
      console.log(`✓ Eliminada: ${acta.number}`);
    } catch (error) {
      console.error(`✗ Error al eliminar ${acta.number}:`, error.message);
    }
  }

  console.log(`\n✅ Proceso completado. Se eliminaron ${actasToDelete.length} actas.`);
  console.log(`✅ Quedan ${VALID_COST_ACTAS.length} actas válidas.`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });


