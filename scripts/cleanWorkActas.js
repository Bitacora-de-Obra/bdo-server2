/* eslint-disable no-console */
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// Solo estas actas de avance deben permanecer (las de la imagen)
const VALID_WORK_ACTAS = [
  'ACTA-019', // Acta de ajustes No.4 correspondiente al Acta 4 ejecución
  'ACTA-014', // Acta de ajustes acta parcial 4
  'ACTA-012', // Acta de ajustes acta parcial 3
  'ACTA-018', // Acta de ajustes No. 3 correspondiente al acta de RPO 5
  'ACTA-024', // Acta parcial 7 contrato obra Acta 5 ejecución
  'ACTA-009', // Acta de competencia ETB
  'ACTA-023', // Acta parcial 6 contrato obra Acta 4 ejecución
  'ACTA-015', // Acta parcial 5 contrato obra Acta 3 ejecución
  'ACTA-025', // Acta parcial 8 contrato interventoría Acta 3 ejecución costos variables
  'ACTA-013', // Acta parcial 4 contrato obra Acta 2 ejecución
  'ACTA-016', // Acta parcial 3 contrato interventoría Acta 1 ejecución costos fijos
  'ACTA-017', // Acta parcial 4 contrato interventoría Acta 1 ejecución costos variables
  'ACTA-003', // Acta cambio de etapa
];

async function main() {
  // Obtener todas las actas de avance
  const allWorkActas = await prisma.workActa.findMany({
    select: { number: true, description: true },
  });

  console.log(`Total de actas de avance encontradas: ${allWorkActas.length}`);

  // Filtrar las que NO están en la lista válida
  const actasToDelete = allWorkActas.filter(
    (acta) => !VALID_WORK_ACTAS.includes(acta.number)
  );

  if (actasToDelete.length === 0) {
    console.log('✅ No hay actas que eliminar. Solo están las 13 actas válidas.');
    return;
  }

  console.log(`\nActas a eliminar (${actasToDelete.length}):`);
  actasToDelete.forEach((acta) => {
    console.log(`  - ${acta.number}: ${acta.description || '(sin descripción)'}`);
  });

  // Eliminar las actas que no están en la lista válida
  let deleted = 0;
  for (const acta of actasToDelete) {
    try {
      // Buscar el acta por su number para obtener su id
      const foundActa = await prisma.workActa.findUnique({
        where: { number: acta.number },
        select: { id: true },
      });
      
      if (!foundActa) {
        console.log(`⚠️  No se encontró el acta ${acta.number}, puede que ya haya sido eliminado`);
        continue;
      }
      
      // Primero eliminar los items relacionados (si existen)
      await prisma.workActaItem.deleteMany({
        where: { workActaId: foundActa.id },
      });
      
      // Luego eliminar el acta
      await prisma.workActa.delete({
        where: { id: foundActa.id },
      });
      
      deleted++;
      console.log(`✓ Eliminada: ${acta.number}`);
    } catch (error) {
      console.error(`✗ Error al eliminar ${acta.number}:`, error.message);
    }
  }

  console.log(`\n✅ Proceso completado. Se eliminaron ${deleted} actas.`);
  console.log(`✅ Quedan ${VALID_WORK_ACTAS.length} actas válidas.`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

