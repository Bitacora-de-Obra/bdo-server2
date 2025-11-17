/* eslint-disable no-console */
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// Mapeo de descripciones actuales a descripciones limpias (sin costo fijo/variable)
const descriptionMap = {
  'Acta de cobro N.8, cobro N.1 fase preliminar - febrero': 'Acta de cobro N.8, cobro N.1 fase preliminar - febrero',
  'Acta de cobro N.10, cobro N.2 fase preliminar - marzo': 'Acta de cobro N.10, cobro N.2 fase preliminar - marzo',
  'Acta de cobro N.18, cobro N.5 fase de obra costo fijo - abril': 'Acta de cobro N.18, cobro N.5 fase de obra - abril',
  'Acta de cobro N.19, cobro N.6 fase de obra costo variable - abril': 'Acta de cobro N.19, cobro N.6 fase de obra - abril',
  'Acta de cobro N.14, cobro N.3 fase de obra costo fijo - mayo': 'Acta de cobro N.14, cobro N.3 fase de obra - mayo',
  'Acta de cobro N.15, cobro N.4 fase de obra costo variable - mayo': 'Acta de cobro N.15, cobro N.4 fase de obra - mayo',
  'Acta de cobro N.20, cobro N.7 saldo fase preliminar': 'Acta de cobro N.20, cobro N.7 saldo fase preliminar',
  'Acta de cobro N.23, cobro N.8 fase de obra costo variable - junio': 'Acta de cobro N.23, cobro N.8 fase de obra - junio',
};

async function main() {
  const allCostActas = await prisma.costActa.findMany({
    select: { id: true, number: true, relatedProgress: true },
  });

  console.log(`Total de actas de cobro encontradas: ${allCostActas.length}\n`);

  let updated = 0;
  for (const acta of allCostActas) {
    if (!acta.relatedProgress) continue;

    // Limpiar descripción removiendo "costo fijo" y "costo variable"
    let cleanDescription = acta.relatedProgress
      .replace(/costo\s+fijo\s+/gi, '')
      .replace(/costo\s+variable\s+/gi, '')
      .replace(/\s+-\s+/g, ' - ') // Normalizar espacios alrededor del guión
      .trim();

    // Si hay un mapeo específico, usarlo
    if (descriptionMap[acta.relatedProgress]) {
      cleanDescription = descriptionMap[acta.relatedProgress];
    }

    if (cleanDescription !== acta.relatedProgress) {
      try {
        await prisma.costActa.update({
          where: { id: acta.id },
          data: { relatedProgress: cleanDescription },
        });
        updated++;
        console.log(`✓ Actualizada: ${acta.number}`);
        console.log(`  Antes: ${acta.relatedProgress}`);
        console.log(`  Después: ${cleanDescription}\n`);
      } catch (error) {
        console.error(`✗ Error al actualizar ${acta.number}:`, error.message);
      }
    } else {
      console.log(`- Sin cambios: ${acta.number} - ${acta.relatedProgress}`);
    }
  }

  console.log(`\n✅ Proceso completado: ${updated} actas actualizadas.`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });


