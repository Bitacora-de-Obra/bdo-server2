/* eslint-disable no-console */
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// Valores del contrato de OBRA (no interventoría)
const CONTRACT_VALUES = {
  totalContractValue: 13331560035, // $ 13.331.560.035,00
  preliminaryPhaseValue: 248487308, // $ 248.487.308,00
  executionPhaseValue: 9491081407.50, // $ 9.491.081.407,50
};

function parseValue(valueStr) {
  if (!valueStr || valueStr === 'NA' || valueStr === '-') return null;
  const cleaned = valueStr.replace(/[$.\s]/g, '').replace(',', '.');
  return parseFloat(cleaned) || null;
}

function parseDate(dateStr) {
  if (!dateStr || dateStr === '-') return null;
  
  if (dateStr.includes('febrero')) return new Date(Date.UTC(2025, 1, 15, 0, 0, 0));
  if (dateStr.includes('marzo')) return new Date(Date.UTC(2025, 2, 15, 0, 0, 0));
  if (dateStr.includes('abril')) return new Date(Date.UTC(2025, 3, 15, 0, 0, 0));
  if (dateStr.includes('mayo')) return new Date(Date.UTC(2025, 4, 15, 0, 0, 0));
  if (dateStr.includes('junio')) return new Date(Date.UTC(2025, 5, 15, 0, 0, 0));
  if (dateStr.includes('julio')) return new Date(Date.UTC(2025, 6, 15, 0, 0, 0));
  if (dateStr.includes('agosto')) return new Date(Date.UTC(2025, 7, 15, 0, 0, 0));
  
  const parts = dateStr.split(/[\/\-]/);
  if (parts.length === 3) {
    const day = parseInt(parts[0], 10);
    const month = parseInt(parts[1], 10) - 1;
    const year = parseInt(parts[2], 10);
    return new Date(Date.UTC(year, month, day, 0, 0, 0));
  }
  return null;
}

function extractPeriod(description) {
  const months = ['enero', 'febrero', 'marzo', 'abril', 'mayo', 'junio', 
                  'julio', 'agosto', 'septiembre', 'octubre', 'noviembre', 'diciembre'];
  for (const month of months) {
    if (description.toLowerCase().includes(month)) {
      return month.charAt(0).toUpperCase() + month.slice(1) + ' 2025';
    }
  }
  return '';
}

// Las 7 actas de cobro correctas del CONTRATO DE OBRA (según la imagen)
const COST_ACTAS = [
  {
    number: 'N.3',
    description: 'Acta de cobro N.3, cobro N.1 fase preliminar - febrero',
    billedAmount: '$ 77.462.858,00',
    month: 'febrero',
    phase: 'preliminar',
  },
  {
    number: 'N.7',
    description: 'Acta de cobro N.7, cobro N.2 fase preliminar - marzo',
    billedAmount: '$ 284.266.256,00',
    month: 'marzo',
    phase: 'preliminar',
  },
  {
    number: 'N.11',
    description: 'Acta de cobro N.11, cobro N.1 fase de obra - abril',
    billedAmount: '$ 8.946.930,00',
    month: 'abril',
    phase: 'ejecución',
  },
  {
    number: 'N.13',
    description: 'Acta de cobro N.13, cobro N.2 fase de obra - mayo',
    billedAmount: '$ 18.708.037,00',
    month: 'mayo',
    phase: 'ejecución',
  },
  {
    number: 'N.15',
    description: 'Acta de cobro N.15, cobro N.3 fase de obra - junio',
    billedAmount: '$ 386.670.278,00',
    month: 'junio',
    phase: 'ejecución',
  },
  {
    number: 'N.21',
    description: 'Acta de cobro N.21, cobro N.4 fase de obra - julio',
    billedAmount: '$ 110.578.255,00',
    month: 'julio',
    phase: 'ejecución',
  },
  {
    number: 'N.22',
    description: 'Acta de cobro N.22, cobro N.5 fase de obra - agosto',
    billedAmount: '$ 131.163.315,00',
    month: 'agosto',
    phase: 'ejecución',
  },
];

async function main() {
  // Eliminar todas las actas de cobro existentes
  console.log('Eliminando actas de cobro existentes...\n');
  const existingCostActas = await prisma.costActa.findMany({
    select: { id: true, number: true },
  });

  for (const acta of existingCostActas) {
    try {
      await prisma.costActa.delete({
        where: { id: acta.id },
      });
      console.log(`✓ Eliminada: ${acta.number}`);
    } catch (error) {
      console.error(`✗ Error al eliminar ${acta.number}:`, error.message);
    }
  }

  console.log(`\nImportando las 7 actas de cobro correctas del CONTRATO DE OBRA...\n`);

  // Crear las 7 actas de cobro correctas
  let created = 0;
  for (const actaData of COST_ACTAS) {
    const number = `COBRO-${actaData.number}`;
    const submissionDate = parseDate(actaData.month);
    const billedAmount = parseValue(actaData.billedAmount);
    const period = extractPeriod(actaData.description);

    if (!submissionDate) {
      console.warn(`⚠️  No se pudo parsear la fecha para acta ${number}: ${actaData.month}`);
      continue;
    }

    if (!billedAmount) {
      console.warn(`⚠️  No se pudo parsear el valor para acta ${number}: ${actaData.billedAmount}`);
      continue;
    }

    try {
      await prisma.costActa.create({
        data: {
          number: number,
          period: period || actaData.month,
          submissionDate: submissionDate,
          approvalDate: submissionDate,
          paymentDueDate: null,
          billedAmount: billedAmount,
          totalContractValue: CONTRACT_VALUES.totalContractValue,
          status: 'APPROVED',
          relatedProgress: actaData.description,
        },
      });
      created++;
      console.log(`✓ Creada: ${number} - ${actaData.description} - ${billedAmount.toLocaleString('es-CO', { style: 'currency', currency: 'COP', minimumFractionDigits: 0 })}`);
    } catch (error) {
      console.error(`✗ Error procesando acta ${number}:`, error.message);
    }
  }

  console.log(`\n✅ Proceso completado: ${created} actas de cobro creadas del CONTRATO DE OBRA.`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });



