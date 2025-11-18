/* eslint-disable no-console */
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// Valores del contrato
const CONTRACT_VALUES = {
  totalContractValue: 13331560035, // $ 13.331.560.035,00
  preliminaryPhaseValue: 248487308, // $ 248.487.308,00
  executionPhaseValue: 13083072727, // $ 13.083.072.727,00 (calculado como total - preliminar)
};

// Historial correcto de actas de cobro (8 actas)
function parseValue(valueStr) {
  if (!valueStr || valueStr === 'NA' || valueStr === '-') return null;
  // Remover $, espacios, puntos y convertir coma a punto
  const cleaned = valueStr.replace(/[$.\s]/g, '').replace(',', '.');
  return parseFloat(cleaned) || null;
}

function parseDate(dateStr) {
  if (!dateStr || dateStr === '-') return null;
  
  // Manejar rangos de fechas (tomar la primera fecha)
  const datePart = dateStr.split(' al ')[0].split(' al ')[0].trim();
  
  // Formato: DD/MM/YYYY o DD-MM-YYYY o nombre de mes
  if (dateStr.includes('febrero')) return new Date(Date.UTC(2025, 1, 15, 0, 0, 0)); // 15 de febrero
  if (dateStr.includes('marzo')) return new Date(Date.UTC(2025, 2, 15, 0, 0, 0)); // 15 de marzo
  if (dateStr.includes('abril')) return new Date(Date.UTC(2025, 3, 15, 0, 0, 0)); // 15 de abril
  if (dateStr.includes('mayo')) return new Date(Date.UTC(2025, 4, 15, 0, 0, 0)); // 15 de mayo
  if (dateStr.includes('junio')) return new Date(Date.UTC(2025, 5, 15, 0, 0, 0)); // 15 de junio
  if (dateStr.includes('julio')) return new Date(Date.UTC(2025, 6, 15, 0, 0, 0)); // 15 de julio
  if (dateStr.includes('agosto')) return new Date(Date.UTC(2025, 7, 15, 0, 0, 0)); // 15 de agosto
  
  const parts = datePart.split(/[\/\-]/);
  if (parts.length === 3) {
    const day = parseInt(parts[0], 10);
    const month = parseInt(parts[1], 10) - 1; // Mes es 0-indexed
    const year = parseInt(parts[2], 10);
    return new Date(Date.UTC(year, month, day, 0, 0, 0));
  }
  return null;
}

function extractPeriod(description) {
  // Extraer el período de la descripción (mes)
  const months = ['enero', 'febrero', 'marzo', 'abril', 'mayo', 'junio', 
                  'julio', 'agosto', 'septiembre', 'octubre', 'noviembre', 'diciembre'];
  for (const month of months) {
    if (description.toLowerCase().includes(month)) {
      return month.charAt(0).toUpperCase() + month.slice(1) + ' 2025';
    }
  }
  // Si es saldo fase preliminar, usar marzo (último mes de preliminar)
  if (description.toLowerCase().includes('saldo fase preliminar')) {
    return 'Marzo 2025';
  }
  return '';
}

// Las 8 actas de cobro correctas
const COST_ACTAS = [
  {
    number: 'N.8',
    description: 'Acta de cobro N.8, cobro N.1 fase preliminar - febrero',
    billedAmount: '$ 91.269.015,00',
    month: 'febrero',
    phase: 'preliminar',
  },
  {
    number: 'N.10',
    description: 'Acta de cobro N.10, cobro N.2 fase preliminar - marzo',
    billedAmount: '$ 91.269.015,00',
    month: 'marzo',
    phase: 'preliminar',
  },
  {
    number: 'N.18',
    description: 'Acta de cobro N.18, cobro N.5 fase de obra costo fijo - abril',
    billedAmount: '$ 130.810.655,00',
    month: 'abril',
    phase: 'ejecución',
  },
  {
    number: 'N.19',
    description: 'Acta de cobro N.19, cobro N.6 fase de obra costo variable - abril',
    billedAmount: '$ 736.725,00',
    month: 'abril',
    phase: 'ejecución',
  },
  {
    number: 'N.14',
    description: 'Acta de cobro N.14, cobro N.3 fase de obra costo fijo - mayo',
    billedAmount: '$ 130.810.655,00',
    month: 'mayo',
    phase: 'ejecución',
  },
  {
    number: 'N.15',
    description: 'Acta de cobro N.15, cobro N.4 fase de obra costo variable - mayo',
    billedAmount: '$ 552.544,00',
    month: 'mayo',
    phase: 'ejecución',
  },
  {
    number: 'N.20',
    description: 'Acta de cobro N.20, cobro N.7 saldo fase preliminar',
    billedAmount: '$ 182.538.028,00',
    month: 'marzo', // Asumiendo marzo para el saldo de fase preliminar
    phase: 'preliminar',
  },
  {
    number: 'N.23',
    description: 'Acta de cobro N.23, cobro N.8 fase de obra costo variable - junio',
    billedAmount: '$ 33.521.015,00',
    month: 'junio',
    phase: 'ejecución',
  },
];

async function main() {
  // Primero eliminar todas las actas de cobro existentes
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

  console.log(`\nImportando las 8 actas de cobro correctas...\n`);

  // Crear las 8 actas de cobro correctas
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

  console.log(`\n✅ Proceso completado: ${created} actas de cobro creadas.`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });



