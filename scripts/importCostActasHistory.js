/* eslint-disable no-console */
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// Valores del contrato
const CONTRACT_VALUES = {
  totalContractValue: 13331560035, // $ 13.331.560.035,00
  preliminaryPhaseValue: 248487308, // $ 248.487.308,00
  executionPhaseValue: 13083072727, // $ 13.083.072.727,00 (calculado como total - preliminar)
};

// Historial de actas de cobro extraído de las tablas
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
  return '';
}

// Actas de cobro extraídas de la tabla
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
  let created = 0;
  let updated = 0;

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
      const existing = await prisma.costActa.findUnique({
        where: { number: number },
      });

      const data = {
        number: number,
        period: period || actaData.month,
        submissionDate: submissionDate,
        approvalDate: submissionDate, // Asumiendo que fueron aprobadas el mismo día
        paymentDueDate: null, // No especificado
        billedAmount: billedAmount,
        totalContractValue: CONTRACT_VALUES.totalContractValue,
        status: 'APPROVED', // Asumiendo que todas están aprobadas
        relatedProgress: actaData.description,
      };

      if (existing) {
        await prisma.costActa.update({
          where: { number: number },
          data,
        });
        updated++;
        console.log(`✓ Actualizada: ${number} - ${actaData.description}`);
      } else {
        await prisma.costActa.create({
          data,
        });
        created++;
        console.log(`✓ Creada: ${number} - ${actaData.description} - ${billedAmount.toLocaleString('es-CO', { style: 'currency', currency: 'COP', minimumFractionDigits: 0 })}`);
      }
    } catch (error) {
      console.error(`✗ Error procesando acta ${number}:`, error.message);
    }
  }

  console.log(`\n✅ Proceso completado: ${created} creadas, ${updated} actualizadas`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });


