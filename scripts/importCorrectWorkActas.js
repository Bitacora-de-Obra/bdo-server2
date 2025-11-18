/* eslint-disable no-console */
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

function parseValue(valueStr) {
  if (!valueStr || valueStr === 'NA' || valueStr === '-') return null;
  const cleaned = valueStr.replace(/[$.\s]/g, '').replace(',', '.');
  return parseFloat(cleaned) || null;
}

function parseDate(dateStr) {
  if (!dateStr) return null;
  
  // Si es un nombre de mes
  if (dateStr.includes('febrero')) return new Date(Date.UTC(2025, 1, 15, 0, 0, 0));
  if (dateStr.includes('marzo')) return new Date(Date.UTC(2025, 2, 15, 0, 0, 0));
  if (dateStr.includes('abril')) return new Date(Date.UTC(2025, 3, 15, 0, 0, 0));
  if (dateStr.includes('mayo')) return new Date(Date.UTC(2025, 4, 15, 0, 0, 0));
  if (dateStr.includes('junio')) return new Date(Date.UTC(2025, 5, 15, 0, 0, 0));
  
  // Formato: DD/MM/YYYY
  const parts = dateStr.split(/[\/\-]/);
  if (parts.length === 3) {
    const day = parseInt(parts[0], 10);
    const month = parseInt(parts[1], 10) - 1;
    const year = parseInt(parts[2], 10);
    return new Date(Date.UTC(year, month, day, 0, 0, 0));
  }
  return null;
}

function extractPeriod(dateStr) {
  if (!dateStr) return '';
  
  if (dateStr.includes('febrero')) {
    const monthNames = ['enero', 'febrero', 'marzo', 'abril', 'mayo', 'junio'];
    return 'Febrero 2025';
  }
  if (dateStr.includes('marzo')) return 'Marzo 2025';
  if (dateStr.includes('abril')) return 'Abril 2025';
  if (dateStr.includes('mayo')) return 'Mayo 2025';
  if (dateStr.includes('junio')) return 'Junio 2025';
  
  return '';
}

// Las 8 actas de avance correspondientes a las 8 actas de cobro
const WORK_ACTAS = [
  {
    numero: '8',
    objeto: 'Acta parcial contrato obra fase preliminar - febrero',
    fecha: 'febrero',
    valor: '$ 91.269.015,00',
  },
  {
    numero: '10',
    objeto: 'Acta parcial contrato obra fase preliminar - marzo',
    fecha: 'marzo',
    valor: '$ 91.269.015,00',
  },
  {
    numero: '18',
    objeto: 'Acta parcial contrato obra fase de ejecución costo fijo - abril',
    fecha: 'abril',
    valor: '$ 130.810.655,00',
  },
  {
    numero: '19',
    objeto: 'Acta parcial contrato obra fase de ejecución costo variable - abril',
    fecha: 'abril',
    valor: '$ 736.725,00',
  },
  {
    numero: '14',
    objeto: 'Acta parcial contrato obra fase de ejecución costo fijo - mayo',
    fecha: 'mayo',
    valor: '$ 130.810.655,00',
  },
  {
    numero: '15',
    objeto: 'Acta parcial contrato obra fase de ejecución costo variable - mayo',
    fecha: 'mayo',
    valor: '$ 552.544,00',
  },
  {
    numero: '20',
    objeto: 'Acta parcial contrato obra saldo fase preliminar',
    fecha: 'marzo',
    valor: '$ 182.538.028,00',
  },
  {
    numero: '23',
    objeto: 'Acta parcial contrato obra fase de ejecución costo variable - junio',
    fecha: 'junio',
    valor: '$ 33.521.015,00',
  },
];

async function main() {
  let created = 0;
  let updated = 0;

  for (const acta of WORK_ACTAS) {
    const numero = `ACTA-${acta.numero.padStart(3, '0')}`;
    const fecha = parseDate(acta.fecha);
    const valor = parseValue(acta.valor);
    const periodo = extractPeriod(acta.fecha);

    if (!fecha) {
      console.warn(`⚠️  No se pudo parsear la fecha para acta ${numero}: ${acta.fecha}`);
      continue;
    }

    try {
      const existing = await prisma.workActa.findUnique({
        where: { number: numero },
      });

      const data = {
        number: numero,
        period: periodo || `Período ${acta.fecha}`,
        date: fecha,
        status: 'APPROVED',
        grossValue: valor,
        description: acta.objeto,
      };

      if (existing) {
        await prisma.workActa.update({
          where: { number: numero },
          data,
        });
        updated++;
        console.log(`✓ Actualizada: ${numero} - ${acta.objeto}`);
      } else {
        await prisma.workActa.create({
          data,
        });
        created++;
        console.log(`✓ Creada: ${numero} - ${acta.objeto}`);
      }
    } catch (error) {
      console.error(`✗ Error procesando acta ${numero}:`, error.message);
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



