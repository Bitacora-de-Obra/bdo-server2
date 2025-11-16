/* eslint-disable no-console */
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// Historial de actas extraído de las tablas compartidas
// Nota: Los valores están en formato colombiano ($ 3.796.432.563,00)
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
  
  // Formato: DD/MM/YYYY o DD-MM-YYYY
  const parts = datePart.split(/[\/\-]/);
  if (parts.length === 3) {
    const day = parseInt(parts[0], 10);
    const month = parseInt(parts[1], 10) - 1; // Mes es 0-indexed
    const year = parseInt(parts[2], 10);
    return new Date(Date.UTC(year, month, day, 0, 0, 0));
  }
  return null;
}

function extractPeriod(dateStr) {
  if (!dateStr) return '';
  // Si tiene rango, extraer el período
  if (dateStr.includes(' al ')) {
    const parts = dateStr.split(' al ');
    if (parts.length === 2) {
      const start = parseDate(parts[0]);
      if (start) {
        const monthNames = ['enero', 'febrero', 'marzo', 'abril', 'mayo', 'junio', 
                          'julio', 'agosto', 'septiembre', 'octubre', 'noviembre', 'diciembre'];
        return `${monthNames[start.getUTCMonth()]} ${start.getUTCFullYear()}`;
      }
    }
  }
  // Si es una fecha única, extraer mes y año
  const date = parseDate(dateStr);
  if (date) {
    const monthNames = ['enero', 'febrero', 'marzo', 'abril', 'mayo', 'junio', 
                      'julio', 'agosto', 'septiembre', 'octubre', 'noviembre', 'diciembre'];
    return `${monthNames[date.getUTCMonth()]} ${date.getUTCFullYear()}`;
  }
  return '';
}

// Actas de obra e interventoría (mezcladas)
const ACTAS_HISTORY = [
  { numero: '1', objeto: 'Acta de inicio', fecha: '31/01/2025', valor: 'NA' },
  { numero: '2', objeto: 'Acta de anticipo', fecha: '27/02/2025', valor: '$ 3.796.432.563,00' },
  { numero: '3', objeto: 'Acta cambio de etapa', fecha: '10/04/2025', valor: 'NA' },
  { numero: '4', objeto: 'Acta parcial de obra No. 1', fecha: '28/02/2025', valor: '$ 1.598.898.636,00' },
  { numero: '5', objeto: 'Acta de competencia VANTI', fecha: '09/04/2025', valor: '$ 154.295,00' },
  { numero: '6', objeto: 'Acta de competencia COLOMBIA TELECOMUNICACIONES S.A. ES', fecha: '31/03/2025', valor: '$ 152.295,00' },
  { numero: '7', objeto: 'Acta parcial de obra No. 2', fecha: '9/04/2025', valor: '$ 1.680.518.700,00' },
  { numero: '8', objeto: 'Acta parcial 1 etapa preliminar interventoría', fecha: '31/01/2025 al 28/02/2025', valor: '$ 182.538.028,00' },
  { numero: '9', objeto: 'Acta de competencia ETB', fecha: '02/07/2025', valor: '$ 154.295,00' },
  { numero: '10', objeto: 'Acta parcial 2 etapa preliminar interventoría', fecha: '01/03/2025 al 31/03/2025', valor: '$ 182.538.028,00' },
  { numero: '11', objeto: 'Acta parcial 3 contrato obra Acta 1 ejecución', fecha: '01/04/2025 al 30/04/2025', valor: '$ 2.081.948.496,00' },
  { numero: '12', objeto: 'Acta de ajustes acta parcial 3', fecha: '22/08/2025', valor: '$ 9.597.930,00' },
  { numero: '13', objeto: 'Acta parcial 4 contrato obra Acta 2 ejecución', fecha: '01/05/2025 al 31/05/2025', valor: '$ 2.081.948.496,00' },
  { numero: '14', objeto: 'Acta de ajustes acta parcial 4', fecha: '22/08/2025', valor: '$ 154.295,00' },
  { numero: '15', objeto: 'Acta parcial 5 contrato obra Acta 3 ejecución', fecha: '01/06/2025 al 30/06/2025', valor: '$ 2.081.948.496,00' },
  { numero: '16', objeto: 'Acta parcial 3 contrato interventoría Acta 1 ejecución costos fijos', fecha: '01/05/2025 al 31/05/2025', valor: '$ 130.810.655,00' },
  { numero: '17', objeto: 'Acta parcial 4 contrato interventoría Acta 1 ejecución costos variables', fecha: '01/05/2025 al 31/05/2025', valor: '$ 552.544,00' },
  { numero: '18', objeto: 'Acta de ajustes No. 3 correspondiente al acta de RPO 5', fecha: '22/08/2025', valor: '$ 9.597.930,00' },
  { numero: '19', objeto: 'Acta de ajustes No.4 correspondiente al Acta 4 ejecución', fecha: '22/08/2025', valor: '$ 2.113.520,00' },
  { numero: '20', objeto: 'Acta parcial 5 contrato interventoría Acta 2 ejecución costos fijos', fecha: '01/04/2025 al 30/04/2025', valor: '$ 130.810.655,00' },
  { numero: '21', objeto: 'Acta parcial 6 contrato interventoría Acta 2 ejecución costos variables', fecha: '01/04/2025 al 30/04/2025', valor: '$ 736.725,00' },
  { numero: '22', objeto: 'Acta parcial 7 contrato interventoría Acta 2 etapa preliminar', fecha: '01/02/2025 al 31/03/2025', valor: '$ 182.538.028,00' },
  { numero: '23', objeto: 'Acta parcial 6 contrato obra Acta 4 ejecución', fecha: '01/07/2025 al 31/07/2025', valor: '$ 110.578.255,00' },
  { numero: '24', objeto: 'Acta parcial 7 contrato obra Acta 5 ejecución', fecha: '1-08-2025 al 31-08-2025', valor: '$ 131.163.315,00' },
  { numero: '25', objeto: 'Acta parcial 8 contrato interventoría Acta 3 ejecución costos variables', fecha: '01/06/2025 al 30/06/2025', valor: '$ 33.521.015,00' },
];

async function main() {
  // Limpiar actas existentes (opcional - comentar si no quieres borrar las existentes)
  // await prisma.workActa.deleteMany({});

  let created = 0;
  let updated = 0;

  for (const acta of ACTAS_HISTORY) {
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
        status: 'APPROVED', // Asumiendo que todas están aprobadas
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

