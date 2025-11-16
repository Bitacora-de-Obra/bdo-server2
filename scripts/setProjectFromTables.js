/* eslint-disable no-console */
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// Datos tomados de las Tablas compartidas (obra e interventoría)
const DATA = {
  obraContractId: 'IDU-2412-2024',
  interventoriaContractId: 'IDU-2428-2024',
  contractorName: 'CONSORCIO CELESTINO MUTIS IJK (NIT 901.899.854-1)',
  supervisorName: 'CONSORCIO DQ (NIT 901.901.415-8)',
  startDateText: '31/01/2025',
  endDateText: '30/11/2025',
  object:
    'Construcción del empalme de la Avenida José Celestino Mutis (AC 63) desde la Transversal 112B Bis A hasta la Carrera 112 y demás obras complementarias requeridas para la armonización de la AV. José Celestino Mutis en la Ciudad de Bogotá, D.C.',
  contratante: 'INSTITUTO DE DESARROLLO URBANO',
  // Valores monetarios (COP) tomados de las tablas
  obraTotalValueCOP: 13331560035,          // $ 13.331.560.035,00
  obraPreliminarValueCOP: 248487308,       // $ 248.487.308,00
  obraEjecucionValueCOP: 13083072727,      // $ 13.083.072.727,00
  interventoriaTotalValueCOP: 2666312007,  // $ 2.666.312.007,00
};

function parseDate(dmy) {
  // dd/mm/yyyy
  const m = dmy.match(/(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})/);
  if (!m) return null;
  const d = parseInt(m[1], 10);
  const mo = parseInt(m[2], 10) - 1;
  const y = parseInt(m[3], 10);
  return new Date(Date.UTC(y, mo, d, 0, 0, 0));
}

async function main() {
  const project = await prisma.project.findFirst();
  if (!project) {
    console.error('No project found.');
    process.exit(1);
  }
  const updated = await prisma.project.update({
    where: { id: project.id },
    data: {
      contractId: DATA.obraContractId,
      object: DATA.object,
      contractorName: DATA.contractorName,
      supervisorName: DATA.supervisorName,
      startDate: parseDate(DATA.startDateText) || project.startDate,
      initialEndDate: parseDate(DATA.endDateText) || project.initialEndDate,
      initialValue: DATA.obraTotalValueCOP,
      interventoriaInitialValue: DATA.interventoriaTotalValueCOP,
    },
  });
  console.log('Project updated from tables:', {
    contractId: updated.contractId,
    contractorName: updated.contractorName,
    supervisorName: updated.supervisorName,
    startDate: updated.startDate,
    initialEndDate: updated.initialEndDate,
  });
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });


