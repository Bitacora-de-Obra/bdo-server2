/* eslint-disable no-console */
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// Objeto del contrato recibido
const CONTRACT_OBJECT = 'CONSTRUCCIÓN DEL EMPALME DE LA AVENIDA JOSÉ CELESTINO MUTIS (AC 63) DESDE LA TRANSVERSAL 112B BIS A HASTA LA CARRERA 112 Y DEMÁS OBRA COMPLEMENTARIAS REQUERIDAS PARA LA ARMONIZACIÓN DE LA AV JOSE CELESTINO MUTIS EN LA CIUDAD DE BOGOTÁ, D.C.';

async function main() {
  const existing = await prisma.project.findFirst();
  if (existing) {
    const updated = await prisma.project.update({
      where: { id: existing.id },
      data: { object: CONTRACT_OBJECT },
    });
    console.log(`Updated project ${updated.id} object.`);
  } else {
    const now = new Date();
    const created = await prisma.project.create({
      data: {
        name: 'Proyecto Mutis',
        contractId: 'IDU-EMP-MUTIS-001',
        object: CONTRACT_OBJECT,
        contractorName: 'Contratista',
        supervisorName: 'Interventoría',
        initialValue: 0,
        startDate: now,
        initialEndDate: now,
        interventoriaContractId: 'IDU-INT-MUTIS-001',
        interventoriaInitialValue: 0,
        technicalSupervisorName: 'Supervisor Técnico',
      },
    });
    console.log(`Created project ${created.id} with object.`);
  }
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });




