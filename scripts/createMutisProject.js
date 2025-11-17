// Create or update the Mutis project with all correct data
// Usage: node scripts/createMutisProject.js

/* eslint-disable no-console */
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// Datos completos del Proyecto Mutis
const MUTIS_PROJECT = {
  name: 'Proyecto Mutis',
  contractId: 'IDU-2412-2024',
  interventoriaContractId: 'IDU-2428-2024',
  contractorName: 'CONSORCIO CELESTINO MUTIS IJK (NIT 901.899.854-1)',
  supervisorName: 'CONSORCIO DQ (NIT 901.901.415-8)',
  object: 'Construcción del empalme de la Avenida José Celestino Mutis (AC 63) desde la Transversal 112B Bis A hasta la Carrera 112 y demás obras complementarias requeridas para la armonización de la AV. José Celestino Mutis en la Ciudad de Bogotá, D.C.',
  contratante: 'INSTITUTO DE DESARROLLO URBANO',
  startDate: new Date('2025-01-31T00:00:00.000Z'), // 31/01/2025
  initialEndDate: new Date('2025-11-30T00:00:00.000Z'), // 30/11/2025
  initialValue: 13331560035, // $ 13.331.560.035,00
  interventoriaInitialValue: 2666312007, // $ 2.666.312.007,00
  technicalSupervisorName: 'CONSORCIO DQ',
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

async function createMutisProject() {
  try {
    console.log('📋 Creando/actualizando Proyecto Mutis...\n');

    // Buscar proyecto existente
    const existing = await prisma.project.findFirst();

    if (existing) {
      // Actualizar proyecto existente
      const updated = await prisma.project.update({
        where: { id: existing.id },
        data: {
          name: MUTIS_PROJECT.name,
          contractId: MUTIS_PROJECT.contractId,
          interventoriaContractId: MUTIS_PROJECT.interventoriaContractId,
          object: MUTIS_PROJECT.object,
          contractorName: MUTIS_PROJECT.contractorName,
          supervisorName: MUTIS_PROJECT.supervisorName,
          technicalSupervisorName: MUTIS_PROJECT.technicalSupervisorName,
          startDate: MUTIS_PROJECT.startDate,
          initialEndDate: MUTIS_PROJECT.initialEndDate,
          initialValue: MUTIS_PROJECT.initialValue,
          interventoriaInitialValue: MUTIS_PROJECT.interventoriaInitialValue,
        },
      });
      console.log('✅ Proyecto Mutis actualizado:', {
        id: updated.id,
        name: updated.name,
        contractId: updated.contractId,
        contractorName: updated.contractorName,
        supervisorName: updated.supervisorName,
        startDate: updated.startDate,
        initialEndDate: updated.initialEndDate,
        initialValue: updated.initialValue,
        interventoriaInitialValue: updated.interventoriaInitialValue,
      });
    } else {
      // Crear nuevo proyecto
      const created = await prisma.project.create({
        data: {
          name: MUTIS_PROJECT.name,
          contractId: MUTIS_PROJECT.contractId,
          interventoriaContractId: MUTIS_PROJECT.interventoriaContractId,
          object: MUTIS_PROJECT.object,
          contractorName: MUTIS_PROJECT.contractorName,
          supervisorName: MUTIS_PROJECT.supervisorName,
          technicalSupervisorName: MUTIS_PROJECT.technicalSupervisorName,
          startDate: MUTIS_PROJECT.startDate,
          initialEndDate: MUTIS_PROJECT.initialEndDate,
          initialValue: MUTIS_PROJECT.initialValue,
          interventoriaInitialValue: MUTIS_PROJECT.interventoriaInitialValue,
        },
      });
      console.log('✅ Proyecto Mutis creado:', {
        id: created.id,
        name: created.name,
        contractId: created.contractId,
        contractorName: created.contractorName,
        supervisorName: created.supervisorName,
        startDate: created.startDate,
        initialEndDate: created.initialEndDate,
        initialValue: created.initialValue,
        interventoriaInitialValue: created.interventoriaInitialValue,
      });
    }
  } catch (error) {
    console.error('❌ Error al crear/actualizar proyecto:', error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

createMutisProject();


