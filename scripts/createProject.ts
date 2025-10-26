import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function createProject() {
  try {
    const project = await prisma.project.create({
      data: {
        name: "Test Project",
        contractId: "TEST-001",
        object: "Test Object",
        contractorName: "Test Contractor",
        supervisorName: "Test Supervisor",
        initialValue: 1000000,
        startDate: new Date("2025-10-25T00:00:00.000Z"),
        initialEndDate: new Date("2026-10-25T00:00:00.000Z"),
        interventoriaContractId: "TEST-INT-001",
        interventoriaInitialValue: 100000,
        technicalSupervisorName: "Test Technical Supervisor"
      }
    });
    console.log('Project created:', project);
  } catch (error) {
    console.error('Error creating project:', error);
  } finally {
    await prisma.$disconnect();
  }
}

createProject();

