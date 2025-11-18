/* eslint-disable no-console */
const fs = require('fs');
const path = require('path');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

function readExtract() {
  const p = path.join(__dirname, '..', 'uploads', 'extracted-project.json');
  if (!fs.existsSync(p)) {
    throw new Error(`extracted-project.json not found at ${p}`);
  }
  const raw = fs.readFileSync(p, 'utf8');
  return JSON.parse(raw);
}

function parseDateMaybe(s) {
  if (!s) return null;
  const m = s.match(/(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{2,4})/);
  if (!m) return null;
  const d = parseInt(m[1], 10);
  const mo = parseInt(m[2], 10) - 1;
  let y = parseInt(m[3], 10);
  if (y < 100) y += 2000;
  const dt = new Date(Date.UTC(y, mo, d, 0, 0, 0));
  return dt;
}

async function main() {
  const ex = readExtract();
  const project = await prisma.project.findFirst();
  if (!project) {
    console.error('No project found. Create one first.');
    process.exit(1);
  }

  const contractId =
    ex.obraContractId && ex.obraContractId.length > 3 && ex.obraContractId !== 'Y'
      ? ex.obraContractId
      : (ex.anyContractId || project.contractId);

  const data = {
    object: ex.object || project.object,
    contractId,
    contractorName: ex.contractorName || project.contractorName,
    supervisorName: ex.interventoriaName || project.supervisorName,
  };

  const startDate = parseDateMaybe(ex.startDate);
  const endDate = parseDateMaybe(ex.endDate);
  if (startDate) data.startDate = startDate;
  if (endDate) data.initialEndDate = endDate;

  const updated = await prisma.project.update({
    where: { id: project.id },
    data,
  });

  console.log('Project updated:', {
    id: updated.id,
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




