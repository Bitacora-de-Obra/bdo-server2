/* eslint-disable no-console */
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function main() {
  const costActas = await prisma.costActa.findMany({
    orderBy: { submissionDate: 'desc' },
    select: {
      number: true,
      period: true,
      submissionDate: true,
      billedAmount: true,
      relatedProgress: true,
    },
  });

  console.log(`\nTotal de actas de cobro encontradas: ${costActas.length}\n`);
  console.log('Actas de cobro actuales:');
  console.log('─'.repeat(100));
  
  costActas.forEach((acta, index) => {
    const dateStr = acta.submissionDate instanceof Date 
      ? acta.submissionDate.toLocaleDateString('es-CO')
      : new Date(acta.submissionDate).toLocaleDateString('es-CO');
    const valueStr = acta.billedAmount 
      ? acta.billedAmount.toLocaleString('es-CO', { style: 'currency', currency: 'COP', minimumFractionDigits: 0 })
      : '$ 0';
    
    console.log(`${index + 1}. ${acta.number.padEnd(15)} | ${(acta.relatedProgress || acta.period || '-').substring(0, 70).padEnd(70)} | ${dateStr} | ${valueStr}`);
  });
  
  console.log('─'.repeat(100));
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });



