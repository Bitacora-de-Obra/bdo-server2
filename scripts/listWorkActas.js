/* eslint-disable no-console */
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function main() {
  const workActas = await prisma.workActa.findMany({
    orderBy: { date: 'desc' },
    select: {
      number: true,
      description: true,
      period: true,
      date: true,
      grossValue: true,
    },
  });

  console.log(`\nTotal de actas de avance encontradas: ${workActas.length}\n`);
  console.log('Actas actuales:');
  console.log('─'.repeat(100));
  
  workActas.forEach((acta, index) => {
    const dateStr = acta.date instanceof Date 
      ? acta.date.toLocaleDateString('es-CO')
      : new Date(acta.date).toLocaleDateString('es-CO');
    const valueStr = acta.grossValue 
      ? acta.grossValue.toLocaleString('es-CO', { style: 'currency', currency: 'COP', minimumFractionDigits: 0 })
      : '$ 0';
    
    console.log(`${index + 1}. ${acta.number.padEnd(15)} | ${(acta.description || '-').substring(0, 60).padEnd(60)} | ${dateStr} | ${valueStr}`);
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


