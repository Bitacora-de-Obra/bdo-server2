const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

async function createTestUsers() {
  try {
    console.log('Creating test users...');
    
    // Hash de contraseña simple para testing
    const hashedPassword = await bcrypt.hash('Test123!', 10);
    
    // Usuario administrador
    const admin = await prisma.user.upsert({
      where: { email: 'admin@bdigitales.com' },
      update: {
        password: hashedPassword,
        status: 'active',
        emailVerifiedAt: new Date(),
      },
      create: {
        email: 'admin@bdigitales.com',
        password: hashedPassword,
        fullName: 'Administrador Test',
        projectRole: 'ADMIN',
        appRole: 'admin',
        entity: 'IDU',
        cargo: 'Administrador',
        status: 'active',
        emailVerifiedAt: new Date(),
      }
    });

    // Usuario supervisor
    const supervisor = await prisma.user.upsert({
      where: { email: 'supervisor@bdigitales.com' },
      update: {
        password: hashedPassword,
        status: 'active',
        emailVerifiedAt: new Date(),
      },
      create: {
        email: 'supervisor@bdigitales.com',
        password: hashedPassword,
        fullName: 'Supervisor Test',
        projectRole: 'SUPERVISOR',
        appRole: 'editor',
        entity: 'Interventoría',
        cargo: 'Supervisor',
        status: 'active',
        emailVerifiedAt: new Date(),
      }
    });

    // Usuario contratista
    const contractor = await prisma.user.upsert({
      where: { email: 'contratista@bdigitales.com' },
      update: {
        password: hashedPassword,
        status: 'active',
        emailVerifiedAt: new Date(),
      },
      create: {
        email: 'contratista@bdigitales.com',
        password: hashedPassword,
        fullName: 'Contratista Test',
        projectRole: 'CONTRACTOR_REP',
        appRole: 'viewer',
        entity: 'Contratista',
        cargo: 'Representante',
        status: 'active',
        emailVerifiedAt: new Date(),
      }
    });

    console.log('Test users created successfully:');
    console.log('- Admin:', admin.email);
    console.log('- Supervisor:', supervisor.email);
    console.log('- Contractor:', contractor.email);
    console.log('Password for all users: Test123!');
    
  } catch (error) {
    console.error('Error creating test users:', error);
  } finally {
    await prisma.$disconnect();
  }
}

createTestUsers();
