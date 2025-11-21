import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function createContractorTest() {
  try {
    const email = 'contratista.prueba@test.com';
    const password = 'Contratista123!';
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Obtener el primer tenant disponible o crear uno de prueba
    let tenant = await prisma.tenant.findFirst();
    
    if (!tenant) {
      console.log('No se encontró ningún tenant. Creando uno de prueba...');
      tenant = await prisma.tenant.create({
        data: {
          name: 'Tenant de Prueba',
          slug: 'tenant-prueba',
        },
      });
    }
    
    // Verificar si el usuario ya existe
    const existingUser = await prisma.user.findFirst({
      where: { 
        email,
        tenantId: tenant.id,
      },
    });

    if (existingUser) {
      console.log('El usuario ya existe. Eliminando...');
      await prisma.user.delete({
        where: { id: existingUser.id },
      });
    }

    const contractor = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        fullName: 'Contratista de Prueba',
        projectRole: 'CONTRACTOR_REP',
        appRole: 'viewer',
        entity: 'CONTRATISTA',
        cargo: 'Contratista de Prueba',
        status: 'active',
        canDownload: true,
        emailVerifiedAt: new Date(),
        tenantId: tenant.id,
      },
    });
    
    console.log('\n✅ Usuario contratista de prueba creado exitosamente:');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(`📧 Email: ${email}`);
    console.log(`🔑 Contraseña: ${password}`);
    console.log(`👤 Nombre: ${contractor.fullName}`);
    console.log(`🏢 Entidad: ${contractor.entity}`);
    console.log(`📋 Rol de Proyecto: ${contractor.projectRole}`);
    console.log(`🔐 Rol de Aplicación: ${contractor.appRole}`);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  } catch (error) {
    console.error('❌ Error creando usuario contratista:', error);
  } finally {
    await prisma.$disconnect();
  }
}

createContractorTest();

