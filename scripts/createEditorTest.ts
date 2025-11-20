import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function createEditorTest() {
  try {
    const email = 'editor.prueba@test.com';
    const password = 'Editor123!';
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

    const editor = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        fullName: 'Editor de Prueba',
        projectRole: 'CONTRACTOR_REP',
        appRole: 'editor',
        entity: 'CONTRATISTA',
        cargo: 'Residente de Costos de Obra',
        status: 'active',
        canDownload: true,
        emailVerifiedAt: new Date(),
        tenantId: tenant.id,
      },
    });
    
    console.log('\n✅ Usuario editor de prueba creado exitosamente:');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(`📧 Email: ${email}`);
    console.log(`🔑 Contraseña: ${password}`);
    console.log(`👤 Nombre: ${editor.fullName}`);
    console.log(`🏢 Entidad: ${editor.entity}`);
    console.log(`📋 Rol de Proyecto: ${editor.projectRole}`);
    console.log(`🔐 Rol de Aplicación: ${editor.appRole}`);
    console.log(`💼 Cargo: ${editor.cargo}`);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    console.log('ℹ️  Este usuario tiene las mismas condiciones que Iván:');
    console.log('   - Rol de aplicación: editor (puede comentar siempre)');
    console.log('   - Rol de proyecto: CONTRACTOR_REP');
    console.log('   - Entidad: CONTRATISTA');
    console.log('   - Puede ser asignado para revisar y firmar bitácoras\n');
  } catch (error) {
    console.error('❌ Error creando usuario editor:', error);
  } finally {
    await prisma.$disconnect();
  }
}

createEditorTest();



