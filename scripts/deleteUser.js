/* eslint-disable no-console */
// Delete a user by email
// Usage: node scripts/deleteUser.js <email>

const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function deleteUser(email) {
  try {
    if (!email) {
      console.error('❌ Por favor proporciona un email: node scripts/deleteUser.js <email>');
      process.exit(1);
    }

    console.log(`🔍 Buscando usuario con email: ${email}...\n`);

    const user = await prisma.user.findUnique({
      where: { email: email.toLowerCase().trim() },
    });

    if (!user) {
      console.error(`❌ No se encontró usuario con email: ${email}`);
      process.exit(1);
    }

    console.log(`📋 Usuario encontrado:`);
    console.log(`   Nombre: ${user.fullName}`);
    console.log(`   Email: ${user.email}`);
    console.log(`   Entidad: ${user.entity || 'N/A'}`);
    console.log(`   Cargo: ${user.cargo || 'N/A'}`);
    console.log(`   Rol de Proyecto: ${user.projectRole}`);
    console.log(`   Rol de Aplicación: ${user.appRole}\n`);

    await prisma.user.delete({
      where: { email: email.toLowerCase().trim() },
    });

    console.log(`✅ Usuario eliminado exitosamente: ${user.fullName} (${user.email})`);
  } catch (error) {
    console.error('❌ Error al eliminar usuario:', error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

const email = process.argv[2];
deleteUser(email).catch((error) => {
  console.error(error);
  process.exit(1);
});



