/* eslint-disable no-console */
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

async function main() {
  const email = 'admin@admin.com';
  const password = 'admin123';
  const hashedPassword = await bcrypt.hash(password, 10);

  // Verificar si el usuario ya existe
  const existingUser = await prisma.user.findUnique({
    where: { email },
  });

  if (existingUser) {
    // Actualizar el usuario existente
    const updated = await prisma.user.update({
      where: { email },
      data: {
        password: hashedPassword,
        fullName: 'Administrador',
        projectRole: 'ADMIN',
        appRole: 'admin',
        status: 'active',
      },
    });
    console.log('Usuario admin actualizado:', updated.email);
  } else {
    // Crear nuevo usuario
    const created = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        fullName: 'Administrador',
        projectRole: 'ADMIN',
        appRole: 'admin',
        status: 'active',
      },
    });
    console.log('Usuario admin creado:', created.email);
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



