// bdo-server-develop/prisma/seed.ts
import { PrismaClient, UserRole, AppRole } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  console.log(`Start seeding ...`);

  // 1. Crear el Proyecto de Prueba
  await prisma.project.upsert({
    where: { id: 'proj-1' },
    update: {},
    create: {
      id: 'proj-1',
      name: 'Ampliación Av. Ciudad de Cali - Tramo 1',
      contractId: 'IDU-LP-SGI-001-2023',
    },
  });
  console.log(`Seeded Project.`);

  // 2. Hashear la contraseña común
  const hashedPassword = await bcrypt.hash('password123', 10);

  // 3. Crear los Usuarios de Prueba
  const users = [
    // ... (copiamos los usuarios de MOCK_USERS del frontend)
    { id: 'user-1', fullName: 'Ana García (Residente)', projectRole: UserRole.RESIDENT, appRole: AppRole.editor, avatarUrl: 'https://randomuser.me/api/portraits/women/68.jpg', email: 'ana.garcia@constructora.com', status: 'active' },
    { id: 'user-2', fullName: 'Carlos Rodriguez (Supervisor)', projectRole: UserRole.SUPERVISOR, appRole: AppRole.editor, avatarUrl: 'https://randomuser.me/api/portraits/men/68.jpg', email: 'carlos.rodriguez@supervision.com', status: 'active' },
    { id: 'user-3', fullName: 'Laura Martinez (Contratista)', projectRole: UserRole.CONTRACTOR_REP, appRole: AppRole.viewer, avatarUrl: 'https://randomuser.me/api/portraits/women/69.jpg', email: 'laura.martinez@constructora.com', status: 'active' },
    { id: 'user-4', fullName: 'Jorge Hernandez (Admin)', projectRole: UserRole.ADMIN, appRole: AppRole.admin, avatarUrl: 'https://randomuser.me/api/portraits/men/69.jpg', email: 'jorge.hernandez@idu.gov.co', status: 'active' },
    { id: 'user-5', fullName: 'Victor Viewer', projectRole: UserRole.RESIDENT, appRole: AppRole.viewer, avatarUrl: 'https://randomuser.me/api/portraits/men/70.jpg', email: 'victor.viewer@constructora.com', status: 'inactive' },
  ];

  for (const u of users) {
    await prisma.user.upsert({
      where: { email: u.email },
      update: {},
      create: {
        ...u,
        password: hashedPassword,
      },
    });
  }
  console.log(`Seeded ${users.length} Users.`);

  console.log('Seeding Contract Items...');
  const contractItems = [
    { id: "item-1", itemCode: "1.008", description: "BASE GRANULAR CLASE B (BG_B) (Suministro, Extendido, Nivelación, Humedecimiento y Compactación con vibrocompactador)", unit: "M3", unitPrice: 182059, contractQuantity: 1148.62 },
    { id: "item-2", itemCode: "2.001", description: "REPLANTEO GENERAL", unit: "M2", unitPrice: 766, contractQuantity: 21133.3 },
    { id: "item-3", itemCode: "2.003", description: "EXCAVACIÓN MECÁNICA EN MATERIAL COMÚN (Incluye Cargue)", unit: "M3", unitPrice: 6093, contractQuantity: 5212.41 },
    { id: "item-4", itemCode: "2.004", description: "EXCAVACIÓN MANUAL EN MATERIAL COMÚN. Incluye cargue.", unit: "M3", unitPrice: 35342, contractQuantity: 135.59 },
    { id: "item-5", itemCode: "2.005", description: "TRANSPORTE Y DISPOSICIÓN FINAL DE ESCOMBROS EN SITIO AUTORIZADO", unit: "M3", unitPrice: 42354, contractQuantity: 10234.01 },
    { id: "item-6", itemCode: "2.010", description: "TRATAMIENTO SUPERFICIAL DOBLE.", unit: "M2", unitPrice: 85227, contractQuantity: 7367.05 },
  ];

  for (const item of contractItems) {
    await prisma.contractItem.upsert({
      where: { itemCode: item.itemCode },
      update: {},
      create: item,
    });
  }
  console.log(`Seeded ${contractItems.length} Contract Items.`);

  console.log(`Seeding finished.`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });