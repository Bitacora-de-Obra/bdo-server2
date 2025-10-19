// bdo-server/prisma/seed.ts
import { PrismaClient, UserRole, AppRole } from '@prisma/client'; // Quitamos ProjectTask de aquí si no lo usamos directamente
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

// Definimos un tipo para las tareas mock (basado en MOCK_PROJECT_TASKS del frontend)
type MockTask = {
  id: string; // Este será usado como taskId
  name: string;
  startDate: string; // Dejamos como string aquí, convertiremos luego
  endDate: string;   // Dejamos como string aquí, convertiremos luego
  progress: number;
  duration: number;
  isSummary: boolean;
  outlineLevel: number;
  dependencies?: string[]; // Opcional, aunque no lo usaremos en el seed
};


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
    { id: 'user-1', fullName: 'Ana García (Residente)', projectRole: UserRole.RESIDENT, appRole: AppRole.editor, avatarUrl: 'https://randomuser.me/api/portraits/women/68.jpg', email: 'ana.garcia@constructora.com', status: 'active' },
    // Asegúrate que el email sea EXACTAMENTE este:
    { id: 'user-2', fullName: 'Carlos Rodriguez (Supervisor)', projectRole: UserRole.SUPERVISOR, appRole: AppRole.editor, avatarUrl: 'https://randomuser.me/api/portraits/men/68.jpg', email: 'carlos.rodriguez@supervision.com', status: 'active' },
    { id: 'user-3', fullName: 'Laura Martinez (Contratista)', projectRole: UserRole.CONTRACTOR_REP, appRole: AppRole.viewer, avatarUrl: 'https://randomuser.me/api/portraits/women/69.jpg', email: 'laura.martinez@constructora.com', status: 'active' },
    { id: 'user-4', fullName: 'Jorge Hernandez (Admin)', projectRole: UserRole.ADMIN, appRole: AppRole.admin, avatarUrl: 'https://randomuser.me/api/portraits/men/69.jpg', email: 'jorge.hernandez@idu.gov.co', status: 'active' },
    { id: 'user-5', fullName: 'Victor Viewer', projectRole: UserRole.RESIDENT, appRole: AppRole.viewer, avatarUrl: 'https://randomuser.me/api/portraits/men/70.jpg', email: 'victor.viewer@constructora.com', status: 'inactive' },
  ];

  for (const u of users) {
    await prisma.user.upsert({
      where: { email: u.email },
      update: {
          // Puedes añadir campos para actualizar si ya existe, si no, déjalo vacío
          // Por ejemplo, asegurar que la contraseña y rol estén actualizados:
          password: hashedPassword,
          projectRole: u.projectRole,
          appRole: u.appRole,
          status: u.status,
          avatarUrl: u.avatarUrl,
          fullName: u.fullName
      },
      create: {
        ...u,
        password: hashedPassword,
      },
    });
  }
  console.log(`Seeded ${users.length} Users.`);

  // 4. Crear Contract Items
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
      update: {}, // Puedes añadir campos para actualizar si ya existe
      create: item,
    });
  }
  console.log(`Seeded ${contractItems.length} Contract Items.`);

  // 5. Crear Project Tasks
  console.log('Seeding Project Tasks...');
  // Copia de MOCK_PROJECT_TASKS del frontend (sin 'children')
  const mockTasks: MockTask[] = [
    { id: "task-1", name: "Fase 1: Preliminares y Movimiento de Tierras", startDate: "2024-07-01", endDate: "2024-08-15", progress: 100, duration: 46, isSummary: true, outlineLevel: 1 },
    { id: "task-2", name: "Movilización y campamentos", startDate: "2024-07-01", endDate: "2024-07-10", progress: 100, duration: 10, isSummary: false, outlineLevel: 2 },
    { id: "task-3", name: "Descapote y limpieza", startDate: "2024-07-11", endDate: "2024-07-20", progress: 100, duration: 10, isSummary: false, outlineLevel: 2, dependencies: ["task-2"] },
    { id: "task-4", name: "Excavación general", startDate: "2024-07-21", endDate: "2024-08-15", progress: 100, duration: 26, isSummary: false, outlineLevel: 2, dependencies: ["task-3"] },
    { id: "task-5", name: "Fase 2: Estructuras y Cimentación", startDate: "2024-08-16", endDate: "2024-10-30", progress: 75, duration: 76, isSummary: true, outlineLevel: 1 },
    { id: "task-6", name: "Construcción de pilotes (Eje 1-5)", startDate: "2024-08-16", endDate: "2024-09-15", progress: 90, duration: 31, isSummary: false, outlineLevel: 2, dependencies: ["task-4"] },
    { id: "task-7", name: "Vigas cabezales", startDate: "2024-09-16", endDate: "2024-10-10", progress: 60, duration: 25, isSummary: false, outlineLevel: 2, dependencies: ["task-6"] },
    { id: "task-8", name: "Muros de contención", startDate: "2024-10-11", endDate: "2024-10-30", progress: 50, duration: 20, isSummary: false, outlineLevel: 2, dependencies: ["task-7"] },
    { id: "task-9", name: "Fase 3: Superestructura y Acabados", startDate: "2024-10-31", endDate: "2025-01-15", progress: 10, duration: 77, isSummary: true, outlineLevel: 1 },
    { id: "task-10", name: "Montaje de vigas prefabricadas", startDate: "2024-10-31", endDate: "2024-11-20", progress: 20, duration: 21, isSummary: false, outlineLevel: 2, dependencies: ["task-8"] },
    { id: "task-11", name: "Placa de concreto", startDate: "2024-11-21", endDate: "2024-12-15", progress: 5, duration: 25, isSummary: false, outlineLevel: 2, dependencies: ["task-10"] },
    { id: "task-12", name: "Instalación de barandas y señalización", startDate: "2024-12-16", endDate: "2025-01-15", progress: 0, duration: 31, isSummary: false, outlineLevel: 2, dependencies: ["task-11"] },
  ];

  // Primero, crea todas las tareas sin relaciones
  for (const task of mockTasks) {
    const taskData = {
      // Usamos el 'id' del mock como 'taskId' que es el @unique en Prisma
      taskId: task.id,
      name: task.name,
      startDate: new Date(task.startDate),
      endDate: new Date(task.endDate),
      progress: task.progress,
      duration: task.duration,
      isSummary: !!task.isSummary,
      outlineLevel: task.outlineLevel,
      // Conectamos al proyecto
      projectId: 'proj-1'
    };
    await prisma.projectTask.upsert({
      where: { taskId: task.id },
      update: taskData,
      create: taskData,
    });
  }
  console.log(`Seeded ${mockTasks.length} Project Tasks (flat).`);

  // (Opcional) Segundo, establecer relaciones padre-hijo si es necesario
  // Esto requiere más lógica para encontrar el 'parentId' basado en 'outlineLevel'
  // Por simplicidad, lo omitimos por ahora, pero podrías añadirlo si tu app lo requiere.

  // (Opcional) Tercero, establecer dependencias (requiere modelar la relación many-to-many en Prisma)
  // Tu schema.prisma actual ya modela la relación many-to-many _TaskDependencies
  // Podrías iterar de nuevo y conectar predecessors/successors si tienes esa info en mockTasks
  console.log('Skipping parent/dependency linking in seed for now.');


  console.log(`Seeding finished.`);
}

main()
  .catch((e) => {
    console.error("Error during seeding:", e); // Añade log específico
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });