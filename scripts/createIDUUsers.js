/* eslint-disable no-console */
// Create IDU users with viewer profile based on the image provided
// Usage: node scripts/createIDUUsers.js

const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

const defaultPassword = 'password123';

// Usuarios de IDU de la imagen
const iduUsers = [
  {
    fullName: 'Isis Paola Díaz Muñiz',
    email: 'isis.diaz@idu.gov.co',
    cargo: 'Ordenación del Gasto',
    entity: 'IDU',
    projectRole: 'SUPERVISOR',
    appRole: 'viewer',
  },
  {
    fullName: 'Jairo Leonardo Jiménez Ferreira',
    email: 'jairo.jimenez@idu.gov.co',
    cargo: 'Supervisor',
    entity: 'IDU',
    projectRole: 'SUPERVISOR',
    appRole: 'viewer',
  },
  {
    fullName: 'Carlos Alberto Leuro Bernal',
    email: 'carlos.leuro@idu.gov.co',
    cargo: 'Apoyo a la Supervisión',
    entity: 'IDU',
    projectRole: 'SUPERVISOR',
    appRole: 'viewer',
  },
  {
    fullName: 'Juan Esteban Alarcón Medina',
    email: 'juan.alarcon@idu.gov.co',
    cargo: 'Apoyo a la Supervisión',
    entity: 'IDU',
    projectRole: 'SUPERVISOR',
    appRole: 'viewer',
  },
  {
    fullName: 'Natalia Ramírez',
    email: 'jeny.ramirez@idu.gov.co',
    cargo: 'Supervisor sst',
    entity: 'IDU',
    projectRole: 'SUPERVISOR',
    appRole: 'viewer',
  },
  {
    fullName: 'Mónica Granados',
    email: 'monica.granados@idu.gov.co',
    cargo: 'Supervisor Ambiental',
    entity: 'IDU',
    projectRole: 'SUPERVISOR',
    appRole: 'viewer',
  },
  {
    fullName: 'David Téllez',
    email: 'davidtellez@idu.gov.co',
    cargo: 'Supervisor Maquinaria',
    entity: 'IDU',
    projectRole: 'SUPERVISOR',
    appRole: 'viewer',
  },
  {
    fullName: 'Stiven Bernal',
    email: 'stiven.bernal@idu.gov.co',
    cargo: 'Supervisor Social',
    entity: 'IDU',
    projectRole: 'SUPERVISOR',
    appRole: 'viewer',
  },
  {
    fullName: 'Andrea Santacruz',
    email: 'andrea.santacruz@idu.gov.co',
    cargo: 'Supervisor Arqueología',
    entity: 'IDU',
    projectRole: 'SUPERVISOR',
    appRole: 'viewer',
  },
  {
    fullName: 'Omar Velásquez',
    email: 'omar.velasquez@idu.gov.co',
    cargo: 'Supervisor Forestal',
    entity: 'IDU',
    projectRole: 'SUPERVISOR',
    appRole: 'viewer',
  },
  {
    fullName: 'Adriana Sepúlveda',
    email: 'adriana.sepulveda@idu.gov.co',
    cargo: 'Supervisor Fauna',
    entity: 'IDU',
    projectRole: 'SUPERVISOR',
    appRole: 'viewer',
  },
];

async function createIDUUsers() {
  try {
    console.log('📦 Creando usuarios de IDU con perfil viewer...\n');

    const hashedPassword = await bcrypt.hash(defaultPassword, 10);

    let created = 0;
    let updated = 0;
    let skipped = 0;

    for (const userData of iduUsers) {
      try {
        const existingUser = await prisma.user.findUnique({
          where: { email: userData.email },
        });

        if (existingUser) {
          // Si el usuario existe, actualizarlo pero NO cambiar el password si ya tiene uno
          const updateData = {
            fullName: userData.fullName,
            entity: userData.entity,
            cargo: userData.cargo,
            projectRole: userData.projectRole,
            appRole: userData.appRole,
            status: 'active',
          };

          await prisma.user.update({
            where: { email: userData.email },
            data: updateData,
          });

          console.log(`✅ Actualizado: ${userData.fullName} (${userData.email})`);
          console.log(`   Cargo: ${userData.cargo} | Entidad: ${userData.entity} | projectRole: ${userData.projectRole} | appRole: ${userData.appRole}\n`);
          updated++;
        } else {
          // Crear nuevo usuario
          await prisma.user.create({
            data: {
              email: userData.email,
              password: hashedPassword,
              fullName: userData.fullName,
              entity: userData.entity,
              cargo: userData.cargo,
              projectRole: userData.projectRole,
              appRole: userData.appRole,
              status: 'active',
            },
          });

          console.log(`➕ Creado: ${userData.fullName} (${userData.email})`);
          console.log(`   Cargo: ${userData.cargo} | Entidad: ${userData.entity} | projectRole: ${userData.projectRole} | appRole: ${userData.appRole}`);
          console.log(`   Password: ${defaultPassword}\n`);
          created++;
        }
      } catch (error) {
        if (error.code === 'P2002') {
          console.log(`⚠️  Usuario ya existe: ${userData.email} (saltado)\n`);
          skipped++;
        } else {
          console.error(`❌ Error procesando ${userData.email}:`, error.message);
        }
      }
    }

    console.log('\n📈 Resumen:');
    console.log(`   ➕ Usuarios creados: ${created}`);
    console.log(`   ✅ Usuarios actualizados: ${updated}`);
    console.log(`   ⏭️  Usuarios saltados: ${skipped}`);
    console.log(`   📊 Total procesado: ${iduUsers.length}\n`);

    console.log('✅ Proceso completado');
    console.log(`\n🔑 Todos los usuarios tienen password: ${defaultPassword}`);
  } catch (error) {
    console.error('❌ Error durante la creación:', error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

createIDUUsers().catch((error) => {
  console.error(error);
  process.exit(1);
});

