/* eslint-disable no-console */
// Create INTERVENTORIA users with their cargos based on the image provided
// Usage: node scripts/createInterventoriaUsers.js

const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

const defaultPassword = 'password123';

// Usuarios de INTERVENTORIA - Lista definitiva
// Nota: Los cargos incluyen "de Interventoría" y están en Title Case
const interventoriaUsers = [
  {
    fullName: 'Juan Diego Arenas',
    email: 'jarenas@arenasingenieros.com',
    cargo: 'Director de Interventoría',
    entity: 'INTERVENTORIA',
    projectRole: 'SUPERVISOR',
    appRole: 'editor',
  },
  {
    fullName: 'Agnes Chávez',
    email: 'residentetecnico2428@gmail.com',
    cargo: 'Residente Técnico de Interventoría',
    entity: 'INTERVENTORIA',
    projectRole: 'SUPERVISOR',
    appRole: 'editor',
  },
  {
    fullName: 'Rosa Cordero',
    email: 'rosacoro@arenasingenieros.com',
    cargo: 'Coordinadora de Interventoría',
    entity: 'INTERVENTORIA',
    projectRole: 'SUPERVISOR',
    appRole: 'editor',
  },
  {
    fullName: 'Isabella de la Hoz',
    email: 'coordinador1@arenasingenieros.com',
    cargo: 'Auxiliar de Ingeniería de Interventoría',
    entity: 'INTERVENTORIA',
    projectRole: 'SUPERVISOR',
    appRole: 'editor',
  },
  {
    fullName: 'Sergio Gómez',
    email: 'coordinador2@arenasingenieros.com',
    cargo: 'Auxiliar de Ingeniería de Interventoría',
    entity: 'INTERVENTORIA',
    projectRole: 'SUPERVISOR',
    appRole: 'editor',
  },
  {
    fullName: 'Xiomara León',
    email: 'residentesst2428@gmail.com',
    cargo: 'Residente SST de Interventoría',
    entity: 'INTERVENTORIA',
    projectRole: 'SUPERVISOR',
    appRole: 'editor',
  },
  {
    fullName: 'Milena Acevedo',
    email: 'amacevedop.ing@gmail.com',
    cargo: 'Inspectora SST/MA de Interventoría',
    entity: 'INTERVENTORIA',
    projectRole: 'SUPERVISOR',
    appRole: 'editor',
  },
  {
    fullName: 'Vanessa Rueda',
    email: 'residenteambiental.2428@gmail.com',
    cargo: 'Residente Ambiental de Interventoría',
    entity: 'INTERVENTORIA',
    projectRole: 'SUPERVISOR',
    appRole: 'editor',
  },
  {
    fullName: 'Diego Vélez',
    email: 'diegovelezforero@gmail.com',
    cargo: 'Residente de Maquinaria de Interventoría',
    entity: 'INTERVENTORIA',
    projectRole: 'SUPERVISOR',
    appRole: 'editor',
  },
  {
    fullName: 'Gabriel Hernández',
    email: 'forestal.mutis2428@gmail.com',
    cargo: 'Residente de Forestal de Interventoría',
    entity: 'INTERVENTORIA',
    projectRole: 'SUPERVISOR',
    appRole: 'editor',
  },
  {
    fullName: 'Cesar Reyes',
    email: 'cesar.riano@gmail.com',
    cargo: 'Residente de Fauna de Interventoría',
    entity: 'INTERVENTORIA',
    projectRole: 'SUPERVISOR',
    appRole: 'editor',
  },
  {
    fullName: 'Mario Rojas',
    email: 'mariofernando.rv@gmail.com',
    cargo: 'Arqueólogo de Interventoría',
    entity: 'INTERVENTORIA',
    projectRole: 'SUPERVISOR',
    appRole: 'editor',
  },
  {
    fullName: 'Andrea García',
    email: 'socialintermutis@gmail.com',
    cargo: 'Residente Social de Interventoría',
    entity: 'INTERVENTORIA',
    projectRole: 'SUPERVISOR',
    appRole: 'editor',
  },
];

async function createInterventoriaUsers() {
  try {
    console.log('📦 Creando usuarios de INTERVENTORIA con sus cargos...\n');

    const hashedPassword = await bcrypt.hash(defaultPassword, 10);

    let created = 0;
    let updated = 0;
    let skipped = 0;

    for (const userData of interventoriaUsers) {
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
    console.log(`   📊 Total procesado: ${interventoriaUsers.length}\n`);

    console.log('✅ Proceso completado');
    console.log(`\n🔑 Todos los usuarios tienen password: ${defaultPassword}`);
  } catch (error) {
    console.error('❌ Error durante la creación:', error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

createInterventoriaUsers().catch((error) => {
  console.error(error);
  process.exit(1);
});

