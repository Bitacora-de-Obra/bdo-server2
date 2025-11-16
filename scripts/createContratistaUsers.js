/* eslint-disable no-console */
// Create CONTRATISTA users with their cargos based on the image provided
// Usage: node scripts/createContratistaUsers.js

const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

const defaultPassword = 'password123';

// Usuarios de CONTRATISTA - Lista definitiva
// Nota: Los cargos incluyen "de Obra" y están en Title Case
const contratistaUsers = [
  {
    fullName: 'Cesar Reyes',
    email: 'directorobra.cto2412@gmail.com',
    cargo: 'Director de Obra',
    entity: 'CONTRATISTA',
    projectRole: 'CONTRACTOR_REP',
    appRole: 'editor',
  },
  {
    fullName: 'Elio Bolaño',
    email: 'residentetecnico.cto2412@gmail.com',
    cargo: 'Residente Técnico de Obra',
    entity: 'CONTRATISTA',
    projectRole: 'CONTRACTOR_REP',
    appRole: 'editor',
  },
  {
    fullName: 'Jhon Florez',
    email: 'residentehidrosanitario.cto2412@gmail.com',
    cargo: 'Residente Hidrosanitario de Obra',
    entity: 'CONTRATISTA',
    projectRole: 'CONTRACTOR_REP',
    appRole: 'editor',
  },
  {
    fullName: 'Iván Acuña',
    email: 'profesionalcostos.cto2412@gmail.com',
    cargo: 'Residente de Costos de Obra',
    entity: 'CONTRATISTA',
    projectRole: 'CONTRACTOR_REP',
    appRole: 'editor',
  },
  {
    fullName: 'Johana Cárdenas',
    email: 'sst.cto2412ijk@gmail.com',
    cargo: 'Residente SST de Obra',
    entity: 'CONTRATISTA',
    projectRole: 'CONTRACTOR_REP',
    appRole: 'editor',
  },
  {
    fullName: 'Dalia Daza',
    email: 'residenteambiental.cto2412@gmail.com',
    cargo: 'Residente Ambiental de Obra',
    entity: 'CONTRATISTA',
    projectRole: 'CONTRACTOR_REP',
    appRole: 'editor',
  },
  {
    fullName: 'Edwar Muñoz',
    email: 'maquinaria.cto2412@gmail.com',
    cargo: 'Residente de Maquinaria de Obra',
    entity: 'CONTRATISTA',
    projectRole: 'CONTRACTOR_REP',
    appRole: 'editor',
  },
  {
    fullName: 'Yesid Rocha',
    email: 'yesidrocha02@hotmail.com',
    cargo: 'Residente de Forestal de Obra',
    entity: 'CONTRATISTA',
    projectRole: 'CONTRACTOR_REP',
    appRole: 'editor',
  },
  {
    fullName: 'Mónica Hernández',
    email: 'biologa.mahdz@gmail.com',
    cargo: 'Residente de Fauna de Obra',
    entity: 'CONTRATISTA',
    projectRole: 'CONTRACTOR_REP',
    appRole: 'editor',
  },
  {
    fullName: 'Santiago Angulo',
    email: 'arqueologia.cto2412@gmail.com',
    cargo: 'Arqueólogo de Obra',
    entity: 'CONTRATISTA',
    projectRole: 'CONTRACTOR_REP',
    appRole: 'editor',
  },
  {
    fullName: 'Ingri Rodríguez',
    email: 'puntoiducontrato2412ijk@gmail.com',
    cargo: 'Residente Social de Obra',
    entity: 'CONTRATISTA',
    projectRole: 'CONTRACTOR_REP',
    appRole: 'editor',
  },
];

async function createContratistaUsers() {
  try {
    console.log('📦 Creando usuarios de CONTRATISTA con sus cargos...\n');

    const hashedPassword = await bcrypt.hash(defaultPassword, 10);

    let created = 0;
    let updated = 0;
    let skipped = 0;

    for (const userData of contratistaUsers) {
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
    console.log(`   📊 Total procesado: ${contratistaUsers.length}\n`);

    console.log('✅ Proceso completado');
    console.log(`\n🔑 Todos los usuarios tienen password: ${defaultPassword}`);
  } catch (error) {
    console.error('❌ Error durante la creación:', error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

createContratistaUsers().catch((error) => {
  console.error(error);
  process.exit(1);
});

