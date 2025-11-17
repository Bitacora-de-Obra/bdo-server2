/* eslint-disable no-console */
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// Datos del corredor vial según la imagen - orden exacto
const elementos = [
  // Primera tabla
  {
    civ: '10010528',
    ubicacion: 'TV 112 B Bis A entre CL 63 y CI 64',
    pkId: '34011612',
    tipoElemento: 'Ciclorruta',
    costado: 'SUR',
    sortOrder: 1,
  },
  {
    civ: '10010528',
    ubicacion: 'TV 112 B Bis A entre CL 63 y Cl 64',
    pkId: '92083835',
    tipoElemento: 'Andén',
    costado: 'SUR',
    sortOrder: 2,
  },
  // Segunda tabla
  {
    civ: '10010528',
    ubicacion: 'TV 112 B Bis A entre CL 63 y Cl 64',
    pkId: '91033590',
    tipoElemento: 'Calzada',
    costado: 'SUR',
    sortOrder: 3,
  },
  {
    civ: '10010528',
    ubicacion: 'TV 112 B Bis A entre CL 63 y CI 64',
    pkId: '91033591',
    tipoElemento: 'Calzada',
    costado: 'NORTE',
    sortOrder: 4,
  },
  {
    civ: '10010528',
    ubicacion: 'TV 112 B Bis A entre CL 63 y CI 64',
    pkId: '92083831',
    tipoElemento: 'Andén',
    costado: 'SUR',
    sortOrder: 5,
  },
  {
    civ: '10004446',
    ubicacion: 'CII 63 entre Cr. 112 y TV 112 B Bis A',
    pkId: '165713',
    tipoElemento: 'Calzada',
    costado: 'CENTRAL',
    sortOrder: 6,
  },
  {
    civ: '10004446',
    ubicacion: 'CII 63 entre Cr. 112 y TV 112 B Bis A',
    pkId: '92086927',
    tipoElemento: 'Andén',
    costado: 'ORIENTAL',
    sortOrder: 7,
  },
  {
    civ: '10004446',
    ubicacion: 'CII 63 entre Cr. 112 y TV 112 B Bis A',
    pkId: '92086927',
    tipoElemento: 'Andén',
    costado: 'ORIENTAL',
    sortOrder: 8,
  },
  {
    civ: '10004446',
    ubicacion: 'CII 63 entre Cr. 112 y TV 112 B Bis A',
    pkId: '92086926',
    tipoElemento: 'Andén',
    costado: 'OCCIDENTAL',
    sortOrder: 9,
  },
];

async function importCorredorVialElements() {
  try {
    console.log('📦 Importando elementos del corredor vial...\n');
    
    const project = await prisma.project.findFirst();
    
    if (!project) {
      console.error('❌ No se encontró ningún proyecto en la base de datos.');
      process.exit(1);
    }
    
    console.log(`📊 Proyecto encontrado: ${project.name} (${project.contractId})\n`);
    
    // Eliminar elementos existentes
    const deleted = await prisma.corredorVialElement.deleteMany({
      where: { projectId: project.id },
    });
    console.log(`🗑️  Elementos eliminados: ${deleted.count}\n`);
    
    // Crear nuevos elementos
    let created = 0;
    for (const elemento of elementos) {
      try {
        await prisma.corredorVialElement.create({
          data: {
            ...elemento,
            projectId: project.id,
          },
        });
        created++;
        console.log(`✅ Creado: CIV ${elemento.civ} - ${elemento.tipoElemento} (${elemento.costado})`);
      } catch (error) {
        console.error(`❌ Error creando elemento CIV ${elemento.civ}:`, error.message);
      }
    }
    
    console.log(`\n📈 Resumen:`);
    console.log(`   ➕ Elementos creados: ${created}`);
    console.log(`   📊 Total procesado: ${elementos.length}\n`);
    
    console.log('✅ Importación completada exitosamente');
  } catch (error) {
    console.error('❌ Error durante la importación:', error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

importCorredorVialElements()
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });


