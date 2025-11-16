/* eslint-disable no-console */
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// CIVs que conforman el corredor vial según la imagen
// Orden exacto como aparecen en la imagen:
// - Primera tabla: CIV 10010528 (aparece 2 veces)
// - Segunda tabla: CIV 10010528 (aparece 3 veces) y CIV 10004446 (aparece 4 veces)
// CIVs únicos en el orden que aparecen:
const CIVs = ['10010528', '10004446'];

async function updateProjectCIVs() {
  try {
    console.log('📦 Actualizando CIVs del proyecto...\n');
    
    const project = await prisma.project.findFirst();
    
    if (!project) {
      console.error('❌ No se encontró ningún proyecto en la base de datos.');
      process.exit(1);
    }
    
    console.log(`📊 Proyecto encontrado: ${project.name} (${project.contractId})\n`);
    
    // Convertir el array a JSON string
    const civsJson = JSON.stringify(CIVs);
    
    const updatedProject = await prisma.project.update({
      where: { id: project.id },
      data: { civs: civsJson },
    });
    
    console.log('✅ CIVs actualizados exitosamente:');
    CIVs.forEach((civ, index) => {
      console.log(`   ${index + 1}. ${civ}`);
    });
    console.log(`\n📝 Total de CIVs: ${CIVs.length}`);
    console.log(`💾 JSON almacenado: ${civsJson}\n`);
    
    console.log('✅ Actualización completada');
  } catch (error) {
    console.error('❌ Error durante la actualización:', error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

updateProjectCIVs()
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

