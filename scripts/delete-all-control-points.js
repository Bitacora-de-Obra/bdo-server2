/**
 * Script para eliminar todos los puntos fijos existentes
 * Ejecutar con: node scripts/delete-all-control-points.js
 */

const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function deleteAllControlPoints() {
  try {
    console.log('🔍 Buscando puntos fijos...');
    
    // Obtener todos los puntos fijos con sus fotos y attachments
    const controlPoints = await prisma.controlPoint.findMany({
      include: {
        photos: {
          include: {
            attachment: true,
          },
        },
      },
    });

    console.log(`📊 Encontrados ${controlPoints.length} punto(s) fijo(s)`);

    if (controlPoints.length === 0) {
      console.log('✅ No hay puntos fijos para eliminar.');
      return;
    }

    // Mostrar información de los puntos fijos
    controlPoints.forEach((point, index) => {
      console.log(`\n${index + 1}. ${point.name || 'Sin nombre'} (ID: ${point.id})`);
      console.log(`   - Descripción: ${point.description || 'Sin descripción'}`);
      console.log(`   - Ubicación: ${point.location || 'Sin ubicación'}`);
      console.log(`   - Fotos: ${point.photos?.length || 0}`);
    });

    console.log('\n⚠️  ADVERTENCIA: Esta acción eliminará TODOS los puntos fijos y sus fotos asociadas.');
    console.log('   También se eliminarán los attachments relacionados de Cloudflare R2.');
    
    // En un script automatizado, procedemos directamente
    // Si quieres confirmación interactiva, descomenta las siguientes líneas:
    // const readline = require('readline');
    // const rl = readline.createInterface({
    //   input: process.stdin,
    //   output: process.stdout,
    // });
    // const answer = await new Promise(resolve => {
    //   rl.question('\n¿Estás seguro? (escribe "SI" para confirmar): ', resolve);
    // });
    // rl.close();
    // if (answer !== 'SI') {
    //   console.log('❌ Operación cancelada.');
    //   return;
    // }

    console.log('\n🗑️  Eliminando puntos fijos...');

    // Eliminar en transacción
    for (const point of controlPoints) {
      console.log(`\n   Eliminando: ${point.name || point.id}`);
      
      // Eliminar fotos y sus attachments
      if (point.photos && point.photos.length > 0) {
        console.log(`   - Eliminando ${point.photos.length} foto(s)...`);
        
        for (const photo of point.photos) {
          if (photo.attachment) {
            // Nota: Los archivos en Cloudflare R2 se eliminarán automáticamente
            // cuando se elimine el attachment de la base de datos (si hay cascade delete)
            // o manualmente si es necesario
            console.log(`     - Eliminando attachment: ${photo.attachment.fileName}`);
            await prisma.attachment.delete({
              where: { id: photo.attachment.id },
            }).catch(err => {
              console.warn(`     ⚠️  No se pudo eliminar attachment ${photo.attachment.id}:`, err.message);
            });
          }
          
          await prisma.photoEntry.delete({
            where: { id: photo.id },
          }).catch(err => {
            console.warn(`     ⚠️  No se pudo eliminar photo ${photo.id}:`, err.message);
          });
        }
      }
      
      // Eliminar el punto fijo
      await prisma.controlPoint.delete({
        where: { id: point.id },
      });
      
      console.log(`   ✅ Punto fijo eliminado: ${point.name || point.id}`);
    }

    console.log(`\n✅ Se eliminaron ${controlPoints.length} punto(s) fijo(s) exitosamente.`);
    
  } catch (error) {
    console.error('❌ Error al eliminar puntos fijos:', error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

// Ejecutar
deleteAllControlPoints()
  .then(() => {
    console.log('\n✅ Script completado.');
    process.exit(0);
  })
  .catch((error) => {
    console.error('\n❌ Error en el script:', error);
    process.exit(1);
  });

