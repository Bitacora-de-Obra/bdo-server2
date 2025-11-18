/**
 * Script para eliminar todas las fotos de un punto fijo específico
 * Uso: node scripts/delete-control-point-photos.js "nombre-del-punto-fijo"
 * O: node scripts/delete-control-point-photos.js --id "id-del-punto-fijo"
 */

const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function deleteControlPointPhotos(pointNameOrId, useId = false) {
  try {
    console.log('🔍 Buscando punto fijo...');
    
    let controlPoint;
    
    if (useId) {
      controlPoint = await prisma.controlPoint.findUnique({
        where: { id: pointNameOrId },
        include: {
          photos: {
            include: {
              attachment: true,
            },
          },
        },
      });
    } else {
      // Buscar todos los puntos fijos y filtrar por nombre (case-insensitive)
      const allPoints = await prisma.controlPoint.findMany({
        include: {
          photos: {
            include: {
              attachment: true,
            },
          },
        },
      });
      
      controlPoint = allPoints.find(
        point => point.name && point.name.toLowerCase().includes(pointNameOrId.toLowerCase())
      );
    }

    if (!controlPoint) {
      console.log(`❌ No se encontró el punto fijo: ${pointNameOrId}`);
      return;
    }

    console.log(`\n📊 Punto fijo encontrado:`);
    console.log(`   - Nombre: ${controlPoint.name || 'Sin nombre'}`);
    console.log(`   - ID: ${controlPoint.id}`);
    console.log(`   - Descripción: ${controlPoint.description || 'Sin descripción'}`);
    console.log(`   - Ubicación: ${controlPoint.location || 'Sin ubicación'}`);
    console.log(`   - Fotos: ${controlPoint.photos?.length || 0}`);

    if (!controlPoint.photos || controlPoint.photos.length === 0) {
      console.log('\n✅ El punto fijo no tiene fotos para eliminar.');
      return;
    }

    console.log('\n⚠️  ADVERTENCIA: Esta acción eliminará TODAS las fotos de este punto fijo.');
    console.log('   También se eliminarán los attachments relacionados de Cloudflare R2.');
    console.log('   El punto fijo se mantendrá, solo se eliminarán las fotos.');

    console.log('\n🗑️  Eliminando fotos...');

    let deletedCount = 0;
    let errorCount = 0;

    // Eliminar fotos y sus attachments
    for (const photo of controlPoint.photos) {
      try {
        if (photo.attachment) {
          console.log(`   - Eliminando attachment: ${photo.attachment.fileName || photo.attachment.id}`);
          
          // Intentar eliminar el archivo de Cloudflare R2 si tiene storagePath
          if (photo.attachment.storagePath) {
            try {
              // Usar el cliente S3 directamente para eliminar de R2
              const { S3Client, DeleteObjectCommand } = require('@aws-sdk/client-s3');
              
              const s3Client = new S3Client({
                region: process.env.S3_REGION || 'auto',
                endpoint: process.env.S3_ENDPOINT,
                credentials: {
                  accessKeyId: process.env.S3_ACCESS_KEY_ID || '',
                  secretAccessKey: process.env.S3_SECRET_ACCESS_KEY || '',
                },
                forcePathStyle: process.env.S3_FORCE_PATH_STYLE === 'true',
              });

              await s3Client.send(
                new DeleteObjectCommand({
                  Bucket: process.env.S3_BUCKET || '',
                  Key: photo.attachment.storagePath,
                })
              );
              console.log(`     ✅ Archivo eliminado de R2: ${photo.attachment.storagePath}`);
            } catch (r2Error) {
              console.warn(`     ⚠️  No se pudo eliminar de R2 (puede que ya no exista): ${r2Error.message}`);
            }
          }
          
          await prisma.attachment.delete({
            where: { id: photo.attachment.id },
          });
        }
        
        await prisma.photoEntry.delete({
          where: { id: photo.id },
        });
        
        deletedCount++;
        console.log(`   ✅ Foto ${deletedCount} eliminada`);
      } catch (error) {
        errorCount++;
        console.error(`   ❌ Error al eliminar foto ${photo.id}:`, error.message);
      }
    }

    console.log(`\n✅ Proceso completado:`);
    console.log(`   - Fotos eliminadas: ${deletedCount}`);
    if (errorCount > 0) {
      console.log(`   - Errores: ${errorCount}`);
    }
    
  } catch (error) {
    console.error('❌ Error al eliminar fotos:', error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

// Obtener argumentos de la línea de comandos
const args = process.argv.slice(2);

if (args.length === 0) {
  console.log('Uso:');
  console.log('  Por nombre: node scripts/delete-control-point-photos.js "Vista No.1"');
  console.log('  Por ID: node scripts/delete-control-point-photos.js --id "id-del-punto-fijo"');
  process.exit(1);
}

const useId = args[0] === '--id';
const pointIdentifier = useId ? args[1] : args[0];

if (!pointIdentifier) {
  console.error('❌ Debes proporcionar el nombre o ID del punto fijo.');
  process.exit(1);
}

// Ejecutar
deleteControlPointPhotos(pointIdentifier, useId)
  .then(() => {
    console.log('\n✅ Script completado.');
    process.exit(0);
  })
  .catch((error) => {
    console.error('\n❌ Error en el script:', error);
    process.exit(1);
  });

