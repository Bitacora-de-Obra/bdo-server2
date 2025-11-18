/**
 * Script para actualizar URLs de attachments a Cloudflare R2
 * 
 * Este script actualiza las URLs de los attachments existentes para que
 * usen la URL pública de Cloudflare R2 en lugar de URLs del servidor.
 * 
 * Uso:
 *   node scripts/update-attachment-urls-r2.js
 */

const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

// Simular getStorage para obtener la URL pública
function getPublicUrl(storagePath) {
  const publicUrl = process.env.CLOUDFLARE_R2_PUBLIC_URL || '';
  if (!publicUrl) {
    throw new Error('CLOUDFLARE_R2_PUBLIC_URL no está configurado');
  }
  return `${publicUrl.replace(/\/$/, '')}/${storagePath}`;
}

async function main() {
  try {
    console.log('🔄 Actualizando URLs de attachments a Cloudflare R2...\n');
    
    const publicUrl = process.env.CLOUDFLARE_R2_PUBLIC_URL || '';
    if (!publicUrl) {
      console.log('❌ CLOUDFLARE_R2_PUBLIC_URL no está configurado');
      console.log('   Configura esta variable de entorno primero');
      return;
    }
    
    console.log(`📋 URL pública configurada: ${publicUrl}\n`);
    
    // Obtener todos los attachments que tienen storagePath pero URL incorrecta
    const attachments = await prisma.attachment.findMany({
      where: {
        storagePath: { not: null },
        OR: [
          { url: { contains: '/api/attachments/' } },
          { url: { contains: 'localhost' } },
          { url: { contains: 'onrender.com' } },
        ]
      }
    });
    
    console.log(`📎 Encontrados ${attachments.length} attachments para actualizar\n`);
    
    if (attachments.length === 0) {
      console.log('✅ No hay attachments que actualizar');
      return;
    }
    
    let updated = 0;
    let errors = 0;
    
    for (const attachment of attachments) {
      try {
        const newUrl = getPublicUrl(attachment.storagePath);
        
        await prisma.attachment.update({
          where: { id: attachment.id },
          data: { url: newUrl }
        });
        
        console.log(`✅ ${attachment.fileName}`);
        console.log(`   ${attachment.url}`);
        console.log(`   → ${newUrl}\n`);
        
        updated++;
      } catch (error) {
        console.error(`❌ Error actualizando ${attachment.fileName}:`, error.message);
        errors++;
      }
    }
    
    console.log(`\n📊 Resumen:`);
    console.log(`   Actualizados: ${updated}`);
    console.log(`   Errores: ${errors}`);
    console.log(`   Total: ${attachments.length}`);
    
  } catch (error) {
    console.error('❌ Error:', error);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

main();


