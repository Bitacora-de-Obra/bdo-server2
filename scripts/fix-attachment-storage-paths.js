/**
 * Script para corregir storagePath de attachments que tienen URLs de R2 pero no storagePath
 * 
 * Este script busca attachments que:
 * - Tienen una URL de R2 pública
 * - No tienen storagePath en la base de datos
 * - Extrae el storagePath desde la URL y lo actualiza
 * 
 * Uso:
 *   node scripts/fix-attachment-storage-paths.js
 */

const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

function extractStoragePathFromR2Url(url) {
  if (!url) return null;
  
  // Si es una URL de R2 pública, extraer el path
  if (url.includes(".r2.dev") || url.includes("r2.cloudflarestorage.com")) {
    try {
      const parsed = new URL(url);
      const pathname = parsed.pathname.replace(/^\/+/, "");
      return pathname || null;
    } catch (error) {
      // Si no es una URL válida, intentar extraer manualmente
      const match = url.match(/\.r2\.dev\/(.+)$/);
      if (match && match[1]) {
        return match[1];
      }
    }
  }
  
  // Si la URL contiene /uploads/, extraer el path
  if (url.includes("/uploads/")) {
    return url.replace(/^.*\/uploads\//, "");
  }
  
  return null;
}

async function main() {
  try {
    console.log('🔄 Corrigiendo storagePath de attachments con URLs de R2...\n');
    
    // Buscar attachments que tienen URL pero no storagePath
    const attachments = await prisma.attachment.findMany({
      where: {
        storagePath: null,
        url: { not: null },
      }
    });
    
    console.log(`📎 Encontrados ${attachments.length} attachments sin storagePath\n`);
    
    if (attachments.length === 0) {
      console.log('✅ No hay attachments que corregir');
      return;
    }
    
    let updated = 0;
    let errors = 0;
    let skipped = 0;
    
    for (const attachment of attachments) {
      try {
        const storagePath = extractStoragePathFromR2Url(attachment.url);
        
        if (!storagePath) {
          console.log(`⏭️  Saltando ${attachment.fileName} - No se pudo extraer storagePath desde URL`);
          console.log(`   URL: ${attachment.url}\n`);
          skipped++;
          continue;
        }
        
        await prisma.attachment.update({
          where: { id: attachment.id },
          data: { storagePath }
        });
        
        console.log(`✅ ${attachment.fileName}`);
        console.log(`   URL: ${attachment.url}`);
        console.log(`   → storagePath: ${storagePath}\n`);
        
        updated++;
      } catch (error) {
        console.error(`❌ Error actualizando ${attachment.fileName}:`, error.message);
        errors++;
      }
    }
    
    console.log(`\n📊 Resumen:`);
    console.log(`   Actualizados: ${updated}`);
    console.log(`   Saltados: ${skipped}`);
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


