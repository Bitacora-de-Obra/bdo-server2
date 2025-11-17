/**
 * Script para verificar URLs de Cloudflare R2
 * 
 * Uso:
 *   node scripts/test-r2-urls.js
 */

const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function main() {
  try {
    console.log('🔍 Verificando configuración de Cloudflare R2...\n');
    
    // Verificar variables de entorno
    const storageDriver = process.env.STORAGE_DRIVER || 'local';
    const publicUrl = process.env.CLOUDFLARE_R2_PUBLIC_URL || '';
    const bucket = process.env.CLOUDFLARE_R2_BUCKET || '';
    
    console.log('📋 Configuración:');
    console.log(`   STORAGE_DRIVER: ${storageDriver}`);
    console.log(`   CLOUDFLARE_R2_BUCKET: ${bucket}`);
    console.log(`   CLOUDFLARE_R2_PUBLIC_URL: ${publicUrl || '(no configurado)'}`);
    console.log('');
    
    if (storageDriver !== 'r2' && storageDriver !== 'cloudflare') {
      console.log('⚠️  STORAGE_DRIVER no está configurado como "r2" o "cloudflare"');
      return;
    }
    
    if (!publicUrl) {
      console.log('⚠️  CLOUDFLARE_R2_PUBLIC_URL no está configurado');
      console.log('   Configura esta variable en Render con:');
      console.log('   https://pub-e07f0269fa994f659a210ce23fc46290.r2.dev');
      return;
    }
    
    // Obtener algunos attachments recientes
    console.log('📎 Verificando attachments recientes...\n');
    const attachments = await prisma.attachment.findMany({
      where: {
        type: { startsWith: 'image/' }
      },
      take: 5,
      orderBy: { createdAt: 'desc' }
    });
    
    if (attachments.length === 0) {
      console.log('   No se encontraron imágenes adjuntas');
      return;
    }
    
    console.log(`   Encontradas ${attachments.length} imágenes:\n`);
    
    attachments.forEach((att, index) => {
      console.log(`${index + 1}. ${att.fileName}`);
      console.log(`   Storage Path: ${att.storagePath || '(no configurado)'}`);
      console.log(`   URL actual: ${att.url}`);
      
      if (att.storagePath) {
        const expectedUrl = `${publicUrl.replace(/\/$/, '')}/${att.storagePath}`;
        console.log(`   URL esperada: ${expectedUrl}`);
        
        if (att.url !== expectedUrl) {
          console.log(`   ⚠️  La URL no coincide con la esperada`);
        } else {
          console.log(`   ✅ URL correcta`);
        }
      }
      console.log('');
    });
    
    // Verificar si las URLs son accesibles
    console.log('🌐 Verificando accesibilidad de URLs...\n');
    const testAttachment = attachments[0];
    if (testAttachment && testAttachment.storagePath) {
      const testUrl = `${publicUrl.replace(/\/$/, '')}/${testAttachment.storagePath}`;
      console.log(`   Probando URL: ${testUrl}`);
      
      try {
        const response = await fetch(testUrl, { method: 'HEAD' });
        if (response.ok) {
          console.log(`   ✅ URL accesible (Status: ${response.status})`);
        } else {
          console.log(`   ❌ URL no accesible (Status: ${response.status})`);
          console.log(`   Posibles causas:`);
          console.log(`   - El dominio público no está habilitado en Cloudflare R2`);
          console.log(`   - Problema de CORS`);
          console.log(`   - El archivo no existe en R2`);
        }
      } catch (error) {
        console.log(`   ❌ Error al verificar URL: ${error.message}`);
      }
    }
    
  } catch (error) {
    console.error('❌ Error:', error);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

main();

