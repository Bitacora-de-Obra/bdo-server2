const { getStorage } = require('./dist/storage');

async function testStorageConfig() {
  try {
    console.log('Testing storage configuration...');
    
    // Verificar variables de entorno
    console.log('Environment variables:');
    console.log('- CLOUDFLARE_ACCOUNT_ID:', process.env.CLOUDFLARE_ACCOUNT_ID ? 'Set' : 'Missing');
    console.log('- CLOUDFLARE_R2_BUCKET:', process.env.CLOUDFLARE_R2_BUCKET || 'Missing');
    console.log('- CLOUDFLARE_R2_ACCESS_KEY_ID:', process.env.CLOUDFLARE_R2_ACCESS_KEY_ID ? 'Set' : 'Missing');
    console.log('- CLOUDFLARE_R2_SECRET_ACCESS_KEY:', process.env.CLOUDFLARE_R2_SECRET_ACCESS_KEY ? 'Set' : 'Missing');
    console.log('- STORAGE_DRIVER:', process.env.STORAGE_DRIVER || 'auto-detect');
    
    // Obtener instancia de storage
    const storage = getStorage();
    console.log('Storage instance created successfully');
    
    // Probar una operación simple
    const testContent = Buffer.from('Test content for R2');
    const testPath = 'test/storage-test.txt';
    
    console.log('Testing file upload...');
    await storage.save({ path: testPath, content: testContent });
    console.log('File uploaded successfully');
    
    console.log('Getting public URL...');
    const publicUrl = storage.getPublicUrl(testPath);
    console.log('Public URL:', publicUrl);
    
    console.log('Testing file download...');
    const downloadedContent = await storage.load(testPath);
    console.log('File downloaded successfully, content:', downloadedContent.toString());
    
    console.log('Cleaning up test file...');
    await storage.delete(testPath);
    console.log('Test file deleted successfully');
    
    console.log('✅ Storage configuration is working correctly!');
    
  } catch (error) {
    console.error('❌ Storage configuration error:', error);
    process.exit(1);
  }
}

testStorageConfig();
