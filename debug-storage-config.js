// Script temporal para verificar configuración de almacenamiento
console.log('=== STORAGE CONFIGURATION DEBUG ===');
console.log('Environment variables:');
console.log('- STORAGE_DRIVER:', process.env.STORAGE_DRIVER || 'not set (auto-detect)');
console.log('- CLOUDFLARE_ACCOUNT_ID:', process.env.CLOUDFLARE_ACCOUNT_ID ? 'Set' : 'Missing');
console.log('- CLOUDFLARE_R2_BUCKET:', process.env.CLOUDFLARE_R2_BUCKET || 'Missing');
console.log('- CLOUDFLARE_R2_ACCESS_KEY_ID:', process.env.CLOUDFLARE_R2_ACCESS_KEY_ID ? 'Set' : 'Missing');
console.log('- CLOUDFLARE_R2_SECRET_ACCESS_KEY:', process.env.CLOUDFLARE_R2_SECRET_ACCESS_KEY ? 'Set' : 'Missing');

// Simular la lógica de detección
const defaultDriver =
  process.env.CLOUDFLARE_ACCOUNT_ID &&
  process.env.CLOUDFLARE_R2_ACCESS_KEY_ID &&
  process.env.CLOUDFLARE_R2_SECRET_ACCESS_KEY
    ? "r2"
    : "local";
const driver = (process.env.STORAGE_DRIVER || defaultDriver).toLowerCase();

console.log('');
console.log('=== DETECTION LOGIC ===');
console.log('- Default driver (auto-detect):', defaultDriver);
console.log('- Final driver used:', driver);

if (driver === 'r2' || driver === 'cloudflare') {
  console.log('✅ PDFs will be stored in Cloudflare R2');
  console.log('- Bucket:', process.env.CLOUDFLARE_R2_BUCKET);
  console.log('- Public URL pattern:', process.env.CLOUDFLARE_R2_PUBLIC_URL || 'Standard R2 URL');
} else {
  console.log('⚠️  PDFs will be stored locally (temporary in Render)');
  console.log('- Upload directory:', process.env.UPLOADS_DIR || 'uploads');
}

console.log('=== END DEBUG ===');
