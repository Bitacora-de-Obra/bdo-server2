// Script de prueba para verificar la conexión con Cloudflare R2
const { getStorage } = require("./dist/storage.js");

async function testCloudflareR2() {
  try {
    console.log("🔍 Probando conexión con Cloudflare R2...");

    const storage = getStorage();
    console.log("✅ Storage instance creada correctamente");

    // Crear un archivo de prueba
    const testContent = Buffer.from(
      "¡Hola desde Cloudflare R2! Test: " + new Date().toISOString()
    );
    const testPath = "test/prueba-conexion.txt";

    console.log("📤 Subiendo archivo de prueba...");
    await storage.save({ path: testPath, content: testContent });
    console.log("✅ Archivo subido correctamente");

    // Obtener URL pública
    const publicUrl = storage.getPublicUrl(testPath);
    console.log("🔗 URL pública:", publicUrl);

    // Intentar leer el archivo
    console.log("📥 Leyendo archivo desde R2...");
    const readContent = await storage.load(testPath);
    console.log("✅ Archivo leído correctamente:", readContent.toString());

    // Limpiar - eliminar archivo de prueba
    console.log("🗑️  Eliminando archivo de prueba...");
    await storage.delete(testPath);
    console.log("✅ Archivo eliminado correctamente");

    console.log(
      "🎉 ¡Prueba completada exitosamente! Cloudflare R2 está funcionando correctamente."
    );
  } catch (error) {
    console.error("❌ Error en la prueba:", error);
    console.error("Detalles del error:", error.message);
  }
}

testCloudflareR2();
