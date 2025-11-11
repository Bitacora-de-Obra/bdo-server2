const {
  S3Client,
  PutObjectCommand,
  ListObjectsV2Command,
} = require("@aws-sdk/client-s3");

// Configuración actualizada desde tu .env - ACCOUNT ID CORREGIDO
const accountId = "f5a8cb8424c5d6a19d528a252365d348";
const accessKeyId = "d96e6b751a5081660efb14ce12b06a35";
const secretAccessKey =
  "9e22c8ccf1559982db9dc233e77a0e3bc5e35a07b2ce3540ff002177fbeb5c24";
const bucket = "bitacora-files";

async function testR2Connection() {
  try {
    console.log("🔍 Probando conexión directa con Cloudflare R2...");

    const client = new S3Client({
      region: "auto",
      endpoint: `https://${accountId}.r2.cloudflarestorage.com`,
      credentials: {
        accessKeyId,
        secretAccessKey,
      },
      forcePathStyle: true,
    });

    // Probar listando objetos del bucket
    console.log("📋 Listando objetos en el bucket...");
    const listCommand = new ListObjectsV2Command({
      Bucket: bucket,
      MaxKeys: 5,
    });

    const response = await client.send(listCommand);
    console.log(
      "✅ Conexión exitosa! Objetos encontrados:",
      response.KeyCount || 0
    );

    if (response.Contents && response.Contents.length > 0) {
      console.log("📁 Archivos en el bucket:");
      response.Contents.forEach((obj) => {
        console.log(`  - ${obj.Key} (${obj.Size} bytes)`);
      });
    } else {
      console.log(
        "📂 El bucket está vacío (esto es normal para un bucket nuevo)"
      );
    }

    // Probar subir un archivo pequeño
    console.log("📤 Probando subir un archivo de prueba...");
    const testContent = Buffer.from(
      `Prueba de Cloudflare R2 - ${new Date().toISOString()}`
    );
    const putCommand = new PutObjectCommand({
      Bucket: bucket,
      Key: "test/conexion-exitosa.txt",
      Body: testContent,
      ContentType: "text/plain",
    });

    await client.send(putCommand);
    console.log("✅ Archivo subido exitosamente!");

    console.log("🎉 ¡Cloudflare R2 está configurado correctamente!");
    console.log(
      "🔗 Tu bucket está en: https://" +
        bucket +
        "." +
        accountId +
        ".r2.cloudflarestorage.com/"
    );
  } catch (error) {
    console.error("❌ Error:", error.message);
    if (error.Code) {
      console.error("Código de error:", error.Code);
    }
  }
}

testR2Connection();
