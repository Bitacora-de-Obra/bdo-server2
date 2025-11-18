/**
 * Utilidades para encriptar y desencriptar firmas de usuarios
 * Las firmas se encriptan usando una clave derivada de la contraseña del usuario
 * para asegurar que ni siquiera el admin pueda acceder a ellas sin la contraseña
 */

import crypto from "crypto";

const ALGORITHM = "aes-256-gcm";
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 16; // 128 bits
const SALT_LENGTH = 32; // 256 bits
const TAG_LENGTH = 16; // 128 bits
const PBKDF2_ITERATIONS = 100000; // Número de iteraciones para PBKDF2

/**
 * Deriva una clave de encriptación desde la contraseña del usuario usando PBKDF2
 */
function deriveKeyFromPassword(
  password: string,
  salt: Buffer
): Buffer {
  return crypto.pbkdf2Sync(
    password,
    salt,
    PBKDF2_ITERATIONS,
    KEY_LENGTH,
    "sha256"
  );
}

/**
 * Encripta el buffer de la firma usando una clave derivada de la contraseña del usuario
 * @param signatureBuffer - Buffer de la imagen de la firma
 * @param userPassword - Contraseña del usuario (en texto plano, se usará para derivar la clave)
 * @returns Objeto con el buffer encriptado, salt, iv y tag
 */
export function encryptSignature(
  signatureBuffer: Buffer,
  userPassword: string
): {
  encrypted: Buffer;
  salt: Buffer;
  iv: Buffer;
  tag: Buffer;
} {
  // Generar salt único para este usuario
  const salt = crypto.randomBytes(SALT_LENGTH);
  
  // Derivar clave desde la contraseña
  const key = deriveKeyFromPassword(userPassword, salt);
  
  // Generar IV único
  const iv = crypto.randomBytes(IV_LENGTH);
  
  // Crear cipher
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  
  // Encriptar
  const encrypted = Buffer.concat([
    cipher.update(signatureBuffer),
    cipher.final(),
  ]);
  
  // Obtener tag de autenticación
  const tag = cipher.getAuthTag();
  
  return {
    encrypted,
    salt,
    iv,
    tag,
  };
}

/**
 * Desencripta el buffer de la firma usando la contraseña del usuario
 * @param encryptedData - Objeto con el buffer encriptado, salt, iv y tag
 * @param userPassword - Contraseña del usuario
 * @returns Buffer desencriptado de la firma
 */
export function decryptSignature(
  encryptedData: {
    encrypted: Buffer;
    salt: Buffer;
    iv: Buffer;
    tag: Buffer;
  },
  userPassword: string
): Buffer {
  // Derivar la misma clave desde la contraseña usando el salt guardado
  const key = deriveKeyFromPassword(userPassword, encryptedData.salt);
  
  // Crear decipher
  const decipher = crypto.createDecipheriv(ALGORITHM, key, encryptedData.iv);
  decipher.setAuthTag(encryptedData.tag);
  
  // Desencriptar
  const decrypted = Buffer.concat([
    decipher.update(encryptedData.encrypted),
    decipher.final(),
  ]);
  
  return decrypted;
}

/**
 * Combina los datos encriptados en un solo buffer para almacenamiento
 * Formato: [salt (32 bytes)][iv (16 bytes)][tag (16 bytes)][encrypted data]
 */
export function packEncryptedSignature(data: {
  encrypted: Buffer;
  salt: Buffer;
  iv: Buffer;
  tag: Buffer;
}): Buffer {
  return Buffer.concat([
    data.salt,
    data.iv,
    data.tag,
    data.encrypted,
  ]);
}

/**
 * Extrae los datos encriptados de un buffer combinado
 */
export function unpackEncryptedSignature(
  packed: Buffer
): {
  encrypted: Buffer;
  salt: Buffer;
  iv: Buffer;
  tag: Buffer;
} {
  const salt = packed.subarray(0, SALT_LENGTH);
  const iv = packed.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const tag = packed.subarray(
    SALT_LENGTH + IV_LENGTH,
    SALT_LENGTH + IV_LENGTH + TAG_LENGTH
  );
  const encrypted = packed.subarray(SALT_LENGTH + IV_LENGTH + TAG_LENGTH);
  
  return {
    salt,
    iv,
    tag,
    encrypted,
  };
}

/**
 * Verifica si una contraseña es correcta para desencriptar una firma
 * (sin desencriptar realmente, solo verifica que la contraseña sea correcta)
 */
export function verifySignaturePassword(
  packedEncrypted: Buffer,
  userPassword: string
): boolean {
  try {
    const encryptedData = unpackEncryptedSignature(packedEncrypted);
    // Intentar desencriptar (si la contraseña es incorrecta, fallará)
    decryptSignature(encryptedData, userPassword);
    return true;
  } catch (error) {
    return false;
  }
}

