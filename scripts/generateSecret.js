#!/usr/bin/env node

/**
 * Simple helper to generate cryptographically secure secrets.
 *
 * Usage:
 *   npm run secrets:generate        # genera secreto hex de 64 bytes
 *   npm run secrets:generate 48     # genera secreto base64 de 48 bytes
 */

const crypto = require("crypto");

const DEFAULT_BYTES = 48;

const bytes = Number(process.argv[2]) || DEFAULT_BYTES;

if (Number.isNaN(bytes) || bytes <= 0) {
  console.error("El número de bytes debe ser un entero positivo.");
  process.exit(1);
}

const buffer = crypto.randomBytes(bytes);
const base64Secret = buffer.toString("base64");
const hexSecret = buffer.toString("hex");

console.log("=== Secret Generator ===");
console.log(`Bytes solicitados: ${bytes}`);
console.log("");
console.log("Base64:");
console.log(base64Secret);
console.log("");
console.log("Hex:");
console.log(hexSecret);
console.log("");
console.log(
  "Copia uno de los valores anteriores en tu gestor de secretos o en los archivos *_SECRET_FILE."
);


