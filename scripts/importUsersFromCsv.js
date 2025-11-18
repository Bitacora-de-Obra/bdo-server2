/* eslint-disable no-console */
// Import users from a semicolon-separated CSV:
// Headers expected: NOMBRE;ENTIDAD;CORREO ELECTRONICO;CARGO;
// Usage:
//   node scripts/importUsersFromCsv.js "uploads/usuarios bitacora digital.csv"
// This will generate scripts/users-to-import.json and then run bulkAddUsers.js

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

function sanitizeEmail(raw) {
  if (!raw) return '';
  // Remove spaces and stray characters commonly found in pasted emails
  let e = String(raw).trim();
  e = e.replace(/\s+/g, ''); // remove all spaces/newlines
  e = e.replace(/[,;]+$/g, ''); // trailing separators
  // Fix accidental 'gmail.c' + 'om' split or similar by just removing spaces already
  return e.toLowerCase();
}

function parseCsvSemicolon(content) {
  const lines = content.split(/\r?\n/);
  const rows = [];
  let buffer = '';
  let inQuoted = false;

  for (let i = 0; i < lines.length; i += 1) {
    let line = lines[i];
    if (!line) line = '';
    // Build a buffer to handle accidental newlines inside quoted fields
    if (buffer) {
      buffer += '\n' + line;
    } else {
      buffer = line;
    }
    // Track quote parity
    const quoteCount = (buffer.match(/"/g) || []).length;
    inQuoted = quoteCount % 2 === 1;
    // Heuristic: when not inside an open quote and we have at least 4 fields, flush
    const parts = buffer.split(';');
    if (!inQuoted && parts.length >= 4) {
      rows.push(parts);
      buffer = '';
    }
  }
  if (buffer) {
    rows.push(buffer.split(';'));
  }
  return rows;
}

function main() {
  const inputArg = process.argv[2] || 'uploads/usuarios bitacora digital.csv';
  const csvPath = path.isAbsolute(inputArg)
    ? inputArg
    : path.join(__dirname, '..', inputArg);
  if (!fs.existsSync(csvPath)) {
    console.error(`CSV not found: ${csvPath}`);
    process.exit(1);
  }
  const raw = fs.readFileSync(csvPath, 'utf8');
  const rows = parseCsvSemicolon(raw).filter((r) => r.join('').trim().length > 0);
  if (rows.length === 0) {
    console.error('CSV has no rows');
    process.exit(1);
  }

  // Detect header
  const header = rows[0].map((h) => h.replace(/"/g, '').trim().toUpperCase());
  const nameIdx = header.findIndex((h) => h.includes('NOMBRE'));
  const emailIdx = header.findIndex((h) => h.includes('CORREO'));
  const entidadIdx = header.findIndex((h) => h.includes('ENTIDAD'));
  const cargoIdx = header.findIndex((h) => h.includes('CARGO'));

  const users = [];
  for (let i = 1; i < rows.length; i += 1) {
    const cols = rows[i].map((c) => c.replace(/"/g, '').trim());
    const fullName = nameIdx >= 0 ? cols[nameIdx] : cols[0] || '';
    const email = sanitizeEmail(emailIdx >= 0 ? cols[emailIdx] : cols[2] || '');
    // Skip invalid or placeholder emails
    if (!email || email === '-' || !email.includes('@')) continue;
    // Defaults; we can improve mapping later if needed
    const projectRole = 'RESIDENT';
    const appRole = 'viewer';
    users.push({
      email,
      fullName: fullName || email,
      projectRole,
      appRole,
    });
  }

  if (users.length === 0) {
    console.error('No valid users parsed from CSV.');
    process.exit(1);
  }

  const outPath = path.join(__dirname, 'users-to-import.json');
  fs.writeFileSync(outPath, JSON.stringify(users, null, 2), 'utf8');
  console.log(`Wrote ${users.length} users to ${outPath}`);

  // Run the bulk importer
  const res = spawnSync('node', [path.join(__dirname, 'bulkAddUsers.js')], {
    stdio: 'inherit',
    cwd: path.join(__dirname, '..'),
    env: process.env,
  });
  process.exit(res.status || 0);
}

main();




