/* eslint-disable no-console */
// Update users from CSV based on ENTIDAD field
// Headers expected: NOMBRE;ENTIDAD;CORREO ELECTRONICO;CARGO;
// Usage: node scripts/updateUsersFromCsv.js

const fs = require('fs');
const path = require('path');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

function sanitizeEmail(raw) {
  if (!raw) return '';
  let e = String(raw).trim();
  e = e.replace(/\s+/g, '');
  e = e.replace(/[,;]+$/g, '');
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
    if (buffer) {
      buffer += '\n' + line;
    } else {
      buffer = line;
    }
    const quoteCount = (buffer.match(/"/g) || []).length;
    inQuoted = quoteCount % 2 === 1;
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

function determineProjectRole(entidad, cargo) {
  const entidadUpper = entidad.toUpperCase();
  const cargoUpper = cargo ? cargo.toUpperCase() : '';

  if (entidadUpper === 'IDU') {
    // IDU puede ser ADMIN o SUPERVISOR dependiendo del cargo
    if (cargoUpper.includes('DIRECTOR') || cargoUpper.includes('ADMIN')) {
      return 'ADMIN';
    }
    return 'SUPERVISOR';
  }

  if (entidadUpper === 'INTERVENTORIA' || entidadUpper === 'INTERVENTORÍA') {
    // Interventoría puede ser RESIDENT o SUPERVISOR
    if (cargoUpper.includes('DIRECTOR') || cargoUpper.includes('COORDINADOR') || cargoUpper.includes('SUPERVISOR')) {
      return 'SUPERVISOR';
    }
    return 'RESIDENT';
  }

  if (entidadUpper === 'CONTRATISTA') {
    return 'CONTRACTOR_REP';
  }

  // Default
  return 'RESIDENT';
}

async function updateUsersFromCsv() {
  try {
    const csvPath = path.join(__dirname, '../uploads/usuarios bitacora digital.csv');
    
    if (!fs.existsSync(csvPath)) {
      console.error(`❌ CSV no encontrado: ${csvPath}`);
      process.exit(1);
    }

    console.log('📦 Leyendo CSV...\n');
    const raw = fs.readFileSync(csvPath, 'utf8');
    const rows = parseCsvSemicolon(raw).filter((r) => r.join('').trim().length > 0);

    if (rows.length === 0) {
      console.error('❌ El CSV no tiene filas válidas');
      process.exit(1);
    }

    // Detectar header
    const header = rows[0].map((h) => h.replace(/"/g, '').trim().toUpperCase());
    const nameIdx = header.findIndex((h) => h.includes('NOMBRE'));
    const emailIdx = header.findIndex((h) => h.includes('CORREO'));
    const entidadIdx = header.findIndex((h) => h.includes('ENTIDAD'));
    const cargoIdx = header.findIndex((h) => h.includes('CARGO'));

    if (nameIdx < 0 || emailIdx < 0 || entidadIdx < 0) {
      console.error('❌ El CSV no tiene las columnas requeridas (NOMBRE, CORREO ELECTRONICO, ENTIDAD)');
      process.exit(1);
    }

    console.log('📊 Procesando usuarios del CSV...\n');

    let updated = 0;
    let notFound = 0;
    let skipped = 0;

    for (let i = 1; i < rows.length; i += 1) {
      const cols = rows[i].map((c) => c.replace(/"/g, '').trim());
      const fullName = nameIdx >= 0 ? cols[nameIdx] : '';
      const email = sanitizeEmail(emailIdx >= 0 ? cols[emailIdx] : '');
      const entidad = entidadIdx >= 0 ? cols[entidadIdx] : '';
      const cargo = cargoIdx >= 0 ? cols[cargoIdx] : '';

      // Saltar filas sin email válido o que sean placeholders
      if (!email || email === '-' || !email.includes('@')) {
        skipped++;
        continue;
      }

      // Saltar filas que son placeholders
      if (fullName.toUpperCase().includes('PERFIL') || fullName.toUpperCase().includes('ESPECIALISTA')) {
        skipped++;
        continue;
      }

      try {
        const existingUser = await prisma.user.findUnique({
          where: { email },
        });

        if (!existingUser) {
          console.log(`⚠️  Usuario no encontrado: ${email} (${fullName})`);
          notFound++;
          continue;
        }

        const newProjectRole = determineProjectRole(entidad, cargo);

        // Solo actualizar si el projectRole es diferente
        if (existingUser.projectRole !== newProjectRole) {
          await prisma.user.update({
            where: { email },
            data: {
              projectRole: newProjectRole,
              fullName: fullName || existingUser.fullName, // Actualizar nombre si está vacío
            },
          });

          console.log(`✅ Actualizado: ${fullName} (${email})`);
          console.log(`   ENTIDAD: ${entidad} | CARGO: ${cargo} | projectRole: ${existingUser.projectRole} → ${newProjectRole}\n`);
          updated++;
        } else {
          console.log(`ℹ️  Sin cambios: ${fullName} (${email}) - projectRole ya es ${newProjectRole}\n`);
        }
      } catch (error) {
        console.error(`❌ Error actualizando ${email}:`, error.message);
      }
    }

    console.log('\n📈 Resumen:');
    console.log(`   ✅ Usuarios actualizados: ${updated}`);
    console.log(`   ⚠️  Usuarios no encontrados: ${notFound}`);
    console.log(`   ⏭️  Filas saltadas: ${skipped}`);
    console.log(`   📊 Total procesado: ${rows.length - 1}\n`);

    console.log('✅ Actualización completada');
  } catch (error) {
    console.error('❌ Error durante la actualización:', error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

updateUsersFromCsv().catch((error) => {
  console.error(error);
  process.exit(1);
});

