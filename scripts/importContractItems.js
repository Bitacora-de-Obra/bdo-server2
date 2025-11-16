/* eslint-disable no-console */
const { PrismaClient } = require('@prisma/client');
const fs = require('fs');
const path = require('path');

const prisma = new PrismaClient();

/**
 * Parsea un valor monetario del formato colombiano ($ 1.122,00) a número
 */
function parseCurrency(valueStr) {
  if (!valueStr || valueStr === 'NA' || valueStr === '-') return null;
  // Remover $, espacios, y puntos (separadores de miles)
  // Reemplazar coma decimal por punto
  const cleaned = valueStr
    .replace(/\$/g, '')
    .replace(/\s/g, '')
    .replace(/\./g, '')
    .replace(',', '.');
  return parseFloat(cleaned) || null;
}

/**
 * Parsea una línea CSV respetando comillas
 */
function parseCSVLine(line) {
  const result = [];
  let current = '';
  let inQuotes = false;
  
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    const nextChar = line[i + 1];
    
    if (char === '"') {
      if (inQuotes && nextChar === '"') {
        // Comilla escapada
        current += '"';
        i++; // Saltar la siguiente comilla
      } else {
        // Toggle estado de comillas
        inQuotes = !inQuotes;
      }
    } else if (char === ',' && !inQuotes) {
      // Separador de campo
      result.push(current.trim());
      current = '';
    } else {
      current += char;
    }
  }
  
  // Agregar el último campo
  result.push(current.trim());
  
  return result;
}

/**
 * Lee y parsea el CSV de items del contrato
 */
function parseCSV(csvPath) {
  const content = fs.readFileSync(csvPath, 'utf-8');
  const lines = content.split('\n').filter(line => line.trim());
  
  // Saltar el header
  const dataLines = lines.slice(1);
  
  const items = [];
  
  for (const line of dataLines) {
    const fields = parseCSVLine(line);
    
    if (fields.length < 4) {
      console.warn(`⚠️  Saltando línea con campos insuficientes: ${line.substring(0, 50)}...`);
      continue;
    }
    
    const itemCode = fields[0].replace(/^"|"$/g, '').trim();
    const description = fields[1].replace(/^"|"$/g, '').trim();
    const unit = fields[2].replace(/^"|"$/g, '').trim();
    const unitPriceStr = fields[3].replace(/^"|"$/g, '').trim();
    
    const unitPrice = parseCurrency(unitPriceStr);
    
    if (!itemCode || !description || !unit || unitPrice === null) {
      console.warn(`⚠️  Saltando línea inválida: ${line.substring(0, 50)}...`);
      continue;
    }
    
    items.push({
      itemCode,
      description,
      unit,
      unitPrice,
      contractQuantity: 0, // Se actualizará cuando se tengan las cantidades contratadas
    });
  }
  
  return items;
}

async function importContractItems() {
  try {
    console.log('📦 Iniciando importación de items del contrato...\n');
    
    const csvPath = path.join(__dirname, '../uploads/extraeme de la pagina 146 a la 159 y hazme un exc... - extraeme de la pagina 146 a la 159 y hazme un exc....csv');
    
    if (!fs.existsSync(csvPath)) {
      console.error(`❌ No se encontró el archivo CSV en: ${csvPath}`);
      process.exit(1);
    }
    
    const items = parseCSV(csvPath);
    console.log(`📊 Se encontraron ${items.length} items en el CSV\n`);
    
    let created = 0;
    let updated = 0;
    let errors = 0;
    
    for (const item of items) {
      try {
        // Intentar actualizar si existe, crear si no
        const existing = await prisma.contractItem.findUnique({
          where: { itemCode: item.itemCode },
        });
        
        if (existing) {
          await prisma.contractItem.update({
            where: { itemCode: item.itemCode },
            data: {
              description: item.description,
              unit: item.unit,
              unitPrice: item.unitPrice,
              // Mantener contractQuantity si ya existe
            },
          });
          updated++;
          console.log(`✅ Actualizado: ${item.itemCode} - ${item.description.substring(0, 50)}...`);
        } else {
          await prisma.contractItem.create({
            data: item,
          });
          created++;
          console.log(`➕ Creado: ${item.itemCode} - ${item.description.substring(0, 50)}...`);
        }
      } catch (error) {
        errors++;
        console.error(`❌ Error procesando ${item.itemCode}:`, error.message);
      }
    }
    
    console.log('\n📈 Resumen de importación:');
    console.log(`   ➕ Items creados: ${created}`);
    console.log(`   ✅ Items actualizados: ${updated}`);
    console.log(`   ❌ Errores: ${errors}`);
    console.log(`   📊 Total procesado: ${items.length}\n`);
    
    console.log('✅ Importación completada exitosamente');
  } catch (error) {
    console.error('❌ Error durante la importación:', error);
    throw error;
  } finally {
    await prisma.$disconnect();
  }
}

importContractItems()
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

