/* eslint-disable no-console */
// Extract basic project data from an interventoría PDF.
// Usage: node scripts/extractProjectFromPdf.js "uploads/INFORME TECNICO No. 8-SEPTIEMBRE V2.pdf"
//
// Heuristic extraction: searches for lines containing keywords and applies regex.

const fs = require('fs');
const path = require('path');
const pdf = require('pdf-parse');

function loadBuffer(filePath) {
  const abs = path.isAbsolute(filePath) ? filePath : path.join(__dirname, '..', filePath);
  if (!fs.existsSync(abs)) {
    throw new Error(`File not found: ${abs}`);
  }
  return { abs, buffer: fs.readFileSync(abs) };
}

function normalizeText(text) {
  return text
    .replace(/\r/g, '\n')
    .replace(/\u00A0/g, ' ')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/[ \t]{2,}/g, ' ')
    .trim();
}

function findFirst(regex, hay) {
  const m = hay.match(regex);
  return m ? (m[1] || m[0]) : null;
}

function looksLikeHeader(line) {
  const stripped = line.replace(/[^\p{L}0-9 ]/gu, '').trim();
  if (stripped.length < 3) return false;
  // Mostly uppercase letters
  const letters = stripped.replace(/[^A-Za-zÁÉÍÓÚÑÜáéíóúñü]/g, '');
  if (!letters) return false;
  const upperRatio = letters.replace(/[a-záéíóúñü]/g, '').length / letters.length;
  return upperRatio > 0.7;
}

function getBlockAfter(lines, startIndex, maxLines = 12) {
  const parts = [];
  for (let i = startIndex + 1; i < Math.min(lines.length, startIndex + 1 + maxLines); i += 1) {
    const ln = lines[i].trim();
    if (!ln) break;
    // stop if next section heading like "1.3", "2.", "ALCANCE", etc.
    if (/^\d+(\.\d+)*(\s|$)/.test(ln)) break;
    if (looksLikeHeader(ln) && ln.length < 120) break;
    // skip toc-like lines with leader dots
    if (/[\.•·]{3,}\s*\d+$/.test(ln)) continue;
    parts.push(ln);
  }
  return parts.join(' ');
}

function getValueAfterKeyword(lines, regex) {
  for (let i = 0; i < lines.length; i += 1) {
    const ln = lines[i];
    const m = ln.match(regex);
    if (m) {
      const after = ln.replace(regex, '').trim();
      if (after) return after;
      // fallback to next non-empty line
      for (let j = i + 1; j < Math.min(lines.length, i + 4); j += 1) {
        const n = lines[j].trim();
        if (n) return n;
      }
    }
  }
  return null;
}

function extractTableKV(lines, startRegex, stopAfterLines = 100) {
  // Find start line (e.g., /^Tabla 2\./i or /^Tabla 4\./i) and collect subsequent lines
  let start = -1;
  for (let i = 0; i < lines.length; i += 1) {
    if (startRegex.test(lines[i])) {
      start = i;
      break;
    }
  }
  if (start < 0) return {};

  const kv = {};
  const end = Math.min(lines.length, start + stopAfterLines);
  for (let i = start + 1; i < end; i += 1) {
    const ln = lines[i].trim();
    if (!ln) continue;
    // Stop if next table or big header appears
    if (/^Tabla\s+\d+/i.test(ln)) break;
    if (looksLikeHeader(ln) && ln.length < 60) {
      // Allow short header rows inside the table
      // but if it's clearly a new section, stop
      if (/^\d+(\.\d+)*(\s|$)/.test(ln)) break;
    }
    // Patterns:
    // "Campo: Valor"
    let m = ln.match(/^([A-Za-zÁÉÍÓÚÑÜáéíóúñü .\/()-]+)\s*[:\-]\s*(.+)$/);
    if (m) {
      const key = m[1].trim().replace(/\s+/g, ' ');
      const val = m[2].trim();
      kv[key] = val;
      continue;
    }
    // "Campo" line followed by "Valor" on next line
    if (i + 1 < end) {
      const next = lines[i + 1].trim();
      if (next && !looksLikeHeader(next) && !/^Tabla\s+\d+/i.test(next)) {
        // Heuristic: short key and longer value
        if (ln.length <= 40 && next.length > 3 && !/:$/.test(ln)) {
          kv[ln] = next;
          i += 1;
          continue;
        }
      }
    }
  }
  return kv;
}

function extract(text) {
  const t = normalizeText(text);
  const lines = t.split('\n').map((l) => l.trim()).filter((l) => l.length > 0);

  // Contract numbers (obra / interventoría)
  const obraId = findFirst(/Contrato\s+de\s+Obra\s*(?:No\.?|N°|Nº)?\s*[:\-]?\s*([A-Z0-9\-\/_.]+)/i, t);
  const interId = findFirst(/Contrato\s+de\s+Interventor[ií]a\s*(?:No\.?|N°|Nº)?\s*[:\-]?\s*([A-Z0-9\-\/_.]+)/i, t);
  const anyId = findFirst(/\b(IDU-[A-Z0-9\-\/_.]+)\b/i, t);

  // Dates near keywords
  const dateRegex = /(\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b)/;
  let startDate = null;
  let endDate = null;
  for (const ln of lines) {
    const lower = ln.toLowerCase();
    const m = ln.match(dateRegex);
    if (!m) continue;
    if (!startDate && (lower.includes('inicio') || lower.includes('acta de inicio'))) {
      startDate = m[1];
      continue;
    }
    if (!endDate && (lower.includes('termin') || lower.includes('final') || lower.includes('plazo hasta'))) {
      endDate = m[1];
    }
  }
  // Fallback: first two dates found
  if (!startDate || !endDate) {
    const allDates = Array.from(t.matchAll(/\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b/g)).map((m) => m[0]);
    if (!startDate && allDates[0]) startDate = allDates[0];
    if (!endDate && allDates[1]) endDate = allDates[1];
  }

  // Object block
  let object = null;
  for (let i = 0; i < lines.length; i += 1) {
    if (/^OBJETO\b/i.test(lines[i]) || /Objeto\s+del\s+Contrato/i.test(lines[i]) || /OBJETO\s+DEL\s+CONTRATO/i.test(lines[i])) {
      const inline = lines[i].replace(/^(OBJETO|Objeto\s+del\s+Contrato|OBJETO\s+DEL\s+CONTRATO)\s*[:\-]?\s*/i, '').trim();
      object = inline || getBlockAfter(lines, i, 20);
      if (object) break;
    }
  }
  if (object) {
    // cleanup index artifacts
    object = object.replace(/[\.•·]{3,}\s*\d+$/g, '').trim();
  }

  // Contractor / Interventoría names
  let contractorName = findFirst(/(?:Contratista|CONTRATISTA)\s*[:\-]\s*([^\n]+)/, t);
  let interventoriaName = findFirst(/(?:Interventor[ií]a|INTERVENTORÍA)\s*[:\-]\s*([^\n]+)/, t);

  if (!contractorName) {
    // Sometimes tables show "... Contratista\n<Nombre>"
    for (let i = 0; i < lines.length - 1; i += 1) {
      if (/^Contratista$/i.test(lines[i])) {
        contractorName = lines[i + 1];
        break;
      }
    }
  }
  if (!interventoriaName) {
    for (let i = 0; i < lines.length - 1; i += 1) {
      if (/^Interventor[ií]a$/i.test(lines[i]) || /^Interventoría$/i.test(lines[i])) {
        interventoriaName = lines[i + 1];
        break;
      }
    }
  }

  // Try read from "Datos generales del contrato" style tables
  const table2 = extractTableKV(lines, /^Tabla\s+2\b/i);
  const table4 = extractTableKV(lines, /^Tabla\s+4\b/i);
  const tableContractor =
    table2['Contratista'] ||
    table4['Contratista'] ||
    getValueAfterKeyword(lines, /^(?:Contratista|CONTRATISTA)\s*[:\-]\s*/i);
  const tableInterv =
    table2['Interventoría'] ||
    table2['Interventoria'] ||
    table4['Interventoría'] ||
    table4['Interventoria'] ||
    getValueAfterKeyword(lines, /^(?:Interventor[ií]a|INTERVENTORÍA)\s*[:\-]\s*/i);
  const obraNum =
    table2['Contrato de Obra No.'] ||
    table2['Contrato de obra No.'] ||
    table2['Contrato No.'] ||
    table4['Contrato de Obra No.'] ||
    table4['Contrato No.'];
  const interNum =
    table4['Contrato de Interventoría No.'] ||
    table4['Contrato de interventoría No.'] ||
    table4['Contrato No.'];
  const actaInicio =
    table2['Acta de inicio'] ||
    table2['Fecha de inicio'] ||
    table4['Acta de inicio'] ||
    getValueAfterKeyword(lines, /(Acta\s+de\s+inicio|Fecha\s+de\s+inicio)\s*[:\-]\s*/i);
  const fechaFin =
    table2['Fecha de terminación'] ||
    table2['Plazo hasta'] ||
    table4['Fecha de terminación'] ||
    getValueAfterKeyword(lines, /(Fecha\s+de\s+terminaci[oó]n|Plazo\s+hasta)\s*[:\-]\s*/i);
  if (!contractorName && tableContractor) contractorName = tableContractor;
  if (!interventoriaName && tableInterv) interventoriaName = tableInterv;
  if (!startDate && actaInicio) startDate = (actaInicio.match(/\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}/) || [null])[0];
  if (!endDate && fechaFin) endDate = (fechaFin.match(/\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}/) || [null])[0];
  // Prefer table-provided contract ids
  const obraIdClean = obraNum ? obraNum.replace(/[^A-Za-z0-9\-\/_.]/g, '') : null;
  const interIdClean = interNum ? interNum.replace(/[^A-Za-z0-9\-\/_.]/g, '') : null;

  // Key Personnel
  const keyPersonnel = [];
  for (let i = 0; i < lines.length; i += 1) {
    if (/PERSONAL\s+CLAVE|Personal\s+Clave|PERSONAL\s+DEL\s+CONTRATO/i.test(lines[i])) {
      const block = getBlockAfter(lines, i, 60);
      const blines = block.split(/\s{2,}|\n/);
      for (const ln of blines) {
        const m = ln.match(/([A-ZÁÉÍÓÚÑ][A-Za-zÁÉÍÓÚÑñüÜ.'\-\s]+)\s+\-\s*([A-Za-zÁÉÍÓÚÑñüÜ.'\-\s]+)/);
        if (m) keyPersonnel.push({ name: m[1].trim(), role: m[2].trim() });
      }
      break;
    }
  }

  return {
    obraContractId: obraIdClean || obraId || null,
    interventoriaContractId: interIdClean || interId || null,
    anyContractId: anyId || null,
    startDate: startDate || null,
    endDate: endDate || null,
    contractorName: contractorName ? contractorName.trim() : null,
    interventoriaName: interventoriaName ? interventoriaName.trim() : null,
    object: object || null,
    keyPersonnel,
  };
}

async function main() {
  const input = process.argv[2];
  if (!input) {
    console.error('Usage: node scripts/extractProjectFromPdf.js <pdf-file>');
    process.exit(1);
  }
  const { abs, buffer } = loadBuffer(input);
  const data = await pdf(buffer);
  const result = extract(data.text || '');
  const outPath = path.join(path.dirname(abs), 'extracted-project.json');
  fs.writeFileSync(outPath, JSON.stringify(result, null, 2), 'utf8');
  console.log(JSON.stringify(result, null, 2));
  console.log(`\nSaved: ${outPath}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});


