import { parseStringPromise } from "xml2js";

export interface CronTaskRecord {
  id?: string;
  name: string;
  startDate: string;
  endDate?: string;
  duration?: number;
  progress?: number;
  outlineLevel?: number;
}

export class CronogramaValidationError extends Error {
  constructor(message: string, public details?: unknown) {
    super(message);
    this.name = "CronogramaValidationError";
  }
}

export const validateCronogramaXml = async (xmlContent: string): Promise<CronTaskRecord[]> => {
  if (!xmlContent?.trim()) {
    throw new CronogramaValidationError("El archivo XML está vacío.");
  }

  let parsed: any;
  try {
    parsed = await parseStringPromise(xmlContent, {
      explicitArray: false,
      mergeAttrs: true,
      trim: true,
    });
  } catch (error) {
    throw new CronogramaValidationError("No se pudo interpretar el XML del cronograma.", error);
  }

  let rows =
    parsed?.Workbook?.Worksheet?.Table?.Row ||
    parsed?.Project?.Tasks?.Task ||
    [];

  if (!Array.isArray(rows)) {
    rows = rows ? [rows] : [];
  }

  if (!rows.length) {
    throw new CronogramaValidationError("El XML no contiene tareas reconocibles.");
  }

  const tasks: CronTaskRecord[] = [];
  rows.forEach((row: any) => {
    const extract = (key: string) => {
      const value = row[key] || row[`_${key}`];
      if (typeof value === "object" && value?._) {
        return String(value._);
      }
      return value ? String(value) : "";
    };

    const name = extract("Name") || extract("name") || extract("TaskName");
    const start = extract("Start") || extract("startDate") || extract("StartDate");

    if (!name) {
      return;
    }
    if (!start) {
      throw new CronogramaValidationError(`La tarea "${name}" no tiene fecha de inicio.`);
    }

    tasks.push({
      id: extract("UID") || extract("Id") || undefined,
      name,
      startDate: start,
      endDate: extract("Finish") || extract("endDate") || undefined,
      progress: Number(extract("PercentComplete")) || undefined,
      duration: Number(extract("Duration")) || undefined,
      outlineLevel: Number(extract("OutlineLevel")) || undefined,
    });
  });

  if (!tasks.length) {
    throw new CronogramaValidationError(
      "No se encontraron tareas válidas en el XML. Verifica el formato de exportación."
    );
  }

  return tasks;
};
