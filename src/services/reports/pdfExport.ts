import path from "path";
import fs from "fs/promises";

export interface PdfExportOptions {
  reportId: string;
  template?: string;
}

export const generateReportPdf = async ({ reportId }: PdfExportOptions) => {
  const fileName = `reporte-${reportId}.pdf`;
  const filePath = path.join(__dirname, "../../../uploads/generated", fileName);
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, Buffer.from("PDF not implemented"));
  return { fileName, filePath };
};
