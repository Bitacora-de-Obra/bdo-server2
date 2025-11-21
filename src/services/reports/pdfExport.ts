import path from "path";
import fs from "fs/promises";
import fsSync from "fs";
import PDFDocument from "pdfkit";
import { PrismaClient } from "@prisma/client";
import { getStorage } from "../../storage";

const GENERATED_SUBDIR = "generated";

interface PdfExportOptions {
  prisma: PrismaClient;
  reportId: string;
  uploadsDir: string;
  baseUrl: string;
  template?: string;
}

const sanitizeFileName = (value: string) =>
  value
    .normalize("NFD")
    .replace(/[^a-zA-Z0-9-_.]+/g, "_")
    .replace(/_{2,}/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 120);

const formatDate = (input: Date) =>
  new Intl.DateTimeFormat("es-CO", {
    year: "numeric",
    month: "long",
    day: "numeric",
  }).format(input);

const formatDateTime = (input: Date, timeZone?: string) =>
  new Intl.DateTimeFormat("es-CO", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    timeZone,
  }).format(input);

const parseRequiredSignatories = (value?: string | null) => {
  if (!value) {
    return [] as Array<{ name?: string; role?: string }>;
  }
  try {
    const parsed = JSON.parse(value);
    if (Array.isArray(parsed)) {
      return parsed as Array<{ name?: string; role?: string }>;
    }
  } catch (error) {
    console.warn("No se pudo parsear requiredSignatoriesJson", { error });
  }
  return [] as Array<{ name?: string; role?: string }>;
};

export const generateReportPdf = async ({
  prisma,
  reportId,
  uploadsDir,
  baseUrl,
}: PdfExportOptions) => {
  const report = await prisma.report.findUnique({
    where: { id: reportId },
    include: {
      author: true,
      attachments: true,
      signatures: { include: { signer: true } },
    },
  });

  if (!report) {
    throw new Error("Informe no encontrado.");
  }

  const project = await prisma.project.findFirst();

  const generatedDir = path.join(uploadsDir, GENERATED_SUBDIR);
  await fs.mkdir(generatedDir, { recursive: true });

  const safeNumber = sanitizeFileName(report.number || "informe");
  const timestamp = new Date();
  const fileName = `${safeNumber || "informe"}-v${report.version}-${
    timestamp.toISOString().split("T")[0]
  }.pdf`;
  const filePath = path.join(generatedDir, fileName);

  await new Promise<void>((resolve, reject) => {
    const doc = new PDFDocument({ size: "LETTER", margin: 48 });
    const writeStream = fsSync.createWriteStream(filePath);

    doc.on("error", reject);
    writeStream.on("error", reject);
    writeStream.on("finish", resolve);

    doc.pipe(writeStream);

    const titleLabel =
      report.type === "Weekly"
        ? "Informe Semanal"
        : report.type === "Monthly"
        ? "Informe Mensual"
        : `Informe ${report.type}`;

    const scopeLabel =
      report.reportScope === "OBRA"
        ? "Obra"
        : report.reportScope === "INTERVENTORIA"
        ? "Interventoría"
        : report.reportScope;

    doc
      .font("Helvetica-Bold")
      .fontSize(20)
      .text(`${titleLabel} · ${scopeLabel}`, { align: "center" })
      .moveDown(0.5);

    doc
      .fontSize(12)
      .font("Helvetica")
      .text(`Generado el ${formatDate(timestamp)} a las ${timestamp.toLocaleTimeString("es-CO")}`, {
        align: "center",
      })
      .moveDown();

    const infoRows: Array<[string, string]> = [
      ["Número", report.number],
      ["Versión", `v${report.version}`],
      ["Estado", report.status],
      ["Periodo", report.period],
      ["Presentado", formatDate(new Date(report.submissionDate))],
      ["Autor", report.author.fullName],
      ["Correo autor", report.author.email],
    ];

    if (project) {
      infoRows.push(["Proyecto", project.name]);
      infoRows.push(["Contrato", project.contractId ?? "—"]);
    }

    infoRows.forEach(([label, value]) => {
      doc
        .font("Helvetica-Bold")
        .text(`${label}: `, { continued: true })
        .font("Helvetica")
        .text(value || "—");
    });

    doc.moveDown();

    doc.font("Helvetica-Bold").fontSize(14).text("Resumen ejecutivo");
    doc.moveDown(0.35);
    doc
      .font("Helvetica")
      .fontSize(11)
      .text(report.summary || "Sin resumen proporcionado.", {
        align: "justify",
      });

    const requiredSignatories = parseRequiredSignatories(
      report.requiredSignatoriesJson
    );

    if (requiredSignatories.length) {
      doc.moveDown();
      doc.font("Helvetica-Bold").fontSize(14).text("Firmantes requeridos");
      doc.moveDown(0.3);
      requiredSignatories.forEach((person, index) => {
        const line = [
          `${index + 1}. ${person.name ?? "Firmante"}`,
          person.role ? ` (${person.role})` : "",
        ].join("");
        doc.font("Helvetica").fontSize(11).text(line);
      });
    }

    const signatures = report.signatures ?? [];
    doc.moveDown();
    doc.font("Helvetica-Bold").fontSize(14).text("Firmas registradas");
    doc.moveDown(0.3);
    if (!signatures.length) {
      doc.font("Helvetica").fontSize(11).text("No hay firmas registradas.");
    } else {
      signatures.forEach((signature, index) => {
        const signerName = signature.signer?.fullName ?? "Firmante";
        const signedAt = signature.signedAt
          ? formatDateTime(new Date(signature.signedAt))
          : "Pendiente";
        doc
          .font("Helvetica")
          .fontSize(11)
          .text(`${index + 1}. ${signerName} — ${signedAt}`);
      });
    }

    const attachments = report.attachments ?? [];
    doc.moveDown();
    doc.font("Helvetica-Bold").fontSize(14).text("Adjuntos existentes");
    doc.moveDown(0.3);

    if (!attachments.length) {
      doc.font("Helvetica").fontSize(11).text("No se registran adjuntos en el informe.");
    } else {
      attachments.forEach((attachment, index) => {
        doc
          .font("Helvetica")
          .fontSize(11)
          .text(
            `${index + 1}. ${attachment.fileName} (${attachment.type || "desconocido"})`,
            {
              link: attachment.url,
              underline: Boolean(attachment.url),
            }
          );
      });
    }

    doc.end();
  });

  const stats = await fs.stat(filePath);
  
  // Leer el PDF generado
  const pdfBuffer = await fs.readFile(filePath);
  
  // Subir a Cloudflare R2 (o almacenamiento configurado)
  const storage = getStorage();
  const storagePath = path.posix.join(GENERATED_SUBDIR, fileName);
  await storage.save({
    path: storagePath,
    content: pdfBuffer,
  });
  
  // Obtener la URL pública del almacenamiento
  const publicUrl = storage.getPublicUrl(storagePath);
  
  const attachment = await prisma.attachment.create({
    data: {
      fileName,
      url: publicUrl,
      storagePath,
      size: stats.size,
      type: "application/pdf",
    },
  });

  await prisma.report.update({
    where: { id: reportId },
    data: {
      attachments: {
        connect: { id: attachment.id },
      },
    },
  });

  // Limpiar archivo temporal local
  try {
    await fs.unlink(filePath);
  } catch (error) {
    console.warn('No se pudo eliminar el archivo temporal:', error);
  }

  return {
    attachment,
    fileName,
    filePath: publicUrl, // Retornar la URL pública en lugar del path local
  };
};
