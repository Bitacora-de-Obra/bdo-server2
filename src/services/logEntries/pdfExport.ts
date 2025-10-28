import path from "path";
import fs from "fs/promises";
import fsSync from "fs";
import PDFDocument from "pdfkit";
import { PrismaClient } from "@prisma/client";

const GENERATED_SUBDIR = "generated";

const entryStatusLabels: Record<string, string> = {
  DRAFT: "Borrador",
  SUBMITTED: "Radicado",
  NEEDS_REVIEW: "En Revisión",
  APPROVED: "Aprobado",
  REJECTED: "Rechazado",
};

const entryTypeLabels: Record<string, string> = {
  GENERAL: "General",
  QUALITY: "Calidad",
  SAFETY: "HSE",
  ADMINISTRATIVE: "Administrativo",
  TECHNICAL: "Técnico",
};

interface LogEntryPdfOptions {
  prisma: PrismaClient;
  logEntryId: string;
  uploadsDir: string;
  baseUrl: string;
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

const formatDateTime = (input: Date) =>
  new Intl.DateTimeFormat("es-CO", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(input);

export const generateLogEntryPdf = async ({
  prisma,
  logEntryId,
  uploadsDir,
  baseUrl,
}: LogEntryPdfOptions) => {
  const entry = await prisma.logEntry.findUnique({
    where: { id: logEntryId },
    include: {
      author: true,
      attachments: true,
      comments: { include: { author: true }, orderBy: { timestamp: "asc" } },
      signatures: { include: { signer: true } },
      assignees: true,
    },
  });

  if (!entry) {
    throw new Error("Anotación no encontrada.");
  }

  const project = await prisma.project.findUnique({
    where: { id: entry.projectId },
  });

  const generatedDir = path.join(uploadsDir, GENERATED_SUBDIR);
  await fs.mkdir(generatedDir, { recursive: true });

  const safeTitle = sanitizeFileName(entry.title || "bitacora");
  const entryDateObj = entry.entryDate
    ? new Date(entry.entryDate)
    : null;
  const entryDate =
    entryDateObj && !Number.isNaN(entryDateObj.getTime())
      ? formatDate(entryDateObj)
      : "Sin fecha";
  const entryDateSlug =
    entryDateObj && !Number.isNaN(entryDateObj.getTime())
      ? entryDateObj.toISOString().split("T")[0]
      : "sin-fecha";

  const fileName = `bitacora-${safeTitle}-${entryDateSlug}.pdf`;
  const filePath = path.join(generatedDir, fileName);

  await new Promise<void>((resolve, reject) => {
    const doc = new PDFDocument({ size: "LETTER", margin: 48 });
    const writeStream = fsSync.createWriteStream(filePath);

    doc.on("error", reject);
    writeStream.on("error", reject);
    writeStream.on("finish", resolve);

    doc.pipe(writeStream);

    doc
      .font("Helvetica-Bold")
      .fontSize(20)
      .text(project ? `${project.name} · Bitácora diaria` : "Bitácora diaria", {
        align: "center",
      })
      .moveDown(0.5);

    doc
      .font("Helvetica")
      .fontSize(12)
      .text(`Folio #${entry.folioNumber}`, { align: "center" })
      .moveDown(0.2);

    doc
      .fontSize(11)
      .text(`Fecha de la jornada: ${entryDate}`, { align: "center" })
      .moveDown();

    doc
      .font("Helvetica-Bold")
      .fontSize(14)
      .text(entry.title, { align: "center" })
      .moveDown();

    const infoRows: Array<[string, string]> = [
      ["Autor", entry.author?.fullName || "—"],
      ["Correo autor", entry.author?.email || "—"],
      ["Estado", entryStatusLabels[entry.status] || entry.status],
      ["Tipo", entryTypeLabels[entry.type] || entry.type],
      ["Confidencial", entry.isConfidential ? "Sí" : "No"],
      [
        "Asignados",
        entry.assignees.length
          ? entry.assignees.map((user) => user.fullName).join(", ")
          : "—",
      ],
      [
        "Registrado",
        entry.createdAt ? formatDateTime(new Date(entry.createdAt)) : "—",
      ],
      [
        "Actualizado",
        entry.updatedAt ? formatDateTime(new Date(entry.updatedAt)) : "—",
      ],
    ];

    if (project) {
      infoRows.push(["Contrato", project.contractId || "—"]);
    }

    infoRows.forEach(([label, value]) => {
      doc
        .font("Helvetica-Bold")
        .fontSize(11)
        .text(`${label}: `, { continued: true })
        .font("Helvetica")
        .text(value || "—");
    });

    const sections: Array<[string, string]> = [
      ["Resumen general del día", entry.description || "Sin resumen."],
      ["Actividades realizadas", entry.activitiesPerformed || "Sin registro."],
      ["Materiales utilizados", entry.materialsUsed || "Sin registro."],
      ["Personal en obra", entry.workforce || "Sin registro."],
      [
        "Condiciones climáticas",
        entry.weatherConditions || "Sin registro.",
      ],
      [
        "Observaciones adicionales",
        entry.additionalObservations || "Sin observaciones.",
      ],
    ];

    sections.forEach(([title, value]) => {
      doc.moveDown();
      doc.font("Helvetica-Bold").fontSize(13).text(title);
      doc.moveDown(0.25);
      doc
        .font("Helvetica")
        .fontSize(11)
        .text(value, {
          align: "justify",
        });
    });

    doc.moveDown();
    doc.font("Helvetica-Bold").fontSize(13).text("Firmas registradas");
    doc.moveDown(0.25);
    if (!entry.signatures.length) {
      doc.font("Helvetica").fontSize(11).text("No hay firmas registradas.");
    } else {
      entry.signatures.forEach((signature, index) => {
        const signerName = signature.signer?.fullName || "Firmante";
        const signedAt = signature.signedAt
          ? formatDateTime(new Date(signature.signedAt))
          : "Pendiente";
        doc
          .font("Helvetica")
          .fontSize(11)
          .text(`${index + 1}. ${signerName} — ${signedAt}`);
      });
    }

    doc.moveDown();
    doc
      .font("Helvetica-Bold")
      .fontSize(13)
      .text("Comentarios")
      .moveDown(0.25);

    if (!entry.comments.length) {
      doc.font("Helvetica").fontSize(11).text("Sin comentarios registrados.");
    } else {
      entry.comments.forEach((comment, index) => {
        const authorName = comment.author?.fullName || "Usuario";
        const timestamp = comment.timestamp
          ? formatDateTime(new Date(comment.timestamp))
          : "—";
        doc
          .font("Helvetica-Bold")
          .fontSize(11)
          .text(`${index + 1}. ${authorName} — ${timestamp}`);
        doc
          .font("Helvetica")
          .fontSize(11)
          .text(comment.content || "Sin contenido.")
          .moveDown(0.2);
      });
    }

    doc.moveDown();
    doc
      .font("Helvetica-Bold")
      .fontSize(13)
      .text("Adjuntos")
      .moveDown(0.25);

    if (!entry.attachments.length) {
      doc.font("Helvetica").fontSize(11).text("No hay archivos adjuntos.");
    } else {
      entry.attachments.forEach((attachment, index) => {
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
  const attachment = await prisma.attachment.create({
    data: {
      fileName,
      url: `${baseUrl}/uploads/${GENERATED_SUBDIR}/${fileName}`,
      size: stats.size,
      type: "application/pdf",
    },
  });

  await prisma.logEntry.update({
    where: { id: logEntryId },
    data: {
      attachments: {
        connect: { id: attachment.id },
      },
    },
  });

  return {
    attachment,
    fileName,
    filePath,
  };
};
