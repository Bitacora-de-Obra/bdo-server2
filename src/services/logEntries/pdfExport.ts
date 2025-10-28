import path from "path";
import fs from "fs/promises";
import fsSync from "fs";
import PDFDocument from "pdfkit";
import { PrismaClient } from "@prisma/client";
import {
  normalizeEquipmentEntries,
  normalizeListItems,
  normalizePersonnelEntries,
  normalizeWeatherReport,
} from "../../utils/logEntryNormalization";

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

const projectRoleLabels: Record<string, string> = {
  RESIDENT: "Residente de Obra",
  SUPERVISOR: "Supervisor",
  CONTRACTOR_REP: "Representante Contratista",
  ADMIN: "Administrador IDU",
};

const signatureTaskStatusLabels: Record<string, string> = {
  PENDING: "Pendiente de firma",
  SIGNED: "Firmado",
  DECLINED: "Rechazado",
  CANCELLED: "Cancelado",
};

const signatureTaskStatusColors: Record<string, string> = {
  PENDING: "#92400E",
  SIGNED: "#15803D",
  DECLINED: "#B91C1C",
  CANCELLED: "#4B5563",
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
      signatureTasks: {
        include: { signer: true },
        orderBy: { assignedAt: "asc" },
      },
    },
  });

  if (!entry) {
    throw new Error("Anotación no encontrada.");
  }

  const project = await prisma.project.findUnique({
    where: { id: entry.projectId },
  });

  const contractorPersonnel = normalizePersonnelEntries(entry.contractorPersonnel);
  const interventoriaPersonnel = normalizePersonnelEntries(
    entry.interventoriaPersonnel
  );
  const equipmentResources = normalizeEquipmentEntries(entry.equipmentResources);
  const executedActivities = normalizeListItems(entry.executedActivities);
  const executedQuantities = normalizeListItems(entry.executedQuantities);
  const scheduledActivities = normalizeListItems(entry.scheduledActivities);
  const qualityControls = normalizeListItems(entry.qualityControls);
  const materialsReceived = normalizeListItems(entry.materialsReceived);
  const safetyNotes = normalizeListItems(entry.safetyNotes);
  const projectIssues = normalizeListItems(entry.projectIssues);
  const siteVisits = normalizeListItems(entry.siteVisits);
  const weatherReportNormalized = normalizeWeatherReport(entry.weatherReport);

  const formatPersonnelEntry = (person: ReturnType<
    typeof normalizePersonnelEntries
  >[number]) => {
    const quantity =
      typeof person.quantity === "number" && !Number.isNaN(person.quantity)
        ? `${person.quantity}`
        : null;
    const base = quantity ? `${quantity} · ${person.role}` : person.role;
    return person.notes ? `${base} — ${person.notes}` : base;
  };

  const formatEquipmentEntry = (
    item: ReturnType<typeof normalizeEquipmentEntries>[number]
  ) => {
    let label = item.name;
    if (item.status) {
      label += ` — ${item.status}`;
    }
    if (item.notes) {
      label += item.status ? ` (${item.notes})` : ` — ${item.notes}`;
    }
    return label;
  };

  const contractorPersonnelLines = contractorPersonnel
    .map(formatPersonnelEntry)
    .filter((value): value is string => Boolean(value));
  const interventoriaPersonnelLines = interventoriaPersonnel
    .map(formatPersonnelEntry)
    .filter((value): value is string => Boolean(value));
  const equipmentResourceLines = equipmentResources
    .map(formatEquipmentEntry)
    .filter((value): value is string => Boolean(value));
  const executedActivitiesLines = executedActivities
    .map((item) => item.text)
    .filter((text) => Boolean(text && text.trim()));
  const executedQuantitiesLines = executedQuantities
    .map((item) => item.text)
    .filter((text) => Boolean(text && text.trim()));
  const scheduledActivitiesLines = scheduledActivities
    .map((item) => item.text)
    .filter((text) => Boolean(text && text.trim()));
  const qualityControlsLines = qualityControls
    .map((item) => item.text)
    .filter((text) => Boolean(text && text.trim()));
  const materialsReceivedLines = materialsReceived
    .map((item) => item.text)
    .filter((text) => Boolean(text && text.trim()));
  const safetyNotesLines = safetyNotes
    .map((item) => item.text)
    .filter((text) => Boolean(text && text.trim()));
  const projectIssuesLines = projectIssues
    .map((item) => item.text)
    .filter((text) => Boolean(text && text.trim()));
  const siteVisitsLines = siteVisits
    .map((item) => item.text)
    .filter((text) => Boolean(text && text.trim()));

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
    const pageWidth = doc.page.width;

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
        "Día del plazo",
        entry.scheduleDay && entry.scheduleDay.trim()
          ? entry.scheduleDay.trim()
          : "—",
      ],
      [
        "Localización / Tramo",
        entry.locationDetails && entry.locationDetails.trim()
          ? entry.locationDetails.trim()
          : entry.location || "—",
      ],
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

    const drawSectionTitle = (title: string) => {
      doc.moveDown();
      doc.font("Helvetica-Bold").fontSize(13).text(title);
      doc.moveDown(0.3);
    };

    const drawSubheading = (title: string) => {
      doc.font("Helvetica-Bold").fontSize(11).text(title);
      doc.moveDown(0.15);
    };

    const drawParagraph = (text: string) => {
      doc.font("Helvetica").fontSize(11).text(text, {
        align: "justify",
      });
      doc.moveDown(0.2);
    };

    const drawParagraphOrPlaceholder = (text?: string | null) => {
      const normalized =
        typeof text === "string" ? text.trim() : "";
      drawParagraph(normalized || "Sin registro.");
    };

    const drawList = (items: string[]) => {
      if (!items.length) {
        drawParagraph("Sin registro.");
      } else {
        doc.font("Helvetica").fontSize(11).list(items, {
          bulletRadius: 2,
        });
        doc.moveDown(0.2);
      }
    };

    const generalInfoItems = [
      project ? `Identificación del proyecto: ${project.name}` : null,
      project?.contractId
        ? `Contrato: ${project.contractId}`
        : null,
      entry.scheduleDay && entry.scheduleDay.trim()
        ? `Día del plazo: ${entry.scheduleDay.trim()}`
        : null,
      entry.locationDetails && entry.locationDetails.trim()
        ? `Localización / Tramo: ${entry.locationDetails.trim()}`
        : entry.location
        ? `Localización / Tramo: ${entry.location}`
        : null,
    ].filter((value): value is string => Boolean(value));

    const rainIntervalLines = (weatherReportNormalized?.rainEvents || [])
      .map((event) => {
        const start =
          event.start && event.start.trim().length
            ? event.start.trim()
            : "—";
        const end =
          event.end && event.end.trim().length
            ? event.end.trim()
            : "—";
        return `${start} a ${end}`;
      })
      .filter((value) => Boolean(value));

    const normalizedWeatherNotes =
      weatherReportNormalized?.notes?.trim?.() || "";

    const weatherConditionsText =
      entry.weatherConditions && entry.weatherConditions.trim()
        ? entry.weatherConditions.trim()
        : "";

    drawSectionTitle("Resumen general del día");
    drawParagraphOrPlaceholder(entry.description);

    drawSectionTitle("Información general y contexto");
    if (generalInfoItems.length) {
      drawList(generalInfoItems);
    } else {
      drawParagraph("Sin datos adicionales.");
    }

    drawSectionTitle("Condiciones climáticas");
    if (
      !weatherReportNormalized &&
      !weatherConditionsText
    ) {
      drawParagraph("Sin registro.");
    } else {
      if (weatherReportNormalized?.summary) {
        drawParagraph(`Resumen: ${weatherReportNormalized.summary}`);
      }
      if (weatherReportNormalized?.temperature) {
        drawParagraph(
          `Temperatura: ${weatherReportNormalized.temperature}`
        );
      }
      if (normalizedWeatherNotes) {
        drawParagraph(`Notas: ${normalizedWeatherNotes}`);
      }
      if (rainIntervalLines.length) {
        drawSubheading("Lluvias registradas");
        drawList(rainIntervalLines);
      }
      if (
        weatherConditionsText &&
        weatherConditionsText !== normalizedWeatherNotes
      ) {
        drawParagraph(weatherConditionsText);
      }
    }

    drawSectionTitle("Recursos utilizados (Personal y Equipos)");
    drawSubheading("Personal en obra (resumen)");
    drawParagraphOrPlaceholder(entry.workforce);
    drawSubheading("Personal del contratista");
    drawList(contractorPersonnelLines);
    drawSubheading("Personal de la interventoría");
    drawList(interventoriaPersonnelLines);
    drawSubheading("Maquinaria y equipo");
    drawList(equipmentResourceLines);
    drawSubheading("Materiales utilizados");
    drawParagraphOrPlaceholder(entry.materialsUsed);

    drawSectionTitle("Ejecución de actividades y avance");
    drawSubheading("Descripción de actividades ejecutadas");
    drawParagraphOrPlaceholder(entry.activitiesPerformed);
    drawSubheading("Cantidades de obra ejecutadas");
    drawList(executedQuantitiesLines);
    drawSubheading("Detalle de actividades por frente");
    drawList(executedActivitiesLines);
    drawSubheading("Actividades programadas y no ejecutadas");
    drawList(scheduledActivitiesLines);

    drawSectionTitle("Control, novedades e incidencias");
    drawSubheading("Control de calidad");
    drawList(qualityControlsLines);
    drawSubheading("Materiales recibidos");
    drawList(materialsReceivedLines);
    drawSubheading("Gestión HSEQ / SST");
    drawList(safetyNotesLines);
    drawSubheading("Novedades y contratiempos");
    drawList(projectIssuesLines);
    drawSubheading("Visitas");
    drawList(siteVisitsLines);

    drawSectionTitle("Cierre y firmas");
    drawSubheading("Observaciones del contratista");
    drawParagraphOrPlaceholder(entry.contractorObservations);
    drawSubheading("Observaciones de la interventoría");
    drawParagraphOrPlaceholder(entry.interventoriaObservations);
    drawSubheading("Observaciones adicionales");
    drawParagraphOrPlaceholder(entry.additionalObservations);

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

    doc.moveDown();
    doc.font("Helvetica-Bold").fontSize(13).text("Firmas requeridas");
    doc.moveDown(0.35);

    const signatureParticipants: Array<{
      id: string;
      fullName: string;
      projectRole?: string | null;
      status: string;
      signedAt?: Date;
    }> = [];
    const participantsById = new Map<string, typeof signatureParticipants[number]>();

    const registerParticipant = (participant: {
      id: string;
      fullName: string;
      projectRole?: string | null;
      status: string;
      signedAt?: Date;
    }) => {
      if (!participant.id) {
        return;
      }
      const existing = participantsById.get(participant.id);
      if (existing) {
        if (
          participant.status === "SIGNED" &&
          existing.status !== "SIGNED"
        ) {
          existing.status = "SIGNED";
          existing.signedAt = participant.signedAt;
        } else if (existing.status !== "SIGNED") {
          existing.status = participant.status;
          existing.signedAt = participant.signedAt;
        }
        return;
      }
      const stored = { ...participant };
      signatureParticipants.push(stored);
      participantsById.set(participant.id, stored);
    };

    (entry.signatureTasks || []).forEach((task: any) => {
      if (!task?.signer) {
        return;
      }
      registerParticipant({
        id: task.signer.id,
        fullName: task.signer.fullName,
        projectRole: task.signer.projectRole,
        status: task.status,
        signedAt: task.signedAt ? new Date(task.signedAt) : undefined,
      });
    });

    (entry.signatures || []).forEach((signature: any) => {
      const signerId = signature.signerId || signature.signer?.id;
      if (!signerId) {
        return;
      }
      registerParticipant({
        id: signerId,
        fullName: signature.signer?.fullName || "Firmante",
        projectRole: signature.signer?.projectRole,
        status: "SIGNED",
        signedAt: signature.signedAt ? new Date(signature.signedAt) : undefined,
      });
    });

    if (!signatureParticipants.length && entry.author) {
      const authorSignature = (entry.signatures || []).find(
        (signature: any) =>
          (signature.signerId || signature.signer?.id) === entry.author?.id
      );
      registerParticipant({
        id: entry.author.id,
        fullName: entry.author.fullName,
        projectRole: entry.author.projectRole,
        status: authorSignature ? "SIGNED" : "PENDING",
        signedAt: authorSignature?.signedAt
          ? new Date(authorSignature.signedAt)
          : undefined,
      });
    }

    if (!signatureParticipants.length && entry.assignees?.length) {
      entry.assignees.forEach((assignee: any) => {
        registerParticipant({
          id: assignee.id,
          fullName: assignee.fullName,
          projectRole: assignee.projectRole,
          status: "PENDING",
        });
      });
    }

    const signatureBoxHeight = 110;
    const signatureBoxWidth =
      pageWidth - doc.page.margins.left - doc.page.margins.right;

    signatureParticipants.forEach((participant, index) => {
      if (
        doc.y + signatureBoxHeight >
        doc.page.height - doc.page.margins.bottom
      ) {
        doc.addPage();
      }

      const currentY = doc.y;
      doc
        .rect(
          doc.page.margins.left,
          currentY,
          signatureBoxWidth,
          signatureBoxHeight
        )
        .stroke();

      const nameLabel = participant.fullName || "Firmante";
      const roleLabel = projectRoleLabels[participant.projectRole || ""] ||
        participant.projectRole ||
        "Cargo / Rol";

      const statusLabelBase =
        signatureTaskStatusLabels[participant.status] || participant.status;
      const statusDetail =
        participant.status === "SIGNED" && participant.signedAt
          ? `${statusLabelBase} · ${formatDateTime(participant.signedAt)}`
          : statusLabelBase;
      const statusColor =
        signatureTaskStatusColors[participant.status] || "#1F2937";

      doc
        .font("Helvetica-Bold")
        .fontSize(11)
        .text(nameLabel, doc.page.margins.left + 16, currentY + 12, {
          width: signatureBoxWidth - 32,
        });

      doc
        .font("Helvetica")
        .fontSize(10)
        .fillColor("#4B5563")
        .text(roleLabel, doc.page.margins.left + 16, currentY + 30, {
          width: signatureBoxWidth - 32,
        })
        .fillColor("#000000");

      doc
        .font("Helvetica")
        .fontSize(10)
        .fillColor(statusColor)
        .text(statusDetail, doc.page.margins.left + 16, currentY + 46, {
          width: signatureBoxWidth - 32,
        })
        .fillColor("#000000");

      doc
        .font("Helvetica")
        .fontSize(10)
        .text("Firma:", doc.page.margins.left + 16, currentY + 58);

      doc
        .moveTo(doc.page.margins.left + 70, currentY + 72)
        .lineTo(doc.page.margins.left + signatureBoxWidth - 16, currentY + 72)
        .stroke();

      doc.y = currentY + signatureBoxHeight + 16;
      if (index === signatureParticipants.length - 1) {
        doc.moveDown();
      }
    });

    doc.end();
  });

  const stats = await fs.stat(filePath);
  const storagePath = path.posix.join(GENERATED_SUBDIR, fileName);
  const attachment = await prisma.attachment.create({
    data: {
      fileName,
      url: `${baseUrl}/uploads/${GENERATED_SUBDIR}/${fileName}`,
      storagePath,
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
