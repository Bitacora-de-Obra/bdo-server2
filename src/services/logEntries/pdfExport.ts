import path from "path";
import fs from "fs/promises";
import fsSync from "fs";
import PDFDocument from "pdfkit";
import { PrismaClient } from "@prisma/client";
import { getStorage } from "../../storage";
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

// Función para obtener el nombre del rol o cargo a mostrar
const getDisplayRole = (cargo: string | null | undefined, projectRole: string | null | undefined, entity: string | null | undefined): string => {
  if (cargo) {
    return cargo;
  }
  
  if (entity) {
    if (entity === 'IDU') return 'IDU';
    if (entity === 'INTERVENTORIA') return 'Interventoría';
    if (entity === 'CONTRATISTA') return 'Contratista';
  }
  
  return projectRoleLabels[projectRole || ''] || projectRole || 'Cargo / Rol';
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
  tenantId?: string; // Para validar tenant (el log entry ya debería estar validado, pero esto es una capa adicional)
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

const decodeBase64Signature = (value?: string | null): Buffer | null => {
  if (!value) return null;
  const parts = value.split("base64,");
  const payload = parts.length > 1 ? parts[1] : value;
  try {
    return Buffer.from(payload, "base64");
  } catch (_error) {
    return null;
  }
};

type PdfDocInstance = InstanceType<typeof PDFDocument>;

const getImageDimensions = (
  doc: PdfDocInstance,
  buffer: Buffer
): { width: number; height: number } | null => {
  const docAny = doc as any;
  if (docAny && typeof docAny.openImage === "function") {
    try {
      const img = docAny.openImage(buffer);
      if (img?.width && img?.height) {
        return { width: img.width, height: img.height };
      }
    } catch (_error) {
      // Ignorar y retornar null
    }
  }
  return null;
};

export const generateLogEntryPdf = async (options: LogEntryPdfOptions) => {
  const { prisma, logEntryId, uploadsDir, baseUrl, tenantId } = options;
  const entry = await prisma.logEntry.findUnique({
    where: { id: logEntryId },
    include: {
      author: {
        select: {
          id: true,
          fullName: true,
          email: true,
          projectRole: true,
          cargo: true,
          entity: true,
        }
      },
      attachments: true,
      comments: { include: { author: true }, orderBy: { timestamp: "asc" } },
      signatures: { 
        include: { 
          signer: {
            select: {
              id: true,
              fullName: true,
              projectRole: true,
              cargo: true,
              entity: true,
            }
          }
        },
        orderBy: { signedAt: "asc" },
      },
      assignees: {
        select: {
          id: true,
          fullName: true,
          projectRole: true,
          cargo: true,
          entity: true,
        }
      },
      signatureTasks: {
        include: { 
          signer: {
            select: {
              id: true,
              fullName: true,
              projectRole: true,
              cargo: true,
              entity: true,
            }
          }
        },
        orderBy: [{ assignedAt: "asc" }, { createdAt: "asc" }, { id: "asc" }],
      },
    },
  });

  if (!entry) {
    throw new Error("Anotación no encontrada.");
  }

  const project = await prisma.project.findUnique({
    where: { id: entry.projectId },
  });

  const contractorPersonnel = normalizePersonnelEntries(
    entry.contractorPersonnel
  );
  const interventoriaPersonnel = normalizePersonnelEntries(
    entry.interventoriaPersonnel
  );
  const equipmentResources = normalizeEquipmentEntries(
    entry.equipmentResources
  );
  const executedActivities = normalizeListItems(entry.executedActivities);
  const executedQuantities = normalizeListItems(entry.executedQuantities);
  const scheduledActivities = normalizeListItems(entry.scheduledActivities);
  const qualityControls = normalizeListItems(entry.qualityControls);
  const materialsReceived = normalizeListItems(entry.materialsReceived);
  const safetyNotes = normalizeListItems(entry.safetyNotes);
  const projectIssues = normalizeListItems(entry.projectIssues);
  const siteVisits = normalizeListItems(entry.siteVisits);
  const weatherReportNormalized = normalizeWeatherReport(entry.weatherReport);

  const formatPersonnelEntry = (
    person: ReturnType<typeof normalizePersonnelEntries>[number]
  ) => {
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
  const entryDateObj = entry.entryDate ? new Date(entry.entryDate) : null;
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

  await new Promise<void>(async (resolve, reject) => {
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

    const formatScheduleDay = (value: number | null | undefined) => {
      if (typeof value === "number" && Number.isFinite(value) && value > 0) {
        return `Día ${value} del proyecto`;
      }
      return "—";
    };

    const infoRows: Array<[string, string]> = [
      ["Autor", entry.author?.fullName || "—"],
      ["Correo autor", entry.author?.email || "—"],
      ["Estado", entryStatusLabels[entry.status] || entry.status],
      ["Tipo", entryTypeLabels[entry.type] || entry.type],
      ["Confidencial", entry.isConfidential ? "Sí" : "No"],
      ["Día del plazo", formatScheduleDay(entry.scheduleDay as number | null)],
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
      const normalized = typeof text === "string" ? text.trim() : "";
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
      project?.contractId ? `Contrato: ${project.contractId}` : null,
      typeof entry.scheduleDay === "number" && Number.isFinite(entry.scheduleDay) && entry.scheduleDay > 0
        ? `Día del plazo: Día ${entry.scheduleDay} del proyecto`
        : null,
      entry.locationDetails && entry.locationDetails.trim()
        ? `Localización / Tramo: ${entry.locationDetails.trim()}`
        : entry.location
        ? `Localización / Tramo: ${entry.location}`
        : null,
    ].filter((value): value is string => Boolean(value));

    const rainIntervalLines = (weatherReportNormalized?.rainEvents || [])
      .map((event) => {
        const formatRain = (value?: string | null) => {
          if (typeof value !== "string") {
            return "—";
          }
          const trimmed = value.trim();
          return trimmed.length ? trimmed : "—";
        };
        const start = formatRain(event.start);
        const end = formatRain(event.end);
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
    if (!weatherReportNormalized && !weatherConditionsText) {
      drawParagraph("Sin registro.");
    } else {
      if (weatherReportNormalized?.summary) {
        drawParagraph(`Resumen: ${weatherReportNormalized.summary}`);
      }
      if (weatherReportNormalized?.temperature) {
        drawParagraph(`Temperatura: ${weatherReportNormalized.temperature}`);
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
    if (!entry.signatures?.length) {
      doc.font("Helvetica").fontSize(11).text("No hay firmas registradas.");
    } else {
      entry.signatures.forEach((signature: any, index: number) => {
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
    doc.font("Helvetica-Bold").fontSize(13).text("Comentarios").moveDown(0.25);

    if (!entry.comments?.length) {
      doc.font("Helvetica").fontSize(11).text("Sin comentarios registrados.");
    } else {
      entry.comments.forEach((comment: any, index: number) => {
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
    doc.font("Helvetica-Bold").fontSize(13).text("Adjuntos").moveDown(0.25);

    if (!entry.attachments?.length) {
      doc.font("Helvetica").fontSize(11).text("No hay archivos adjuntos.");
    } else {
      // Separar imágenes de otros archivos
      const images = entry.attachments.filter(
        (att: any) => att.type && att.type.startsWith("image/")
      );
      const otherFiles = entry.attachments.filter(
        (att: any) => !att.type || !att.type.startsWith("image/")
      );

      // Mostrar imágenes con layout mejorado
      if (images.length > 0) {
        doc.font("Helvetica-Bold").fontSize(12).text("Fotos del día:");
        doc.moveDown(0.3);

        // Procesar imágenes una por una con mejor control
        for (let i = 0; i < images.length; i++) {
          const image = images[i];

          try {
            // Agregar nombre de archivo
            doc
              .font("Helvetica-Bold")
              .fontSize(10)
              .text(`${i + 1}. ${image.fileName}`);
            doc.moveDown(0.2);

            // Intentar cargar la imagen desde storage
            let imageBuffer: Buffer | null = null;
            
            if (image.storagePath) {
              try {
                // Primero intentar desde storage (Cloudflare R2)
                const storage = getStorage();
                imageBuffer = await storage.load(image.storagePath);
              } catch (storageError) {
                console.warn(`No se pudo cargar imagen desde storage: ${image.storagePath}`, storageError);
                
                // Fallback: intentar desde filesystem local
                const imagePath = path.join(uploadsDir, image.storagePath);
                if (fsSync.existsSync(imagePath)) {
                  imageBuffer = await fs.readFile(imagePath);
                }
              }
            }

            if (imageBuffer) {
              // Verificar si necesitamos nueva página
              const imageHeight = 150;
              if (doc.y + imageHeight > doc.page.height - 100) {
                doc.addPage();
              }

              // Agregar imagen con posición fija
              const startY = doc.y;
              doc.image(imageBuffer, 50, startY, {
                fit: [250, imageHeight],
              });

              // Mover cursor después de la imagen
              doc.y = startY + imageHeight + 20;
            } else {
              doc
                .font("Helvetica")
                .fontSize(10)
                .text(`[Imagen no encontrada: ${image.fileName}]`);
              doc.moveDown(0.3);
            }
          } catch (error) {
            console.error(`Error procesando imagen ${image.fileName}:`, error);
            doc
              .font("Helvetica")
              .fontSize(10)
              .text(`[Error cargando imagen: ${image.fileName}]`);
            doc.moveDown(0.3);
          }
        }

        if (otherFiles.length > 0) {
          doc.moveDown(0.5);
        }
      }

      // Mostrar otros archivos
      if (otherFiles.length > 0) {
        if (images.length > 0) {
          doc.font("Helvetica-Bold").fontSize(12).text("Otros archivos:");
          doc.moveDown(0.2);
        }

        otherFiles.forEach((attachment: any, index: number) => {
          doc
            .font("Helvetica")
            .fontSize(11)
            .text(
              `${index + 1}. ${attachment.fileName} (${
                attachment.type || "desconocido"
              })`,
              {
                link: attachment.url,
                underline: Boolean(attachment.url),
              }
            );
        });
      }
    }

    // Forzar que la sección de firmas inicie en una nueva página con layout predecible
    doc.addPage();
    doc.font("Helvetica-Bold").fontSize(13).text("Firmas requeridas");
    doc.moveDown(0.35);

    const signatureParticipants: Array<{
      id: string;
      fullName: string;
      projectRole?: string | null;
      cargo?: string | null;
      entity?: string | null;
      status: string;
      signedAt?: Date;
    }> = [];
    const participantsById = new Map<
      string,
      (typeof signatureParticipants)[number]
    >();

    const registerParticipant = (participant: {
      id: string;
      fullName: string;
      projectRole?: string | null;
      cargo?: string | null;
      entity?: string | null;
      status: string;
      signedAt?: Date;
    }) => {
      if (!participant.id) {
        return;
      }
      const existing = participantsById.get(participant.id);
      if (existing) {
        if (participant.status === "SIGNED" && existing.status !== "SIGNED") {
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
        cargo: task.signer.cargo,
        entity: task.signer.entity,
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
        cargo: signature.signer?.cargo,
        entity: signature.signer?.entity,
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
        cargo: entry.author.cargo,
        entity: entry.author.entity,
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
          cargo: assignee.cargo,
          entity: assignee.entity,
          status: "PENDING",
        });
      });
    }

    const signedParticipantIds = signatureParticipants
      .filter((participant) => participant.status === "SIGNED")
      .map((participant) => participant.id);

    const signatureImages = new Map<string, Buffer>();
    if (signedParticipantIds.length) {
      const userSignatures = await prisma.userSignature.findMany({
        where: { userId: { in: signedParticipantIds } },
        select: {
          userId: true,
          storagePath: true,
          signature: true,
          url: true,
        },
      });
      const storage = getStorage();

      for (const userSignature of userSignatures) {
        let buffer: Buffer | null = null;

        if (userSignature.storagePath) {
          try {
            buffer = await storage.read(userSignature.storagePath);
          } catch (error) {
            console.warn("No se pudo leer firma desde storagePath", {
              userId: userSignature.userId,
              storagePath: userSignature.storagePath,
              error,
            });
          }
        }

        if (!buffer) {
          buffer = decodeBase64Signature(userSignature.signature);
        }

        if (buffer) {
          signatureImages.set(userSignature.userId, buffer);
        }
      }
    }

    const signatureBoxHeight = 140;
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
      const roleLabel = getDisplayRole(
        participant.cargo,
        participant.projectRole,
        participant.entity
      );

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

      // Área de firma centrada y más amplia para evitar que se vea comprimida
      const signatureAreaTop = currentY + 70;
      const signatureAreaHeight = 70;
      const signatureAreaX = doc.page.margins.left + 24;
      const signatureAreaWidth =
        signatureBoxWidth - (signatureAreaX - doc.page.margins.left) - 24;
      const signatureLineY = signatureAreaTop + signatureAreaHeight - 10;

      doc
        .font("Helvetica")
        .fontSize(10)
        .text("Firma:", doc.page.margins.left + 16, signatureAreaTop - 18);
      const signatureBuffer = participant.id
        ? signatureImages.get(participant.id)
        : null;

      if (signatureBuffer) {
        const maxSignatureWidth = signatureAreaWidth - 16;
        const maxSignatureHeight = signatureAreaHeight - 12;
        try {
          const imageDimensions = getImageDimensions(doc, signatureBuffer);
          const naturalWidth = imageDimensions?.width || maxSignatureWidth;
          const naturalHeight = imageDimensions?.height || maxSignatureHeight;
          const scale =
            naturalWidth && naturalHeight
              ? Math.min(
                  maxSignatureWidth / naturalWidth,
                  maxSignatureHeight / naturalHeight,
                  1
                )
              : 1;
          const renderWidth = naturalWidth * scale;
          const renderHeight = naturalHeight * scale;
          const renderX =
            signatureAreaX + Math.max(0, (maxSignatureWidth - renderWidth) / 2);
          const renderY =
            signatureAreaTop + Math.max(0, (maxSignatureHeight - renderHeight) / 2);

          // Limpiar el área para evitar fantasmas detrás
          doc.save();
          doc
            .rect(
              signatureAreaX - 8,
              signatureAreaTop - 6,
              signatureAreaWidth + 16,
              signatureAreaHeight + 16
            )
            .fill("#FFFFFF");
          doc.restore();

          doc.image(signatureBuffer, renderX, renderY, {
            width: renderWidth,
            height: renderHeight,
          });
        } catch (error) {
          console.warn("No se pudo renderizar la firma manuscrita en PDF", {
            signerId: participant.id,
            error,
          });
        }
      }

      doc
        .moveTo(signatureAreaX, signatureLineY)
        .lineTo(signatureAreaX + signatureAreaWidth, signatureLineY)
        .stroke();

      doc.y = currentY + signatureBoxHeight + 16;
      if (index === signatureParticipants.length - 1) {
        doc.moveDown();
      }
    });

    doc.end();
  });

  const stats = await fs.stat(filePath);
  
  // Organizar PDFs generados por tenant, año y mes
  const now = new Date();
  const year = now.getFullYear().toString();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  
  // Construir path con tenant si está disponible
  const pathParts: string[] = [];
  if (options.tenantId) {
    const normalizedTenantId = options.tenantId.replace(/[^a-zA-Z0-9_-]/g, "");
    pathParts.push('tenants', normalizedTenantId);
  }
  pathParts.push("generated", "log-entries", year, month, fileName);
  
  const storagePath = path.posix.join(...pathParts);
  
  // Upload file to storage
  const storage = getStorage();
  const fileBuffer = await fs.readFile(filePath);
  await storage.save({
    path: storagePath,
    content: fileBuffer
  });
  
  const attachment = await prisma.attachment.create({
    data: {
      fileName,
      url: storage.getPublicUrl(storagePath),
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
