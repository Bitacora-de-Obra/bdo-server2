import path from "path";
import fs from "fs/promises";
import ExcelJS from "exceljs";
import { PrismaClient, ReportScope } from "@prisma/client";

interface GenerateWeeklyReportOptions {
  prisma: PrismaClient;
  reportId: string;
  uploadsDir: string;
  baseUrl: string;
}

const GENERATED_SUBDIR = "generated";

const sanitizeFileName = (value: string) =>
  value
    .normalize("NFD")
    .replace(/[^a-zA-Z0-9-_\.]+/g, "_")
    .replace(/_{2,}/g, "_")
    .replace(/^_+|_+$/g, "")
    .substring(0, 120);

const formatDate = (date: Date) =>
  date.toLocaleDateString("es-CO", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  });

const formatDateTime = (date: Date) =>
  date.toLocaleString("es-CO", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });

export async function generateWeeklyReportExcel({
  prisma,
  reportId,
  uploadsDir,
  baseUrl,
}: GenerateWeeklyReportOptions) {
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

  if (report.type !== "Weekly") {
    throw new Error("Solo se pueden generar informes semanales en Excel.");
  }

  const project = await prisma.project.findFirst();

  const weekEnd = new Date(report.submissionDate);
  weekEnd.setHours(0, 0, 0, 0);
  const weekStart = new Date(weekEnd);
  weekStart.setDate(weekStart.getDate() - 6);

  const weekEndInclusive = new Date(weekEnd);
  weekEndInclusive.setHours(23, 59, 59, 999);

  const tasks = await prisma.projectTask.findMany({
    where: {
      AND: [
        { startDate: { lte: weekEndInclusive } },
        { endDate: { gte: weekStart } },
      ],
    },
    orderBy: [{ startDate: "asc" }],
  });

  const logEntries = await prisma.logEntry.findMany({
    where: {
      AND: [
        { activityStartDate: { lte: weekEndInclusive } },
        { activityEndDate: { gte: weekStart } },
      ],
    },
    include: {
      author: true,
      attachments: true,
      assignees: true,
    },
    orderBy: { activityStartDate: "asc" },
  });

  const communications = await prisma.communication.findMany({
    where: {
      sentDate: { gte: weekStart, lte: weekEndInclusive },
    },
    orderBy: { sentDate: "asc" },
  });

  const commitments = await prisma.commitment.findMany({
    where: {
      dueDate: { gte: weekStart, lte: weekEndInclusive },
    },
    include: {
      acta: true,
      responsible: true,
    },
    orderBy: { dueDate: "asc" },
  });

  const workbook = new ExcelJS.Workbook();
  const sheet = workbook.addWorksheet("Informe Semanal", {
    views: [{ state: "frozen", ySplit: 8 }],
  });

  sheet.properties.defaultRowHeight = 18;

  // Title
  sheet.mergeCells("A1", "H1");
  const titleCell = sheet.getCell("A1");
  titleCell.value =
    report.reportScope === ReportScope.OBRA
      ? "INFORME SEMANAL DE OBRA"
      : "INFORME SEMANAL DE INTERVENTORÍA";
  titleCell.font = { size: 16, bold: true, color: { argb: "FFFFFFFF" } };
  titleCell.alignment = { horizontal: "center" };
  titleCell.fill = {
    type: "pattern",
    pattern: "solid",
    fgColor: { argb: "FF1E40AF" },
  };

  const infoRows = [
    [
      "Proyecto",
      project?.name || "—",
      "Contrato",
      project?.contractId || project?.id || "—",
      "Versión",
      `v${report.version}`,
      "Estado",
      report.status,
    ],
    [
      "Periodo",
      report.period,
      "Semana",
      `${formatDate(weekStart)} - ${formatDate(weekEnd)}`,
      "Presentado",
      formatDate(new Date(report.submissionDate)),
      "Elaborado por",
      report.author.fullName,
    ],
  ];

  infoRows.forEach((row, index) => {
    const excelRow = sheet.getRow(index + 3);
    excelRow.values = [undefined, ...row];
    excelRow.eachCell({ includeEmpty: true }, (cell) => {
      cell.font = { size: 11 };
      cell.border = {
        top: { style: "thin", color: { argb: "FFCBD5F5" } },
        bottom: { style: "thin", color: { argb: "FFCBD5F5" } },
      };
    });
  });

  const addSectionHeader = (label: string) => {
    const row = sheet.addRow([label]);
    row.getCell(1).font = { bold: true, size: 12, color: { argb: "FF1E3A8A" } };
    row.getCell(1).fill = {
      type: "pattern",
      pattern: "solid",
      fgColor: { argb: "FFE0E7FF" },
    };
    row.getCell(1).alignment = { horizontal: "left" };
    sheet.mergeCells(row.number, 1, row.number, 8);
    sheet.addRow([]);
  };

  sheet.addRow([]);
  addSectionHeader("Resumen Ejecutivo");
  const summaryRow = sheet.addRow([report.summary || "Sin comentarios." ]);
  summaryRow.height = 40;
  summaryRow.getCell(1).alignment = { wrapText: true, vertical: "top" };
  sheet.mergeCells(summaryRow.number, 1, summaryRow.number, 8);
  sheet.addRow([]);

  // Tasks Section
  addSectionHeader("Actividades de la semana");
  sheet.addRow([
    "Actividad",
    "Inicio",
    "Fin",
    "% Programado",
    "% Ejecutado",
    "Duración (días)",
    "Nivel",
    "Resumen",
  ]).font = { bold: true };

  tasks.forEach((task) => {
    const planned = task.progress ?? 0;
    sheet.addRow([
      task.name,
      formatDate(new Date(task.startDate)),
      formatDate(new Date(task.endDate)),
      `${planned.toFixed(1)}%`,
      `${task.isSummary ? "—" : planned.toFixed(1) + "%"}`,
      task.duration,
      task.outlineLevel,
      task.isSummary ? "Tarea resumen" : "",
    ]);
  });

  sheet.addRow([]);

  // Log entries section
  addSectionHeader("Bitácora - Hechos relevantes");
  sheet.addRow([
    "Folio",
    "Título",
    "Estado",
    "Autor",
    "Fecha Actividad",
    "Ubicación",
    "Asignados",
    "Adjuntos",
  ]).font = { bold: true };

  logEntries.forEach((entry) => {
    const start = formatDate(new Date(entry.activityStartDate));
    const end = formatDate(new Date(entry.activityEndDate));
    sheet.addRow([
      entry.folioNumber,
      entry.title,
      entry.status,
      entry.author?.fullName || "—",
      `${start} - ${end}`,
      entry.location || "—",
      entry.assignees?.length || 0,
      entry.attachments?.length || 0,
    ]);
  });

  sheet.addRow([]);

  // Communications section
  addSectionHeader("Comunicaciones emitidas/recibidas");
  sheet.addRow([
    "Radicado",
    "Asunto",
    "Estado",
    "Fecha",
    "Remitente",
    "Destinatario",
    "Notas",
    "Vencimiento",
  ]).font = { bold: true };

  communications.forEach((comm) => {
    sheet.addRow([
      comm.radicado,
      comm.subject,
      comm.status,
      comm.sentDate ? formatDate(new Date(comm.sentDate)) : "—",
      comm.senderEntity || "—",
      comm.recipientEntity || "—",
      comm.notes || "",
      comm.dueDate ? formatDate(new Date(comm.dueDate)) : "—",
    ]);
  });

  sheet.addRow([]);

  // Commitments section
  addSectionHeader("Compromisos con vencimiento en la semana");
  sheet.addRow([
    "Acta",
    "Descripción",
    "Responsable",
    "Fecha Compromiso",
    "Estado",
    "Registrado",
    "Actualizado",
    "Notas",
  ]).font = { bold: true };

  commitments.forEach((commitment) => {
    sheet.addRow([
      commitment.acta?.number || "—",
      commitment.description,
      commitment.responsible?.fullName || "—",
      formatDate(new Date(commitment.dueDate)),
      commitment.status,
      formatDate(new Date(commitment.createdAt)),
      formatDate(new Date(commitment.updatedAt)),
      "",
    ]);
  });

  sheet.addRow([]);

  sheet.columns.forEach((col) => {
    if (!col) return;
    col.width = 20;
  });
  sheet.getColumn(1).width = 40;
  sheet.getColumn(2).width = 18;
  sheet.getColumn(3).width = 18;
  sheet.getColumn(4).width = 20;
  sheet.getColumn(5).width = 20;
  sheet.getColumn(6).width = 20;
  sheet.getColumn(7).width = 15;
  sheet.getColumn(8).width = 25;

  const generatedDir = path.join(uploadsDir, GENERATED_SUBDIR);
  await fs.mkdir(generatedDir, { recursive: true });

  const safeNumber = sanitizeFileName(report.number);
  const fileName = `${safeNumber || "informe"}-v${report.version}-${formatDate(
    weekEnd
  ).replace(/\//g, "-")}.xlsx`;
  const filePath = path.join(generatedDir, fileName);

  await workbook.xlsx.writeFile(filePath);

  const stats = await fs.stat(filePath);

  const attachment = await prisma.attachment.create({
    data: {
      fileName,
      url: `${baseUrl}/uploads/${GENERATED_SUBDIR}/${fileName}`,
      size: stats.size,
      type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
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

  return {
    attachment,
    filePath,
  };
}
