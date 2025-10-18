import express from "express";
import cors from "cors";
import { PrismaClient, UserRole, WorkActaStatus, CostActaStatus, ReportStatus, ReportScope /* <-- Añade ReportStatus aquí */ } from '@prisma/client';
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import "dotenv/config";
import multer from "multer";
import path from "path";

// Importamos los mapas desde el nuevo archivo de utilidades
import {
  actaAreaMap,
  actaStatusMap,
  entryTypeMap,
  entryStatusMap,
  deliveryMethodMap,
  drawingDisciplineMap,
  workActaStatusMap,
  costActaStatusMap,
  reportScopeMap,
  reportStatusMap
  
} from "./utils/enum-maps";
// Importa el middleware de autenticación (suponiendo que está en src/middleware/auth.ts)
// import { authMiddleware } from './middleware/auth'; // Descomenta cuando lo implementes

const app = express();
const prisma = new PrismaClient();
const port = 4000;

app.use(cors()); // Considera configurar orígenes específicos para producción
app.use(express.json());

// --- CONFIGURACIÓN DE MULTER (Subida de Archivos) ---

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => {
    // Crea un nombre de archivo único para evitar colisiones
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(
      null,
      file.fieldname + "-" + uniqueSuffix + path.extname(file.originalname)
    );
  },
});
const upload = multer({ storage });

// Servir archivos estáticos desde la carpeta 'uploads'
// __dirname se refiere al directorio actual del archivo (dist/ en tiempo de ejecución)
app.use("/uploads", express.static(path.join(__dirname, "../uploads")));

// --- Endpoint para subir un único archivo ---
app.post("/api/upload", upload.single("file"), async (req, res) => {
  // Asegúrate que 'async' esté aquí
  if (!req.file) {
    // Devuelve JSON en caso de error también
    return res.status(400).json({ error: "No se subió ningún archivo." });
  }

  try {
    // 1. Crear el registro en la base de datos
    const newAttachment = await prisma.attachment.create({
      data: {
        fileName: req.file.originalname,
        // Construye la URL completa
        url: `http://localhost:${port}/uploads/${req.file.filename}`, // Usa la variable port
        size: req.file.size,
        type: req.file.mimetype,
        // logEntryId, actaId, costActaId, reportId son null inicialmente
      },
    });

    // 2. Devolver el objeto Attachment completo (incluye el 'id' de la base de datos)
    res.status(201).json(newAttachment); // Código 201 Created
  } catch (error) {
    console.error("Error al crear el registro Attachment:", error);
    res
      .status(500)
      .json({ error: "Error al procesar el archivo en la base de datos." });
  }
});

// --- RUTAS DE AUTENTICACIÓN ---
// TODO: Implementar registro y login seguros
app.post("/api/auth/register", async (req, res) => {
  res.status(501).json({ message: "Not Implemented" });
});
app.post("/api/auth/login", async (req, res) => {
  res.status(501).json({ message: "Not Implemented" });
});
app.get("/api/users", async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        fullName: true,
        email: true,
        projectRole: true,
        avatarUrl: true,
        appRole: true,
        status: true,
      },
    });
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: "Error al obtener usuarios." });
  }
});
// TODO: Añadir ruta GET /api/auth/me para verificar token

// --- RUTAS PARA COMUNICACIONES ---
app.get("/api/communications", async (req, res) => {
  try {
    const communications = await prisma.communication.findMany({
      orderBy: { sentDate: "desc" },
      include: { uploader: true },
    });
    const formattedComms = communications.map((comm) => ({
      ...comm,
      senderDetails: {
        entity: comm.senderEntity,
        personName: comm.senderName,
        personTitle: comm.senderTitle,
      },
      recipientDetails: {
        entity: comm.recipientEntity,
        personName: comm.recipientName,
        personTitle: comm.recipientTitle,
      },
      statusHistory: [],
      attachments: [],
    }));
    res.json(formattedComms);
  } catch (error) {
    console.error("Error al obtener comunicaciones:", error);
    res
      .status(500)
      .json({ error: "No se pudieron obtener las comunicaciones." });
  }
});

app.post("/api/communications", async (req, res) => {
  try {
    const {
      radicado,
      subject,
      description,
      senderDetails,
      recipientDetails,
      signerName,
      sentDate,
      dueDate,
      deliveryMethod,
      notes,
      parentId,
      uploaderId,
    } = req.body;
    const prismaDeliveryMethod = deliveryMethodMap[deliveryMethod] || "SYSTEM";
    const newComm = await prisma.communication.create({
      data: {
        radicado,
        subject,
        description,
        senderEntity: senderDetails.entity,
        senderName: senderDetails.personName,
        senderTitle: senderDetails.personTitle,
        recipientEntity: recipientDetails.entity,
        recipientName: recipientDetails.personName,
        recipientTitle: recipientDetails.personTitle,
        signerName,
        sentDate: new Date(sentDate),
        dueDate: dueDate ? new Date(dueDate) : null,
        deliveryMethod: prismaDeliveryMethod,
        notes,
        uploader: { connect: { id: uploaderId } },
        parent: parentId ? { connect: { id: parentId } } : undefined,
      },
      include: { uploader: true },
    });
    const formattedComm = {
      ...newComm,
      senderDetails: {
        entity: newComm.senderEntity,
        personName: newComm.senderName,
        personTitle: newComm.senderTitle,
      },
      recipientDetails: {
        entity: newComm.recipientEntity,
        personName: newComm.recipientName,
        personTitle: newComm.recipientTitle,
      },
      statusHistory: [],
      attachments: [],
    };
    res.status(201).json(formattedComm);
  } catch (error) {
    console.error("Error al crear la comunicación:", error);
    res.status(500).json({ error: "No se pudo crear la comunicación." });
  }
});
// TODO: Añadir PUT /api/communications/:id para actualizar estado, etc.

// --- RUTAS PARA PLANOS (DRAWINGS) ---
app.get("/api/drawings", async (req, res) => {
  try {
    const drawings = await prisma.drawing.findMany({
      orderBy: { createdAt: "desc" },
      include: {
        versions: {
          orderBy: { versionNumber: "desc" },
          include: { uploader: true },
        },
        comments: { include: { author: true }, orderBy: { timestamp: "asc" } },
      },
    });
    // Formatear la disciplina antes de enviar
    const formattedDrawings = drawings.map((d) => ({
      ...d,
      discipline:
        Object.keys(drawingDisciplineMap).find(
          (key) => drawingDisciplineMap[key] === d.discipline
        ) || d.discipline,
    }));
    res.json(formattedDrawings);
  } catch (error) {
    console.error("Error al obtener los planos:", error);
    res.status(500).json({ error: "No se pudieron obtener los planos." });
  }
});

app.post("/api/drawings", async (req, res) => {
  try {
    const { code, title, discipline, version } = req.body;
    const prismaDiscipline = drawingDisciplineMap[discipline] || "OTHER";
    if (!code || !title || !discipline || !version) {
      return res
        .status(400)
        .json({ error: "Faltan datos para crear el plano." });
    }
    const newDrawing = await prisma.drawing.create({
      data: {
        code,
        title,
        discipline: prismaDiscipline,
        versions: {
          create: [
            {
              versionNumber: 1,
              fileName: version.fileName,
              url: version.url,
              size: version.size,
              uploader: { connect: { id: version.uploaderId } },
            },
          ],
        },
      },
      include: {
        versions: { include: { uploader: true } },
        comments: { include: { author: true } },
      }, // Incluir comments
    });
    // Formatear disciplina en la respuesta
    const formattedDrawing = {
      ...newDrawing,
      discipline:
        Object.keys(drawingDisciplineMap).find(
          (key) => drawingDisciplineMap[key] === newDrawing.discipline
        ) || newDrawing.discipline,
    };
    res.status(201).json(formattedDrawing);
  } catch (error) {
    console.error("Error al crear el plano:", error);
    if ((error as any).code === "P2002") {
      return res
        .status(409)
        .json({ error: "Ya existe un plano con este código." });
    }
    res.status(500).json({ error: "No se pudo crear el plano." });
  }
});

app.post("/api/drawings/:id/versions", async (req, res) => {
  try {
    const { id } = req.params;
    const { version } = req.body;
    if (!version) {
      return res
        .status(400)
        .json({ error: "Faltan los datos de la nueva versión." });
    }
    const existingDrawing = await prisma.drawing.findUnique({
      where: { id },
      include: { versions: { orderBy: { versionNumber: "desc" } } },
    });
    if (!existingDrawing) {
      return res.status(404).json({ error: "El plano no fue encontrado." });
    }
    const latestVersionNumber = existingDrawing.versions[0]?.versionNumber || 0;
    const updatedDrawing = await prisma.drawing.update({
      where: { id: id },
      data: {
        status: "VIGENTE",
        versions: {
          create: {
            versionNumber: latestVersionNumber + 1,
            fileName: version.fileName,
            url: version.url,
            size: version.size,
            uploader: { connect: { id: version.uploaderId } },
          },
        },
      },
      include: {
        versions: {
          orderBy: { versionNumber: "desc" },
          include: { uploader: true },
        },
        comments: { include: { author: true } },
      }, // Incluir comments
    });
    // Formatear disciplina en la respuesta
    const formattedDrawing = {
      ...updatedDrawing,
      discipline:
        Object.keys(drawingDisciplineMap).find(
          (key) => drawingDisciplineMap[key] === updatedDrawing.discipline
        ) || updatedDrawing.discipline,
    };
    res.status(201).json(formattedDrawing);
  } catch (error) {
    console.error("Error al añadir nueva versión:", error);
    res.status(500).json({ error: "No se pudo añadir la nueva versión." });
  }
});

app.post("/api/drawings/:id/comments", async (req, res) => {
  try {
    const { id } = req.params;
    const { content, authorId } = req.body;
    if (!content || !authorId) {
      return res
        .status(400)
        .json({ error: "El contenido y el autor son obligatorios." });
    }
    const newComment = await prisma.comment.create({
      data: {
        content,
        author: { connect: { id: authorId } },
        drawing: { connect: { id: id } },
      },
      include: { author: true },
    });
    res.status(201).json(newComment);
  } catch (error) {
    console.error("Error al añadir el comentario al plano:", error);
    res.status(500).json({ error: "No se pudo añadir el comentario." });
  }
});

// --- RUTAS PARA ACTAS DE COMITÉ ---
app.get("/api/actas", async (req, res) => {
  try {
    const actas = await prisma.acta.findMany({
      orderBy: { date: "desc" },
      include: {
        attachments: true,
        commitments: { include: { responsible: true } },
        signatures: { include: { signer: true } },
      },
    });
    // Formatear enums antes de enviar
    const formattedActas = actas.map((acta) => ({
      ...acta,
      area:
        Object.keys(actaAreaMap).find(
          (key) => actaAreaMap[key] === acta.area
        ) || acta.area,
      status:
        Object.keys(actaStatusMap).find(
          (key) => actaStatusMap[key] === acta.status
        ) || acta.status,
    }));
    res.json(formattedActas);
  } catch (error) {
    console.error("Error al obtener actas:", error);
    res.status(500).json({ error: "No se pudieron obtener las actas." });
  }
});

app.post("/api/actas", async (req, res) => {
  try {
    const {
      number,
      title,
      date,
      area,
      status,
      summary,
      commitments = [],
      attachments = [],
      requiredSignatories = [],
    } = req.body;
    const prismaArea = actaAreaMap[area] || "OTHER";
    const prismaStatus = actaStatusMap[status] || "DRAFT";
    const newActa = await prisma.acta.create({
      data: {
        number,
        title,
        date: new Date(date),
        area: prismaArea,
        status: prismaStatus,
        summary,
        commitments: {
          create: commitments.map((c: any) => ({
            description: c.description,
            dueDate: new Date(c.dueDate),
            status: "PENDING",
            responsible: { connect: { id: c.responsible.id } },
          })),
        },
        attachments: {
          create: attachments.map((att: any) => ({
            fileName: att.fileName,
            url: att.url,
            size: att.size,
            type: att.type,
          })),
        },
        requiredSignatoriesJson: JSON.stringify(
          requiredSignatories.map((u: any) => u.id)
        ),
      },
      include: {
        commitments: { include: { responsible: true } },
        attachments: true,
        signatures: { include: { signer: true } },
      },
    });
    // Formatear enums en la respuesta
    const formattedActa = {
      ...newActa,
      area:
        Object.keys(actaAreaMap).find(
          (key) => actaAreaMap[key] === newActa.area
        ) || newActa.area,
      status:
        Object.keys(actaStatusMap).find(
          (key) => actaStatusMap[key] === newActa.status
        ) || newActa.status,
    };
    res.status(201).json(formattedActa);
  } catch (error) {
    console.error("Error al crear el acta:", error);
    res.status(500).json({ error: "No se pudo crear el acta." });
  }
});

// TODO: Añadir PUT /api/actas/:id
// TODO: Añadir PUT /api/commitments/:id

// --- RUTAS DE BITÁCORA ---
app.get("/api/log-entries", async (req, res) => {
  try {
    const entries = await prisma.logEntry.findMany({
      orderBy: { createdAt: "desc" },
      include: {
        author: true,
        attachments: true,
        comments: { include: { author: true }, orderBy: { timestamp: "asc" } },
        signatures: { include: { signer: true } },
        assignees: true,
      },
    });
    // Formatear enums antes de enviar
    const formattedEntries = entries.map((entry) => ({
      ...entry,
      type:
        Object.keys(entryTypeMap).find(
          (key) => entryTypeMap[key] === entry.type
        ) || entry.type,
      status:
        Object.keys(entryStatusMap).find(
          (key) => entryStatusMap[key] === entry.status
        ) || entry.status,
    }));
    res.json(formattedEntries);
  } catch (error) {
    console.error("Error al obtener las anotaciones:", error);
    res.status(500).json({ error: "No se pudieron obtener las anotaciones." });
  }
});

app.post("/api/log-entries", async (req, res) => {
  try {
    const {
      title,
      description,
      type,
      subject,
      location,
      activityStartDate,
      activityEndDate,
      isConfidential,
      status,
      authorId,
      projectId,
      assignees = [],
    } = req.body;
    if (!title || !authorId || !projectId) {
      return res
        .status(400)
        .json({ error: "Título, autor y proyecto son obligatorios." });
    }
    const prismaType = entryTypeMap[type] || "GENERAL";
    const prismaStatus = entryStatusMap[status] || "DRAFT";
    const newEntry = await prisma.logEntry.create({
      data: {
        title,
        description,
        type: prismaType,
        subject,
        location,
        activityStartDate: new Date(activityStartDate),
        activityEndDate: new Date(activityEndDate),
        isConfidential,
        status: prismaStatus,
        author: { connect: { id: authorId } },
        project: { connect: { id: projectId } },
        assignees: {
          connect: assignees.map((user: { id: string }) => ({ id: user.id })),
        },
      },
      include: {
        author: true,
        attachments: true,
        comments: true,
        signatures: true,
        assignees: true,
      },
    });
    // Formatear enums en la respuesta
    const formattedEntry = {
      ...newEntry,
      type:
        Object.keys(entryTypeMap).find(
          (key) => entryTypeMap[key] === newEntry.type
        ) || newEntry.type,
      status:
        Object.keys(entryStatusMap).find(
          (key) => entryStatusMap[key] === newEntry.status
        ) || newEntry.status,
    };
    res.status(201).json(formattedEntry);
  } catch (error) {
    console.error("Error al crear la anotación:", error);
    res.status(500).json({ error: "No se pudo crear la anotación." });
  }
});

app.put("/api/log-entries/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const {
      title,
      description,
      type,
      subject,
      location,
      activityStartDate,
      activityEndDate,
      isConfidential,
      status,
      assignees = [],
    } = req.body;
    const prismaType = entryTypeMap[type] || "GENERAL";
    const prismaStatus = entryStatusMap[status] || "DRAFT";
    const updatedEntry = await prisma.logEntry.update({
      where: { id: id },
      data: {
        title,
        description,
        type: prismaType,
        subject,
        location,
        activityStartDate: new Date(activityStartDate),
        activityEndDate: new Date(activityEndDate),
        isConfidential,
        status: prismaStatus,
        assignees: {
          set: assignees.map((user: { id: string }) => ({ id: user.id })),
        },
      },
      include: {
        author: true,
        attachments: true,
        comments: { include: { author: true }, orderBy: { timestamp: "asc" } },
        signatures: { include: { signer: true } },
        assignees: true,
      },
    });
    // Formatear enums en la respuesta
    const formattedEntry = {
      ...updatedEntry,
      type:
        Object.keys(entryTypeMap).find(
          (key) => entryTypeMap[key] === updatedEntry.type
        ) || updatedEntry.type,
      status:
        Object.keys(entryStatusMap).find(
          (key) => entryStatusMap[key] === updatedEntry.status
        ) || updatedEntry.status,
    };
    res.json(formattedEntry);
  } catch (error) {
    console.error("Error al actualizar la anotación:", error);
    res.status(500).json({ error: "No se pudo actualizar la anotación." });
  }
});

app.delete("/api/log-entries/:id", async (req, res) => {
  try {
    const { id } = req.params;
    await prisma.logEntry.delete({ where: { id: id } });
    res.status(204).send();
  } catch (error) {
    console.error("Error al eliminar la anotación:", error);
    if ((error as any).code === "P2025") {
      return res.status(404).json({ error: "La anotación no fue encontrada." });
    }
    res.status(500).json({ error: "No se pudo eliminar la anotación." });
  }
});

// TODO: Añadir /api/log-entries/:id/comments
// TODO: Añadir /api/log-entries/:id/signatures

// --- RUTAS PARA AVANCE DE OBRA ---
app.get("/api/contract-items", async (req, res) => {
  try {
    const items = await prisma.contractItem.findMany({
      orderBy: { itemCode: "asc" },
    });
    res.json(items);
  } catch (error) {
    console.error("Error al obtener los ítems del contrato:", error);
    res
      .status(500)
      .json({ error: "No se pudieron obtener los ítems del contrato." });
  }
});

app.get("/api/work-actas", async (req, res) => {
  try {
    const actas = await prisma.workActa.findMany({
      orderBy: { date: "desc" },
      include: { items: { include: { contractItem: true } } },
    });
    // Formatear enums antes de enviar
    const formattedActas = actas.map((acta) => ({
      ...acta,
      // Aquí no hay enums de string, así que no necesitamos formatear status
    }));
    res.json(formattedActas);
  } catch (error) {
    console.error("Error al obtener las actas de avance:", error);
    res
      .status(500)
      .json({ error: "No se pudieron obtener las actas de avance." });
  }
});

app.post("/api/work-actas", async (req, res) => {
  try {
    const { number, period, date, status, items } = req.body;
    if (!number || !period || !date || !items || items.length === 0) {
      return res
        .status(400)
        .json({ error: "Faltan datos para crear el acta de avance." });
    }
    // const prismaStatus = (status as WorkActaStatus) || 'DRAFT'; // <-- ELIMINA ESTA LÍNEA
    const prismaStatus = workActaStatusMap[status] || "DRAFT"; // <-- AÑADE ESTA LÍNEA

    const newActa = await prisma.workActa.create({
      data: {
        number,
        period,
        date: new Date(date),
        status: prismaStatus, // <-- USA LA VARIABLE TRADUCIDA
        items: {
          create: items.map(
            (item: { contractItemId: string; quantity: number }) => ({
              quantity: item.quantity,
              contractItem: { connect: { id: item.contractItemId } },
            })
          ),
        },
      },
      include: { items: { include: { contractItem: true } } },
    });
    // Formatear respuesta (opcional, ya que los enums de WorkActaStatus no se envían como strings)
    res.status(201).json(newActa);
  } catch (error) {
    console.error("Error al crear el acta de avance:", error);
    if ((error as any).code === "P2002") {
      return res
        .status(409)
        .json({ error: "Ya existe un acta de avance con este número." });
    }
    res.status(500).json({ error: "No se pudo crear el acta de avance." });
  }
});

app.put("/api/work-actas/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    const prismaStatus = workActaStatusMap[status] || undefined; // <-- AÑADE ESTA LÍNEA
    if (
      !prismaStatus ||
      !Object.values(WorkActaStatus).includes(prismaStatus)
    ) {
      return res.status(400).json({ error: "Estado inválido proporcionado." });
    }
    const updateData: any = { status: prismaStatus };
    const updatedActa = await prisma.workActa.update({
      where: { id: id },
      data: updateData,
      include: { items: { include: { contractItem: true } } },
    });
    res.json(updatedActa); // No necesita formateo de enums de string
  } catch (error) {
    console.error("Error al actualizar el acta de avance:", error);
    if ((error as any).code === "P2025") {
      return res
        .status(404)
        .json({ error: "El acta de avance no fue encontrada." });
    }
    res.status(500).json({ error: "No se pudo actualizar el acta de avance." });
  }
});

// --- RUTAS PARA COSTOS INTERVENTORÍA ---

// Obtener todas las actas de costo
app.get("/api/cost-actas", async (req, res) => {
  try {
    const actas = await prisma.costActa.findMany({
      orderBy: { submissionDate: "desc" },
      include: {
        observations: {
          // Incluimos observaciones
          include: { author: true },
          orderBy: { timestamp: "asc" },
        },
        attachments: true, // Incluimos adjuntos
      },
    });
    // Formatear estado antes de enviar
    const formattedActas = actas.map((acta) => ({
      ...acta,
      // Formateamos el estado para que coincida con el frontend
      status:
        Object.keys(costActaStatusMap).find(
          (key) => costActaStatusMap[key] === acta.status
        ) || acta.status,
    }));
    res.json(formattedActas);
  } catch (error) {
    console.error("Error al obtener las actas de costo:", error);
    res
      .status(500)
      .json({ error: "No se pudieron obtener las actas de costo." });
  }
});

// Crear una nueva acta de costo
app.post("/api/cost-actas", async (req, res) => {
  try {
    // Recibimos los IDs de los adjuntos que ya se subieron
    const {
      number,
      period,
      submissionDate,
      billedAmount,
      totalContractValue,
      relatedProgress,
      attachments = [], // attachments es ahora un array de objetos { id: string }
    } = req.body;

    if (
      !number ||
      !period ||
      !submissionDate ||
      !billedAmount ||
      !totalContractValue
    ) {
      return res.status(400).json({
        error: "Faltan datos obligatorios para crear el acta de costo.",
      });
    }

    const newCostActa = await prisma.costActa.create({
      data: {
        number,
        period,
        submissionDate: new Date(submissionDate),
        billedAmount: parseFloat(billedAmount),
        totalContractValue: parseFloat(totalContractValue),
        relatedProgress,
        status: CostActaStatus.SUBMITTED, // Estado inicial por defecto
        attachments: {
          // Conectamos los adjuntos existentes usando sus IDs
          connect: attachments.map((att: { id: string }) => ({ id: att.id })),
        },
      },
      include: {
        // Devolvemos el acta creada completa
        observations: { include: { author: true } },
        attachments: true,
      },
    });

    res.status(201).json(newCostActa); // No necesita formateo
  } catch (error) {
    console.error("Error al crear el acta de costo:", error);
    if ((error as any).code === "P2002") {
      // Error de código único duplicado
      return res
        .status(409)
        .json({ error: "Ya existe un acta de costo con este número." });
    }
    res.status(500).json({ error: "No se pudo crear el acta de costo." });
  }
});

app.put("/api/cost-actas/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { status, relatedProgress } = req.body;

    const prismaStatus = costActaStatusMap[status] || undefined;
    if (
      !prismaStatus ||
      !Object.values(CostActaStatus).includes(prismaStatus)
    ) {
      return res.status(400).json({ error: "Estado inválido proporcionado." });
    }

    // Preparamos los datos a actualizar
    const updateData: any = {
      status: prismaStatus,
      relatedProgress: relatedProgress, // Actualizamos relatedProgress si viene
    };

    // Lógica especial si se aprueba: calcular fechas
    if (prismaStatus === "APPROVED") {
      const approvalDate = new Date();
      updateData.approvalDate = approvalDate;
      const paymentDueDate = new Date(approvalDate);
      paymentDueDate.setDate(paymentDueDate.getDate() + 30); // Añade 30 días calendario
      updateData.paymentDueDate = paymentDueDate;
    }

    const updatedActa = await prisma.costActa.update({
      where: { id: id },
      data: updateData,
      include: {
        // Devolvemos el acta completa actualizada
        observations: {
          include: { author: true },
          orderBy: { timestamp: "asc" },
        },
        attachments: true,
      },
    });

    // Formatear estado en la respuesta
    const formattedActa = {
      ...updatedActa,
      status:
        Object.keys(costActaStatusMap).find(
          (key) => costActaStatusMap[key] === updatedActa.status
        ) || updatedActa.status,
    };
    res.json(formattedActa);
  } catch (error) {
    console.error("Error al actualizar el acta de costo:", error);
    if ((error as any).code === "P2025") {
      return res
        .status(404)
        .json({ error: "El acta de costo no fue encontrada." });
    }
    res.status(500).json({ error: "No se pudo actualizar el acta de costo." });
  }
});

// Añadir una observación a un acta de costo
app.post("/api/cost-actas/:id/observations", async (req, res) => {
  try {
    const { id } = req.params;
    const { text, authorId } = req.body;

    if (!text || !authorId) {
      return res.status(400).json({
        error: "El texto y el autor son obligatorios para la observación.",
      });
    }

    const newObservation = await prisma.observation.create({
      data: {
        text,
        author: { connect: { id: authorId } },
        costActa: { connect: { id: id } },
      },
      include: { author: true }, // Devolvemos la observación con el autor
    });

    res.status(201).json(newObservation);
  } catch (error) {
    console.error("Error al añadir la observación:", error);
    if ((error as any).code === "P2025") {
      // Si el acta o el autor no existen
      return res.status(404).json({
        error: "El acta de costo o el usuario autor no fueron encontrados.",
      });
    }
    res.status(500).json({ error: "No se pudo añadir la observación." });
  }
});

// --- RUTAS PARA INFORMES (Reports) ---

// Obtener todos los informes (filtrables por query params ?type=Weekly&scope=OBRA)
app.get("/api/reports", async (req, res) => {
  try {
    const { type, scope } = req.query; // Filtros opcionales del frontend (ej: "Interventoría")

    const whereClause: any = {};
    if (type) whereClause.type = type as string;
    
    // Traduce el scope del query param al enum de Prisma ANTES de hacer la consulta
    if (scope) {
      const prismaScope = reportScopeMap[scope as string];
      if (prismaScope) {
        whereClause.reportScope = prismaScope;
      }
    }

    const reports = await prisma.report.findMany({
      where: whereClause,
      orderBy: { submissionDate: 'desc' },
      include: {
        author: true,
        attachments: true,
        signatures: { include: { signer: true } }
      }
    });

    // Formatea la respuesta para que los enums vuelvan a ser texto legible por el frontend
    const formattedReports = reports.map(report => ({
        ...report,
        reportScope: Object.keys(reportScopeMap).find(key => reportScopeMap[key] === report.reportScope) || report.reportScope,
        status: Object.keys(reportStatusMap).find(key => reportStatusMap[key] === report.status) || report.status,
    }));

    res.json(formattedReports);
  } catch (error) {
    console.error("Error al obtener los informes:", error);
    res.status(500).json({ error: 'No se pudieron obtener los informes.' });
  }
});

// Crear un nuevo informe
app.post("/api/reports", async (req, res) => {
  try {
    const {
      type, reportScope, number, period, submissionDate, summary, authorId,
      requiredSignatories = [], attachments = [] // Recibe IDs de adjuntos
    } = req.body;

    if (!type || !reportScope || !number || !period || !submissionDate || !summary || !authorId) {
      return res.status(400).json({ error: 'Faltan datos obligatorios para crear el informe.' });
    }

    // --- TRADUCCIÓN DE ENUMS ---
    const prismaReportScope = reportScopeMap[reportScope];
    if (!prismaReportScope) {
        return res.status(400).json({ error: `El valor de reportScope '${reportScope}' no es válido.` });
    }
    // No necesitamos traducir 'status' al crear, porque siempre será DRAFT.
    // ----------------------------

    const newReport = await prisma.report.create({
      data: {
        type,
        reportScope: prismaReportScope, // Usa la variable traducida
        number,
        period,
        submissionDate: new Date(submissionDate),
        summary,
        status: "DRAFT", // Estado inicial por defecto es DRAFT (borrador)
        author: { connect: { id: authorId } },
        requiredSignatoriesJson: JSON.stringify(requiredSignatories.map((u: any) => u.id)),
        attachments: {
          connect: attachments.map((att: { id: string }) => ({ id: att.id }))
        }
      },
      include: { // Devolvemos el informe creado completo
        author: true,
        attachments: true,
        signatures: { include: { signer: true } }
      }
    });

    // Formatea la respuesta para que el frontend la entienda
     const formattedReport = {
        ...newReport,
        reportScope: Object.keys(reportScopeMap).find(key => reportScopeMap[key] === newReport.reportScope) || newReport.reportScope,
        status: Object.keys(reportStatusMap).find(key => reportStatusMap[key] === newReport.status) || newReport.status,
    };

    res.status(201).json(formattedReport);

  } catch (error) {
    console.error("Error al crear el informe:", error);
    if ((error as any).code === 'P2002') { // Error de número único duplicado
         return res.status(409).json({ error: 'Ya existe un informe con este número.' });
    }
    res.status(500).json({ error: 'No se pudo crear el informe.' });
  }
});

// Actualizar un informe (principalmente estado)
app.put('/api/reports/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { status, summary, requiredSignatories = [] } = req.body; // Campos que permitimos actualizar

    const prismaStatus = reportStatusMap[status] || undefined;
    if (!prismaStatus || !Object.values(ReportStatus).includes(prismaStatus)) {
      return res.status(400).json({ error: 'Estado inválido proporcionado.' });
    }

    const updateData: any = {
      status: prismaStatus,
      summary, // Permite actualizar el resumen si viene
      requiredSignatoriesJson: JSON.stringify(requiredSignatories.map((u: any) => u.id)) // Actualiza firmantes requeridos
    };

    const updatedReport = await prisma.report.update({
      where: { id: id },
      data: updateData,
      include: { // Devolvemos el informe completo actualizado
        author: true,
        attachments: true,
        signatures: { include: { signer: true } }
      }
    });

    // Formatear respuesta
    const formattedReport = {
        ...updatedReport,
        reportScope: Object.keys(reportScopeMap).find(key => reportScopeMap[key] === updatedReport.reportScope) || updatedReport.reportScope,
        status: Object.keys(reportStatusMap).find(key => reportStatusMap[key] === updatedReport.status) || updatedReport.status,
    };
    res.json(formattedReport);

  } catch (error) {
    console.error("Error al actualizar el informe:", error);
    if ((error as any).code === 'P2025') {
        return res.status(404).json({ error: 'El informe no fue encontrado.' });
    }
    res.status(500).json({ error: 'No se pudo actualizar el informe.' });
  }
});

// Añadir una firma a un informe
app.post('/api/reports/:id/signatures', async (req, res) => {
    try {
        const { id } = req.params;
        const { signerId, password } = req.body; // Recibimos el ID del firmante y su contraseña

        if (!signerId || !password) {
            return res.status(400).json({ error: 'Se requiere ID del firmante y contraseña.' });
        }

        // 1. Verificar contraseña del firmante
        const signer = await prisma.user.findUnique({ where: { id: signerId } });
        if (!signer) {
            return res.status(404).json({ error: 'Usuario firmante no encontrado.' });
        }
        const passwordMatch = await bcrypt.compare(password, signer.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Contraseña incorrecta.' });
        }

        // 2. Verificar que el informe exista
        const report = await prisma.report.findUnique({ where: { id } });
        if (!report) {
            return res.status(404).json({ error: 'Informe no encontrado.' });
        }

        // 3. Añadir la firma (evita duplicados si ya firmó)
        const existingSignature = await prisma.signature.findFirst({
            where: { reportId: id, signerId: signerId }
        });

        if (existingSignature) {
            // Si ya existe, simplemente devolvemos el informe actual
             const currentReport = await prisma.report.findUnique({
                where: { id },
                include: { author: true, attachments: true, signatures: { include: { signer: true } } }
            });
             const formattedReport = {
                ...currentReport,
                reportScope: Object.keys(reportScopeMap).find(key => reportScopeMap[key] === currentReport!.reportScope) || currentReport!.reportScope,
                status: Object.keys(reportStatusMap).find(key => reportStatusMap[key] === currentReport!.status) || currentReport!.status,
            };
            return res.json(formattedReport); // Ya estaba firmado
        }

        await prisma.signature.create({
            data: {
                signer: { connect: { id: signerId } },
                report: { connect: { id: id } }
            }
        });

        // 4. (Opcional) Lógica para cambiar el estado a 'APROBADO' si todos firman
        // Necesitarías leer 'requiredSignatoriesJson', parsearlo,
        // contar las firmas actuales y comparar. Si coinciden, actualiza el estado.
        // const requiredIds = JSON.parse(report.requiredSignatoriesJson || '[]');
        // const currentSignatures = await prisma.signature.count({ where: { reportId: id } });
        // let finalStatus = report.status;
        // if (requiredIds.length > 0 && currentSignatures + 1 >= requiredIds.length && report.status === 'SUBMITTED') {
        //     finalStatus = ReportStatus.APPROVED;
        //     await prisma.report.update({ where: { id }, data: { status: finalStatus } });
        // }
        // Por ahora, no cambiaremos el estado automáticamente al firmar.

        // 5. Devolver el informe actualizado con la nueva firma
        const updatedReport = await prisma.report.findUnique({
            where: { id },
            include: { author: true, attachments: true, signatures: { include: { signer: true } } }
        });

         const formattedReport = {
            ...updatedReport,
            reportScope: Object.keys(reportScopeMap).find(key => reportScopeMap[key] === updatedReport!.reportScope) || updatedReport!.reportScope,
            status: Object.keys(reportStatusMap).find(key => reportStatusMap[key] === updatedReport!.status) || updatedReport!.status,
        };
        res.status(201).json(formattedReport); // Código 201 porque se creó una firma

    } catch (error) {
        console.error("Error al añadir la firma al informe:", error);
        res.status(500).json({ error: 'No se pudo añadir la firma.' });
    }
});

// --- RUTAS PARA AVANCE FOTOGRÁFICO ---

// Obtener todos los puntos de control con sus fotos
app.get('/api/control-points', async (req, res) => {
  try {
    const points = await prisma.controlPoint.findMany({
      orderBy: { createdAt: 'asc' },
      include: {
        photos: { // Incluye las fotos asociadas
          orderBy: { date: 'asc' }, // Ordena las fotos por fecha
          include: {
            author: true // Incluye quién tomó la foto
          }
        }
      }
    });
    res.json(points);
  } catch (error) {
    console.error("Error al obtener los puntos de control:", error);
    res.status(500).json({ error: 'No se pudieron obtener los puntos de control.' });
  }
});

// Crear un nuevo punto de control
app.post('/api/control-points', async (req, res) => {
  try {
    const { name, description, location } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'El nombre del punto de control es obligatorio.' });
    }

    const newPoint = await prisma.controlPoint.create({
      data: { name, description, location },
      include: { photos: { include: { author: true } } } // Devuelve el punto nuevo (vacío de fotos)
    });
    res.status(201).json(newPoint);

  } catch (error) {
    console.error("Error al crear el punto de control:", error);
    res.status(500).json({ error: 'No se pudo crear el punto de control.' });
  }
});

// Añadir una foto a un punto de control existente
app.post('/api/control-points/:id/photos', async (req, res) => {
  try {
    const { id } = req.params; // ID del ControlPoint
    // Recibe el ID del Attachment y las notas
    const { notes, authorId, attachmentId } = req.body; 

    if (!authorId || !attachmentId) {
      return res.status(400).json({ error: 'Faltan datos del autor o del archivo adjunto.' });
    }

    // Verifica que el punto de control exista (opcional pero bueno)
    const controlPointExists = await prisma.controlPoint.findUnique({ where: { id } });
    if (!controlPointExists) {
      return res.status(404).json({ error: 'Punto de control no encontrado.' });
    }

    // Busca el Attachment para obtener su URL
    const attachment = await prisma.attachment.findUnique({ where: { id: attachmentId } });
    if (!attachment) {
        return res.status(404).json({ error: 'Archivo adjunto no encontrado.' });
    }

    // Crea la PhotoEntry
    const newPhoto = await prisma.photoEntry.create({
      data: {
        notes,
        url: attachment.url, // <-- ¡AÑADE ESTA LÍNEA! Pasa la URL del attachment
        author: { connect: { id: authorId } },
        controlPoint: { connect: { id: id } },
        attachment: { connect: { id: attachmentId } } 
      },
      include: { 
          author: true,
          attachment: true // Incluye el attachment en la respuesta
      } 
    });

    // Formatea la respuesta para incluir la URL directamente si el frontend la necesita así
    const formattedPhoto = {
        ...newPhoto,
        url: newPhoto.attachment?.url || newPhoto.url // Asegura que la URL esté disponible
    };

    res.status(201).json(formattedPhoto);

  } catch (error) {
    console.error("Error al añadir la foto:", error);
     if ((error as any).code === 'P2025') { 
        return res.status(404).json({ error: 'El autor, punto de control o archivo adjunto no fueron encontrados.' });
    }
    res.status(500).json({ error: 'No se pudo añadir la foto.' });
  }
});

app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});
