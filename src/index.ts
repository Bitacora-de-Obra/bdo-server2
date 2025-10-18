import express from "express";
import cors from "cors";
import {
  PrismaClient,
  UserRole,
  WorkActaStatus,
  CostActaStatus,
} from "@prisma/client"; // Asegúrate de importar WorkActaStatus
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
app.post("/api/upload", upload.single("file"), (req, res) => {
  if (!req.file) {
    return res.status(400).send("No se subió ningún archivo.");
  }
  // Devuelve la información necesaria para guardar en la base de datos
  res.json({
    message: "Archivo subido exitosamente",
    fileName: req.file.originalname,
    url: `http://localhost:4000/uploads/${req.file.filename}`, // La URL donde se puede acceder al archivo
    size: req.file.size,
    type: req.file.mimetype,
  });
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
      return res
        .status(400)
        .json({
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
      return res
        .status(400)
        .json({
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
      return res
        .status(404)
        .json({
          error: "El acta de costo o el usuario autor no fueron encontrados.",
        });
    }
    res.status(500).json({ error: "No se pudo añadir la observación." });
  }
});

app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});
