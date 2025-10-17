import express from 'express';
import cors from 'cors';
import { PrismaClient, EntryType, EntryStatus, ActaArea, ActaStatus, CommitmentStatus } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import 'dotenv/config';
import multer from 'multer';
import path from 'path';

const app = express();
const prisma = new PrismaClient();
const port = 4000;

app.use(cors());
app.use(express.json());

// --- CONFIGURACIÓN DE MULTER ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});
const upload = multer({ storage });
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

// --- RUTAS ---

// Ruta para subir archivos
app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).send('No se subió ningún archivo.');
  res.json({
    message: 'Archivo subido exitosamente',
    fileName: req.file.originalname,
    url: `http://localhost:4000/uploads/${req.file.filename}`,
    size: req.file.size,
    type: req.file.mimetype,
  });
});

// Rutas de Autenticación (No necesitan cambios)
app.post('/api/auth/register', async (req, res) => { /* ... */ });
app.post('/api/auth/login', async (req, res) => { /* ... */ });
app.get('/api/users', async (req, res) => { /* ... */ });

// Rutas de Bitácora (No necesitan cambios)
app.get('/api/log-entries', async (req, res) => { /* ... */ });
app.post('/api/log-entries', async (req, res) => { /* ... */ });
app.put('/api/log-entries/:id', async (req, res) => { /* ... */ });
app.delete('/api/log-entries/:id', async (req, res) => { /* ... */ });
app.post('/api/log-entries/:id/comments', async (req, res) => { /* ... */ });
app.post('/api/log-entries/:id/signatures', async (req, res) => { /* ... */ });


// --- RUTAS PARA ACTAS DE COMITÉ (CORREGIDAS) ---

// Obtener todas las actas
app.get('/api/actas', async (req, res) => {
  try {
    const actas = await prisma.acta.findMany({
      orderBy: { date: 'desc' },
      include: {
        attachments: true, // <-- CORRECCIÓN: Añadido para incluir adjuntos
        commitments: {
          include: {
            responsible: true
          }
        }
      }
    });
    res.json(actas);
  } catch (error) {
    res.status(500).json({ error: 'No se pudieron obtener las actas.' });
  }
});

// Crear una nueva acta
app.post('/api/actas', async (req, res) => {
  try {
    const { number, title, date, area, status, summary, commitments = [], attachments = [] } = req.body;

    // --- CORRECCIÓN: Mapas rellenados ---
    const areaMap: { [key: string]: ActaArea } = {
      'Comité de Obra': 'COMITE_OBRA', 'Comité HSE': 'HSE', 'Comité Ambiental': 'AMBIENTAL',
      'Comité Social': 'SOCIAL', 'Comité Jurídico': 'JURIDICO', 'Comité Técnico': 'TECNICO', 'Otro': 'OTHER',
    };
    const statusMap: { [key: string]: ActaStatus } = {
      'Firmada': 'SIGNED', 'En Borrador': 'DRAFT', 'Para Firmas': 'FOR_SIGNATURES', 'Cerrada': 'CLOSED',
    };
    const prismaArea = areaMap[area] || 'OTHER';
    const prismaStatus = statusMap[status] || 'DRAFT';
    
    // El resto de la lógica para crear usuarios y el acta está bien
    const defaultPassword = await bcrypt.hash('password123', 10);
    for (const c of commitments) { /* ... */ }

    const newActa = await prisma.acta.create({
      data: {
        number, title, date: new Date(date), area: prismaArea, status: prismaStatus, summary,
        commitments: { create: commitments.map((c: any) => ({ description: c.description, dueDate: new Date(c.dueDate), status: 'PENDING', responsible: { connect: { id: c.responsible.id } } })) },
        attachments: { create: attachments.map((att: any) => ({ fileName: att.fileName, url: att.url, size: att.size, type: att.type })) }
      },
      include: { attachments: true, commitments: { include: { responsible: true } } }
    });
    res.status(201).json(newActa);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'No se pudo crear el acta.' });
  }
});

// Actualizar un compromiso (No necesita cambios)
app.put('/api/commitments/:id', async (req, res) => { /* ... */ });


app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});