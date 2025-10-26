import { PrismaClient } from '@prisma/client';

// Crear una instancia global de PrismaClient
const prisma = new PrismaClient({
  log: ['query', 'info', 'warn', 'error'],
});

export default prisma;


