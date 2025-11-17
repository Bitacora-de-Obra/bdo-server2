const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function createTestData() {
  console.log('Creating test data for PDF generation...');
  
  try {
    // Get or create a test project
    let project = await prisma.project.findFirst();
    
    if (!project) {
      project = await prisma.project.create({
        data: {
          name: 'Proyecto Test PDF',
          code: 'TEST-PDF',
          location: 'Bogotá, Colombia',
          description: 'Proyecto de prueba para generación de PDFs',
          startDate: new Date('2024-01-01'),
          endDate: new Date('2024-12-31'),
          budget: 1000000000,
          status: 'ACTIVE',
          category: 'INFRASTRUCTURE',
          priority: 'HIGH'
        }
      });
      console.log('✅ Created test project');
    }

    // Get admin user
    const adminUser = await prisma.user.findFirst({
      where: { email: 'admin@bdigitales.com' }
    });

    if (!adminUser) {
      console.log('❌ Admin user not found');
      return;
    }

    // Create a test log entry if none exists
    const existingLogEntry = await prisma.logEntry.findFirst();
    
    if (!existingLogEntry) {
      await prisma.logEntry.create({
        data: {
          projectId: project.id,
          userId: adminUser.id,
          entryType: 'INCIDENT',
          title: 'Entrada de Prueba para PDF',
          description: 'Esta es una entrada de prueba para generar PDFs y verificar la funcionalidad de almacenamiento en Cloudflare R2.',
          date: new Date(),
          weather: 'Soleado',
          temperature: 22,
          workingHours: 8,
          workersCount: 15,
          location: 'Zona A - Construcción Principal',
          observations: 'Observaciones de prueba para el sistema de generación de PDFs',
          status: 'ACTIVE'
        }
      });
      console.log('✅ Created test log entry');
    }

    // Create a test weekly report if none exists
    const existingReport = await prisma.weeklyReport.findFirst();
    
    if (!existingReport) {
      const startOfWeek = new Date();
      startOfWeek.setDate(startOfWeek.getDate() - startOfWeek.getDay());
      
      const endOfWeek = new Date(startOfWeek);
      endOfWeek.setDate(startOfWeek.getDate() + 6);

      await prisma.weeklyReport.create({
        data: {
          projectId: project.id,
          createdById: adminUser.id,
          weekStart: startOfWeek,
          weekEnd: endOfWeek,
          number: 'WR-TEST-001',
          title: 'Reporte Semanal de Prueba',
          summary: 'Reporte semanal de prueba para verificar la generación de PDFs',
          progress: 75.5,
          issues: 'No se presentaron inconvenientes mayores durante la semana',
          nextWeekPlanning: 'Continuar con las actividades programadas según cronograma',
          status: 'APPROVED',
          scope: 'PROJECT'
        }
      });
      console.log('✅ Created test weekly report');
    }

    console.log('✅ Test data creation completed');
    
  } catch (error) {
    console.error('❌ Error creating test data:', error);
  } finally {
    await prisma.$disconnect();
  }
}

createTestData();
