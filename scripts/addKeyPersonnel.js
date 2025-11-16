/* eslint-disable no-console */
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// Personal clave de OBRA (CONTRATISTA) extraído de las tablas con dedicaciones
const PERSONNEL_OBRA = [
  { name: 'Cesar Augusto Reyes', role: 'Director De Obra', company: 'Contratista', email: 'directorobra.cto2412@gmail.com', phone: '-', dedication: '50%' },
  { name: 'Tatiana González', role: 'Coordinador De Obra', company: 'Contratista', email: '-', phone: '-', dedication: '100%' },
  { name: 'Elio Fernando Bolaño', role: 'Residente De Obra', company: 'Contratista', email: 'residentetecnico.cto2412@gmail.com', phone: '-', dedication: '100%' },
  { name: 'Sandro José Prieto', role: 'Especialista En Diseño Geométrico', company: 'Contratista', email: '-', phone: '-', dedication: '0%' },
  { name: 'Fausto Guerrero Castro', role: 'Especialista En Urbanismo Y Espacio Público', company: 'Contratista', email: '-', phone: '-', dedication: '25%' },
  { name: 'Ricardo Alberto Mendoza', role: 'Especialista En Geotecnia', company: 'Contratista', email: '-', phone: '-', dedication: '20%' },
  { name: 'Lucia Constanza Moreno', role: 'Especialista En Pavimentos', company: 'Contratista', email: '-', phone: '-', dedication: '30%' },
  { name: 'Ernesto Riveros Ospina', role: 'Especialista Redes Hidrosanitarias', company: 'Contratista', email: '-', phone: '-', dedication: '25%' },
  { name: 'John Bleyder Flores Martínez', role: 'Residente De Redes Hidrosanitarias', company: 'Contratista', email: 'residentehidrosanitario.cto2412@gmail.com', phone: '-', dedication: '100%' },
  { name: 'Juan Fernando Ballestas', role: 'Especialista Redes Secas Y Gas', company: 'Contratista', email: '-', phone: '-', dedication: '25%' },
  { name: 'Iván Felipe Acuña', role: 'Profesional En Costos, Presupuestos Y Programación', company: 'Contratista', email: 'profesionalcostos.cto2412@gmail.com', phone: '-', dedication: '25%' },
  { name: 'Manuel Fernando Salazar', role: 'Especialista Bim-Sig-Cad/Coordinador BIM', company: 'Contratista', email: '-', phone: '-', dedication: '50%' },
  { name: 'Jhorts Maykol Ortiz', role: 'Modelador BIM', company: 'Contratista', email: '-', phone: '-', dedication: '20%' },
  { name: 'Adonai Toro Valero', role: 'Especialista En Estructuras', company: 'Contratista', email: '-', phone: '-', dedication: '20%' },
  { name: 'Johana Florez Rojas', role: 'Especialista En Transito Y Transporte', company: 'Contratista', email: '-', phone: '-', dedication: '30%' },
  { name: 'Andrés Amaya', role: 'Residente Transito Y Transporte', company: 'Contratista', email: '-', phone: '-', dedication: '80%' },
  { name: 'Andrés Rojas', role: 'Ingeniero Modelador', company: 'Contratista', email: '-', phone: '-', dedication: '30%' },
  { name: 'Santiago Angulo', role: 'Profesional Arqueólogo / Antropólogo', company: 'Contratista', email: 'arqueologia.cto2412@gmail.com', phone: '-', dedication: '100%' },
  { name: 'Claudia Viviana Pinzón', role: 'Profesional de ingeniería SIG/CAD', company: 'Contratista', email: '-', phone: '-', dedication: '30%' },
  { name: 'Dalia Carolina Daza', role: 'Residente Ambiental', company: 'Contratista', email: 'residenteambiental.cto2412@gmail.com', phone: '-', dedication: '100%' },
  { name: 'Nelson Yesid Rocha', role: 'Residente Forestal', company: 'Contratista', email: 'yesidrocha02@hotmail.com', phone: '-', dedication: '30%' },
  { name: 'Mónica Ariana Hernández', role: 'Residente En Fauna Silvestre', company: 'Contratista', email: 'biologa.mahdz@gmail.com', phone: '-', dedication: '30%' },
  { name: 'Johanna Cárdenas', role: 'Residente Sst', company: 'Contratista', email: 'sst.cto2412ijk@gmail.com', phone: '-', dedication: '100%' },
  { name: 'Edwar Gerardo Muñoz', role: 'Residente Maquinaria Y Equipos', company: 'Contratista', email: 'maquinaria.cto2412@gmail.com', phone: '-', dedication: '40%' },
  { name: 'Ingri Rodríguez', role: 'Residente Social', company: 'Contratista', email: 'puntoiducontrato2412ijk@gmail.com', phone: '-', dedication: '100%' },
  { name: 'Jeraldine Caicedo', role: 'Asistente social', company: 'Contratista', email: '-', phone: '-', dedication: '100%' },
  { name: 'Angélica Patricia Sepúlveda Silva', role: 'Comunicador Social', company: 'Contratista', email: '-', phone: '-', dedication: '50%' },
  { name: 'Liliana Valenzuela Salas', role: 'Pedagogo O Licenciado', company: 'Contratista', email: '-', phone: '-', dedication: '50%' },
  { name: 'Michael Daniel López Gordillo', role: 'Profesional Arquitecto Actas De Vecindad', company: 'Contratista', email: '-', phone: '-', dedication: '50%' },
  { name: 'Jeritza Yamilka Sarmiento', role: 'Profesional Social Actas De Vecindad', company: 'Contratista', email: '-', phone: '-', dedication: '50%' },
  { name: 'Karen Daniela Bernal Duarte', role: 'Auxiliar De Ingeniería', company: 'Contratista', email: '-', phone: '-', dedication: '25%' },
  { name: 'Oscar Alberto Hernández', role: 'Guía cívico', company: 'Contratista', email: '-', phone: '-', dedication: '100%' },
  { name: 'Víctor Useche', role: 'Inspector II', company: 'Contratista', email: '-', phone: '-', dedication: '100%' },
  { name: 'Martha Liliana Martínez Rodríguez', role: 'Inspector SST - MA', company: 'Contratista', email: '-', phone: '-', dedication: '100%' },
  { name: 'Karen Nova', role: 'Topógrafo inspector', company: 'Contratista', email: '-', phone: '-', dedication: '50%' },
  { name: 'Elkin Pinzón', role: 'Cadenero 1', company: 'Contratista', email: '-', phone: '-', dedication: '50%' },
  { name: 'Alexander Espitia', role: 'Cadenero 2', company: 'Contratista', email: '-', phone: '-', dedication: '50%' },
  { name: 'Karen Ciro', role: 'Secretaria II', company: 'Contratista', email: '-', phone: '-', dedication: '50%' },
  { name: 'David Rodríguez', role: 'Conductor', company: 'Contratista', email: '-', phone: '-', dedication: '100%' },
  { name: 'Jeison López', role: 'Almacenista', company: 'Contratista', email: '-', phone: '-', dedication: '100%' },
  { name: 'Doralba Silvana', role: 'Boal 1', company: 'Contratista', email: '-', phone: '-', dedication: '100%' },
  { name: 'Dayana León', role: 'Boal 2', company: 'Contratista', email: '-', phone: '-', dedication: '100%' },
  { name: 'José Robayo', role: 'Boal 3', company: 'Contratista', email: '-', phone: '-', dedication: '100%' },
  { name: 'Claudio Ríos', role: 'Paletero', company: 'Contratista', email: '-', phone: '-', dedication: '100%' },
  { name: 'Lizet Cortez', role: 'Paletero', company: 'Contratista', email: '-', phone: '-', dedication: '100%' },
  { name: 'Edilson Sánchez', role: 'Paletero', company: 'Contratista', email: '-', phone: '-', dedication: '100%' },
  { name: 'Luis Ángel Moreno', role: 'Ayudante de arqueología', company: 'Contratista', email: '-', phone: '-', dedication: '30%' },
];

async function main() {
  const project = await prisma.project.findFirst();
  if (!project) {
    console.error('No project found.');
    process.exit(1);
  }

  // Eliminar personal clave existente para reemplazarlo
  await prisma.keyPersonnel.deleteMany({
    where: { projectId: project.id },
  });

  // Agregar solo personal de obra (contratista) con orden
  await prisma.keyPersonnel.createMany({
    data: PERSONNEL_OBRA.map((p, index) => ({
      projectId: project.id,
      name: p.name,
      role: p.role,
      company: p.company,
      email: p.email || '-',
      phone: p.phone || '-',
      dedication: p.dedication || null,
      sortOrder: index, // Mantener el orden exacto del array
    })),
  });

  console.log(`Added ${PERSONNEL_OBRA.length} key personnel (Obra/Contratista) with dedications.`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
