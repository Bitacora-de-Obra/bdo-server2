import { UserRole, ActaArea, ActaStatus, EntryType, EntryStatus, DeliveryMethod, DrawingDiscipline, WorkActaStatus } from '@prisma/client'; // <-- MODIFICA ESTA LÍNEA
/**
 * Mapea los valores de rol del frontend (en español) a los valores del enum de Prisma.
 * Este es el "traductor" entre el cliente y la base de datos.
 */
export const roleMap: { [key: string]: UserRole } = {
    'Residente de Obra': 'RESIDENT',
    'Supervisor': 'SUPERVISOR',
    'Representante Contratista': 'CONTRACTOR_REP',
    'Administrador IDU': 'ADMIN',
    'Invitado': 'GUEST', // <-- Añade la nueva "traducción" aquí
};

/**
 * Mapea las áreas de las actas del frontend a los valores del enum de Prisma.
 */
export const actaAreaMap: { [key: string]: ActaArea } = {
    'Comité de Obra': 'COMITE_OBRA', 
    'Comité HSE': 'HSE', 
    'Comité Ambiental': 'AMBIENTAL',
    'Comité Social': 'SOCIAL', 
    'Comité Jurídico': 'JURIDICO', 
    'Comité Técnico': 'TECNICO', 
    'Otro': 'OTHER',
};

/**
 * Mapea los estados de las actas del frontend a los valores del enum de Prisma.
 */
export const actaStatusMap: { [key: string]: ActaStatus } = {
    'Firmada': 'SIGNED', 
    'En Borrador': 'DRAFT', 
    'Para Firmas': 'FOR_SIGNATURES', 
    'Cerrada': 'CLOSED',
};

export const entryTypeMap: { [key: string]: EntryType } = {
    'Calidad': 'QUALITY',
    'Administrativo': 'ADMINISTRATIVE',
    'HSE': 'SAFETY',
    'General': 'GENERAL',
};

/**
 * Mapea los estados de anotación del frontend a los valores del enum de Prisma.
 */
export const entryStatusMap: { [key: string]: EntryStatus } = {
    'Aprobado': 'APPROVED',
    'En Revisión': 'NEEDS_REVIEW',
    'Radicado': 'SUBMITTED',
    'Rechazado': 'REJECTED',
    'Borrador': 'DRAFT',
};

export const deliveryMethodMap: { [key: string]: DeliveryMethod } = { // <-- AÑADE ESTE BLOQUE
    'Correo Electrónico': 'MAIL',
    'Impreso': 'PRINTED',
    'Sistema BDO': 'SYSTEM',
    'Fax': 'FAX',
};

export const drawingDisciplineMap: { [key: string]: DrawingDiscipline } = {
    'Arquitectónico': 'ARQUITECTONICO',
    'Estructural': 'ESTRUCTURAL',
    'Eléctrico': 'ELECTRICO',
    'Hidrosanitario': 'HIDROSANITARIO',
    'Mecánico': 'MECANICO',
    'Urbanismo y Paisajismo': 'URBANISMO',
    'Señalización y PMT': 'SEÑALIZACION',
    'Geotecnia y Suelos': 'GEOTECNIA',
    'Otro': 'OTHER',
};

export const workActaStatusMap: { [key: string]: WorkActaStatus } = { // <-- AÑADE ESTE BLOQUE
    'Aprobada': 'APPROVED',
    'En Revisión': 'IN_REVIEW',
    'En Borrador': 'DRAFT',
};