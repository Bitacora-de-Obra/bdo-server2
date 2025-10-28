import { UserRole, ActaArea, ActaStatus, EntryType, EntryStatus, DeliveryMethod, DrawingDiscipline, WorkActaStatus, CostActaStatus, ReportScope , ReportStatus, CommitmentStatus, CommunicationStatus, ModificationType, CommunicationDirection } from '@prisma/client';
/**
 * Mapea los valores de rol del frontend (en español) a los valores del enum de Prisma.
 * Este es el "traductor" entre el cliente y la base de datos.
 */
export const roleMap: { [key: string]: UserRole } = {
    'Residente de Obra': 'RESIDENT',
    'Supervisor': 'SUPERVISOR',
    'Representante Contratista': 'CONTRACTOR_REP',
    'Administrador IDU': 'ADMIN',
    'Invitado': 'CONTRACTOR_REP', // Usamos CONTRACTOR_REP como valor por defecto
};

/**
 * Mapea las áreas de las actas del frontend a los valores del enum de Prisma.
 */
export const actaAreaMap: { [key: string]: ActaArea } = {
    'Comité de Obra': 'COMITE_OBRA', 
    'Comité HSE': 'HSE', 
    'Comité Ambiental': 'AMBIENTAL',
    'Comité Social': 'SOCIAL', 
    'Comité Jurídico': 'OTHER', 
    'Comité Técnico': 'COMITE_TECNICO', 
    'Otro': 'OTHER',
};

/**
 * Mapea los estados de las actas del frontend a los valores del enum de Prisma.
 */
export const actaStatusMap: { [key: string]: ActaStatus } = {
    'Firmada': 'SIGNED', 
    'En Borrador': 'DRAFT', 
    'Para Firmas': 'FOR_SIGNATURES', 
    'Cerrada': 'CANCELLED',
};

export const entryTypeMap: { [key: string]: EntryType } = {
    'Calidad': 'QUALITY',
    'Administrativo': 'ADMINISTRATIVE',
    'HSE': 'SAFETY',
    'General': 'GENERAL',
    'TECHNICAL': 'TECHNICAL', // Añadido para manejar el tipo técnico
    'Técnico': 'TECHNICAL', // Versión en español
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
    'Firmado': 'SIGNED',
    'SIGNED': 'SIGNED',
    'NEEDS_REVIEW': 'NEEDS_REVIEW', // Añadido para manejar el estado en inglés
};

export const deliveryMethodMap: { [key: string]: DeliveryMethod } = { // <-- AÑADE ESTE BLOQUE
    'Correo Electrónico': 'MAIL',
    'Sistema BDO': 'SYSTEM',
    'Físico': 'PHYSICAL',
};

export const drawingDisciplineMap: { [key: string]: DrawingDiscipline } = {
    'Arquitectónico': 'ARQUITECTONICO',
    'Estructural': 'ESTRUCTURAL',
    'Eléctrico': 'ELECTRICO',
    'Hidrosanitario': 'HIDROSANITARIO',
    'Mecánico': 'MECANICO',
    'Señalización y PMT': 'SENALIZACION',
    'Otro': 'OTHER',
};

export const workActaStatusMap: { [key: string]: WorkActaStatus } = {
    'APPROVED': 'APPROVED',
    'IN_REVIEW': 'IN_REVIEW',
    'DRAFT': 'DRAFT',
    'REJECTED': 'REJECTED',
    'Aprobada': 'APPROVED',
    'En Revisión': 'IN_REVIEW',
    'En Borrador': 'DRAFT',
    'Rechazada': 'REJECTED',
};

export const costActaStatusMap: { [key: string]: CostActaStatus } = { // <-- AÑADE ESTE BLOQUE
    'Radicada': 'SUBMITTED',
    'En Revisión': 'IN_REVIEW',
    'Observada': 'OBSERVED',
    'Aprobada': 'APPROVED',
    'En Trámite de Pago': 'IN_PAYMENT',
    'Pagada': 'PAID',
};

export const reportScopeMap: { [key: string]: ReportScope } = { // <-- AÑADE ESTE BLOQUE
    'Obra': 'OBRA',
    'Interventoría': 'INTERVENTORIA',
};

export const reportStatusMap: { [key: string]: ReportStatus } = { // <-- AÑADE ESTE BLOQUE
    'Borrador': 'DRAFT',
    'Presentado': 'SUBMITTED',
    'Aprobado': 'APPROVED',
    'Con Observaciones': 'OBSERVED',
};

export const commitmentStatusMap: { [key: string]: CommitmentStatus } = {
    'Pendiente': 'PENDING',
    'Completado': 'COMPLETED',
    'Cancelado': 'CANCELLED',
    'Atrasado': 'DELAYED',
    'PENDING': 'PENDING',
    'COMPLETED': 'COMPLETED',
    'CANCELLED': 'CANCELLED',
    'DELAYED': 'DELAYED',
};

export const communicationStatusMap: { [key: string]: CommunicationStatus } = {
    'Pendiente': 'PENDIENTE',
    'En Trámite': 'EN_TRAMITE',
    'Resuelto': 'RESUELTO',
    'PENDIENTE': 'PENDIENTE',
    'EN_TRÁMITE': 'EN_TRAMITE',
    'EN_TRAMITE': 'EN_TRAMITE',
    'RESUELTO': 'RESUELTO',
};

export const communicationDirectionMap: { [key: string]: CommunicationDirection } = {
    'Enviada': 'SENT',
    'Recibida': 'RECEIVED',
    'SENT': 'SENT',
    'RECEIVED': 'RECEIVED',
};

export const modificationTypeMap: { [key: string]: ModificationType } = {
    'ADDITION': 'ADDITION',
    'TIME_EXTENSION': 'TIME_EXTENSION',
    'SCOPE_CHANGE': 'SCOPE_CHANGE',
    'SUSPENSION': 'SUSPENSION',
    'REINSTATEMENT': 'REINSTATEMENT',
    'OTHER': 'OTHER',
    'Adición en Valor': 'ADDITION',
    'Prórroga en Tiempo': 'TIME_EXTENSION',
    'Cambio de Alcance': 'SCOPE_CHANGE',
    'Suspensión': 'SUSPENSION',
    'Reinicio': 'REINSTATEMENT',
    'Otro': 'OTHER',
};
