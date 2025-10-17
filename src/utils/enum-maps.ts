import { UserRole, ActaArea, ActaStatus } from '@prisma/client';

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