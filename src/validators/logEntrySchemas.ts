import { z } from 'zod';
import { commonSchemas } from '../middleware/validation';

/**
 * Schema para crear una nueva anotación (log entry)
 */
export const createLogEntrySchema = z.object({
  body: z.object({
    title: z.string().min(1, 'El título es obligatorio').max(500, 'El título es demasiado largo'),
    description: z.string().optional(),
    type: z.enum(['GENERAL', 'TECHNICAL', 'SAFETY', 'ENVIRONMENTAL', 'SOCIAL']).optional(),
    status: z.enum(['DRAFT', 'SUBMITTED', 'NEEDS_REVIEW', 'APPROVED', 'SIGNED']).optional(),
    entryDate: z.string().datetime().or(z.date()).optional(),
    activityStartDate: z.string().datetime().or(z.date()).optional(),
    activityEndDate: z.string().datetime().or(z.date()).optional(),
    scheduleDay: z.number().int().min(0).max(365).nullable().optional(),
    isConfidential: z.boolean().optional(),
    
    // Campos de texto
    activitiesPerformed: z.string().optional(),
    materialsUsed: z.string().optional(),
    workforce: z.string().optional(),
    weatherConditions: z.string().optional(),
    additionalObservations: z.string().optional(),
    locationDetails: z.string().optional(),
    contractorObservations: z.string().optional(),
    interventoriaObservations: z.string().optional(),
    safetyFindings: z.string().optional(),
    safetyContractorResponse: z.string().optional(),
    environmentFindings: z.string().optional(),
    environmentContractorResponse: z.string().optional(),
    socialObservations: z.string().optional(),
    socialContractorResponse: z.string().optional(),
    socialPhotoSummary: z.string().optional(),

    // Campos JSON (validar estructura básica)
    contractorPersonnel: z.array(z.any()).optional(),
    interventoriaPersonnel: z.array(z.any()).optional(),
    equipmentResources: z.array(z.any()).optional(),
    executedActivities: z.array(z.any()).optional(),
    executedQuantities: z.array(z.any()).optional(),
    scheduledActivities: z.array(z.any()).optional(),
    qualityControls: z.array(z.any()).optional(),
    materialsReceived: z.array(z.any()).optional(),
    safetyNotes: z.array(z.any()).optional(),
    projectIssues: z.array(z.any()).optional(),
    siteVisits: z.array(z.any()).optional(),
    weatherReport: z.any().optional(),
    socialActivities: z.array(z.any()).optional(),

    // IDs de usuarios (para firmantes y asignados)
    requiredSignatories: z.array(commonSchemas.uuid).optional(),
    assigneeIds: z.array(commonSchemas.uuid).optional(),
  }),
});

/**
 * Schema para actualizar una anotación
 */
export const updateLogEntrySchema = z.object({
  params: z.object({
    id: commonSchemas.uuid,
  }),
  body: z.object({
    title: z.string().min(1).max(500).optional(),
    description: z.string().optional(),
    type: z.enum(['GENERAL', 'TECHNICAL', 'SAFETY', 'ENVIRONMENTAL', 'SOCIAL']).optional(),
    status: z.enum(['DRAFT', 'SUBMITTED', 'NEEDS_REVIEW', 'APPROVED', 'SIGNED']).optional(),
    entryDate: z.string().datetime().or(z.date()).optional(),
    activityStartDate: z.string().datetime().or(z.date()).optional(),
    activityEndDate: z.string().datetime().or(z.date()).optional(),
    scheduleDay: z.number().int().min(0).max(365).nullable().optional(),
    isConfidential: z.boolean().optional(),
    
    // Campos de texto (todos opcionales en update)
    activitiesPerformed: z.string().optional(),
    materialsUsed: z.string().optional(),
    workforce: z.string().optional(),
    weatherConditions: z.string().optional(),
    additionalObservations: z.string().optional(),
    locationDetails: z.string().optional(),
    contractorObservations: z.string().optional(),
    interventoriaObservations: z.string().optional(),
    safetyFindings: z.string().optional(),
    safetyContractorResponse: z.string().optional(),
    environmentFindings: z.string().optional(),
    environmentContractorResponse: z.string().optional(),
    socialObservations: z.string().optional(),
    socialContractorResponse: z.string().optional(),
    socialPhotoSummary: z.string().optional(),

    // Campos JSON
    contractorPersonnel: z.array(z.any()).optional(),
    interventoriaPersonnel: z.array(z.any()).optional(),
    equipmentResources: z.array(z.any()).optional(),
    executedActivities: z.array(z.any()).optional(),
    executedQuantities: z.array(z.any()).optional(),
    scheduledActivities: z.array(z.any()).optional(),
    qualityControls: z.array(z.any()).optional(),
    materialsReceived: z.array(z.any()).optional(),
    safetyNotes: z.array(z.any()).optional(),
    projectIssues: z.array(z.any()).optional(),
    siteVisits: z.array(z.any()).optional(),
    weatherReport: z.any().optional(),
    socialActivities: z.array(z.any()).optional(),

    // IDs
    requiredSignatories: z.array(commonSchemas.uuid).optional(),
    assigneeIds: z.array(commonSchemas.uuid).optional(),
  }).partial(), // Todos los campos son opcionales en update
});

/**
 * Schema para obtener anotaciones (query params)
 */
export const getLogEntriesSchema = z.object({
  query: z.object({
    status: z.enum(['DRAFT', 'SUBMITTED', 'NEEDS_REVIEW', 'APPROVED', 'SIGNED']).optional(),
    type: z.enum(['GENERAL', 'TECHNICAL', 'SAFETY', 'ENVIRONMENTAL', 'SOCIAL']).optional(),
    startDate: z.string().datetime().optional(),
    endDate: z.string().datetime().optional(),
    page: z.string().transform((val) => parseInt(val, 10)).pipe(z.number().int().positive()).optional(),
    limit: z.string().transform((val) => parseInt(val, 10)).pipe(z.number().int().positive().max(100)).optional(),
  }).optional(),
});



