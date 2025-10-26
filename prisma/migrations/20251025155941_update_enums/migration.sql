/*
  Warnings:

  - You are about to alter the column `area` on the `Acta` table. The data in that column could be lost. The data in that column will be cast from `VarChar(191)` to `Enum(EnumId(6))`.
  - You are about to alter the column `status` on the `Acta` table. The data in that column could be lost. The data in that column will be cast from `VarChar(191)` to `Enum(EnumId(7))`.
  - You are about to alter the column `status` on the `Commitment` table. The data in that column could be lost. The data in that column will be cast from `VarChar(191)` to `Enum(EnumId(8))`.
  - You are about to alter the column `deliveryMethod` on the `Communication` table. The data in that column could be lost. The data in that column will be cast from `VarChar(191)` to `Enum(EnumId(2))`.
  - You are about to alter the column `status` on the `Communication` table. The data in that column could be lost. The data in that column will be cast from `VarChar(191)` to `Enum(EnumId(3))`.
  - You are about to alter the column `status` on the `CostActa` table. The data in that column could be lost. The data in that column will be cast from `VarChar(191)` to `Enum(EnumId(9))`.
  - You are about to alter the column `discipline` on the `Drawing` table. The data in that column could be lost. The data in that column will be cast from `VarChar(191)` to `Enum(EnumId(12))`.
  - You are about to alter the column `status` on the `Drawing` table. The data in that column could be lost. The data in that column will be cast from `VarChar(191)` to `Enum(EnumId(13))`.
  - You are about to alter the column `type` on the `LogEntry` table. The data in that column could be lost. The data in that column will be cast from `VarChar(191)` to `Enum(EnumId(4))`.
  - You are about to alter the column `status` on the `LogEntry` table. The data in that column could be lost. The data in that column will be cast from `VarChar(191)` to `Enum(EnumId(5))`.
  - You are about to alter the column `reportScope` on the `Report` table. The data in that column could be lost. The data in that column will be cast from `VarChar(191)` to `Enum(EnumId(10))`.
  - You are about to alter the column `status` on the `Report` table. The data in that column could be lost. The data in that column will be cast from `VarChar(191)` to `Enum(EnumId(11))`.
  - You are about to alter the column `projectRole` on the `User` table. The data in that column could be lost. The data in that column will be cast from `VarChar(191)` to `Enum(EnumId(0))`.
  - You are about to alter the column `appRole` on the `User` table. The data in that column could be lost. The data in that column will be cast from `VarChar(191)` to `Enum(EnumId(1))`.

*/
-- AlterTable
ALTER TABLE `Acta` MODIFY `area` ENUM('COMITE_OBRA', 'COMITE_TECNICO', 'HSE', 'CALIDAD', 'SOCIAL', 'AMBIENTAL', 'OTHER') NOT NULL,
    MODIFY `status` ENUM('DRAFT', 'FOR_SIGNATURES', 'SIGNED', 'CANCELLED') NOT NULL;

-- AlterTable
ALTER TABLE `Commitment` MODIFY `status` ENUM('PENDING', 'COMPLETED', 'CANCELLED', 'DELAYED') NOT NULL;

-- AlterTable
ALTER TABLE `Communication` MODIFY `deliveryMethod` ENUM('SYSTEM', 'MAIL', 'PHYSICAL') NOT NULL,
    MODIFY `status` ENUM('PENDIENTE', 'EN_TRAMITE', 'RESUELTO', 'ARCHIVADO') NOT NULL;

-- AlterTable
ALTER TABLE `CostActa` MODIFY `status` ENUM('SUBMITTED', 'IN_REVIEW', 'OBSERVED', 'APPROVED', 'IN_PAYMENT', 'PAID', 'REJECTED') NOT NULL;

-- AlterTable
ALTER TABLE `Drawing` MODIFY `discipline` ENUM('ARQUITECTONICO', 'ESTRUCTURAL', 'HIDROSANITARIO', 'ELECTRICO', 'MECANICO', 'SEÑALIZACION', 'OTHER') NOT NULL,
    MODIFY `status` ENUM('VIGENTE', 'OBSOLETO', 'ANULADO') NOT NULL;

-- AlterTable
ALTER TABLE `LogEntry` MODIFY `type` ENUM('GENERAL', 'QUALITY', 'SAFETY', 'ADMINISTRATIVE', 'TECHNICAL') NOT NULL,
    MODIFY `status` ENUM('DRAFT', 'SUBMITTED', 'NEEDS_REVIEW', 'APPROVED', 'REJECTED') NOT NULL;

-- AlterTable
ALTER TABLE `Report` MODIFY `reportScope` ENUM('OBRA', 'INTERVENTORIA') NOT NULL,
    MODIFY `status` ENUM('DRAFT', 'SUBMITTED', 'OBSERVED', 'APPROVED', 'REJECTED') NOT NULL;

-- AlterTable
ALTER TABLE `User` MODIFY `projectRole` ENUM('ADMIN', 'RESIDENT', 'SUPERVISOR', 'CONTRACTOR_REP') NOT NULL,
    MODIFY `appRole` ENUM('admin', 'editor', 'viewer') NOT NULL;
