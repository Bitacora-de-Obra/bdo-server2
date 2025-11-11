/*
  Warnings:

  - You are about to alter the column `area` on the `Acta` table. The data in that column could be lost. The data in that column will be cast from `Enum(EnumId(4))` to `VarChar(191)`.
  - You are about to alter the column `status` on the `Acta` table. The data in that column could be lost. The data in that column will be cast from `Enum(EnumId(7))` to `VarChar(191)`.
  - You are about to alter the column `status` on the `Commitment` table. The data in that column could be lost. The data in that column will be cast from `Enum(EnumId(1))` to `VarChar(191)`.
  - You are about to alter the column `deliveryMethod` on the `Communication` table. The data in that column could be lost. The data in that column will be cast from `Enum(EnumId(13))` to `VarChar(191)`.
  - You are about to alter the column `status` on the `Communication` table. The data in that column could be lost. The data in that column will be cast from `Enum(EnumId(14))` to `VarChar(191)`.
  - You are about to alter the column `status` on the `CostActa` table. The data in that column could be lost. The data in that column will be cast from `Enum(EnumId(10))` to `VarChar(191)`.
  - You are about to alter the column `discipline` on the `Drawing` table. The data in that column could be lost. The data in that column will be cast from `Enum(EnumId(2))` to `VarChar(191)`.
  - You are about to alter the column `status` on the `Drawing` table. The data in that column could be lost. The data in that column will be cast from `Enum(EnumId(5))` to `VarChar(191)`.
  - You are about to drop the column `projectId` on the `LogEntry` table. All the data in the column will be lost.
  - You are about to drop the column `requiredSignatoriesJson` on the `LogEntry` table. All the data in the column will be lost.
  - You are about to alter the column `type` on the `LogEntry` table. The data in that column could be lost. The data in that column will be cast from `Enum(EnumId(11))` to `VarChar(191)`.
  - You are about to alter the column `status` on the `LogEntry` table. The data in that column could be lost. The data in that column will be cast from `Enum(EnumId(12))` to `VarChar(191)`.
  - You are about to alter the column `reportScope` on the `Report` table. The data in that column could be lost. The data in that column will be cast from `Enum(EnumId(0))` to `VarChar(191)`.
  - You are about to alter the column `status` on the `Report` table. The data in that column could be lost. The data in that column will be cast from `Enum(EnumId(9))` to `VarChar(191)`.
  - You are about to alter the column `projectRole` on the `User` table. The data in that column could be lost. The data in that column will be cast from `Enum(EnumId(3))` to `VarChar(191)`.
  - You are about to alter the column `appRole` on the `User` table. The data in that column could be lost. The data in that column will be cast from `Enum(EnumId(8))` to `VarChar(191)`.
  - You are about to drop the `ContractItem` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `ProjectTask` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `WorkActa` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `WorkActaItem` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `_LogEntryAssignees` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `_TaskDependencies` table. If the table is not empty, all the data it contains will be lost.
  - Added the required column `updatedAt` to the `Commitment` table without a default value. This is not possible if the table is not empty.
  - Made the column `description` on table `Communication` required. This step will fail if there are existing NULL values in that column.
  - Added the required column `contractorName` to the `Project` table without a default value. This is not possible if the table is not empty.
  - Added the required column `initialEndDate` to the `Project` table without a default value. This is not possible if the table is not empty.
  - Added the required column `initialValue` to the `Project` table without a default value. This is not possible if the table is not empty.
  - Added the required column `interventoriaContractId` to the `Project` table without a default value. This is not possible if the table is not empty.
  - Added the required column `interventoriaInitialValue` to the `Project` table without a default value. This is not possible if the table is not empty.
  - Added the required column `object` to the `Project` table without a default value. This is not possible if the table is not empty.
  - Added the required column `startDate` to the `Project` table without a default value. This is not possible if the table is not empty.
  - Added the required column `supervisorName` to the `Project` table without a default value. This is not possible if the table is not empty.
  - Added the required column `technicalSupervisorName` to the `Project` table without a default value. This is not possible if the table is not empty.
  - Added the required column `updatedAt` to the `Project` table without a default value. This is not possible if the table is not empty.
  - Added the required column `updatedAt` to the `User` table without a default value. This is not possible if the table is not empty.

*/
-- DropForeignKey
ALTER TABLE `Attachment` DROP FOREIGN KEY `Attachment_actaId_fkey`;

-- DropForeignKey
ALTER TABLE `Attachment` DROP FOREIGN KEY `Attachment_commentId_fkey`;

-- DropForeignKey
ALTER TABLE `Attachment` DROP FOREIGN KEY `Attachment_costActaId_fkey`;

-- DropForeignKey
ALTER TABLE `Attachment` DROP FOREIGN KEY `Attachment_logEntryId_fkey`;

-- DropForeignKey
ALTER TABLE `Attachment` DROP FOREIGN KEY `Attachment_reportId_fkey`;

-- DropForeignKey
ALTER TABLE `Comment` DROP FOREIGN KEY `Comment_drawingId_fkey`;

-- DropForeignKey
ALTER TABLE `Comment` DROP FOREIGN KEY `Comment_logEntryId_fkey`;

-- DropForeignKey
ALTER TABLE `Commitment` DROP FOREIGN KEY `Commitment_actaId_fkey`;

-- DropForeignKey
ALTER TABLE `Communication` DROP FOREIGN KEY `Communication_parentId_fkey`;

-- DropForeignKey
ALTER TABLE `DrawingVersion` DROP FOREIGN KEY `DrawingVersion_drawingId_fkey`;

-- DropForeignKey
ALTER TABLE `LogEntry` DROP FOREIGN KEY `LogEntry_projectId_fkey`;

-- DropForeignKey
ALTER TABLE `Observation` DROP FOREIGN KEY `Observation_costActaId_fkey`;

-- DropForeignKey
ALTER TABLE `PhotoEntry` DROP FOREIGN KEY `PhotoEntry_controlPointId_fkey`;

-- DropForeignKey
ALTER TABLE `ProjectTask` DROP FOREIGN KEY `ProjectTask_parentId_fkey`;

-- DropForeignKey
ALTER TABLE `ProjectTask` DROP FOREIGN KEY `ProjectTask_projectId_fkey`;

-- DropForeignKey
ALTER TABLE `Signature` DROP FOREIGN KEY `Signature_actaId_fkey`;

-- DropForeignKey
ALTER TABLE `Signature` DROP FOREIGN KEY `Signature_logEntryId_fkey`;

-- DropForeignKey
ALTER TABLE `Signature` DROP FOREIGN KEY `Signature_reportId_fkey`;

-- DropForeignKey
ALTER TABLE `Signature` DROP FOREIGN KEY `Signature_signerId_fkey`;

-- DropForeignKey
ALTER TABLE `WorkActaItem` DROP FOREIGN KEY `WorkActaItem_contractItemId_fkey`;

-- DropForeignKey
ALTER TABLE `WorkActaItem` DROP FOREIGN KEY `WorkActaItem_workActaId_fkey`;

-- DropForeignKey
ALTER TABLE `_LogEntryAssignees` DROP FOREIGN KEY `_LogEntryAssignees_A_fkey`;

-- DropForeignKey
ALTER TABLE `_LogEntryAssignees` DROP FOREIGN KEY `_LogEntryAssignees_B_fkey`;

-- DropForeignKey
ALTER TABLE `_TaskDependencies` DROP FOREIGN KEY `_TaskDependencies_A_fkey`;

-- DropForeignKey
ALTER TABLE `_TaskDependencies` DROP FOREIGN KEY `_TaskDependencies_B_fkey`;

-- DropIndex
DROP INDEX `Attachment_actaId_fkey` ON `Attachment`;

-- DropIndex
DROP INDEX `Attachment_commentId_fkey` ON `Attachment`;

-- DropIndex
DROP INDEX `Attachment_costActaId_fkey` ON `Attachment`;

-- DropIndex
DROP INDEX `Attachment_logEntryId_fkey` ON `Attachment`;

-- DropIndex
DROP INDEX `Attachment_reportId_fkey` ON `Attachment`;

-- DropIndex
DROP INDEX `Comment_drawingId_fkey` ON `Comment`;

-- DropIndex
DROP INDEX `Comment_logEntryId_fkey` ON `Comment`;

-- DropIndex
DROP INDEX `Commitment_actaId_fkey` ON `Commitment`;

-- DropIndex
DROP INDEX `Communication_parentId_fkey` ON `Communication`;

-- DropIndex
DROP INDEX `DrawingVersion_drawingId_fkey` ON `DrawingVersion`;

-- DropIndex
DROP INDEX `LogEntry_projectId_fkey` ON `LogEntry`;

-- DropIndex
DROP INDEX `Observation_costActaId_fkey` ON `Observation`;

-- DropIndex
DROP INDEX `PhotoEntry_controlPointId_fkey` ON `PhotoEntry`;

-- DropIndex
DROP INDEX `Signature_actaId_fkey` ON `Signature`;

-- DropIndex
DROP INDEX `Signature_logEntryId_fkey` ON `Signature`;

-- DropIndex
DROP INDEX `Signature_reportId_fkey` ON `Signature`;

-- DropIndex
DROP INDEX `Signature_signerId_fkey` ON `Signature`;

-- AlterTable
ALTER TABLE `Acta` MODIFY `area` VARCHAR(191) NOT NULL,
    MODIFY `status` VARCHAR(191) NOT NULL,
    MODIFY `summary` VARCHAR(191) NOT NULL,
    MODIFY `requiredSignatoriesJson` VARCHAR(191) NULL;

-- AlterTable
ALTER TABLE `Attachment` ADD COLUMN `communicationId` VARCHAR(191) NULL,
    ADD COLUMN `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    ADD COLUMN `weeklyReportId` VARCHAR(191) NULL,
    MODIFY `url` VARCHAR(191) NOT NULL;

-- AlterTable
ALTER TABLE `Comment` MODIFY `content` VARCHAR(191) NOT NULL;

-- AlterTable
ALTER TABLE `Commitment` ADD COLUMN `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    ADD COLUMN `updatedAt` DATETIME(3) NOT NULL,
    MODIFY `description` VARCHAR(191) NOT NULL,
    MODIFY `status` VARCHAR(191) NOT NULL;

-- AlterTable
ALTER TABLE `Communication` MODIFY `description` VARCHAR(191) NOT NULL,
    MODIFY `deliveryMethod` VARCHAR(191) NOT NULL,
    MODIFY `notes` VARCHAR(191) NULL,
    MODIFY `status` VARCHAR(191) NOT NULL;

-- AlterTable
ALTER TABLE `ControlPoint` MODIFY `description` VARCHAR(191) NULL;

-- AlterTable
ALTER TABLE `CostActa` MODIFY `status` VARCHAR(191) NOT NULL,
    MODIFY `relatedProgress` VARCHAR(191) NULL;

-- AlterTable
ALTER TABLE `Drawing` MODIFY `discipline` VARCHAR(191) NOT NULL,
    MODIFY `status` VARCHAR(191) NOT NULL;

-- AlterTable
ALTER TABLE `DrawingVersion` MODIFY `url` VARCHAR(191) NOT NULL;

-- AlterTable
ALTER TABLE `LogEntry` DROP COLUMN `projectId`,
    DROP COLUMN `requiredSignatoriesJson`,
    MODIFY `description` VARCHAR(191) NOT NULL,
    MODIFY `type` VARCHAR(191) NOT NULL,
    MODIFY `status` VARCHAR(191) NOT NULL;

-- AlterTable
ALTER TABLE `Observation` MODIFY `text` VARCHAR(191) NOT NULL;

-- AlterTable
ALTER TABLE `PhotoEntry` MODIFY `url` VARCHAR(191) NOT NULL,
    MODIFY `notes` VARCHAR(191) NULL;

-- AlterTable
ALTER TABLE `Project` ADD COLUMN `contractorName` VARCHAR(191) NOT NULL,
    ADD COLUMN `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    ADD COLUMN `initialEndDate` DATETIME(3) NOT NULL,
    ADD COLUMN `initialValue` DOUBLE NOT NULL,
    ADD COLUMN `interventoriaContractId` VARCHAR(191) NOT NULL,
    ADD COLUMN `interventoriaInitialValue` DOUBLE NOT NULL,
    ADD COLUMN `object` VARCHAR(191) NOT NULL,
    ADD COLUMN `startDate` DATETIME(3) NOT NULL,
    ADD COLUMN `supervisorName` VARCHAR(191) NOT NULL,
    ADD COLUMN `technicalSupervisorName` VARCHAR(191) NOT NULL,
    ADD COLUMN `updatedAt` DATETIME(3) NOT NULL;

-- AlterTable
ALTER TABLE `Report` MODIFY `reportScope` VARCHAR(191) NOT NULL,
    MODIFY `status` VARCHAR(191) NOT NULL,
    MODIFY `summary` VARCHAR(191) NOT NULL,
    MODIFY `requiredSignatoriesJson` VARCHAR(191) NULL;

-- AlterTable
ALTER TABLE `User` ADD COLUMN `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    ADD COLUMN `updatedAt` DATETIME(3) NOT NULL,
    MODIFY `projectRole` VARCHAR(191) NOT NULL,
    MODIFY `avatarUrl` VARCHAR(191) NULL,
    MODIFY `appRole` VARCHAR(191) NOT NULL;

-- DropTable
DROP TABLE `ContractItem`;

-- DropTable
DROP TABLE `ProjectTask`;

-- DropTable
DROP TABLE `WorkActa`;

-- DropTable
DROP TABLE `WorkActaItem`;

-- DropTable
DROP TABLE `_LogEntryAssignees`;

-- DropTable
DROP TABLE `_TaskDependencies`;

-- CreateTable
CREATE TABLE `KeyPersonnel` (
    `id` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NOT NULL,
    `role` VARCHAR(191) NOT NULL,
    `company` VARCHAR(191) NOT NULL,
    `email` VARCHAR(191) NOT NULL,
    `phone` VARCHAR(191) NOT NULL,
    `projectId` VARCHAR(191) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `CommunicationStatusHistory` (
    `id` VARCHAR(191) NOT NULL,
    `status` VARCHAR(191) NOT NULL,
    `timestamp` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `communicationId` VARCHAR(191) NOT NULL,
    `userId` VARCHAR(191) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `ContractModification` (
    `id` VARCHAR(191) NOT NULL,
    `number` VARCHAR(191) NOT NULL,
    `type` VARCHAR(191) NOT NULL,
    `date` DATETIME(3) NOT NULL,
    `value` DOUBLE NULL,
    `days` INTEGER NULL,
    `justification` VARCHAR(191) NOT NULL,
    `attachmentId` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ContractModification_number_key`(`number`),
    UNIQUE INDEX `ContractModification_attachmentId_key`(`attachmentId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `WeeklyReport` (
    `id` VARCHAR(191) NOT NULL,
    `number` VARCHAR(191) NOT NULL,
    `startDate` DATETIME(3) NOT NULL,
    `endDate` DATETIME(3) NOT NULL,
    `summary` VARCHAR(191) NOT NULL,
    `progressSummary` VARCHAR(191) NULL,
    `nextWeekPlan` VARCHAR(191) NULL,
    `issues` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `WeeklyReport_number_key`(`number`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `_Assignees` (
    `A` VARCHAR(191) NOT NULL,
    `B` VARCHAR(191) NOT NULL,

    UNIQUE INDEX `_Assignees_AB_unique`(`A`, `B`),
    INDEX `_Assignees_B_index`(`B`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `KeyPersonnel` ADD CONSTRAINT `KeyPersonnel_projectId_fkey` FOREIGN KEY (`projectId`) REFERENCES `Project`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Communication` ADD CONSTRAINT `Communication_parentId_fkey` FOREIGN KEY (`parentId`) REFERENCES `Communication`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `CommunicationStatusHistory` ADD CONSTRAINT `CommunicationStatusHistory_communicationId_fkey` FOREIGN KEY (`communicationId`) REFERENCES `Communication`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `CommunicationStatusHistory` ADD CONSTRAINT `CommunicationStatusHistory_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `User`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `ContractModification` ADD CONSTRAINT `ContractModification_attachmentId_fkey` FOREIGN KEY (`attachmentId`) REFERENCES `Attachment`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Comment` ADD CONSTRAINT `Comment_logEntryId_fkey` FOREIGN KEY (`logEntryId`) REFERENCES `LogEntry`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Comment` ADD CONSTRAINT `Comment_drawingId_fkey` FOREIGN KEY (`drawingId`) REFERENCES `Drawing`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Signature` ADD CONSTRAINT `Signature_signerId_fkey` FOREIGN KEY (`signerId`) REFERENCES `User`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Signature` ADD CONSTRAINT `Signature_logEntryId_fkey` FOREIGN KEY (`logEntryId`) REFERENCES `LogEntry`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Signature` ADD CONSTRAINT `Signature_actaId_fkey` FOREIGN KEY (`actaId`) REFERENCES `Acta`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Signature` ADD CONSTRAINT `Signature_reportId_fkey` FOREIGN KEY (`reportId`) REFERENCES `Report`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Attachment` ADD CONSTRAINT `Attachment_logEntryId_fkey` FOREIGN KEY (`logEntryId`) REFERENCES `LogEntry`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Attachment` ADD CONSTRAINT `Attachment_communicationId_fkey` FOREIGN KEY (`communicationId`) REFERENCES `Communication`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Attachment` ADD CONSTRAINT `Attachment_actaId_fkey` FOREIGN KEY (`actaId`) REFERENCES `Acta`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Attachment` ADD CONSTRAINT `Attachment_costActaId_fkey` FOREIGN KEY (`costActaId`) REFERENCES `CostActa`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Attachment` ADD CONSTRAINT `Attachment_reportId_fkey` FOREIGN KEY (`reportId`) REFERENCES `Report`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Attachment` ADD CONSTRAINT `Attachment_commentId_fkey` FOREIGN KEY (`commentId`) REFERENCES `Comment`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Attachment` ADD CONSTRAINT `Attachment_weeklyReportId_fkey` FOREIGN KEY (`weeklyReportId`) REFERENCES `WeeklyReport`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Commitment` ADD CONSTRAINT `Commitment_actaId_fkey` FOREIGN KEY (`actaId`) REFERENCES `Acta`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Observation` ADD CONSTRAINT `Observation_costActaId_fkey` FOREIGN KEY (`costActaId`) REFERENCES `CostActa`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `DrawingVersion` ADD CONSTRAINT `DrawingVersion_drawingId_fkey` FOREIGN KEY (`drawingId`) REFERENCES `Drawing`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `PhotoEntry` ADD CONSTRAINT `PhotoEntry_controlPointId_fkey` FOREIGN KEY (`controlPointId`) REFERENCES `ControlPoint`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `_Assignees` ADD CONSTRAINT `_Assignees_A_fkey` FOREIGN KEY (`A`) REFERENCES `LogEntry`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `_Assignees` ADD CONSTRAINT `_Assignees_B_fkey` FOREIGN KEY (`B`) REFERENCES `User`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
