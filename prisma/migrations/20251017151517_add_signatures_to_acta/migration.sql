/*
  Warnings:

  - Added the required column `updatedAt` to the `Acta` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE `Acta` ADD COLUMN `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    ADD COLUMN `updatedAt` DATETIME(3) NOT NULL;

-- AlterTable
ALTER TABLE `Signature` ADD COLUMN `actaId` VARCHAR(191) NULL;

-- AlterTable
ALTER TABLE `User` MODIFY `projectRole` ENUM('RESIDENT', 'SUPERVISOR', 'CONTRACTOR_REP', 'ADMIN', 'GUEST') NOT NULL;

-- AddForeignKey
ALTER TABLE `Signature` ADD CONSTRAINT `Signature_actaId_fkey` FOREIGN KEY (`actaId`) REFERENCES `Acta`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
