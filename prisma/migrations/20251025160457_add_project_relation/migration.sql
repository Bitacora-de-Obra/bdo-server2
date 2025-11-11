/*
  Warnings:

  - Added the required column `projectId` to the `LogEntry` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE `LogEntry` ADD COLUMN `projectId` VARCHAR(191) NOT NULL;

-- AddForeignKey
ALTER TABLE `LogEntry` ADD CONSTRAINT `LogEntry_projectId_fkey` FOREIGN KEY (`projectId`) REFERENCES `Project`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
