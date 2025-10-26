/*
  Warnings:

  - The values [SEÑALIZACION] on the enum `Drawing_discipline` will be removed. If these variants are still used in the database, this will fail.

*/
-- AlterTable
ALTER TABLE `Drawing` MODIFY `discipline` ENUM('ARQUITECTONICO', 'ESTRUCTURAL', 'HIDROSANITARIO', 'ELECTRICO', 'MECANICO', 'SENALIZACION', 'OTHER') NOT NULL;

-- CreateTable
CREATE TABLE `LogEntryHistory` (
    `id` VARCHAR(191) NOT NULL,
    `fieldName` VARCHAR(191) NOT NULL,
    `oldValue` VARCHAR(191) NULL,
    `newValue` VARCHAR(191) NULL,
    `timestamp` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `logEntryId` VARCHAR(191) NOT NULL,
    `userId` VARCHAR(191) NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `LogEntryHistory` ADD CONSTRAINT `LogEntryHistory_logEntryId_fkey` FOREIGN KEY (`logEntryId`) REFERENCES `LogEntry`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `LogEntryHistory` ADD CONSTRAINT `LogEntryHistory_userId_fkey` FOREIGN KEY (`userId`) REFERENCES `User`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;
