-- AlterTable
ALTER TABLE `LogEntry` ADD COLUMN `requiredSignatoriesJson` TEXT NULL;

-- CreateTable
CREATE TABLE `Signature` (
    `id` VARCHAR(191) NOT NULL,
    `signedAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `signerId` VARCHAR(191) NOT NULL,
    `logEntryId` VARCHAR(191) NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `Signature` ADD CONSTRAINT `Signature_signerId_fkey` FOREIGN KEY (`signerId`) REFERENCES `User`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Signature` ADD CONSTRAINT `Signature_logEntryId_fkey` FOREIGN KEY (`logEntryId`) REFERENCES `LogEntry`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
