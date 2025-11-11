-- AlterTable
ALTER TABLE `Attachment` ADD COLUMN `reportId` VARCHAR(191) NULL;

-- AlterTable
ALTER TABLE `Signature` ADD COLUMN `reportId` VARCHAR(191) NULL;

-- CreateTable
CREATE TABLE `Report` (
    `id` VARCHAR(191) NOT NULL,
    `type` VARCHAR(191) NOT NULL,
    `reportScope` ENUM('OBRA', 'INTERVENTORIA') NOT NULL,
    `number` VARCHAR(191) NOT NULL,
    `period` VARCHAR(191) NOT NULL,
    `submissionDate` DATETIME(3) NOT NULL,
    `status` ENUM('DRAFT', 'SUBMITTED', 'APPROVED', 'OBSERVED') NOT NULL DEFAULT 'DRAFT',
    `summary` TEXT NOT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,
    `authorId` VARCHAR(191) NOT NULL,
    `requiredSignatoriesJson` TEXT NULL,

    UNIQUE INDEX `Report_number_key`(`number`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `Attachment` ADD CONSTRAINT `Attachment_reportId_fkey` FOREIGN KEY (`reportId`) REFERENCES `Report`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Signature` ADD CONSTRAINT `Signature_reportId_fkey` FOREIGN KEY (`reportId`) REFERENCES `Report`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Report` ADD CONSTRAINT `Report_authorId_fkey` FOREIGN KEY (`authorId`) REFERENCES `User`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
