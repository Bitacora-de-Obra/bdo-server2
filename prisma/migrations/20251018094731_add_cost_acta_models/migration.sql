-- AlterTable
ALTER TABLE `Attachment` ADD COLUMN `costActaId` VARCHAR(191) NULL;

-- CreateTable
CREATE TABLE `CostActa` (
    `id` VARCHAR(191) NOT NULL,
    `number` VARCHAR(191) NOT NULL,
    `period` VARCHAR(191) NOT NULL,
    `submissionDate` DATETIME(3) NOT NULL,
    `approvalDate` DATETIME(3) NULL,
    `paymentDueDate` DATETIME(3) NULL,
    `billedAmount` DOUBLE NOT NULL,
    `totalContractValue` DOUBLE NOT NULL,
    `status` ENUM('SUBMITTED', 'IN_REVIEW', 'OBSERVED', 'APPROVED', 'IN_PAYMENT', 'PAID') NOT NULL DEFAULT 'SUBMITTED',
    `relatedProgress` TEXT NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `CostActa_number_key`(`number`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Observation` (
    `id` VARCHAR(191) NOT NULL,
    `text` TEXT NOT NULL,
    `timestamp` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `authorId` VARCHAR(191) NOT NULL,
    `costActaId` VARCHAR(191) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `Attachment` ADD CONSTRAINT `Attachment_costActaId_fkey` FOREIGN KEY (`costActaId`) REFERENCES `CostActa`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Observation` ADD CONSTRAINT `Observation_authorId_fkey` FOREIGN KEY (`authorId`) REFERENCES `User`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Observation` ADD CONSTRAINT `Observation_costActaId_fkey` FOREIGN KEY (`costActaId`) REFERENCES `CostActa`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
