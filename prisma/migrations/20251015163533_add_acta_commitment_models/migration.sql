-- DropForeignKey
ALTER TABLE `Attachment` DROP FOREIGN KEY `Attachment_commentId_fkey`;

-- DropForeignKey
ALTER TABLE `Attachment` DROP FOREIGN KEY `Attachment_logEntryId_fkey`;

-- DropForeignKey
ALTER TABLE `Comment` DROP FOREIGN KEY `Comment_logEntryId_fkey`;

-- DropIndex
DROP INDEX `Attachment_commentId_fkey` ON `Attachment`;

-- DropIndex
DROP INDEX `Attachment_logEntryId_fkey` ON `Attachment`;

-- DropIndex
DROP INDEX `Comment_logEntryId_fkey` ON `Comment`;

-- CreateTable
CREATE TABLE `Acta` (
    `id` VARCHAR(191) NOT NULL,
    `number` VARCHAR(191) NOT NULL,
    `title` VARCHAR(191) NOT NULL,
    `date` DATETIME(3) NOT NULL,
    `area` ENUM('COMITE_OBRA', 'HSE', 'AMBIENTAL', 'SOCIAL', 'JURIDICO', 'TECNICO', 'OTHER') NOT NULL,
    `status` ENUM('SIGNED', 'DRAFT', 'FOR_SIGNATURES', 'CLOSED') NOT NULL,
    `summary` TEXT NOT NULL,

    UNIQUE INDEX `Acta_number_key`(`number`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `Commitment` (
    `id` VARCHAR(191) NOT NULL,
    `description` TEXT NOT NULL,
    `dueDate` DATETIME(3) NOT NULL,
    `status` ENUM('PENDING', 'COMPLETED') NOT NULL DEFAULT 'PENDING',
    `actaId` VARCHAR(191) NOT NULL,
    `responsibleId` VARCHAR(191) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `Comment` ADD CONSTRAINT `Comment_logEntryId_fkey` FOREIGN KEY (`logEntryId`) REFERENCES `LogEntry`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Attachment` ADD CONSTRAINT `Attachment_logEntryId_fkey` FOREIGN KEY (`logEntryId`) REFERENCES `LogEntry`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Attachment` ADD CONSTRAINT `Attachment_commentId_fkey` FOREIGN KEY (`commentId`) REFERENCES `Comment`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Commitment` ADD CONSTRAINT `Commitment_actaId_fkey` FOREIGN KEY (`actaId`) REFERENCES `Acta`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Commitment` ADD CONSTRAINT `Commitment_responsibleId_fkey` FOREIGN KEY (`responsibleId`) REFERENCES `User`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
