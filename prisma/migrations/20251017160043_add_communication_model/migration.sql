-- CreateTable
CREATE TABLE `Communication` (
    `id` VARCHAR(191) NOT NULL,
    `radicado` VARCHAR(191) NOT NULL,
    `subject` VARCHAR(191) NOT NULL,
    `description` TEXT NULL,
    `senderEntity` VARCHAR(191) NOT NULL,
    `senderName` VARCHAR(191) NOT NULL,
    `senderTitle` VARCHAR(191) NOT NULL,
    `recipientEntity` VARCHAR(191) NOT NULL,
    `recipientName` VARCHAR(191) NOT NULL,
    `recipientTitle` VARCHAR(191) NOT NULL,
    `signerName` VARCHAR(191) NOT NULL,
    `sentDate` DATETIME(3) NOT NULL,
    `dueDate` DATETIME(3) NULL,
    `deliveryMethod` ENUM('MAIL', 'PRINTED', 'SYSTEM', 'FAX') NOT NULL,
    `notes` TEXT NULL,
    `status` ENUM('PENDIENTE', 'EN_TRAMITE', 'RESUELTO') NOT NULL DEFAULT 'PENDIENTE',
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,
    `uploaderId` VARCHAR(191) NOT NULL,
    `parentId` VARCHAR(191) NULL,

    UNIQUE INDEX `Communication_radicado_key`(`radicado`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `Communication` ADD CONSTRAINT `Communication_uploaderId_fkey` FOREIGN KEY (`uploaderId`) REFERENCES `User`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `Communication` ADD CONSTRAINT `Communication_parentId_fkey` FOREIGN KEY (`parentId`) REFERENCES `Communication`(`id`) ON DELETE NO ACTION ON UPDATE NO ACTION;
