-- CreateTable
CREATE TABLE `ControlPoint` (
    `id` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NOT NULL,
    `description` TEXT NULL,
    `location` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `PhotoEntry` (
    `id` VARCHAR(191) NOT NULL,
    `url` TEXT NOT NULL,
    `date` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `notes` TEXT NULL,
    `authorId` VARCHAR(191) NOT NULL,
    `controlPointId` VARCHAR(191) NOT NULL,
    `attachmentId` VARCHAR(191) NULL,

    UNIQUE INDEX `PhotoEntry_attachmentId_key`(`attachmentId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `PhotoEntry` ADD CONSTRAINT `PhotoEntry_authorId_fkey` FOREIGN KEY (`authorId`) REFERENCES `User`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `PhotoEntry` ADD CONSTRAINT `PhotoEntry_controlPointId_fkey` FOREIGN KEY (`controlPointId`) REFERENCES `ControlPoint`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `PhotoEntry` ADD CONSTRAINT `PhotoEntry_attachmentId_fkey` FOREIGN KEY (`attachmentId`) REFERENCES `Attachment`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;
