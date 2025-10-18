-- CreateTable
CREATE TABLE `Drawing` (
    `id` VARCHAR(191) NOT NULL,
    `code` VARCHAR(191) NOT NULL,
    `title` VARCHAR(191) NOT NULL,
    `discipline` ENUM('ARQUITECTONICO', 'ESTRUCTURAL', 'ELECTRICO', 'HIDROSANITARIO', 'MECANICO', 'URBANISMO', 'SEÑALIZACION', 'GEOTECNIA', 'OTHER') NOT NULL,
    `status` ENUM('VIGENTE', 'OBSOLETO') NOT NULL DEFAULT 'VIGENTE',
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `Drawing_code_key`(`code`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `DrawingVersion` (
    `id` VARCHAR(191) NOT NULL,
    `versionNumber` INTEGER NOT NULL,
    `fileName` VARCHAR(191) NOT NULL,
    `url` TEXT NOT NULL,
    `size` INTEGER NOT NULL,
    `uploadDate` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `drawingId` VARCHAR(191) NOT NULL,
    `uploaderId` VARCHAR(191) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `DrawingVersion` ADD CONSTRAINT `DrawingVersion_drawingId_fkey` FOREIGN KEY (`drawingId`) REFERENCES `Drawing`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `DrawingVersion` ADD CONSTRAINT `DrawingVersion_uploaderId_fkey` FOREIGN KEY (`uploaderId`) REFERENCES `User`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE;
