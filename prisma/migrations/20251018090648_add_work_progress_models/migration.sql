-- CreateTable
CREATE TABLE `ContractItem` (
    `id` VARCHAR(191) NOT NULL,
    `itemCode` VARCHAR(191) NOT NULL,
    `description` TEXT NOT NULL,
    `unit` VARCHAR(191) NOT NULL,
    `unitPrice` DOUBLE NOT NULL,
    `contractQuantity` DOUBLE NOT NULL,

    UNIQUE INDEX `ContractItem_itemCode_key`(`itemCode`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `WorkActa` (
    `id` VARCHAR(191) NOT NULL,
    `number` VARCHAR(191) NOT NULL,
    `period` VARCHAR(191) NOT NULL,
    `date` DATETIME(3) NOT NULL,
    `status` ENUM('APPROVED', 'IN_REVIEW', 'DRAFT') NOT NULL DEFAULT 'DRAFT',
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `WorkActa_number_key`(`number`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `WorkActaItem` (
    `id` VARCHAR(191) NOT NULL,
    `quantity` DOUBLE NOT NULL,
    `workActaId` VARCHAR(191) NOT NULL,
    `contractItemId` VARCHAR(191) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `WorkActaItem` ADD CONSTRAINT `WorkActaItem_workActaId_fkey` FOREIGN KEY (`workActaId`) REFERENCES `WorkActa`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `WorkActaItem` ADD CONSTRAINT `WorkActaItem_contractItemId_fkey` FOREIGN KEY (`contractItemId`) REFERENCES `ContractItem`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
