-- CreateTable
CREATE TABLE `ProjectTask` (
    `id` VARCHAR(191) NOT NULL,
    `taskId` VARCHAR(191) NOT NULL,
    `name` VARCHAR(191) NOT NULL,
    `startDate` DATETIME(3) NOT NULL,
    `endDate` DATETIME(3) NOT NULL,
    `progress` INTEGER NOT NULL DEFAULT 0,
    `duration` INTEGER NOT NULL,
    `isSummary` BOOLEAN NOT NULL DEFAULT false,
    `outlineLevel` INTEGER NOT NULL DEFAULT 1,
    `parentId` VARCHAR(191) NULL,
    `projectId` VARCHAR(191) NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updatedAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `ProjectTask_taskId_key`(`taskId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `_TaskDependencies` (
    `A` VARCHAR(191) NOT NULL,
    `B` VARCHAR(191) NOT NULL,

    UNIQUE INDEX `_TaskDependencies_AB_unique`(`A`, `B`),
    INDEX `_TaskDependencies_B_index`(`B`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `ProjectTask` ADD CONSTRAINT `ProjectTask_parentId_fkey` FOREIGN KEY (`parentId`) REFERENCES `ProjectTask`(`id`) ON DELETE SET NULL ON UPDATE NO ACTION;

-- AddForeignKey
ALTER TABLE `ProjectTask` ADD CONSTRAINT `ProjectTask_projectId_fkey` FOREIGN KEY (`projectId`) REFERENCES `Project`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `_TaskDependencies` ADD CONSTRAINT `_TaskDependencies_A_fkey` FOREIGN KEY (`A`) REFERENCES `ProjectTask`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `_TaskDependencies` ADD CONSTRAINT `_TaskDependencies_B_fkey` FOREIGN KEY (`B`) REFERENCES `ProjectTask`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
