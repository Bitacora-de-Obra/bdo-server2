-- AlterTable
ALTER TABLE `Comment` ADD COLUMN `drawingId` VARCHAR(191) NULL,
    MODIFY `logEntryId` VARCHAR(191) NULL;

-- AddForeignKey
ALTER TABLE `Comment` ADD CONSTRAINT `Comment_drawingId_fkey` FOREIGN KEY (`drawingId`) REFERENCES `Drawing`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
