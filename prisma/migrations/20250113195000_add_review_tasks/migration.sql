-- CreateEnum (skip if already exists)
-- Note: ReviewTaskStatus enum is created by Prisma automatically, no need to create it manually

-- CreateTable
CREATE TABLE IF NOT EXISTS `LogEntryReviewTask` (
  `id` VARCHAR(191) NOT NULL,
  `logEntryId` VARCHAR(191) NOT NULL,
  `reviewerId` VARCHAR(191) NOT NULL,
  `status` ENUM('PENDING', 'COMPLETED') NOT NULL DEFAULT 'PENDING',
  `assignedAt` DATETIME(3) NULL,
  `completedAt` DATETIME(3) NULL,
  `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updatedAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE INDEX `LogEntryReviewTask_logEntryId_reviewerId_key`(`logEntryId`, `reviewerId`),
  INDEX `LogEntryReviewTask_logEntryId_idx`(`logEntryId`),
  INDEX `LogEntryReviewTask_reviewerId_idx`(`reviewerId`),
  CONSTRAINT `LogEntryReviewTask_logEntryId_fkey` FOREIGN KEY (`logEntryId`) REFERENCES `LogEntry`(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `LogEntryReviewTask_reviewerId_fkey` FOREIGN KEY (`reviewerId`) REFERENCES `User`(`id`) ON DELETE RESTRICT ON UPDATE CASCADE
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

