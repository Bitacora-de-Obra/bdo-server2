-- Add columns to track contractor review workflow
ALTER TABLE `LogEntry`
ADD COLUMN `contractorReviewCompleted` BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN `contractorReviewCompletedAt` DATETIME(3) NULL,
ADD COLUMN `contractorReviewerId` VARCHAR(191) NULL;

-- Add foreign key and index for contractor reviewer relationship
ALTER TABLE `LogEntry`
ADD CONSTRAINT `LogEntry_contractorReviewerId_fkey`
  FOREIGN KEY (`contractorReviewerId`) REFERENCES `User`(`id`)
  ON DELETE SET NULL ON UPDATE CASCADE;

CREATE INDEX `LogEntry_contractorReviewerId_idx` ON `LogEntry`(`contractorReviewerId`);

