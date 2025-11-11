-- Add versioning support to reports
ALTER TABLE `Report`
    ADD COLUMN `version` INT NOT NULL DEFAULT 1,
    ADD COLUMN `previousReportId` VARCHAR(191) NULL;

-- Drop existing unique index on number
DROP INDEX `Report_number_key` ON `Report`;

-- Create new composite unique index
CREATE UNIQUE INDEX `Report_number_version_key` ON `Report`(`number`, `version`);

-- Add self-referencing foreign key for version chain
ALTER TABLE `Report`
    ADD CONSTRAINT `Report_previousReportId_fkey`
    FOREIGN KEY (`previousReportId`) REFERENCES `Report`(`id`)
    ON DELETE SET NULL
    ON UPDATE CASCADE;
