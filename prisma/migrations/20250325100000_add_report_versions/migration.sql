-- Add `version` column if missing
SET @version_column_exists := (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'Report'
    AND COLUMN_NAME = 'version'
);

SET @add_version_sql := IF(
  @version_column_exists = 0,
  'ALTER TABLE `Report` ADD COLUMN `version` INT NOT NULL DEFAULT 1',
  'SELECT "Column `version` already exists, skipping"'
);

PREPARE add_version_stmt FROM @add_version_sql;
EXECUTE add_version_stmt;
DEALLOCATE PREPARE add_version_stmt;

-- Add `previousReportId` column if missing
SET @previous_column_exists := (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.COLUMNS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'Report'
    AND COLUMN_NAME = 'previousReportId'
);

SET @add_previous_sql := IF(
  @previous_column_exists = 0,
  'ALTER TABLE `Report` ADD COLUMN `previousReportId` VARCHAR(191) NULL',
  'SELECT "Column `previousReportId` already exists, skipping"'
);

PREPARE add_previous_stmt FROM @add_previous_sql;
EXECUTE add_previous_stmt;
DEALLOCATE PREPARE add_previous_stmt;

-- Drop old unique index if it still exists
SET @old_index_exists := (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'Report'
    AND INDEX_NAME = 'Report_number_key'
);

SET @drop_old_index_sql := IF(
  @old_index_exists > 0,
  'ALTER TABLE `Report` DROP INDEX `Report_number_key`',
  'SELECT "Index `Report_number_key` not present, skipping drop"'
);

PREPARE drop_old_index_stmt FROM @drop_old_index_sql;
EXECUTE drop_old_index_stmt;
DEALLOCATE PREPARE drop_old_index_stmt;

-- Create new composite unique index if missing
SET @new_index_exists := (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.STATISTICS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'Report'
    AND INDEX_NAME = 'Report_number_version_key'
);

SET @create_new_index_sql := IF(
  @new_index_exists = 0,
  'CREATE UNIQUE INDEX `Report_number_version_key` ON `Report`(`number`, `version`)',
  'SELECT "Index `Report_number_version_key` already exists, skipping create"'
);

PREPARE create_new_index_stmt FROM @create_new_index_sql;
EXECUTE create_new_index_stmt;
DEALLOCATE PREPARE create_new_index_stmt;

-- Add self-referencing foreign key if missing
SET @fk_exists := (
  SELECT COUNT(*)
  FROM INFORMATION_SCHEMA.TABLE_CONSTRAINTS
  WHERE TABLE_SCHEMA = DATABASE()
    AND TABLE_NAME = 'Report'
    AND CONSTRAINT_NAME = 'Report_previousReportId_fkey'
);

SET @add_fk_sql := IF(
  @fk_exists = 0,
  'ALTER TABLE `Report` ADD CONSTRAINT `Report_previousReportId_fkey` FOREIGN KEY (`previousReportId`) REFERENCES `Report`(`id`) ON DELETE SET NULL ON UPDATE CASCADE',
  'SELECT "Foreign key `Report_previousReportId_fkey` already exists, skipping"'
);

PREPARE add_fk_stmt FROM @add_fk_sql;
EXECUTE add_fk_stmt;
DEALLOCATE PREPARE add_fk_stmt;
