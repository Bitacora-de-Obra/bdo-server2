ALTER TABLE `LogEntry`
    ADD COLUMN `safetyFindings` LONGTEXT NULL;

ALTER TABLE `LogEntry`
    ADD COLUMN `safetyContractorResponse` LONGTEXT NULL;

ALTER TABLE `LogEntry`
    ADD COLUMN `environmentFindings` LONGTEXT NULL;

ALTER TABLE `LogEntry`
    ADD COLUMN `environmentContractorResponse` LONGTEXT NULL;

ALTER TABLE `LogEntry`
    ADD COLUMN `socialActivities` JSON NULL;

ALTER TABLE `LogEntry`
    ADD COLUMN `socialObservations` LONGTEXT NULL;

ALTER TABLE `LogEntry`
    ADD COLUMN `socialContractorResponse` LONGTEXT NULL;

ALTER TABLE `LogEntry`
    ADD COLUMN `socialPhotoSummary` LONGTEXT NULL;

