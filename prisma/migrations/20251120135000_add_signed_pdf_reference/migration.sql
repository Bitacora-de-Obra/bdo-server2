-- Add column to track the latest signed PDF attachment per log entry
ALTER TABLE `LogEntry`
  ADD COLUMN `signedPdfAttachmentId` VARCHAR(191) NULL;

-- Reference attachments table so we always know which file has the latest signatures
ALTER TABLE `LogEntry`
  ADD CONSTRAINT `LogEntry_signedPdfAttachmentId_fkey`
  FOREIGN KEY (`signedPdfAttachmentId`) REFERENCES `Attachment`(`id`)
  ON DELETE SET NULL ON UPDATE CASCADE;

