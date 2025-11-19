-- Add mustUpdatePassword flag to users for forced password reset on first login
ALTER TABLE `User`
ADD COLUMN `mustUpdatePassword` BOOLEAN NOT NULL DEFAULT false AFTER `tokenVersion`;

