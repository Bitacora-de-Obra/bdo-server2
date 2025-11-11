CREATE TABLE IF NOT EXISTS `ChatbotUsage` (
  `id` VARCHAR(191) NOT NULL,
  `userId` VARCHAR(191) NOT NULL,
  `date` DATE NOT NULL,
  `queryCount` INT NOT NULL DEFAULT 0,
  `cost` DECIMAL(10, 4) NOT NULL DEFAULT 0.0000,
  `model` VARCHAR(191) NULL,
  `tokensUsed` INT NOT NULL DEFAULT 0,
  `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updatedAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE INDEX `ChatbotUsage_userId_date_key`(`userId`, `date`),
  INDEX `ChatbotUsage_userId_idx`(`userId`),
  INDEX `ChatbotUsage_date_idx`(`date`),
  CONSTRAINT `ChatbotUsage_userId_fkey`
    FOREIGN KEY (`userId`) REFERENCES `User`(`id`)
    ON DELETE CASCADE ON UPDATE CASCADE
);

-- Create table that stores the individual chatbot interactions
CREATE TABLE IF NOT EXISTS `ChatbotInteraction` (
  `id` VARCHAR(191) NOT NULL,
  `userId` VARCHAR(191) NOT NULL,
  `question` LONGTEXT NOT NULL,
  `answer` LONGTEXT NOT NULL,
  `model` VARCHAR(191) NOT NULL,
  `tokensPrompt` INT NULL,
  `tokensCompletion` INT NULL,
  `selectedSections` JSON NULL,
  `metadata` JSON NULL,
  `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  INDEX `ChatbotInteraction_userId_createdAt_idx`(`userId`, `createdAt`),
  CONSTRAINT `ChatbotInteraction_userId_fkey`
    FOREIGN KEY (`userId`) REFERENCES `User`(`id`)
    ON DELETE CASCADE ON UPDATE CASCADE
);

-- Create table that stores feedback linked to chatbot interactions
CREATE TABLE IF NOT EXISTS `ChatbotFeedback` (
  `id` VARCHAR(191) NOT NULL,
  `interactionId` VARCHAR(191) NOT NULL,
  `rating` ENUM('POSITIVE', 'NEGATIVE') NOT NULL,
  `comment` LONGTEXT NULL,
  `metadata` JSON NULL,
  `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE INDEX `ChatbotFeedback_interactionId_key`(`interactionId`),
  CONSTRAINT `ChatbotFeedback_interactionId_fkey`
    FOREIGN KEY (`interactionId`) REFERENCES `ChatbotInteraction`(`id`)
    ON DELETE CASCADE ON UPDATE CASCADE
);

