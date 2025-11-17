-- CreateTable
CREATE TABLE `SecurityEventLog` (
    `id` VARCHAR(191) NOT NULL,
    `type` VARCHAR(64) NOT NULL,
    `severity` VARCHAR(32) NOT NULL,
    `ipAddress` VARCHAR(128) NULL,
    `userAgent` VARCHAR(512) NULL,
    `userId` VARCHAR(191) NULL,
    `email` VARCHAR(255) NULL,
    `path` VARCHAR(255) NULL,
    `method` VARCHAR(16) NULL,
    `details` JSON NULL,
    `metadata` JSON NULL,
    `createdAt` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateIndex
CREATE INDEX `SecurityEventLog_type_idx` ON `SecurityEventLog`(`type`);

-- CreateIndex
CREATE INDEX `SecurityEventLog_severity_idx` ON `SecurityEventLog`(`severity`);

-- CreateIndex
CREATE INDEX `SecurityEventLog_createdAt_idx` ON `SecurityEventLog`(`createdAt`);

-- CreateIndex
CREATE INDEX `SecurityEventLog_userId_idx` ON `SecurityEventLog`(`userId`);

-- CreateIndex
CREATE INDEX `SecurityEventLog_ipAddress_idx` ON `SecurityEventLog`(`ipAddress`);


