-- CreateTable
CREATE TABLE `User` (
    `id` VARCHAR(191) NOT NULL,
    `fullName` VARCHAR(191) NOT NULL,
    `email` VARCHAR(191) NOT NULL,
    `projectRole` ENUM('RESIDENT', 'SUPERVISOR', 'CONTRACTOR_REP', 'ADMIN') NOT NULL,
    `avatarUrl` VARCHAR(191) NOT NULL,
    `appRole` ENUM('admin', 'editor', 'viewer') NOT NULL,
    `status` VARCHAR(191) NOT NULL,
    `lastLoginAt` DATETIME(3) NULL,

    UNIQUE INDEX `User_email_key`(`email`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
