// Bulk create/update users from a JSON list.
// Usage:
//   1) Edit scripts/users-to-import.json with the desired users.
//   2) Run: npm run users:import
//
// Each user item should be:
// { "email": "user@example.com", "fullName": "Nombre Apellido", "projectRole": "RESIDENT|SUPERVISOR|CONTRACTOR_REP|ADMIN", "appRole": "admin|editor|viewer" }
// Password will be set to "password123" for all imported users.

/* eslint-disable no-console */
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function main() {
  const filePath = path.join(__dirname, 'users-to-import.json');
  if (!fs.existsSync(filePath)) {
    console.error(`Input file not found: ${filePath}`);
    console.error('Create scripts/users-to-import.json with an array of users.');
    process.exit(1);
  }

  const raw = fs.readFileSync(filePath, 'utf8');
  let users;
  try {
    users = JSON.parse(raw);
  } catch (e) {
    console.error('Invalid JSON in users-to-import.json');
    process.exit(1);
  }

  if (!Array.isArray(users) || users.length === 0) {
    console.error('users-to-import.json must be a non-empty array');
    process.exit(1);
  }

  const password = 'password123';
  const passwordHash = await bcrypt.hash(password, 10);

  const validProjectRoles = new Set(['ADMIN', 'RESIDENT', 'SUPERVISOR', 'CONTRACTOR_REP']);
  const validAppRoles = new Set(['admin', 'editor', 'viewer']);

  let created = 0;
  let updated = 0;
  for (const u of users) {
    const email = (u.email || '').trim().toLowerCase();
    const fullName = (u.fullName || '').trim();
    const projectRole = (u.projectRole || 'RESIDENT').trim();
    const appRole = (u.appRole || 'viewer').trim();

    if (!email || !fullName) {
      console.warn(`Skipping user with missing email/fullName: ${JSON.stringify(u)}`);
      continue;
    }
    if (!validProjectRoles.has(projectRole)) {
      console.warn(`Invalid projectRole for ${email}, defaulting to RESIDENT`);
    }
    if (!validAppRoles.has(appRole)) {
      console.warn(`Invalid appRole for ${email}, defaulting to viewer`);
    }

    const data = {
      email,
      fullName,
      password: passwordHash,
      projectRole: validProjectRoles.has(projectRole) ? projectRole : 'RESIDENT',
      appRole: validAppRoles.has(appRole) ? appRole : 'viewer',
      status: 'active',
    };

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      await prisma.user.update({
        where: { email },
        data,
      });
      updated += 1;
      console.log(`Updated: ${email}`);
    } else {
      await prisma.user.create({ data });
      created += 1;
      console.log(`Created: ${email}`);
    }
  }

  console.log(`Done. Created: ${created}, Updated: ${updated}`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });




