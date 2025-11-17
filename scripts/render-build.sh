#!/bin/bash
set -e

echo "🔧 Starting Render build process..."

# Force install all dependencies including devDependencies
# Render sets NODE_ENV=production which skips devDependencies by default
echo "📦 Installing dependencies (including devDependencies)..."
NODE_ENV=development npm ci

# Verify @types packages are installed
echo "🔍 Verifying TypeScript types are installed..."
if [ ! -d "node_modules/@types/jsonwebtoken" ]; then
  echo "❌ Error: @types/jsonwebtoken not found!"
  exit 1
fi
if [ ! -d "node_modules/@types/bcryptjs" ]; then
  echo "❌ Error: @types/bcryptjs not found!"
  exit 1
fi
if [ ! -d "node_modules/@types/nodemailer" ]; then
  echo "❌ Error: @types/nodemailer not found!"
  exit 1
fi
if [ ! -d "node_modules/@types/pdfkit" ]; then
  echo "❌ Error: @types/pdfkit not found!"
  exit 1
fi
echo "✅ TypeScript types verified"

# Generate Prisma Client (this doesn't require DB connection)
echo "🔨 Generating Prisma Client..."
npx prisma generate

# Note: Migrations should be run separately via Render's postdeploy script
# or manually after deployment. Prisma Client generation doesn't require DB.

# Verify Prisma Client was generated
if [ ! -d "node_modules/.prisma/client" ]; then
  echo "❌ Error: Prisma Client was not generated!"
  exit 1
fi

# Verify SecurityEventLog exists
if ! grep -q "SecurityEventLog" node_modules/.prisma/client/index.d.ts; then
  echo "❌ Error: SecurityEventLog not found in Prisma Client!"
  echo "📋 Checking schema..."
  grep -A 5 "model SecurityEventLog" prisma/schema.prisma || echo "SecurityEventLog not in schema!"
  exit 1
fi

echo "✅ Prisma Client generated successfully"

# Build TypeScript
echo "🔨 Building TypeScript..."
npm run build

echo "✅ Build completed successfully!"

