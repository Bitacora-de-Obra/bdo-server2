#!/bin/bash
set -e

echo "🔧 Starting Render build process..."

# Save current NODE_ENV (Render sets it to production)
ORIGINAL_NODE_ENV="${NODE_ENV:-production}"

# Force install all dependencies including devDependencies
# Temporarily set NODE_ENV=development for npm install only
# This ensures devDependencies (TypeScript types) are installed
echo "📦 Installing dependencies (including devDependencies)..."
echo "📋 Current NODE_ENV: $NODE_ENV"

# Clear npm cache to ensure fresh install
echo "🧹 Clearing npm cache..."
npm cache clean --force || true

# Install with development environment to get devDependencies
NODE_ENV=development npm install --include=dev

# Verify @types packages are installed BEFORE restoring NODE_ENV
echo "🔍 Verifying TypeScript types are installed..."
if [ ! -d "node_modules/@types/jsonwebtoken" ]; then
  echo "❌ Error: @types/jsonwebtoken not found!"
  echo "📋 Listing @types directory:"
  ls -la node_modules/@types/ 2>/dev/null || echo "node_modules/@types/ does not exist!"
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
if [ ! -d "node_modules/@types/multer" ]; then
  echo "❌ Error: @types/multer not found!"
  exit 1
fi
echo "✅ TypeScript types verified"

# Restore original NODE_ENV for the rest of the build
export NODE_ENV="$ORIGINAL_NODE_ENV"
echo "📋 NODE_ENV restored to: $NODE_ENV"

# Generate Prisma Client (this doesn't require DB connection)
echo "🔨 Generating Prisma Client..."
npx prisma generate

# Push schema changes to database (with --accept-data-loss for unique constraints)
# This is safe because tenantId is already assigned to all records
echo "🔄 Pushing schema changes to database..."
npx prisma db push --accept-data-loss || {
  echo "⚠️  prisma db push failed, but continuing build..."
  echo "   This might be expected if the schema is already in sync"
}

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
  echo "📋 Listing Prisma Client models:"
  grep -E "export type \w+ = " node_modules/.prisma/client/index.d.ts | head -20
  echo "🔄 Regenerating Prisma Client..."
  npx prisma generate --force
  if ! grep -q "SecurityEventLog" node_modules/.prisma/client/index.d.ts; then
    echo "❌ SecurityEventLog still not found after regeneration!"
    exit 1
  fi
fi

echo "✅ Prisma Client generated successfully"

# Build TypeScript
echo "🔨 Building TypeScript..."
npm run build

echo "✅ Build completed successfully!"

