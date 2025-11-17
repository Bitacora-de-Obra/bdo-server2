#!/bin/bash
set -e

echo "🔧 Starting Render build process..."

# Install all dependencies including devDependencies
echo "📦 Installing dependencies..."
npm ci --include=dev

# Generate Prisma Client
echo "🔨 Generating Prisma Client..."
npx prisma generate

# Verify Prisma Client was generated
if [ ! -d "node_modules/.prisma/client" ]; then
  echo "❌ Error: Prisma Client was not generated!"
  exit 1
fi

# Verify SecurityEventLog exists
if ! grep -q "SecurityEventLog" node_modules/.prisma/client/index.d.ts; then
  echo "❌ Error: SecurityEventLog not found in Prisma Client!"
  exit 1
fi

echo "✅ Prisma Client generated successfully"

# Build TypeScript
echo "🔨 Building TypeScript..."
npm run build

echo "✅ Build completed successfully!"

