#!/bin/bash
set -e

echo "🔧 Starting Render build process (direct command version)..."

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Generate Prisma Client first (needed for the script)
echo "🔨 Generating Prisma Client..."
npx prisma generate

# Create composite unique indexes manually (avoids AUTO_INCREMENT issues)
echo "🔄 Creating composite unique indexes..."
node scripts/create-composite-unique-indexes.js || {
  echo "⚠️  Script de índices falló, pero continuando..."
}

# Push schema changes (skip generate since we already did it)
echo "🔄 Pushing remaining schema changes to database..."
npx prisma db push --accept-data-loss --skip-generate || {
  echo "⚠️  prisma db push falló, pero continuando..."
}

# Build TypeScript
echo "🔨 Building TypeScript..."
npm run build

echo "✅ Build completed successfully!"

