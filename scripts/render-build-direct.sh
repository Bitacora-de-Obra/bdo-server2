#!/bin/bash
set -e

echo "🔧 Starting Render build process (direct command version)..."

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Push schema with --accept-data-loss flag
echo "🔄 Pushing schema changes to database..."
npx prisma db push --accept-data-loss

# Generate Prisma Client
echo "🔨 Generating Prisma Client..."
npx prisma generate

# Build TypeScript
echo "🔨 Building TypeScript..."
npm run build

echo "✅ Build completed successfully!"

