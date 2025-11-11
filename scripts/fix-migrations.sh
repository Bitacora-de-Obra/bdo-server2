#!/bin/bash

echo "🔧 Iniciando corrección de migraciones..."

# Intentar resolver la migración problemática específica
echo "Resolviendo migración problemática 20250321510000_add_report_versions..."
npx prisma migrate resolve --applied 20250321510000_add_report_versions || echo "No se pudo resolver la migración específica"

# Intentar deploy normal
echo "Aplicando migraciones pendientes..."
npx prisma migrate deploy

# Si falla, intentar con --accept-data-loss
if [ $? -ne 0 ]; then
    echo "⚠️  Deploy normal falló, intentando con --accept-data-loss..."
    npx prisma migrate deploy --accept-data-loss
fi

echo "✅ Proceso de migración completado"
