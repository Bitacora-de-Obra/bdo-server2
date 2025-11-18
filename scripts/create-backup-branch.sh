#!/bin/bash

# Script para crear una rama de backup antes de hacer cambios grandes
# Uso: ./scripts/create-backup-branch.sh [nombre-backup]

set -e

BACKUP_NAME=${1:-"backup-$(date +%Y%m%d-%H%M%S)"}
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
BACKUP_BRANCH="backup/${CURRENT_BRANCH}-${BACKUP_NAME}"

echo "🔄 Creando backup de la rama actual..."
echo "   Rama actual: $CURRENT_BRANCH"
echo "   Backup: $BACKUP_BRANCH"

# Crear rama de backup
git checkout -b "$BACKUP_BRANCH"
git push origin "$BACKUP_BRANCH"

# Volver a la rama original
git checkout "$CURRENT_BRANCH"

echo ""
echo "✅ Backup creado exitosamente: $BACKUP_BRANCH"
echo "   Puedes volver a este punto con: git checkout $BACKUP_BRANCH"
echo ""



