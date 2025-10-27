#!/bin/sh
set -e

if [ -n "$DATABASE_URL" ]; then
  echo "[*] Running database migrations"
  npx prisma migrate deploy

  if [ "$PRISMA_RUN_SEED" = "true" ]; then
    echo "[*] Running database seed"
    npx prisma db seed
  fi
fi

exec "$@"
