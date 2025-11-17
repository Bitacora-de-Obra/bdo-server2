#!/bin/bash

# Script para ejecutar remotamente la creación de usuarios de prueba
# Se ejecuta directamente en el servidor de Render

echo "Running test users creation script on production..."

# Verificar que tenemos acceso a la base de datos
if [ -z "$DATABASE_URL" ]; then
    echo "ERROR: DATABASE_URL not found"
    exit 1
fi

# Ejecutar el script de creación de usuarios
node scripts/create-test-users.js

echo "Test users creation completed."
