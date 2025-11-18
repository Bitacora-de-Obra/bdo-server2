#!/bin/bash

BASE_URL="https://bdo-server2.onrender.com"

echo "=== CREATING TEST DATA FOR PDF GENERATION ==="
echo ""

# Login as admin
echo "1. Logging in as admin..."
LOGIN_RESPONSE=$(curl -s -X POST "${BASE_URL}/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@bdigitales.com","password":"Test123!"}')

TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"accessToken":"[^"]*"' | cut -d'"' -f4)

if [[ -z "$TOKEN" ]]; then
  echo "❌ Failed to extract access token"
  exit 1
fi

echo "✅ Login successful"
echo ""

# Create a test project if none exists
echo "2. Creating test project..."
PROJECT_RESPONSE=$(curl -s -X POST "${BASE_URL}/api/projects" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Proyecto Test PDF",
    "code": "TEST-PDF",
    "location": "Bogotá, Colombia",
    "description": "Proyecto de prueba para generación de PDFs",
    "startDate": "2024-01-01T00:00:00.000Z",
    "endDate": "2024-12-31T00:00:00.000Z",
    "budget": 1000000000,
    "status": "ACTIVE",
    "category": "INFRASTRUCTURE",
    "priority": "HIGH"
  }')

echo "Project creation response: $PROJECT_RESPONSE"
echo ""

# Create a test log entry
echo "3. Creating test log entry..."
LOGENTRY_RESPONSE=$(curl -s -X POST "${BASE_URL}/api/logentries" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "entryType": "GENERAL",
    "title": "Entrada de Prueba para PDF",
    "description": "Esta es una entrada de prueba para generar PDFs y verificar la funcionalidad de almacenamiento en Cloudflare R2.",
    "date": "2024-11-18T00:00:00.000Z",
    "weather": "Soleado",
    "temperature": 22,
    "workingHours": 8,
    "workersCount": 15,
    "location": "Zona A - Construcción Principal",
    "observations": "Observaciones de prueba para el sistema de generación de PDFs"
  }')

echo "Log entry creation response: $LOGENTRY_RESPONSE"
echo ""

echo "=== TEST DATA CREATION COMPLETED ==="
