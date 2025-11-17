#!/bin/bash

echo "=== CREATING TEST DATA IN PRODUCTION ==="

BASE_URL="https://bdo-server2.onrender.com"

# Login as admin
echo "1. Logging in as admin..."
LOGIN_RESPONSE=$(curl -s -X POST "${BASE_URL}/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@bdigitales.com","password":"Test123!"}')

if [[ $? -ne 0 ]]; then
  echo "❌ Login request failed"
  exit 1
fi

# Extract token
TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"accessToken":"[^"]*"' | cut -d'"' -f4)

if [[ -z "$TOKEN" ]]; then
  echo "❌ Failed to extract access token"
  exit 1
fi

echo "✅ Login successful"

# Create a test log entry
echo "2. Creating test log entry..."
LOGENTRY_RESPONSE=$(curl -s -X POST "${BASE_URL}/api/logentries" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "entryType": "GENERAL",
    "title": "Entrada de Prueba para PDF",
    "description": "Esta es una entrada de prueba para generar PDFs y verificar la funcionalidad de almacenamiento en Cloudflare R2.",
    "date": "2025-11-17",
    "weather": "Soleado",
    "temperature": 22,
    "workingHours": 8,
    "workersCount": 15,
    "location": "Zona A - Construcción Principal",
    "observations": "Observaciones de prueba para el sistema de generación de PDFs"
  }')

echo "Log entry creation response: $LOGENTRY_RESPONSE"

# Create a test report  
echo "3. Creating test report..."
REPORT_RESPONSE=$(curl -s -X POST "${BASE_URL}/api/reports" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "number": "REP-TEST-001",
    "title": "Reporte de Prueba para PDF",
    "summary": "Reporte de prueba para verificar la generación de PDFs",
    "workCompleted": "Actividades completadas según cronograma",
    "issuesFound": "No se presentaron inconvenientes mayores",
    "nextSteps": "Continuar con las siguientes fases del proyecto",
    "status": "APPROVED"
  }')

echo "Report creation response: $REPORT_RESPONSE"

echo "✅ Test data creation completed"
