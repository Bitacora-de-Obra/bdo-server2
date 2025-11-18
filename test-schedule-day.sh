#!/bin/bash

BASE_URL="https://bdo-server2.onrender.com"

echo "=== TESTING SCHEDULE DAY CALCULATION ==="
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

# Get first project to use its ID
echo "2. Getting project ID..."
PROJECT_RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" "${BASE_URL}/api/projects")

# Extract first project ID (simple extraction for this test)
PROJECT_ID=$(echo "$PROJECT_RESPONSE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [[ -z "$PROJECT_ID" ]]; then
  echo "❌ Failed to extract project ID"
  exit 1
fi

echo "✅ Project ID: $PROJECT_ID"
echo ""

# Create a log entry with scheduleDay
echo "3. Creating log entry with scheduleDay..."

# Get current date in YYYY-MM-DD format
CURRENT_DATE=$(date +"%Y-%m-%d")

LOGENTRY_DATA=$(cat <<EOF
{
  "title": "Test Anotación - Día del Plazo",
  "description": "Esta es una prueba para verificar que el scheduleDay se calcule correctamente en el PDF.",
  "type": "GENERAL",
  "status": "DRAFT",
  "entryDate": "${CURRENT_DATE}T00:00:00.000Z",
  "scheduleDay": "Día 45 del proyecto",
  "projectId": "${PROJECT_ID}",
  "isConfidential": false,
  "location": "Zona de Pruebas",
  "subject": "Prueba de cálculo de día del plazo"
}
EOF
)

LOGENTRY_RESPONSE=$(curl -s -X POST "${BASE_URL}/api/log-entries" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$LOGENTRY_DATA")

echo "Log entry creation response:"
echo "$LOGENTRY_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$LOGENTRY_RESPONSE"
echo ""

# Extract log entry ID
LOG_ENTRY_ID=$(echo "$LOGENTRY_RESPONSE" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [[ -n "$LOG_ENTRY_ID" ]]; then
  echo "✅ Log entry created with ID: $LOG_ENTRY_ID"
  echo ""
  
  # Generate PDF for this specific log entry
  echo "4. Generating PDF for the new log entry..."
  PDF_RESPONSE=$(curl -s -X POST "${BASE_URL}/api/logentries/${LOG_ENTRY_ID}/pdf" \
    -H "Authorization: Bearer $TOKEN")
  
  echo "PDF generation response:"
  echo "$PDF_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$PDF_RESPONSE"
  echo ""
  
  # Extract PDF URL
  PDF_URL=$(echo "$PDF_RESPONSE" | grep -o '"url":"[^"]*"' | cut -d'"' -f4)
  
  if [[ -n "$PDF_URL" ]]; then
    echo "✅ PDF generated successfully!"
    echo "PDF URL: $PDF_URL"
    echo ""
    echo "5. Testing direct PDF access..."
    HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$PDF_URL")
    echo "HTTP Status: $HTTP_STATUS"
    
    if [[ "$HTTP_STATUS" == "200" ]]; then
      echo "✅ PDF is accessible - scheduleDay should now show 'Día 45 del proyecto' instead of 0"
    else
      echo "❌ PDF is not accessible"
    fi
  else
    echo "❌ No PDF URL found in response"
  fi
else
  echo "❌ Failed to create log entry"
fi

echo ""
echo "=== SCHEDULE DAY TEST COMPLETED ==="
echo ""
echo "INSTRUCTIONS:"
echo "1. Open the PDF URL above in your browser"
echo "2. Check the 'Día del plazo' field - it should show 'Día 45 del proyecto' instead of '0'"
echo "3. Also verify in the 'Información general y contexto' section"
