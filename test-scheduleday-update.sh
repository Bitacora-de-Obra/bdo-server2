#!/bin/bash

BASE_URL="https://bdo-server2.onrender.com"

echo "=== TESTING SCHEDULE DAY CALCULATION UPDATE ==="
echo ""

# Login as admin
echo "1. Logging in as admin..."
TOKEN=$(curl -s -X POST "${BASE_URL}/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@bdigitales.com","password":"Test123!"}' | \
  grep -o '"accessToken":"[^"]*"' | cut -d'"' -f4)

if [[ -z "$TOKEN" ]]; then
  echo "❌ Failed to extract access token"
  exit 1
fi

echo "✅ Login successful"
echo ""

# Generate PDF to see current scheduleDay
echo "2. Generating PDF with current data..."
CURRENT_PDF_RESPONSE=$(curl -s -X POST "${BASE_URL}/api/admin/test-pdf-generation" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":"logEntry"}')

echo "Current PDF: $CURRENT_PDF_RESPONSE"
echo ""

# Get the PDF URL
PDF_URL=$(echo "$CURRENT_PDF_RESPONSE" | grep -o '"url":"[^"]*"' | cut -d'"' -f4)
echo "📄 Current PDF URL: $PDF_URL"
echo ""

echo "✅ Test completed - check the PDF to see if scheduleDay shows correctly"
