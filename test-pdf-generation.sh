#!/bin/bash

BASE_URL="https://bdo-server2.onrender.com"

echo "=== TESTING PDF GENERATION ==="
echo ""

# Login as admin
echo "1. Logging in as admin..."
LOGIN_RESPONSE=$(curl -s -X POST "${BASE_URL}/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@bdigitales.com","password":"Test123!"}')

if [[ $? -ne 0 ]]; then
  echo "❌ Login request failed"
  exit 1
fi

echo "Login response: $LOGIN_RESPONSE"

# Extract token (simple extraction for this test)
TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"accessToken":"[^"]*"' | cut -d'"' -f4)

if [[ -z "$TOKEN" ]]; then
  echo "❌ Failed to extract access token"
  exit 1
fi

echo "✅ Login successful"
echo ""

# Check storage configuration
echo "2. Checking storage configuration..."
STORAGE_RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" "${BASE_URL}/api/admin/debug-storage")
echo "Storage config: $STORAGE_RESPONSE"
echo ""

# Test log entry PDF generation
echo "3. Testing log entry PDF generation..."
LOGENTRY_RESPONSE=$(curl -s -X POST "${BASE_URL}/api/admin/test-pdf-generation" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":"logEntry"}')

echo "Log entry PDF response: $LOGENTRY_RESPONSE"
echo ""

# Test report PDF generation
echo "4. Testing report PDF generation..."
REPORT_RESPONSE=$(curl -s -X POST "${BASE_URL}/api/admin/test-pdf-generation" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":"report"}')

echo "Report PDF response: $REPORT_RESPONSE"
echo ""

echo "=== TEST COMPLETED ==="
