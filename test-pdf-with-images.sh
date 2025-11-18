#!/bin/bash

BASE_URL="https://bdo-server2.onrender.com"

echo "=== TESTING PDF WITH IMAGES ==="
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

# Test PDF generation that should include images
echo "2. Testing log entry PDF generation with images..."
LOGENTRY_RESPONSE=$(curl -s -X POST "${BASE_URL}/api/admin/test-pdf-generation" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":"logEntry"}')

echo "Log entry PDF response:"
echo "$LOGENTRY_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$LOGENTRY_RESPONSE"
echo ""

# Extract the PDF URL for direct access
PDF_URL=$(echo "$LOGENTRY_RESPONSE" | grep -o '"url":"[^"]*"' | cut -d'"' -f4)

if [[ -n "$PDF_URL" ]]; then
  echo "3. Testing direct PDF access..."
  echo "PDF URL: $PDF_URL"
  
  # Test if we can access the PDF
  HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$PDF_URL")
  echo "HTTP Status: $HTTP_STATUS"
  
  if [[ "$HTTP_STATUS" == "200" ]]; then
    echo "✅ PDF is accessible"
    
    # Get PDF size
    PDF_SIZE=$(curl -s -I "$PDF_URL" | grep -i content-length | cut -d' ' -f2 | tr -d '\r')
    echo "PDF Size: ${PDF_SIZE} bytes"
  else
    echo "❌ PDF is not accessible"
  fi
else
  echo "❌ No PDF URL found in response"
fi

echo ""
echo "=== PDF TEST COMPLETED ==="
echo ""
echo "Next steps:"
echo "1. Wait for deployment to complete (~2-3 minutes)"
echo "2. Try generating a PDF from an annotation with images in the web app"
echo "3. Check if images now appear in the generated PDF"
