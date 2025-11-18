#!/bin/bash

echo "=== TESTING CLOUDFLARE R2 ACCESS ==="
echo ""

# Test the public R2 URL directly
R2_PUBLIC_URL="https://pub-e07f0269fa994f659a210ce23fc46290.r2.dev"

echo "1. Testing R2 bucket accessibility..."
curl -I "$R2_PUBLIC_URL" 2>/dev/null | head -5
echo ""

echo "2. Testing a sample image path..."
# Try to access a common image path pattern
curl -I "$R2_PUBLIC_URL/attachments/test.png" 2>/dev/null | head -5
echo ""

echo "3. Checking CORS headers..."
curl -H "Origin: https://bdigitales.com" \
     -H "Access-Control-Request-Method: GET" \
     -H "Access-Control-Request-Headers: X-Requested-With" \
     -X OPTIONS \
     "$R2_PUBLIC_URL/test" 2>/dev/null | grep -i "access-control"
echo ""

echo "4. Testing from main domain..."
curl -H "Origin: https://bdigitales.com" \
     -I "$R2_PUBLIC_URL/test" 2>/dev/null | grep -i "access-control"
echo ""

echo "=== R2 ACCESS TEST COMPLETED ==="
