const fetch = require('node-fetch');

const BASE_URL = 'https://bdo-server2.onrender.com';

async function testPdfGeneration() {
  console.log('=== TESTING PDF GENERATION ===\n');

  try {
    // First, login as admin
    console.log('1. Logging in as admin...');
    const loginResponse = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: 'admin@bdigitales.com',
        password: 'Test123!'
      })
    });

    if (!loginResponse.ok) {
      throw new Error(`Login failed: ${loginResponse.status} ${loginResponse.statusText}`);
    }

    const loginData = await loginResponse.json();
    const token = loginData.tokens.accessToken;
    console.log('✅ Login successful\n');

    // Check storage configuration
    console.log('2. Checking storage configuration...');
    const storageResponse = await fetch(`${BASE_URL}/api/admin/debug-storage`, {
      headers: {
        'Authorization': `Bearer ${token}`,
      }
    });

    if (!storageResponse.ok) {
      throw new Error(`Storage debug failed: ${storageResponse.status} ${storageResponse.statusText}`);
    }

    const storageData = await storageResponse.json();
    console.log('Storage Configuration:', JSON.stringify(storageData, null, 2));
    console.log('');

    // Test PDF generation for log entry
    console.log('3. Testing log entry PDF generation...');
    const logEntryPdfResponse = await fetch(`${BASE_URL}/api/admin/test-pdf-generation`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        type: 'logEntry'
      })
    });

    if (!logEntryPdfResponse.ok) {
      const errorText = await logEntryPdfResponse.text();
      console.log(`❌ Log entry PDF generation failed: ${logEntryPdfResponse.status} ${logEntryPdfResponse.statusText}`);
      console.log('Error details:', errorText);
    } else {
      const logEntryPdfData = await logEntryPdfResponse.json();
      console.log('✅ Log entry PDF generation successful:');
      console.log(JSON.stringify(logEntryPdfData, null, 2));
    }
    console.log('');

    // Test PDF generation for report
    console.log('4. Testing report PDF generation...');
    const reportPdfResponse = await fetch(`${BASE_URL}/api/admin/test-pdf-generation`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        type: 'report'
      })
    });

    if (!reportPdfResponse.ok) {
      const errorText = await reportPdfResponse.text();
      console.log(`❌ Report PDF generation failed: ${reportPdfResponse.status} ${reportPdfResponse.statusText}`);
      console.log('Error details:', errorText);
    } else {
      const reportPdfData = await reportPdfResponse.json();
      console.log('✅ Report PDF generation successful:');
      console.log(JSON.stringify(reportPdfData, null, 2));
    }

  } catch (error) {
    console.error('❌ Test failed:', error.message);
  }

  console.log('\n=== TEST COMPLETED ===');
}

// Run the test
testPdfGeneration();
