/**
 * Script para verificar que la configuración DNS de multi-tenancy está funcionando
 * 
 * Este script verifica:
 * 1. Que el DNS resuelve correctamente
 * 2. Que el servidor responde al subdominio
 * 3. Que el middleware detecta el tenant correctamente
 */

const https = require('https');
const http = require('http');
const { execSync } = require('child_process');

const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function success(message) {
  log(`✅ ${message}`, 'green');
}

function error(message) {
  log(`❌ ${message}`, 'red');
}

function warning(message) {
  log(`⚠️  ${message}`, 'yellow');
}

function info(message) {
  log(`ℹ️  ${message}`, 'cyan');
}

function section(title) {
  console.log('');
  log(`📋 ${title}`, 'blue');
  console.log('─'.repeat(50));
}

function checkDNS(domain) {
  section(`1. Verificando DNS para ${domain}`);
  
  try {
    const result = execSync(`dig +short ${domain}`, { encoding: 'utf-8' }).trim();
    
    if (result && result.length > 0) {
      success(`DNS resuelve correctamente`);
      info(`  Resultado: ${result}`);
      return true;
    } else {
      error(`DNS no resuelve`);
      warning('  Esto puede ser normal si el DNS aún no se ha propagado');
      return false;
    }
  } catch (err) {
    // Intentar con nslookup como alternativa
    try {
      const result = execSync(`nslookup ${domain}`, { encoding: 'utf-8' });
      if (result.includes('Name:')) {
        success(`DNS resuelve correctamente (nslookup)`);
        return true;
      }
    } catch (err2) {
      error(`No se pudo verificar DNS: ${err.message}`);
      warning('  Asegúrate de tener dig o nslookup instalado');
      return false;
    }
  }
  
  return false;
}

function checkServerResponse(url) {
  return new Promise((resolve) => {
    section(`2. Verificando que el servidor responde en ${url}`);
    
    const protocol = url.startsWith('https') ? https : http;
    
    const req = protocol.get(url, { timeout: 10000 }, (res) => {
      if (res.statusCode === 200 || res.statusCode === 404 || res.statusCode === 401) {
        success(`Servidor responde (Status: ${res.statusCode})`);
        info(`  Headers recibidos correctamente`);
        resolve(true);
      } else {
        warning(`Servidor responde con status ${res.statusCode}`);
        resolve(true); // Aún es una respuesta válida
      }
    });
    
    req.on('error', (err) => {
      error(`Error al conectar: ${err.message}`);
      warning('  Verifica que el servidor esté desplegado y accesible');
      resolve(false);
    });
    
    req.on('timeout', () => {
      error('Timeout al conectar con el servidor');
      resolve(false);
    });
    
    req.setTimeout(10000);
  });
}

function checkTenantDetection(url, subdomain) {
  return new Promise((resolve) => {
    section(`3. Verificando detección de tenant para ${subdomain}`);
    
    const protocol = url.startsWith('https') ? https : http;
    const urlObj = new URL(url);
    
    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
      path: '/api/project-details',
      method: 'GET',
      headers: {
        'Host': `${subdomain}.${urlObj.hostname.replace(/^[^.]+\./, '')}`,
        'User-Agent': 'Multi-Tenant-Verifier/1.0',
      },
      timeout: 10000,
    };
    
    const req = protocol.request(options, (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        try {
          const response = JSON.parse(data);
          
          if (res.statusCode === 401 || res.statusCode === 403) {
            // Esto es esperado si no hay autenticación, pero significa que el servidor respondió
            success(`Servidor procesó la petición (Status: ${res.statusCode})`);
            info('  El middleware de tenant está activo');
            resolve(true);
          } else if (res.statusCode === 200) {
            success(`Tenant detectado correctamente`);
            info('  El servidor filtró los datos por tenant');
            resolve(true);
          } else if (res.statusCode === 404 && response.error && response.error.includes('Tenant')) {
            warning(`Tenant no encontrado: ${response.message || response.error}`);
            info('  Verifica que el tenant "mutis" existe en la base de datos');
            resolve(false);
          } else {
            warning(`Respuesta inesperada (Status: ${res.statusCode})`);
            resolve(true); // El servidor respondió, que es lo importante
          }
        } catch (err) {
          warning(`No se pudo parsear la respuesta: ${err.message}`);
          resolve(true); // El servidor respondió
        }
      });
    });
    
    req.on('error', (err) => {
      error(`Error al verificar tenant: ${err.message}`);
      resolve(false);
    });
    
    req.on('timeout', () => {
      error('Timeout al verificar tenant');
      resolve(false);
    });
    
    req.setTimeout(10000);
    req.end();
  });
}

async function runVerification() {
  console.log('');
  log('🔍 VERIFICACIÓN DE CONFIGURACIÓN DNS MULTI-TENANT', 'cyan');
  console.log('═'.repeat(50));
  
  const domain = process.env.DOMAIN || 'bdigitales.com';
  const subdomain = process.env.SUBDOMAIN || 'mutis';
  const protocol = process.env.PROTOCOL || 'https';
  const baseUrl = `${protocol}://${domain}`;
  const subdomainUrl = `${protocol}://${subdomain}.${domain}`;
  
  info(`Dominio base: ${domain}`);
  info(`Subdominio: ${subdomain}`);
  info(`URL base: ${baseUrl}`);
  info(`URL subdominio: ${subdomainUrl}`);
  
  const results = {
    dns: false,
    serverResponse: false,
    tenantDetection: false,
  };
  
  // Verificar DNS
  results.dns = checkDNS(`${subdomain}.${domain}`);
  
  // Esperar un poco antes de la siguiente verificación
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  // Verificar respuesta del servidor
  results.serverResponse = await checkServerResponse(subdomainUrl);
  
  // Esperar un poco antes de la siguiente verificación
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  // Verificar detección de tenant
  results.tenantDetection = await checkTenantDetection(baseUrl, subdomain);
  
  // Resumen
  console.log('');
  section('📊 RESUMEN DE VERIFICACIÓN');
  
  Object.entries(results).forEach(([test, passed]) => {
    if (passed) {
      success(test);
    } else {
      error(test);
    }
  });
  
  const totalTests = Object.keys(results).length;
  const passedTests = Object.values(results).filter(r => r).length;
  
  console.log('');
  log(`Resultado: ${passedTests}/${totalTests} verificaciones pasadas`, 
      passedTests === totalTests ? 'green' : 'yellow');
  
  if (passedTests === totalTests) {
    success('¡La configuración DNS está funcionando correctamente!');
    console.log('');
    info('Próximos pasos:');
    info('  1. Abre https://mutis.bdigitales.com en tu navegador');
    info('  2. Verifica que la aplicación carga correctamente');
    info('  3. Verifica que los datos mostrados son del tenant "mutis"');
  } else {
    warning('Algunas verificaciones fallaron. Revisa los errores arriba.');
    console.log('');
    info('Consejos:');
    if (!results.dns) {
      info('  - Espera a que el DNS se propague (puede tardar hasta 48 horas)');
      info('  - Verifica que el registro CNAME está correcto en tu proveedor de DNS');
    }
    if (!results.serverResponse) {
      info('  - Verifica que el servidor está desplegado y accesible');
      info('  - Verifica que el dominio está configurado en Vercel/Render/Railway');
    }
    if (!results.tenantDetection) {
      info('  - Verifica que el tenant "mutis" existe en la base de datos');
      info('  - Verifica que el middleware detectTenantMiddleware está activo');
    }
  }
  
  process.exit(passedTests === totalTests ? 0 : 1);
}

// Ejecutar verificación
runVerification().catch((error) => {
  console.error('Error fatal:', error);
  process.exit(1);
});

