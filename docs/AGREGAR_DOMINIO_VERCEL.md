# 🔧 Agregar mutis.bdigitales.com en Vercel

## 📋 Pasos Detallados

### 1. Agregar el Dominio

1. En el dashboard de Vercel, ve a tu proyecto
2. Ve a **Settings** → **Domains**
3. Haz clic en el botón **"Add Domain"** (arriba a la derecha)
4. En el campo de texto, ingresa: `mutis.bdigitales.com`
5. Haz clic en **"Add"** o presiona Enter

### 2. Verificación Automática

Vercel automáticamente:
- Verificará que el DNS está configurado correctamente
- Verificará que el registro CNAME apunta a Vercel
- Configurará el certificado SSL automáticamente

### 3. Estado de Verificación

Después de agregar el dominio, verás uno de estos estados:

- **🟡 Validating**: Vercel está verificando el DNS (puede tardar unos minutos)
- **🟢 Valid Configuration**: El dominio está listo y funcionando
- **🔴 Invalid Configuration**: Hay un problema con el DNS

### 4. Si Aparece "Invalid Configuration"

Si después de agregar `mutis.bdigitales.com` aparece "Invalid Configuration":

1. **Verifica el DNS**:
   ```bash
   dig mutis.bdigitales.com
   ```
   Debería mostrar que apunta a `cname.vercel-dns.com`

2. **Espera la propagación**:
   - Los cambios de DNS pueden tardar 15-30 minutos
   - Vercel puede tardar unos minutos en detectar el cambio

3. **Haz clic en "Refresh"**:
   - En la fila de `mutis.bdigitales.com`, haz clic en el botón "Refresh"
   - Esto fuerza a Vercel a verificar nuevamente el DNS

4. **Verifica el registro CNAME**:
   - Asegúrate de que el registro CNAME en tu proveedor de DNS sea:
     ```
     Tipo: CNAME
     Nombre: mutis
     Valor: cname.vercel-dns.com.
     ```

### 5. Verificar que Funciona

Una vez que el dominio muestre "Valid Configuration":

1. **Abre en el navegador**:
   ```
   https://mutis.bdigitales.com
   ```

2. **Verifica el certificado SSL**:
   - Deberías ver el candado verde en la barra de direcciones
   - El certificado debería ser válido

3. **Prueba el API**:
   ```bash
   curl -I https://mutis.bdigitales.com/api/project-details
   ```

4. **Ejecuta el script de verificación**:
   ```bash
   cd bdo-server
   DOMAIN=bdigitales.com SUBDOMAIN=mutis node scripts/verify-dns-config.js
   ```

## ⚠️ Notas Importantes

1. **Wildcard vs Dominio Específico**:
   - Aunque tienes `*.bdigitales.com` en DNS, Vercel necesita que agregues cada subdominio específicamente
   - El wildcard en DNS permite que funcione, pero Vercel necesita saber qué dominios aceptar

2. **Tiempo de Propagación**:
   - DNS: 15-30 minutos (puede tardar hasta 48 horas)
   - Vercel verificación: 1-5 minutos después de agregar el dominio

3. **SSL Automático**:
   - Vercel proporciona certificados SSL automáticamente
   - No necesitas configuración adicional

4. **Múltiples Proyectos**:
   - Si tienes frontend y backend en proyectos separados, agrega `mutis.bdigitales.com` a ambos
   - O configura uno como dominio principal y el otro como subdominio diferente

## 🐛 Troubleshooting

### El dominio no se verifica

- Verifica que el DNS está propagado: `dig mutis.bdigitales.com`
- Espera unos minutos y haz clic en "Refresh"
- Verifica que el CNAME apunta correctamente

### Error "Domain already exists"

- El dominio puede estar en otro proyecto de Vercel
- Ve a ese proyecto y elimínalo, o transfiérelo al proyecto actual

### El dominio se verifica pero no carga

- Verifica que el proyecto está desplegado
- Verifica que el dominio está asignado al deployment correcto
- Revisa los logs de Vercel para ver si hay errores

