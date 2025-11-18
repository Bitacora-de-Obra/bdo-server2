# 🔧 Configurar DNS para Multi-Tenancy

Esta guía te ayudará a configurar el DNS para que `mutis.bdigitales.com` funcione correctamente con el sistema multi-tenant.

## 📋 Requisitos Previos

- Acceso al panel de control de tu proveedor de DNS (donde está configurado `bdigitales.com`)
- Acceso al panel de Vercel (o la plataforma donde está desplegado)
- El tenant "mutis" ya debe estar creado en la base de datos

## 🔧 Paso 1: Configurar DNS en tu Proveedor

### Opción A: Si usas Vercel (Recomendado)

Vercel maneja automáticamente los subdominios cuando agregas un dominio. Solo necesitas:

1. **Ir al Dashboard de Vercel**
   - Ve a tu proyecto (frontend o backend)
   - Ve a Settings → Domains

2. **Agregar el dominio principal (si no está)**
   - Agrega `bdigitales.com`
   - Vercel te dará registros DNS para configurar

3. **Agregar el subdominio**
   - Agrega `mutis.bdigitales.com`
   - Vercel automáticamente creará el registro CNAME necesario

4. **Configurar en tu proveedor de DNS**
   - Ve a tu proveedor de DNS (GoDaddy, Namecheap, Cloudflare, etc.)
   - Agrega un registro **CNAME**:
     ```
     Tipo: CNAME
     Nombre: mutis
     Valor: cname.vercel-dns.com (o el que Vercel te indique)
     TTL: 3600 (o automático)
     ```

### Opción B: Si usas otro proveedor (Render, Railway, etc.)

1. **Obtener la IP o dominio del servidor**
   - Si es Render: obtén el dominio del servicio (ej: `tu-app.onrender.com`)
   - Si es Railway: obtén el dominio del servicio

2. **Configurar en tu proveedor de DNS**
   - Agrega un registro **CNAME**:
     ```
     Tipo: CNAME
     Nombre: mutis
     Valor: tu-servidor.onrender.com (o la IP si es registro A)
     TTL: 3600
     ```

## ⚙️ Paso 2: Configurar el Servidor para Aceptar el Subdominio

### Si usas Vercel

Vercel automáticamente acepta todos los subdominios del dominio configurado. No necesitas configuración adicional.

### Si usas Render

1. Ve a tu servicio en Render
2. En Settings → Custom Domains
3. Agrega `mutis.bdigitales.com`
4. Render te dará instrucciones para verificar el dominio

### Si usas Railway

1. Ve a tu servicio en Railway
2. En Settings → Domains
3. Agrega `mutis.bdigitales.com`
4. Railway te dará instrucciones para verificar el dominio

## 🔍 Paso 3: Verificar la Configuración

### Verificar DNS

```bash
# Verificar que el DNS está configurado
dig mutis.bdigitales.com
# o
nslookup mutis.bdigitales.com
```

Deberías ver que `mutis.bdigitales.com` apunta al mismo servidor que `bdigitales.com`.

### Verificar que el Servidor Responde

```bash
# Probar que el servidor responde
curl -I https://mutis.bdigitales.com
```

### Verificar que el Middleware Detecta el Tenant

Una vez que el DNS esté configurado, puedes probar:

```bash
# Hacer una petición al API con el subdominio
curl -H "Host: mutis.bdigitales.com" https://mutis.bdigitales.com/api/project-details
```

El servidor debería detectar automáticamente el tenant "mutis" y filtrar los datos.

## 🧪 Paso 4: Probar en el Navegador

1. Abre `https://mutis.bdigitales.com` en tu navegador
2. Deberías ver la aplicación funcionando normalmente
3. Todos los datos mostrados deberían ser del tenant "mutis"
4. Si intentas acceder a `https://bdigitales.com` (sin subdominio), debería funcionar igual (pero sin filtrado por tenant si no hay subdominio)

## ⚠️ Notas Importantes

1. **Propagación DNS**: Los cambios de DNS pueden tardar entre 5 minutos y 48 horas en propagarse. Normalmente toma 15-30 minutos.

2. **SSL/TLS**: Vercel, Render y Railway automáticamente proporcionan certificados SSL para los subdominios. No necesitas configuración adicional.

3. **CORS**: Asegúrate de que `CORS_ALLOWED_ORIGINS` en tu backend incluya:
   ```
   https://bdigitales.com
   https://www.bdigitales.com
   https://mutis.bdigitales.com
   ```

4. **Frontend**: El frontend no necesita cambios. El backend detecta automáticamente el tenant desde el header `Host`.

## 🐛 Troubleshooting

### El subdominio no resuelve

- Verifica que el registro CNAME está correcto en tu proveedor de DNS
- Espera a que el DNS se propague (puede tardar hasta 48 horas)
- Usa `dig` o `nslookup` para verificar la configuración

### El servidor no detecta el tenant

- Verifica que el middleware `detectTenantMiddleware` está activo
- Revisa los logs del servidor para ver si hay errores
- Verifica que el tenant "mutis" existe en la base de datos

### Error 404 "Tenant no encontrado"

- Verifica que el tenant "mutis" existe en la tabla `Tenant`
- Verifica que el subdomain en la base de datos es exactamente "mutis" (sin espacios, minúsculas)
- Verifica que `isActive = true` en el tenant

## 📚 Recursos Adicionales

- [Documentación de Vercel sobre dominios](https://vercel.com/docs/concepts/projects/domains)
- [Documentación de Render sobre dominios](https://render.com/docs/custom-domains)
- [Documentación de Railway sobre dominios](https://docs.railway.app/deploy/configuring-domains)

