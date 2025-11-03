# Configuración del correo (SMTP)

Este proyecto utiliza **Nodemailer** para enviar notificaciones (verificación de cuenta, restablecimiento de contraseña, recordatorios y avisos de comunicaciones). El servidor solo intentará enviar correos cuando detecte una configuración SMTP válida.

## Variables de entorno necesarias

Define las siguientes variables en `.env` o en el entorno donde se ejecute `bdo-server`:

| Variable | Descripción |
| --- | --- |
| `SMTP_HOST` | Host del servidor SMTP (obligatorio). Si no se define, el módulo se desactiva. |
| `SMTP_PORT` | Puerto del servidor. Valores comunes: `587` (STARTTLS) u `465` (TLS directo). |
| `SMTP_SECURE` | `true` si el servidor requiere TLS implícito (puerto 465). `false` para STARTTLS. |
| `SMTP_USER` / `SMTP_PASS` | Credenciales de autenticación. Opcionales si el servidor acepta conexiones sin autenticación. |
| `EMAIL_FROM` | Dirección que aparecerá como remitente. Si no se indica, se usará `SMTP_USER`. |
| `APP_BASE_URL` | URL base del frontend para construir enlaces en los correos. |
| `EMAIL_VERIFICATION_URL` | (Opcional) URL completa para la verificación de correo. Permite sobrescribir la generada automáticamente. |
| `PASSWORD_RESET_URL` | (Opcional) URL completa para restablecer contraseñas. |
| `COMMITMENT_REMINDER_CC` / `COMMITMENT_REMINDER_BCC` | (Opcional) Correos en copia para los recordatorios de compromisos. Usa comas para múltiples direcciones. |
| `COMMITMENT_REMINDER_SUBJECT` | (Opcional) Asunto personalizado para los recordatorios. |

Consulta `bdo-server/.env.example` para ver un ejemplo preconfigurado con Mailtrap.

## Ejemplo con Mailtrap

1. Crea una cuenta gratuita en [https://mailtrap.io](https://mailtrap.io) y genera un inbox SMTP.
2. Copia los valores `Host`, `Port`, `Username` y `Password`.
3. Actualiza tu `.env`:

   ```env
   SMTP_HOST=sandbox.smtp.mailtrap.io
   SMTP_PORT=2525
   SMTP_SECURE=false
   SMTP_USER=xxxxxxxxxxxx
   SMTP_PASS=yyyyyyyyyyyy
   EMAIL_FROM="Bitácora Digital <no-reply@bitacora.local>"
   APP_BASE_URL=http://localhost:5173
   ```

4. Reinicia el servidor backend.

## Verificar la configuración

El backend expone endpoints administrativos para validar el módulo de correo (requieren un token de acceso de un usuario con `appRole=admin`):

1. **Consultar estado**

   ```
   GET /api/admin/system/email
   ```

   Parámetros opcionales:

   - `?verify=true`: ejecuta `transporter.verify()` y devuelve el resultado en la respuesta (`verification.verified`).

2. **Enviar correo de prueba**

   ```
   POST /api/admin/system/email/test
   Body JSON opcional: { "to": "correo@destino.com" }
   ```

   Si no se proporciona `to`, el backend usa el correo del usuario autenticado. La respuesta incluye `success: true` cuando el envío es exitoso.

En los logs del servidor verás un mensaje al inicio informando si el servicio SMTP está habilitado o no.

## Resolución de problemas

- **"El servicio de correo no está configurado"**: confirma que `SMTP_HOST` tiene un valor y reinicia el servidor.
- **Errores TLS o autenticación**: revisa `SMTP_SECURE`, el puerto y credenciales. Algunos proveedores requieren contraseñas específicas de aplicación.
- **No llegan los correos**: usa el endpoint de prueba y revisa los logs. Con Mailtrap deberías verlos en la bandeja del servicio.
- **Enlaces incorrectos**: ajusta `APP_BASE_URL`, `EMAIL_VERIFICATION_URL` y `PASSWORD_RESET_URL` para apuntar a tu dominio público.

Con la configuración correcta el sistema enviará correos de verificación, restablecimiento, recordatorios y notificaciones de asignaciones sin intervención adicional.
