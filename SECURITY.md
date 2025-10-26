# Seguridad y configuración

Para desplegar el backend con las contraseñas y tokens protegidos, define las siguientes variables de entorno según el entorno:

- `NODE_ENV=production`: habilita automáticamente cookies seguras y cabeceras reforzadas.
- `COOKIE_SECURE=true`: fuerza que la cookie de refresh solo viaje por HTTPS (útil en entornos que no usan `NODE_ENV=production`).
- `COOKIE_SAMESITE=none|lax|strict`: ajusta la política `SameSite` de la cookie (`none` requiere HTTPS).
- `COOKIE_DOMAIN=dominio.idu.gov.co`: establece el dominio explícito para la cookie cuando el backend se sirve detrás de un proxy o subdominio.
- `TRUST_PROXY=true`: debería habilitarse cuando Express está detrás de un proxy inverso (Nginx, Load Balancer) para que la detección de HTTPS y rate-limit por IP funcionen.
- `LOGIN_RATE_LIMIT_WINDOW_MS` y `LOGIN_RATE_LIMIT_MAX`: controlan la ventana y el número máximo de intentos de inicio de sesión antes de bloquear temporalmente la IP.
- `REFRESH_RATE_LIMIT_WINDOW_MS` y `REFRESH_RATE_LIMIT_MAX`: limitan la frecuencia con la que un cliente puede solicitar refresh tokens.

Recuerda actualizar el `origin` permitido en `cors` cuando cambie el dominio del frontend y mantener los tokens de acceso/refresh protegidos en un `https` reverse proxy.
