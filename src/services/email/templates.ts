/**
 * Plantillas HTML para correos electrónicos
 */

const getLogoUrl = () => {
  // Si hay una URL pública del logo, usarla
  const logoUrl = process.env.EMAIL_LOGO_URL;
  if (logoUrl) {
    return logoUrl;
  }
  
  // Si no, usar el logo desde el frontend (ubicado en /logo.png en la carpeta public)
  const frontendUrl = process.env.APP_BASE_URL || process.env.FRONTEND_URL || "https://bdigitales.com";
  // Usar el logo desde la carpeta public (nombre fijo, sin hash)
  return `${frontendUrl.replace(/\/$/, "")}/logo.png`;
};

/**
 * Genera el HTML base para todos los correos con el logo y estilos
 */
export const getEmailBaseTemplate = (content: string): string => {
  const logoUrl = getLogoUrl();
  
  return `
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Bitácora Digital de Obra</title>
  <style>
    body {
      margin: 0;
      padding: 0;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      background-color: #f3f4f6;
      line-height: 1.6;
      color: #1f2937;
    }
    .email-container {
      max-width: 600px;
      margin: 0 auto;
      background-color: #ffffff;
    }
    .email-header {
      background: linear-gradient(135deg, #0D47A1 0%, #1976D2 100%);
      padding: 32px 24px;
      text-align: center;
    }
    .email-logo {
      max-width: 120px;
      height: auto;
      margin-bottom: 16px;
    }
    .email-title {
      color: #ffffff;
      font-size: 24px;
      font-weight: 600;
      margin: 0;
      letter-spacing: -0.5px;
    }
    .email-subtitle {
      color: rgba(255, 255, 255, 0.9);
      font-size: 14px;
      margin: 8px 0 0 0;
    }
    .email-body {
      padding: 32px 24px;
    }
    .email-content {
      color: #374151;
      font-size: 16px;
      line-height: 1.7;
    }
    .email-content h1 {
      color: #111827;
      font-size: 24px;
      font-weight: 600;
      margin: 0 0 16px 0;
    }
    .email-content h2 {
      color: #111827;
      font-size: 20px;
      font-weight: 600;
      margin: 24px 0 12px 0;
    }
    .email-content p {
      margin: 0 0 16px 0;
    }
    .email-content ul, .email-content ol {
      margin: 16px 0;
      padding-left: 24px;
    }
    .email-content li {
      margin: 8px 0;
    }
    .email-button {
      display: inline-block;
      padding: 14px 32px;
      background-color: #0D47A1;
      color: #ffffff !important;
      text-decoration: none;
      border-radius: 6px;
      font-weight: 600;
      font-size: 16px;
      margin: 24px 0;
      text-align: center;
    }
    .email-button:hover {
      background-color: #1565C0;
    }
    .email-button-secondary {
      background-color: #1976D2;
    }
    .email-button-secondary:hover {
      background-color: #1E88E5;
    }
    .email-info-box {
      background-color: #f0f9ff;
      border-left: 4px solid #0D47A1;
      padding: 16px;
      margin: 24px 0;
      border-radius: 4px;
    }
    .email-info-box strong {
      color: #0D47A1;
    }
    .email-warning-box {
      background-color: #fffbeb;
      border-left: 4px solid #F9A825;
      padding: 16px;
      margin: 24px 0;
      border-radius: 4px;
    }
    .email-footer {
      background-color: #f9fafb;
      padding: 24px;
      text-align: center;
      border-top: 1px solid #e5e7eb;
    }
    .email-footer-text {
      color: #6b7280;
      font-size: 14px;
      margin: 8px 0;
    }
    .email-footer-link {
      color: #0D47A1;
      text-decoration: none;
    }
    .email-footer-link:hover {
      text-decoration: underline;
    }
    @media only screen and (max-width: 600px) {
      .email-body {
        padding: 24px 16px;
      }
      .email-header {
        padding: 24px 16px;
      }
      .email-title {
        font-size: 20px;
      }
    }
  </style>
</head>
<body>
  <div class="email-container">
    <div class="email-header">
      <img src="${logoUrl}" alt="Bitácora Digital" class="email-logo" />
      <h1 class="email-title">Bitácora Digital</h1>
      <p class="email-subtitle">Construye, Digitaliza, Avanza</p>
    </div>
    <div class="email-body">
      <div class="email-content">
        ${content}
      </div>
    </div>
    <div class="email-footer">
      <p class="email-footer-text">
        <strong>Bitácora Digital de Obra</strong><br/>
        Sistema de gestión de proyectos de construcción
      </p>
      <p class="email-footer-text">
        Este correo fue enviado automáticamente. Por favor no respondas a este mensaje.
      </p>
      <p class="email-footer-text">
        <a href="${process.env.APP_BASE_URL || process.env.FRONTEND_URL || 'https://bdigitales.com'}" class="email-footer-link">
          Acceder a la plataforma
        </a>
      </p>
    </div>
  </div>
</body>
</html>
  `.trim();
};

/**
 * Genera un botón de acción para el correo
 */
export const getEmailButton = (text: string, url: string, secondary = false): string => {
  const buttonClass = secondary ? 'email-button email-button-secondary' : 'email-button';
  return `<div style="text-align: center; margin: 24px 0;">
    <a href="${url}" class="${buttonClass}" style="display: inline-block; padding: 14px 32px; background-color: ${secondary ? '#1976D2' : '#0D47A1'}; color: #ffffff !important; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 16px;">
      ${text}
    </a>
  </div>`;
};

/**
 * Genera una caja de información
 */
export const getEmailInfoBox = (content: string, type: 'info' | 'warning' = 'info'): string => {
  const bgColor = type === 'warning' ? '#fffbeb' : '#f0f9ff';
  const borderColor = type === 'warning' ? '#F9A825' : '#0D47A1';
  return `<div style="background-color: ${bgColor}; border-left: 4px solid ${borderColor}; padding: 16px; margin: 24px 0; border-radius: 4px;">
    ${content}
  </div>`;
};

