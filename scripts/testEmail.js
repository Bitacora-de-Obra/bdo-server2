require('dotenv').config();
const nodemailer = require('nodemailer');

const smtpHost = process.env.SMTP_HOST;
const smtpPort = Number(process.env.SMTP_PORT || 587);
const smtpSecure = process.env.SMTP_SECURE === "true";
const smtpUser = process.env.SMTP_USER;
const smtpPass = process.env.SMTP_PASS;
const defaultFrom = process.env.EMAIL_FROM || smtpUser || "no-reply@bitacora-digital.local";

const testEmail = async () => {
  const to = 'mariacamilaarenasd@gmail.com';
  
  if (!smtpHost) {
    console.error('❌ SMTP no está configurado. Define SMTP_HOST en .env');
    process.exit(1);
  }

  try {
    console.log('Configurando transporte SMTP...');
    const transporter = nodemailer.createTransport({
      host: smtpHost,
      port: smtpPort,
      secure: smtpSecure,
      auth: smtpUser ? {
        user: smtpUser,
        pass: smtpPass || "",
      } : undefined,
    });

    console.log('Verificando conexión SMTP...');
    await transporter.verify();
    console.log('✅ Conexión SMTP verificada');

    const subject = "Bitácora Digital · Correo de prueba";
    const html = `
      <p>Hola,</p>
      <p>Este es un correo de prueba del sistema Bitácora Digital.</p>
      <p>El envío confirma que la configuración SMTP está operativa.</p>
      <p>Fecha y hora: <strong>${new Date().toLocaleString("es-CO", {
        timeZone: process.env.REMINDER_TIMEZONE || "America/Bogota",
      })}</strong></p>
      <hr/>
      <p>Si tú no solicitaste esta prueba, puedes ignorar este correo.</p>
    `;

    const text = [
      "Hola,",
      "Este es un correo de prueba del sistema Bitácora Digital.",
      "El envío confirma que la configuración SMTP está operativa.",
      `Fecha y hora: ${new Date().toLocaleString("es-CO", {
        timeZone: process.env.REMINDER_TIMEZONE || "America/Bogota",
      })}`,
      "",
      "Si tú no solicitaste esta prueba, puedes ignorar este correo.",
    ].join("\n");

    console.log('Enviando correo de prueba a:', to);
    await transporter.sendMail({
      from: defaultFrom,
      to,
      subject,
      html,
      text,
    });

    console.log('✅ Correo enviado correctamente!');
    process.exit(0);
  } catch (error) {
    console.error('❌ Error al enviar correo:', error.message);
    console.error(error);
    process.exit(1);
  }
};

testEmail();

