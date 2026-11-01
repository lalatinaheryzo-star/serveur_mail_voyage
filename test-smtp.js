const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '.env') });
const nodemailer = require('nodemailer');

async function test() {
  const pass = (process.env.SMTP_PASS || '').replace(/^"(.*)"$/, '$1');
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: pass,
    },
  });

  const sujet = 'Test code vérification';
  const texte = 'Test envoi email';

  try {
    const info = await transporter.sendMail({
      from: process.env.FROM_EMAIL || process.env.SMTP_USER,
      to: process.env.SMTP_USER,
      subject: sujet,
      text: texte,
    });
    console.log('EMAIL SENT SUCCESS:', info.messageId);
  } catch (err) {
    console.error('EMAIL FAILED:', err.message);
  }
}

test();
