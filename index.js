const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '.env') });
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const app = express();

// ── Reverse Proxy (Render / Heroku / Nginx) ───────────────────────────
// Indispensable sur Render pour éviter l'erreur ERR_ERL_UNEXPECTED_X_FORWARDED_FOR
app.set('trust proxy', 1);

// ── Sécurité & Headers ────────────────────────────────────────────────
// crossOriginResourcePolicy: 'cross-origin' évite le blocage des requêtes du frontend
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}));

// ── CORS (Accepte les requêtes du frontend local et distant) ───────────
app.use(cors({
  origin: (origin, callback) => {
    // Autoriser toutes les requêtes (Vercel, localhost:3000, localhost:5173, etc.)
    callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
}));

app.use(express.json({ limit: '200kb' }));

// ── Rate Limiter ──────────────────────────────────────────────────────
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30, // 30 requêtes par minute
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Trop de requêtes, veuillez réessayer dans une minute.' },
});

// ── PostgreSQL (même base Supabase que Spring Boot) ───────────────────
const connectionString = process.env.DATABASE_URL || process.env.DB_URL;
const pool = connectionString
  ? new Pool({
      connectionString,
      ssl: { rejectUnauthorized: false },
      max: 5,
      statement_timeout: 20000,
    })
  : new Pool({
      host: process.env.DB_HOST || 'aws-0-eu-north-1.pooler.supabase.com',
      port: Number(process.env.DB_PORT) || 6543,
      database: process.env.DB_NAME || 'postgres',
      user: process.env.DB_USERNAME || 'postgres.zmbbhlfhbkrbomaerxpj',
      password: process.env.DB_PASSWORD || 'reservationmada2026',
      ssl: { rejectUnauthorized: false },
      max: 5,
      statement_timeout: 20000,
    });

pool.on('error', (err) => {
  console.error('Erreur inattendue client PostgreSQL:', err.message);
});

// Test rapide de la connexion au démarrage
pool.query('SELECT 1').then(() => {
  console.log('PostgreSQL connecté.');
}).catch((err) => {
  console.warn('Avertissement connexion PostgreSQL:', err.message);
});

// ── Constantes Métier ────────────────────────────────────────────────
const CODE_VALIDITE_MINUTES = 30;
const MAX_TENTATIVES_CODE = 5;
const DELAI_MIN_ENTRE_DEMANDES_SECONDES = 60;
const BCRYPT_ROUNDS = 10;
const MESSAGE_CODE_INVALIDE = 'Code invalide ou expiré.';

// ── Travail factice BCrypt (anti timing-attack) ─────────────────────
let hashFactice = null;
async function travailFactice(secret) {
  if (!hashFactice) {
    hashFactice = await bcrypt.hash('mot-de-passe-factice-jamais-utilise', BCRYPT_ROUNDS);
  }
  await bcrypt.compare(secret || '', hashFactice);
}

// ── Masquer l'email dans les logs ───────────────────────────────────
function masquerEmail(email) {
  if (!email) return '-';
  const at = email.indexOf('@');
  if (at <= 0) return '***';
  return email.charAt(0) + '***' + email.substring(at);
}

// ════════════════════════════════════════════════════════════════════
//  MODULE D'ENVOI D'E-MAILS MULTI-FOURNISSEUR (HTTPS + SMTP)
// ════════════════════════════════════════════════════════════════════
// Render bloque les ports SMTP sortants (25, 465, 587) sur l'offre gratuite.
// Ce module prend en charge les API HTTPS (port 443) qui fonctionnent à 100%
// sur Render (Resend, Brevo, Gmail API) ainsi que SMTP standard en local.

function creerTransporteurSmtp() {
  const missingSmtp = ['SMTP_HOST', 'SMTP_USER', 'SMTP_PASS'].filter(
    (key) => !process.env[key]
  );
  if (missingSmtp.length) return null;
  const pass = (process.env.SMTP_PASS || '').replace(/^"(.*)"$/, '$1');
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: pass,
    },
    // Délais courts pour éviter de bloquer la requête pendant 2 minutes si le port est filtré par l'hébergeur
    connectionTimeout: 6000,
    greetingTimeout: 6000,
    socketTimeout: 6000,
  });
}

/**
 * Envoi via Resend HTTP API (HTTPS port 443 - recommandé sur Render)
 * Configuration requise : variable d'environnement RESEND_API_KEY
 */
async function envoyerViaResend(destinataire, sujet, texte) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) return false;

  const from = process.env.RESEND_FROM || process.env.FROM_EMAIL || 'onboarding@resend.dev';
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from,
      to: [destinataire],
      subject: sujet,
      text: texte,
    }),
  });

  if (!res.ok) {
    const errText = await res.text();
    console.error('Erreur API Resend:', res.status, errText);
    return false;
  }
  return true;
}

/**
 * Envoi via Brevo HTTP API (HTTPS port 443 - gratuit 300 mails/jour)
 * Configuration requise : variable d'environnement BREVO_API_KEY
 */
async function envoyerViaBrevo(destinataire, sujet, texte) {
  const apiKey = process.env.BREVO_API_KEY;
  if (!apiKey) return false;

  const senderEmail = process.env.FROM_EMAIL || process.env.SMTP_USER || 'no-reply@reservation-madagascar.mg';
  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'api-key': apiKey,
      'Content-Type': 'application/json',
      accept: 'application/json',
    },
    body: JSON.stringify({
      sender: { name: 'Réservation Madagascar', email: senderEmail },
      to: [{ email: destinataire }],
      subject: sujet,
      textContent: texte,
    }),
  });

  if (!res.ok) {
    const errText = await res.text();
    console.error('Erreur API Brevo:', res.status, errText);
    return false;
  }
  return true;
}

/**
 * Envoi via Gmail OAuth2 REST API (HTTPS port 443)
 */
async function envoyerViaGmailApi(destinataire, sujet, texte) {
  const { GMAIL_OAUTH_CLIENT_ID, GMAIL_OAUTH_CLIENT_SECRET, GMAIL_OAUTH_REFRESH_TOKEN } = process.env;
  if (!GMAIL_OAUTH_CLIENT_ID || !GMAIL_OAUTH_CLIENT_SECRET || !GMAIL_OAUTH_REFRESH_TOKEN) return false;

  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: GMAIL_OAUTH_CLIENT_ID,
      client_secret: GMAIL_OAUTH_CLIENT_SECRET,
      refresh_token: GMAIL_OAUTH_REFRESH_TOKEN,
      grant_type: 'refresh_token',
    }),
  });
  if (!tokenRes.ok) {
    console.error('Erreur OAuth2 Gmail:', await tokenRes.text());
    return false;
  }
  const tokenData = await tokenRes.json();
  const accessToken = tokenData.access_token;

  const sender = process.env.GMAIL_SENDER_ADDRESS || process.env.SMTP_USER || 'me';
  const utf8Subject = `=?utf-8?B?${Buffer.from(sujet).toString('base64')}?=`;
  const messageParts = [
    `From: ${sender}`,
    `To: ${destinataire}`,
    `Subject: ${utf8Subject}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    '',
    texte,
  ];
  const rawMessage = Buffer.from(messageParts.join('\r\n'))
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  const sendRes = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ raw: rawMessage }),
  });

  return sendRes.ok;
}

/**
 * Fonction centrale d'envoi d'e-mail avec fallback
 */
async function envoyerEmail({ destinataire, sujet, texte }) {
  // 1. Tenter Resend (HTTPS 443)
  if (process.env.RESEND_API_KEY) {
    try {
      const ok = await envoyerViaResend(destinataire, sujet, texte);
      if (ok) return true;
    } catch (err) {
      console.error('Échec Resend:', err.message);
    }
  }

  // 2. Tenter Brevo (HTTPS 443)
  if (process.env.BREVO_API_KEY) {
    try {
      const ok = await envoyerViaBrevo(destinataire, sujet, texte);
      if (ok) return true;
    } catch (err) {
      console.error('Échec Brevo:', err.message);
    }
  }

  // 3. Tenter Gmail API REST (HTTPS 443)
  if (process.env.GMAIL_OAUTH_REFRESH_TOKEN) {
    try {
      const ok = await envoyerViaGmailApi(destinataire, sujet, texte);
      if (ok) return true;
    } catch (err) {
      console.error('Échec Gmail API REST:', err.message);
    }
  }

  // 4. Tenter SMTP standard (nodemailer)
  const transporter = creerTransporteurSmtp();
  if (transporter) {
    try {
      const from = process.env.FROM_EMAIL || process.env.SMTP_USER;
      await transporter.sendMail({
        from,
        to: destinataire,
        subject: sujet,
        text: texte,
      });
      return true;
    } catch (err) {
      console.error(`Échec envoi SMTP à ${masquerEmail(destinataire)}:`, err.message);
      if (err.message && (err.message.includes('timeout') || err.code === 'ETIMEDOUT')) {
        console.warn(
          `\n[NOTE RENDER] Les instances gratuites de Render bloquent les ports SMTP (587, 465, 25).\n` +
          `Pour que l'envoi d'e-mail se fasse automatiquement depuis Render, ajoutez RESEND_API_KEY ou BREVO_API_KEY dans les variables d'environnement de Render (elles utilisent HTTPS port 443).\n`
        );
      }
    }
  }

  return false;
}

// ════════════════════════════════════════════════════════════════════
//  ROUTER PRINCIPAL (Monté sur /api ET sur / pour éliminer les 404)
// ════════════════════════════════════════════════════════════════════
const router = express.Router();
router.use(limiter);

// ── Healthcheck ───────────────────────────────────────────────────────
router.get(['/health', '/'], (req, res) => {
  res.json({
    status: 'ok',
    service: 'serveur-mail-voyage-auth',
    timestamp: new Date().toISOString(),
  });
});

// ── POST /auth/password/nouveau-code ─────────────────────────────────
router.post('/auth/password/nouveau-code', async (req, res) => {
  const { email } = req.body || {};
  if (!email || typeof email !== 'string' || !/^\S+@\S+\.\S+$/.test(email.trim())) {
    return res.status(400).json({ error: 'Adresse e-mail invalide.' });
  }

  const adresse = email.trim().toLowerCase();
  let client;

  try {
    client = await pool.connect();

    // ── Phase 1 : vérification + réservation ────────────────────────
    await client.query('BEGIN');
    const { rows } = await client.query(
      `SELECT id, email, prenom, role, reset_derniere_demande
       FROM utilisateurs WHERE LOWER(email) = $1 FOR UPDATE`,
      [adresse]
    );

    if (rows.length === 0 || rows[0].role === 'ADMIN') {
      // Travail factice anti timing-attack
      await travailFactice(String(crypto.randomInt(1_000_000)));
      await client.query('COMMIT');
      return res.status(204).end();
    }

    const user = rows[0];
    const maintenant = new Date();
    const derniere = user.reset_derniere_demande
      ? new Date(user.reset_derniere_demande)
      : null;

    if (
      derniere &&
      maintenant - derniere < DELAI_MIN_ENTRE_DEMANDES_SECONDES * 1000
    ) {
      await client.query('COMMIT');
      return res.status(204).end();
    }

    // ── Phase 2 : Générer le code 6 chiffres et l'enregistrer EN BASE ──
    const codeNum = crypto.randomInt(1_000_000);
    const code = String(codeNum).padStart(6, '0');
    const hash = await bcrypt.hash(code, BCRYPT_ROUNDS);
    const expiration = new Date(
      Date.now() + CODE_VALIDITE_MINUTES * 60 * 1000
    );

    await client.query(
      `UPDATE utilisateurs
       SET code_verification = $1,
           code_verification_expiration = $2,
           reset_tentatives = 0,
           reset_derniere_demande = NOW()
       WHERE id = $3`,
      [hash, expiration.toISOString(), user.id]
    );
    await client.query('COMMIT');

    // Code affiché dans les logs du serveur (permet le test immédiat même si l'e-mail tarde ou est filtré)
    console.log(
      `[AUTH] Code de réinitialisation pour ${masquerEmail(user.email)} : ${code} (valide ${CODE_VALIDITE_MINUTES} min)`
    );

    // ── Phase 3 : Envoi de l'e-mail ─────────────────────────────────
    const sujet = 'Réinitialisation de votre mot de passe – Réservation en ligne à Madagascar';
    const texte =
      `Bonjour ${user.prenom || '-'},\n\n` +
      `Vous avez demandé la réinitialisation du mot de passe de votre compte ` +
      `Réservation en ligne à Madagascar.\n\n` +
      `Votre code de vérification :\n\n` +
      `    ${code}\n\n` +
      `Ce code expire dans 30 minutes et ne peut être utilisé qu'une seule fois.\n` +
      `Si vous n'êtes pas à l'origine de cette demande, ignorez cet e-mail ` +
      `et ne communiquez ce code à personne.\n\n` +
      `Réservation en ligne à Madagascar`;

    const envoye = await envoyerEmail({
      destinataire: user.email,
      sujet,
      texte,
    });

    if (envoye) {
      console.log(`[AUTH] E-mail envoyé avec succès à ${masquerEmail(user.email)}.`);
    } else {
      console.warn(`[AUTH] L'e-mail n'a pas pu être expédié, mais le code reste utilisable via les logs ci-dessus.`);
    }

    return res.status(204).end();
  } catch (err) {
    if (client) {
      await client.query('ROLLBACK').catch(() => {});
    }
    console.error('Erreur nouveau-code:', err.message);
    return res.status(500).json({ error: 'Erreur serveur.' });
  } finally {
    if (client) client.release();
  }
});

// ── POST /auth/password/reinitialiser ────────────────────────────────
router.post('/auth/password/reinitialiser', async (req, res) => {
  const { email, code, password } = req.body || {};

  if (!password || password.length < 6) {
    return res
      .status(400)
      .json({ error: 'Le mot de passe doit contenir au moins 6 caractères.' });
  }
  if (!email || !code) {
    return res.status(400).json({ error: MESSAGE_CODE_INVALIDE });
  }

  const adresse = (email || '').trim().toLowerCase();
  const codeSaisi = (code || '').trim();
  let client;

  try {
    client = await pool.connect();
    await client.query('BEGIN');
    const { rows } = await client.query(
      `SELECT id, role, code_verification, code_verification_expiration,
              reset_tentatives
       FROM utilisateurs WHERE LOWER(email) = $1 FOR UPDATE`,
      [adresse]
    );

    if (rows.length === 0 || rows[0].role === 'ADMIN') {
      await travailFactice(codeSaisi);
      await client.query('COMMIT');
      return res.status(400).json({ error: MESSAGE_CODE_INVALIDE });
    }

    const user = rows[0];
    const maintenant = new Date();
    const hash = user.code_verification;
    const expiration = user.code_verification_expiration
      ? new Date(user.code_verification_expiration)
      : null;

    if (!hash || !expiration) {
      await travailFactice(codeSaisi);
      await client.query('COMMIT');
      return res.status(400).json({ error: MESSAGE_CODE_INVALIDE });
    }

    if (expiration < maintenant || user.reset_tentatives >= MAX_TENTATIVES_CODE) {
      await client.query(
        `UPDATE utilisateurs
         SET code_verification = NULL,
             code_verification_expiration = NULL,
             reset_tentatives = 0
         WHERE id = $1`,
        [user.id]
      );
      await travailFactice(codeSaisi);
      await client.query('COMMIT');
      return res.status(400).json({ error: MESSAGE_CODE_INVALIDE });
    }

    const codeOk = await bcrypt.compare(codeSaisi, hash);

    if (!codeOk) {
      const essais = user.reset_tentatives + 1;
      if (essais >= MAX_TENTATIVES_CODE) {
        await client.query(
          `UPDATE utilisateurs
           SET code_verification = NULL,
               code_verification_expiration = NULL,
               reset_tentatives = 0
           WHERE id = $1`,
          [user.id]
        );
        console.warn(`Code invalidé après ${MAX_TENTATIVES_CODE} essais (compte ${user.id}).`);
      } else {
        await client.query(
          `UPDATE utilisateurs SET reset_tentatives = $1 WHERE id = $2`,
          [essais, user.id]
        );
      }
      await client.query('COMMIT');
      return res.status(400).json({ error: MESSAGE_CODE_INVALIDE });
    }

    // Succès : mise à jour du mot de passe
    const nouveauHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    await client.query(
      `UPDATE utilisateurs
       SET mot_de_passe = $1,
           mot_de_passe_modifie_le = NOW(),
           code_verification = NULL,
           code_verification_expiration = NULL,
           reset_tentatives = 0,
           login_echecs = 0,
           login_verrou_jusqua = NULL
       WHERE id = $2`,
      [nouveauHash, user.id]
    );
    await client.query('COMMIT');

    console.log(`[AUTH] Mot de passe réinitialisé avec succès pour le compte ${user.id}.`);
    return res.status(204).end();
  } catch (err) {
    if (client) {
      await client.query('ROLLBACK').catch(() => {});
    }
    console.error('Erreur reinitialiser:', err.message);
    return res.status(500).json({ error: 'Erreur serveur.' });
  } finally {
    if (client) client.release();
  }
});

// ── Alias de compatibilité ───────────────────────────────────────────
router.post('/auth/forgot-password', (req, res) => {
  req.url = '/auth/password/nouveau-code';
  router.handle(req, res);
});

// ── POST /contact ────────────────────────────────────────────────────
router.post('/contact', async (req, res) => {
  const { nom, email, sujet, message } = req.body || {};
  if (!nom || !email || !sujet || !message) {
    return res.status(400).json({ error: 'Tous les champs sont requis.' });
  }
  const emailRe = /^\S+@\S+\.\S+$/;
  if (!emailRe.test(email)) {
    return res.status(400).json({ error: 'Email invalide.' });
  }

  try {
    const to = process.env.TO_EMAIL || process.env.SMTP_USER || 'lalatinaheryzo@gmail.com';
    const envoye = await envoyerEmail({
      destinataire: to,
      sujet: `${sujet} (de ${nom} <${email}>)`,
      texte: `Nom: ${nom}\nEmail: ${email}\n\n${message}`,
    });

    if (envoye) {
      return res.json({ ok: true, message: 'Message envoyé.' });
    } else {
      return res.status(500).json({ error: "Impossible d'envoyer l'e-mail de contact." });
    }
  } catch (err) {
    console.error('Erreur envoi contact:', err.message);
    return res.status(500).json({ error: "Erreur serveur lors de l'envoi du message." });
  }
});

// ── Montage du routeur sur /api ET sur / ─────────────────────────────
// Garantit la compatibilité quel que soit le chemin appelé par le frontend
app.use('/api', router);
app.use('/', router);

// ── Démarrage du serveur ──────────────────────────────────────────────
const port = process.env.PORT || 4001;
app.listen(port, () => {
  console.log(`serveur js demarré`);
});
