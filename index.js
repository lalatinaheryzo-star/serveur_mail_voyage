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

app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json({ limit: '200kb' }));

const limiter = rateLimit({ windowMs: 60 * 1000, max: 12 });
app.use('/api/', limiter);

// ── PostgreSQL (même base Supabase que Spring Boot) ─────────────────
const pool = new Pool({
  host: process.env.DB_HOST || 'aws-0-eu-north-1.pooler.supabase.com',
  port: Number(process.env.DB_PORT) || 6543,
  database: process.env.DB_NAME || 'postgres',
  user: process.env.DB_USERNAME || 'postgres.zmbbhlfhbkrbomaerxpj',
  password: process.env.DB_PASSWORD,
  ssl: { rejectUnauthorized: false },
  max: 5,
  statement_timeout: 20000,
});

pool.on('error', (err) => {
  console.error('Erreur inattendue client PostgreSQL:', err.message);
});

// Vérification de la connexion au démarrage (sans bloquer si temporairement inaccessible)
pool.query('SELECT 1').then(() => {
  console.log('PostgreSQL connecté.');
}).catch((err) => {
  console.warn('Avertissement connexion PostgreSQL:', err.message);
});

// ── Constantes (identiques au Spring Boot) ──────────────────────────
const CODE_VALIDITE_MINUTES = 30;
const MAX_TENTATIVES_CODE = 5;
const DELAI_MIN_ENTRE_DEMANDES_SECONDES = 60;
const BCRYPT_ROUNDS = 10;
const MESSAGE_CODE_INVALIDE = 'Code invalide ou expiré.';

// ── Transporteur SMTP (réutilisé pour contact + password reset) ─────
function creerTransporteur() {
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
  });
}

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
//  MOT DE PASSE OUBLIÉ — endpoints migrés du Spring Boot
// ════════════════════════════════════════════════════════════════════

/**
 * POST /api/auth/password/nouveau-code
 * Génère un code 6 chiffres et l'envoie par e-mail SMTP.
 * Réponse identique que l'adresse soit connue ou non (anti-enumeration).
 */
app.post('/api/auth/password/nouveau-code', async (req, res) => {
  const { email } = req.body || {};
  if (!email || typeof email !== 'string' || !/^\S+@\S+\.\S+$/.test(email.trim())) {
    return res.status(400).json({ error: 'Adresse e-mail invalide.' });
  }

  const adresse = email.trim().toLowerCase();
  let client;

  try {
    client = await pool.connect();
    // ── Phase 1 : vérification + réservation (transaction) ──────────
    await client.query('BEGIN');
    const { rows } = await client.query(
      `SELECT id, email, prenom, role, reset_derniere_demande
       FROM utilisateurs WHERE LOWER(email) = $1 FOR UPDATE`,
      [adresse]
    );

    if (rows.length === 0 || rows[0].role === 'ADMIN') {
      // Travail factice pour égaliser le temps de réponse
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

    // Réserver la demande (enregistrer le timestamp)
    await client.query(
      `UPDATE utilisateurs SET reset_derniere_demande = NOW() WHERE id = $1`,
      [user.id]
    );
    await client.query('COMMIT');

    // ── Phase 2 : générer le code + envoyer l'e-mail (hors transaction) ──
    const codeNum = crypto.randomInt(1_000_000);
    const code = String(codeNum).padStart(6, '0');

    const transporter = creerTransporteur();
    if (!transporter) {
      console.error('Configuration SMTP manquante — code non envoyé.');
      return res.status(204).end();
    }

    const from = process.env.FROM_EMAIL || process.env.SMTP_USER;
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

    let envoye = false;
    try {
      await transporter.sendMail({
        from,
        to: user.email,
        subject:
          'Réinitialisation de votre mot de passe – Réservation en ligne à Madagascar',
        text: texte,
      });
      envoye = true;
      console.log(
        `Code de réinitialisation envoyé à ${masquerEmail(user.email)}.`
      );
    } catch (err) {
      console.error(
        `Échec envoi code à ${masquerEmail(user.email)}:`,
        err.message
      );
    }

    if (!envoye) {
      return res.status(204).end();
    }

    // ── Phase 3 : enregistrer le hash du code (transaction) ─────────
    const hash = await bcrypt.hash(code, BCRYPT_ROUNDS);
    const expiration = new Date(
      Date.now() + CODE_VALIDITE_MINUTES * 60 * 1000
    );

    await client.query('BEGIN');
    await client.query(
      `UPDATE utilisateurs
       SET code_verification = $1,
           code_verification_expiration = $2,
           reset_tentatives = 0
       WHERE id = $3`,
      [hash, expiration.toISOString(), user.id]
    );
    await client.query('COMMIT');

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

/**
 * POST /api/auth/password/reinitialiser
 * Valide le code + définit le nouveau mot de passe.
 * Toutes les erreurs renvoient le même message (anti-enumeration).
 */
app.post('/api/auth/password/reinitialiser', async (req, res) => {
  const { email, code, password } = req.body || {};

  // Validation du nouveau mot de passe (indépendant du compte)
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

    // Compte inconnu ou ADMIN
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

    // Aucun code en attente
    if (!hash || !expiration) {
      await travailFactice(codeSaisi);
      await client.query('COMMIT');
      return res.status(400).json({ error: MESSAGE_CODE_INVALIDE });
    }

    // Code expiré ou max tentatives atteint
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

    // Vérification du code
    const codeOk = await bcrypt.compare(codeSaisi, hash);

    if (!codeOk) {
      const essais = user.reset_tentatives + 1;
      if (essais >= MAX_TENTATIVES_CODE) {
        // Invalider le code
        await client.query(
          `UPDATE utilisateurs
           SET code_verification = NULL,
               code_verification_expiration = NULL,
               reset_tentatives = 0
           WHERE id = $1`,
          [user.id]
        );
        console.warn(
          `Code invalidé après ${MAX_TENTATIVES_CODE} essais (compte ${user.id}).`
        );
      } else {
        await client.query(
          `UPDATE utilisateurs SET reset_tentatives = $1 WHERE id = $2`,
          [essais, user.id]
        );
      }
      await client.query('COMMIT');
      return res.status(400).json({ error: MESSAGE_CODE_INVALIDE });
    }

    // ── Succès : changer le mot de passe ────────────────────────────
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

    console.log(`Mot de passe réinitialisé pour le compte ${user.id}.`);
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

/**
 * POST /api/auth/forgot-password
 * Compatibilité avec les clients mobiles : alias de nouveau-code.
 */
app.post('/api/auth/forgot-password', async (req, res) => {
  req.url = '/api/auth/password/nouveau-code';
  app.handle(req, res);
});

// ════════════════════════════════════════════════════════════════════
//  FORMULAIRE DE CONTACT (inchangé)
// ════════════════════════════════════════════════════════════════════

app.post('/api/contact', async (req, res) => {
  const { nom, email, sujet, message } = req.body || {};
  if (!nom || !email || !sujet || !message) {
    return res.status(400).json({ error: 'Tous les champs sont requis.' });
  }
  const emailRe = /^\S+@\S+\.\S+$/;
  if (!emailRe.test(email)) {
    return res.status(400).json({ error: 'Email invalide.' });
  }

  const missingSmtp = ['SMTP_HOST', 'SMTP_USER', 'SMTP_PASS', 'TO_EMAIL']
    .filter((key) => !process.env[key]);
  if (missingSmtp.length) {
    return res.status(500).json({
      error: `Configuration SMTP manquante: ${missingSmtp.join(', ')}.`
    });
  }

  try {
    const transporter = creerTransporteur();
    if (!transporter) {
      return res.status(500).json({ error: 'Configuration SMTP manquante.' });
    }

    const from = process.env.FROM_EMAIL || process.env.SMTP_USER || 'no-reply@example.com';
    const to = process.env.TO_EMAIL || process.env.SMTP_USER || from;

    const mailOptions = {
      from,
      to,
      subject: `${sujet} (de ${nom})`,
      text: `Nom: ${nom}\nEmail: ${email}\n\n${message}`
    };

    await transporter.sendMail(mailOptions);
    return res.json({ ok: true, message: 'Message envoyé.' });
  } catch (err) {
    console.error('Erreur envoi email:', err && err.message ? err.message : err);
    return res.status(500).json({ error: 'Erreur serveur lors de l\'envoi du message.' });
  }
});

const port = process.env.PORT || 4001;
app.listen(port, () => {
  console.log('serveur js demarré');
});
