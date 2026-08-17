const express = require("express");
const path = require("path");
const crypto = require("crypto");
const session = require("express-session");
const connectPgSimple = require("connect-pg-simple");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 10000;
const isProduction = process.env.NODE_ENV === "production";

app.set("trust proxy", 1);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProduction
    ? { rejectUnauthorized: false }
    : false
});

const PgSession = connectPgSimple(session);

app.use(express.json({ limit: "64kb" }));
app.use(express.urlencoded({ extended: true, limit: "64kb" }));

// Basic production security headers. Keep framing available for provider survey
// pages; the survey player itself embeds third-party content.
app.use((req, res, next) => {
  res.set("X-Content-Type-Options", "nosniff");
  res.set("Referrer-Policy", "strict-origin-when-cross-origin");
  res.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  next();
});

// Never cache application pages; navigation must always reflect the current session.
app.use((req, res, next) => {
  if (req.path.endsWith(".html") || req.path === "/") {
    res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
    res.set("Pragma", "no-cache");
  }
  next();
});

app.use(session({
  name: "liliantech.sid",
  store: new PgSession({
    pool,
    tableName: "user_sessions",
    createTableIfMissing: true
  }),
  secret: process.env.SESSION_SECRET || "CHANGE_THIS_SESSION_SECRET_IN_RENDER",
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    path: "/",
    httpOnly: true,
    secure: isProduction,
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

// Page navigation is session-aware. Authenticated members stay inside the dashboard
// when they click Home, rather than being treated as logged out by the public homepage.
app.get("/", (req, res, next) => {
  if (req.session && req.session.userId) {
    return res.redirect("/dashboard.html");
  }
  next();
});

app.get("/surveys", (req, res) => {
  if (req.session && req.session.userId) {
    return res.redirect("/dashboard.html#surveys");
  }
  res.redirect("/#surveys");
});

// Protect the admin document itself, not just its API calls. Normal members
// should not be able to open /admin.html directly.
app.get("/admin.html", async (req, res) => {
  if (!req.session.userId) return res.redirect("/login.html");
  try {
    const result = await pool.query('SELECT full_name, email FROM users WHERE id=$1', [req.session.userId]);
    const user = result.rows[0];
    // Admin page access is based ONLY on the three explicitly authorized emails.
    // The database role is not trusted for this page gate.
    if (!isDesignatedAdmin(user)) {
      return res.status(403).send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access denied — LilianTech</title><link rel="stylesheet" href="/styles.css"></head><body><main class="section"><div class="container card feature" style="max-width:560px"><div class="brand">Lilian<span>Tech</span></div><h1>Access denied</h1><p class="muted">The administration area is restricted to authorized administrators.</p><a class="button primary" href="/dashboard.html">Back to dashboard</a></div></main></body></html>`);
    }
    return res.sendFile(path.join(__dirname, "public", "admin.html"));
  } catch (error) {
    console.error("Admin page access check failed:", error);
    return res.status(500).send("Unable to verify administrator access.");
  }
});

app.get('/sw.js',(req,res)=>res.sendFile(path.join(__dirname,'public','sw.js'),{headers:{'Cache-Control':'no-cache'}}));

app.use(express.static(path.join(__dirname, "public")));

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      full_name VARCHAR(120) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      balance NUMERIC(14,6) NOT NULL DEFAULT 0.000000,
      role VARCHAR(20) NOT NULL DEFAULT 'member',
      phone VARCHAR(40),
      payment_method VARCHAR(40),
      payment_details TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS survey_activity (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      survey_id VARCHAR(120) NOT NULL,
      title VARCHAR(255) NOT NULL,
      reward NUMERIC(14,6) NOT NULL DEFAULT 0.000000,
      status VARCHAR(20) NOT NULL DEFAULT 'in_progress',
      started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      completed_at TIMESTAMPTZ,
      UNIQUE(user_id, survey_id)
    );
    CREATE TABLE IF NOT EXISTS ai_questions (
      id SERIAL PRIMARY KEY,
      question_hash VARCHAR(64) UNIQUE NOT NULL,
      category VARCHAR(80) NOT NULL,
      topic VARCHAR(180) NOT NULL,
      region VARCHAR(80) NOT NULL DEFAULT 'Global',
      question TEXT NOT NULL,
      options JSONB NOT NULL,
      reward NUMERIC(14,6) NOT NULL DEFAULT 0.001000,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS ai_survey_bundles (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title VARCHAR(255) NOT NULL,
      category VARCHAR(80) NOT NULL DEFAULT 'Global Opinion',
      question_ids JSONB NOT NULL,
      reward_total NUMERIC(14,6) NOT NULL DEFAULT 0.010000,
      status VARCHAR(20) NOT NULL DEFAULT 'available',
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS survey_campaigns (
      id SERIAL PRIMARY KEY,
      title VARCHAR(120) NOT NULL,
      category VARCHAR(80) NOT NULL DEFAULT 'Global Opinion',
      question_ids JSONB NOT NULL,
      reward_total NUMERIC(14,6) NOT NULL DEFAULT 0.010000,
      max_responses INTEGER NOT NULL DEFAULT 100,
      response_count INTEGER NOT NULL DEFAULT 0,
      status VARCHAR(20) NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS survey_assignments (
      id SERIAL PRIMARY KEY,
      campaign_id INTEGER NOT NULL REFERENCES survey_campaigns(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      status VARCHAR(20) NOT NULL DEFAULT 'available',
      answers JSONB,
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
      UNIQUE(campaign_id,user_id)
    );
    CREATE TABLE IF NOT EXISTS push_subscriptions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      endpoint TEXT NOT NULL UNIQUE,
      p256dh TEXT NOT NULL,
      auth TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS notification_log (
      id SERIAL PRIMARY KEY,
      campaign_id INTEGER REFERENCES survey_campaigns(id) ON DELETE SET NULL,
      channel VARCHAR(20) NOT NULL,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      status VARCHAR(30) NOT NULL,
      detail TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE users ADD COLUMN IF NOT EXISTS next_survey_batch_at TIMESTAMPTZ;
    ALTER TABLE survey_campaigns ADD COLUMN IF NOT EXISTS owner_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE;
    CREATE INDEX IF NOT EXISTS idx_survey_campaigns_owner ON survey_campaigns(owner_user_id);
    UPDATE users u SET next_survey_batch_at=NOW()+INTERVAL '30 minutes'
    WHERE u.next_survey_batch_at IS NULL AND EXISTS (
      SELECT 1 FROM survey_assignments a WHERE a.user_id=u.id AND a.status='completed'
    ) AND (SELECT COUNT(*) FROM survey_assignments a2 WHERE a2.user_id=u.id AND a2.status='completed') % 5 = 0;

    CREATE TABLE IF NOT EXISTS withdrawals (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      amount NUMERIC(12,2) NOT NULL CHECK (amount > 0),
      method VARCHAR(40) NOT NULL,
      details TEXT NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      admin_note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      processed_at TIMESTAMPTZ,
      provider_reference VARCHAR(180),
      payout_error TEXT
    );
    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type VARCHAR(30) NOT NULL,
      amount NUMERIC(14,6) NOT NULL,
      description VARCHAR(255) NOT NULL,
      reference_id VARCHAR(120),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS provider_surveys (
      id SERIAL PRIMARY KEY,
      provider_id VARCHAR(80) NOT NULL,
      external_id VARCHAR(160) NOT NULL,
      title VARCHAR(255) NOT NULL,
      reward NUMERIC(12,2) NOT NULL DEFAULT 0,
      minutes INTEGER NOT NULL DEFAULT 10,
      country VARCHAR(10) DEFAULT 'US',
      status VARCHAR(20) NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(provider_id, external_id)
    );
    CREATE TABLE IF NOT EXISTS provider_transactions (
      id SERIAL PRIMARY KEY,
      provider_id VARCHAR(80) NOT NULL,
      transaction_id VARCHAR(180) NOT NULL,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      survey_id VARCHAR(160),
      status VARCHAR(30) NOT NULL,
      amount NUMERIC(12,2) NOT NULL DEFAULT 0,
      publisher_revenue NUMERIC(12,2) NOT NULL DEFAULT 0,
      user_reward NUMERIC(12,2) NOT NULL DEFAULT 0,
      margin NUMERIC(12,2) NOT NULL DEFAULT 0,
      raw_payload JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(provider_id, transaction_id)
    );
  `);

  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) NOT NULL DEFAULT 'member'`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(40)`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS payment_method VARCHAR(40)`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS payment_details TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS terms_accepted_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS privacy_accepted_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS provider_reference VARCHAR(180)`);
  await pool.query(`ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS payout_error TEXT`);
  await pool.query(`ALTER TABLE provider_transactions ADD COLUMN IF NOT EXISTS publisher_revenue NUMERIC(12,2) NOT NULL DEFAULT 0`);
  await pool.query(`ALTER TABLE provider_transactions ADD COLUMN IF NOT EXISTS user_reward NUMERIC(12,2) NOT NULL DEFAULT 0`);
  await pool.query(`ALTER TABLE provider_transactions ADD COLUMN IF NOT EXISTS margin NUMERIC(12,2) NOT NULL DEFAULT 0`);
  await pool.query(`ALTER TABLE survey_campaigns ADD COLUMN IF NOT EXISTS max_responses INTEGER NOT NULL DEFAULT 1000`);
  await pool.query(`ALTER TABLE survey_campaigns ADD COLUMN IF NOT EXISTS response_count INTEGER NOT NULL DEFAULT 0`);
  // v15: standardize AI participation rewards to $0.001 per question / $0.010 per 10-question survey.
  await pool.query(`UPDATE ai_questions SET reward=0.001000 WHERE reward=0.005000`);
  await pool.query(`UPDATE survey_campaigns SET reward_total=0.010000 WHERE reward_total=0.050000`);
  await pool.query(`ALTER TABLE survey_campaigns ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_survey_campaigns_status ON survey_campaigns(status,created_at)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_survey_assignments_user ON survey_assignments(user_id,status)`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_push_subscriptions_user ON push_subscriptions(user_id)`);
  await pool.query(`ALTER TABLE users ALTER COLUMN balance TYPE NUMERIC(14,6)`);
  await pool.query(`ALTER TABLE transactions ALTER COLUMN amount TYPE NUMERIC(14,6)`);
  await pool.query(`ALTER TABLE survey_activity ALTER COLUMN reward TYPE NUMERIC(14,6)`);
  await pool.query(`ALTER TABLE users ALTER COLUMN balance TYPE NUMERIC(14,6)`);
  await pool.query(`ALTER TABLE transactions ALTER COLUMN amount TYPE NUMERIC(14,6)`);

  // One-time cleanup of development/demo artifacts from earlier builds.
  await pool.query(`DELETE FROM provider_surveys WHERE LOWER(provider_id) IN ('demo','test','local','mock') OR LOWER(title) LIKE '%demo%' OR LOWER(title) LIKE '%test survey%'`);
  await pool.query(`DELETE FROM survey_activity WHERE LOWER(survey_id) LIKE 'demo-%' OR LOWER(survey_id) LIKE 'test-%' OR LOWER(survey_id) LIKE 'local-%' OR LOWER(title) LIKE '%demo%' OR LOWER(title) LIKE '%test survey%'`);
  await pool.query(`DELETE FROM transactions WHERE LOWER(description) LIKE '%demo%' OR LOWER(description) LIKE '%test earning%' OR LOWER(description) LIKE '%test survey%'`);
  await pool.query(`DELETE FROM withdrawals WHERE LOWER(details) LIKE '%demo%' OR LOWER(details) LIKE '%test%'`);
  await pool.query(`DELETE FROM provider_transactions WHERE LOWER(COALESCE(raw_payload::text,'')) LIKE '%demo%' OR LOWER(COALESCE(raw_payload::text,'')) LIKE '%test%'`);
  await pool.query(`UPDATE users u SET balance = COALESCE((SELECT SUM(t.amount) FROM transactions t WHERE t.user_id=u.id), 0)`);

  const adminEmails = getAdminEmails();
  await pool.query(
    `UPDATE users SET role = CASE WHEN LOWER(email)=ANY($1::text[]) THEN 'admin' ELSE 'member' END`,
    [adminEmails]
  );

  // Remove the old branded titles from any bundles created by earlier builds.
  // New bundles receive AI-generated project names.
  const oldTitles = await pool.query(`SELECT id FROM ai_survey_bundles WHERE title ILIKE 'LilianTech%Survey%' ORDER BY id ASC`);
  const renamePool = ['Aether','Hedgehog','Nimbus','Solace','Quill','Mosaic','Orbit','Ember','Harbor','Lumen','Cinder','Vertex','Meadow','Echo','Pioneer','Atlas','Clover','Sable','Nova','Drift'];
  for (let i = 0; i < oldTitles.rows.length; i++) {
    await pool.query(`UPDATE ai_survey_bundles SET title=$1 WHERE id=$2`, [renamePool[i % renamePool.length], oldTitles.rows[i].id]);
  }
  console.log("Database initialized successfully.");
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
  const [salt, originalHash] = storedHash.split(":");

  if (!salt || !originalHash) {
    return false;
  }

  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  const originalBuffer = Buffer.from(originalHash, "hex");
  const hashBuffer = Buffer.from(hash, "hex");

  if (originalBuffer.length !== hashBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(hashBuffer, originalBuffer);
}

const authAttempts = new Map();
const providerSurveyCache = new Map();
let aiQuestionGenerationPromise = null;
const AI_QUESTION_MODEL = String(process.env.OPENAI_QUESTION_MODEL || 'gpt-5.6-luna').trim();
const AI_QUESTION_REWARD = Number(process.env.AI_QUESTION_REWARD || 0.001);
const AI_QUESTION_BATCH_SIZE = Math.max(10, Math.min(50, Number(process.env.AI_QUESTION_BATCH_SIZE || 30)));
const AI_SURVEY_SIZE = 10;
const AI_SURVEY_PREFETCH = Math.max(2, Math.min(10, Number(process.env.AI_SURVEY_PREFETCH || 3)));
const AI_QUESTION_PREFETCH = Math.max(5, Math.min(25, Number(process.env.AI_QUESTION_PREFETCH || 10)));
const SURVEY_BATCH_SIZE = 5;
const SURVEY_MAX_RESPONSES = Math.max(1, Math.min(1000000, Number(process.env.SURVEY_MAX_RESPONSES || 1000)));
const SURVEY_PREFETCH = SURVEY_BATCH_SIZE;
const SURVEY_REFRESH_MS = 30 * 60 * 1000;
const NOTIFICATION_EMAIL_ENABLED = String(process.env.NOTIFICATION_EMAIL_ENABLED || 'true').toLowerCase() === 'true';
const NOTIFICATION_PUSH_ENABLED = String(process.env.NOTIFICATION_PUSH_ENABLED || 'true').toLowerCase() === 'true';
const notificationClients = new Set();
let nodemailer = null;
let webpush = null;
try { nodemailer = require('nodemailer'); } catch {}
try { webpush = require('web-push'); } catch {}

function questionHash(text) {
  return crypto.createHash('sha256').update(String(text).trim().toLowerCase().replace(/\s+/g, ' '), 'utf8').digest('hex');
}

function normalizeQuestionOptions(options) {
  if (!Array.isArray(options)) return [];
  return options.map(x => String(x || '').trim()).filter(Boolean).slice(0, 5);
}

async function generateAiQuestionBatch() {
  const apiKey = String(process.env.OPENAI_API_KEY || '').trim();
  if (!apiKey) throw new Error('OPENAI_API_KEY is not configured.');

  const existing = await pool.query(`SELECT question, topic FROM ai_questions ORDER BY created_at DESC LIMIT 120`);
  const existingText = existing.rows.map(x => `- ${x.question} [${x.topic}]`).join('\n');
  const prompt = `Generate ${AI_QUESTION_BATCH_SIZE} UNIQUE global consumer-opinion questions for LilianTech.

Categories must rotate among: Brands & Products, Technology, Shopping, Food & Beverage, Travel, Entertainment, Finance & Services, Lifestyle, Politics & Current Affairs.

Rules:
- Every question must be multiple choice with exactly 4 or 5 meaningful options.
- Questions should collect opinions, preferences, awareness, priorities or intentions, not test factual knowledge.
- Include recognizable global brands when appropriate, but never imply that a brand paid for the question or that an advertiser will pay LilianTech.
- Political/current-affairs questions must be neutral, non-partisan and suitable for a global audience; ask about opinions, priorities, awareness or perceived importance rather than requiring a current factual answer.
- Do not target protected traits or ask for highly sensitive personal data.
- Avoid repetitive wording, near-duplicates, yes/no questions, leading questions, and questions with an obviously correct answer.
- Questions must be useful for consumer and public-opinion research.
- Use globally understandable English.
- Return ONLY valid JSON matching the requested schema.

Previously used questions to avoid duplicating or paraphrasing:
${existingText || '(none yet)'}`;

  const response = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model: AI_QUESTION_MODEL,
      messages: [
        { role: 'system', content: 'You create concise, neutral, globally relevant multiple-choice opinion questions. Output only the requested JSON.' },
        { role: getAdminEmails().includes(normalizedEmail) ? 'admin' : 'user', content: prompt }
      ],
      response_format: {
        type: 'json_schema',
        json_schema: {
          name: 'liliantech_question_batch',
          strict: true,
          schema: {
            type: 'object',
            additionalProperties: false,
            properties: {
              questions: {
                type: 'array',
                items: {
                  type: 'object',
                  additionalProperties: false,
                  properties: {
                    category: { type: 'string' },
                    topic: { type: 'string' },
                    region: { type: 'string' },
                    question: { type: 'string' },
                    options: { type: 'array', items: { type: 'string' }, minItems: 4, maxItems: 5 }
                  },
                  required: ['category','topic','region','question','options']
                }
              }
            },
            required: ['questions']
          }
        }
      }
    })
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`OpenAI question generation failed (${response.status}): ${detail.slice(0, 500)}`);
  }
  const data = await response.json();
  const content = data.choices?.[0]?.message?.content;
  if (!content) throw new Error('OpenAI returned no question data.');
  const parsed = JSON.parse(content);
  const created = [];
  for (const item of (parsed.questions || [])) {
    const question = String(item.question || '').trim();
    const options = normalizeQuestionOptions(item.options);
    if (!question || options.length < 4) continue;
    const hash = questionHash(question);
    const result = await pool.query(
      `INSERT INTO ai_questions (question_hash, category, topic, region, question, options, reward)
       VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (question_hash) DO NOTHING RETURNING id`,
      [hash, String(item.category || 'General').trim().slice(0,80), String(item.topic || 'General').trim().slice(0,180), String(item.region || 'Global').trim().slice(0,80), question, JSON.stringify(options), Number.isFinite(AI_QUESTION_REWARD) && AI_QUESTION_REWARD > 0 ? AI_QUESTION_REWARD : 0.001]
    );
    if (result.rows.length) created.push(result.rows[0].id);
  }
  return created.length;
}

async function ensureAiQuestionInventory(userId, minimum = AI_QUESTION_PREFETCH) {
  const count = await pool.query(`SELECT COUNT(*)::int AS count FROM ai_questions q WHERE q.active=TRUE`, []);
  if (Number(count.rows[0].count) >= minimum) return;
  if (!aiQuestionGenerationPromise) {
    aiQuestionGenerationPromise = generateAiQuestionBatch().finally(() => { aiQuestionGenerationPromise = null; });
  }
  await aiQuestionGenerationPromise;
}

async function getAiQuestionInventory(userId, limit = AI_QUESTION_PREFETCH) {
  await ensureAiQuestionInventory(userId, limit);
  const result = await pool.query(
    `SELECT q.id, q.category, q.topic, q.region, q.question, q.options, q.reward, q.created_at
     FROM ai_questions q
     WHERE q.active=TRUE
       AND NOT EXISTS (SELECT 1 FROM survey_activity a WHERE a.user_id=$1 AND a.survey_id=CONCAT('ai-', q.id))
     ORDER BY q.created_at ASC, q.id ASC
     LIMIT $2`,
    [userId, limit]
  );
  return result.rows.map(q => ({
    id: `ai-${q.id}`,
    title: q.question,
    question: q.question,
    options: Array.isArray(q.options) ? q.options : JSON.parse(q.options || '[]'),
    category: q.category,
    topic: q.topic,
    region: q.region,
    reward: Number(q.reward),
    minutes: 1,
    provider: 'LilianTech AI',
    providerId: 'liliantech-ai',
    source: 'ai',
    live: true
  }));
}

async function getAiQuestionById(surveyId) {
  const id = String(surveyId || '').replace(/^ai-/, '');
  if (!/^\d+$/.test(id)) return null;
  const result = await pool.query(`SELECT id, category, topic, region, question, options, reward FROM ai_questions WHERE id=$1 AND active=TRUE`, [Number(id)]);
  const q = result.rows[0];
  if (!q) return null;
  return {
    id: `ai-${q.id}`, title: q.question, question: q.question, options: Array.isArray(q.options) ? q.options : JSON.parse(q.options || '[]'),
    category: q.category, topic: q.topic, region: q.region, reward: Number(q.reward), minutes: 1, provider: 'LilianTech AI', providerId: 'liliantech-ai', source: 'ai', live: true
  };
}
function authRateLimit(req, res, next) {
  const key = String(req.ip || req.headers["x-forwarded-for"] || "unknown");
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
  const maxAttempts = 10;
  const entry = authAttempts.get(key);
  if (!entry || now - entry.startedAt >= windowMs) {
    authAttempts.set(key, { startedAt: now, count: 1 });
    return next();
  }
  if (entry.count >= maxAttempts) {
    res.set("Retry-After", String(Math.ceil((windowMs - (now - entry.startedAt)) / 1000)));
    return res.status(429).json({ error: "Too many authentication attempts. Please try again later." });
  }
  entry.count += 1;
  return next();
}

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: "Authentication required."
    });
  }

  next();
}

function getMinimumWithdrawal() {
  const value = Number(process.env.MIN_WITHDRAWAL || 25);
  return Number.isFinite(value) && value > 0 ? value : 25;
}

function getRewardShare(providerId = '') {
  const key = `${String(providerId).toUpperCase()}_REWARD_SHARE`;
  const value = Number(process.env[key] ?? process.env.REWARD_SHARE ?? 0.70);
  return Number.isFinite(value) && value > 0 && value <= 1 ? value : 0.70;
}

function calculateUserReward(providerId, publisherRevenueUsd, explicitUserReward = null) {
  const explicit = Number(explicitUserReward);
  if (Number.isFinite(explicit) && explicit >= 0) return Number(explicit.toFixed(2));
  const gross = Number(publisherRevenueUsd || 0);
  return Number((gross * getRewardShare(providerId)).toFixed(2));
}

function bitlabsPointsToUsd(points) {
  const rate = Number(process.env.BITLABS_POINTS_PER_USD || 0);
  const value = Number(points || 0);
  if (!Number.isFinite(rate) || rate <= 0 || !Number.isFinite(value) || value < 0) return 0;
  return Number((value / rate).toFixed(2));
}


function getTheoremReachExchangeRate() {
  const value = Number(process.env.THEOREMREACH_EXCHANGE_RATE || 100);
  return Number.isFinite(value) && value > 0 ? value : 100;
}

function theoremReachHashValid(req) {
  const secret = String(process.env.THEOREMREACH_SECRET_KEY || '').trim();
  if (!secret) return false;
  const raw = String(req.originalUrl || '/');
  const queryIndex = raw.indexOf('?');
  if (queryIndex < 0) return false;
  const basePath = raw.slice(0, queryIndex);
  const query = raw.slice(queryIndex + 1);
  const kept = query.split('&').filter(part => !part.toLowerCase().startsWith('hash='));
  const baseUrl = `${basePath}${kept.length ? `?${kept.join('&')}` : ''}`;
  const digest = crypto.createHmac('sha1', secret).update(baseUrl, 'utf8').digest('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  const supplied = String(req.query.hash || req.body?.hash || '');
  return supplied.length > 0 && crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(supplied));
}

function theoremReachEntryUrl(userId) {
  const template = String(process.env.THEOREMREACH_ENTRY_URL || '').trim();
  const apiKey = String(process.env.THEOREMREACH_API_KEY || '').trim();
  const transactionId = `lt-${userId}-${Date.now()}`;
  if (!template && !apiKey) return '';
  const source = template || 'https://theoremreach.com/respondent_entry/direct?api_key={api_key}&user_id={user_id}&transaction_id={transaction_id}';
  const replacements = {
    '{api_key}': encodeURIComponent(apiKey),
    '{user_id}': encodeURIComponent(String(userId)),
    '{external_transaction_id}': encodeURIComponent(transactionId),
    '{session_id}': encodeURIComponent(transactionId),
    '{transaction_id}': encodeURIComponent(transactionId)
  };
  return Object.entries(replacements).reduce((url,[token,value])=>url.split(token).join(value),source);
}

function getAdminEmails() {
  // Hard-coded authorization list. Render environment variables cannot expand
  // administrator access beyond these three accounts.
  return [
    'wachirabernard983@gmail.com',
    'stellawanjiku90@gmail.com',
    'wachirabernard193@gmail.com'
  ];
}

function getAdminIdentity() {
  const email = String(process.env.ADMIN_EMAIL || 'wachirabernard193@gmail.com').trim().toLowerCase();
  return {
    name: String(process.env.ADMIN_NAME || 'Bernard Wachira').trim(),
    email,
    emails: getAdminEmails()
  };
}

function isDesignatedAdmin(user) {
  // Administrator authorization is tied to the three hard-coded emails.
  // This intentionally does not depend on a stale database role value, so
  // accounts created before the admin-role update still receive admin access.
  return Boolean(
    user &&
    getAdminEmails().includes(String(user.email || '').trim().toLowerCase())
  );
}

function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Authentication required." });
  pool.query('SELECT full_name, email, role FROM users WHERE id = $1', [req.session.userId])
    .then(result => {
      const u = result.rows[0];
      if (!isDesignatedAdmin(u)) return res.status(403).json({ error: "Administrator access required." });
      next();
    })
    .catch(() => res.status(500).json({ error: "Unable to verify administrator access." }));
}

async function getUserById(id) {
  const result = await pool.query(
    `SELECT id, full_name, email, balance, role, phone, payment_method, payment_details, created_at
     FROM users
     WHERE id = $1`,
    [id]
  );

  const user = result.rows[0] || null;
  if (user && getAdminEmails().includes(String(user.email || '').trim().toLowerCase())) {
    user.role = 'admin';
  }
  return user;
}

app.get("/health", (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({
    status: "ok",
    app: "LilianTech"
  });
});

app.get("/api/me", async (req, res) => {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.set("Pragma", "no-cache");
  try {
    if (!req.session.userId) {
      return res.status(401).json({
        authenticated: false
      });
    }

    const user = await getUserById(req.session.userId);

    if (!user) {
      req.session.destroy(() => {});
      return res.status(401).json({
        authenticated: false
      });
    }

    res.json({
      authenticated: true,
      user
    });
  } catch (error) {
    console.error("Session check error:", error);

    res.status(500).json({
      error: "Unable to check login session."
    });
  }
});

app.get("/api/surveys", requireAuth, async (req, res) => {
  try {
    res.set("Cache-Control", "no-store");
    const user = await getUserById(req.session.userId);
    const cooldown = await pool.query(`SELECT next_survey_batch_at FROM users WHERE id=$1::integer`, [req.session.userId]);
    if (cooldown.rows[0]?.next_survey_batch_at) res.set("X-Survey-Next-Available", new Date(cooldown.rows[0].next_survey_batch_at).toISOString());
    res.json(await getAllSurveyInventory(user, req));
  } catch (error) {
    console.error("Survey inventory error:", error);
    res.status(503).json({ error: `Unable to load surveys right now. ${error.message || ''}`.trim() });
  }
});

app.get("/api/providers", requireAdmin, (req, res) => {
  res.sendFile(
    path.join(__dirname, "data", "providers.json")
  );
});

app.post("/api/register", authRateLimit, async (req, res) => {
  try {
    const { fullName, email, password, termsAccepted, privacyAccepted } = req.body;

    if (!fullName || !email || !password) {
      return res.status(400).json({
        error: "Full name, email and password are required."
      });
    }

    if (!termsAccepted || !privacyAccepted) {
      return res.status(400).json({ error: "Please accept the Terms of Service and Privacy Policy to create your account." });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: "Password must be at least 8 characters."
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const existingUser = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [normalizedEmail]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        error: "An account with this email already exists."
      });
    }

    const passwordHash = hashPassword(password);

    const isAdminEmail = getAdminEmails().includes(normalizedEmail);
    const result = await pool.query(
      `INSERT INTO users
       (full_name, email, password_hash, role, terms_accepted_at, privacy_accepted_at)
       VALUES ($1, $2, $3, $4, NOW(), NOW())
       RETURNING id, full_name, email, balance, role, created_at`,
      [fullName.trim(), normalizedEmail, passwordHash, isAdminEmail ? 'admin' : 'member']
    );

    res.status(201).json({
      message: "Account created successfully.",
      user: result.rows[0]
    });

  } catch (error) {
    console.error("Registration error:", error);

    res.status(500).json({
      error: "Unable to create account."
    });
  }
});

app.post("/api/login", authRateLimit, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Email and password are required."
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const result = await pool.query(
      `SELECT id, full_name, email, password_hash, balance
       FROM users
       WHERE email = $1`,
      [normalizedEmail]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const user = result.rows[0];

    if (!verifyPassword(password, user.password_hash)) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    await new Promise((resolve, reject) => {
      req.session.regenerate((error) => {
        if (error) return reject(error);

        req.session.userId = user.id;
        req.session.save((saveError) => {
          if (saveError) return reject(saveError);
          resolve();
        });
      });
    });

    res.json({
      message: "Login successful.",
      user: {
        id: user.id,
        full_name: user.full_name,
        email: user.email,
        balance: user.balance
      }
    });

  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      error: "Unable to log in."
    });
  }
});

app.post("/api/logout", (req, res) => {
  if (!req.session) {
    return res.json({ message: "Logged out successfully." });
  }

  req.session.destroy((error) => {
    if (error) {
      console.error("Logout error:", error);

      return res.status(500).json({
        error: "Unable to log out."
      });
    }

    res.clearCookie("liliantech.sid", {
      path: "/",
      httpOnly: true,
      secure: isProduction,
      sameSite: "lax"
    });

    res.json({
      message: "Logged out successfully."
    });
  });
});

app.get("/api/account", requireAuth, async (req, res) => {
  try {
    const user = await getUserById(req.session.userId);

    if (!user) {
      return res.status(401).json({
        error: "Account not found."
      });
    }

    res.json({ user });
  } catch (error) {
    console.error("Account error:", error);

    res.status(500).json({
      error: "Unable to load account."
    });
  }
});


async function generateAiProjectNames(count = 5) {
  const apiKey = String(process.env.OPENAI_API_KEY || '').trim();
  if (!apiKey) throw new Error('OPENAI_API_KEY is not configured.');
  const response = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: {'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json'},
    body: JSON.stringify({
      model: AI_QUESTION_MODEL,
      messages: [
        { role: 'system', content: 'Create short, memorable, abstract project names. Output only the requested JSON.' },
        { role: 'user', content: `Generate ${count} unique project names for a global opinion research platform. Names should feel like short project codenames (examples of the style only: Aether, Hedgehog), be one or two words, non-political, non-commercial, not existing company or product names, and not contain the words survey, research, LilianTech, AI, project, study, task, test or question.` }
      ],
      response_format: {type:'json_schema', json_schema:{name:'project_names', strict:true, schema:{type:'object',additionalProperties:false,properties:{names:{type:'array',items:{type:'string'},minItems:1,maxItems:20}},required:['names']}}}
    })
  });
  if (!response.ok) throw new Error(`OpenAI project-name generation failed (${response.status}).`);
  const data = await response.json();
  const content = data.choices?.[0]?.message?.content;
  if (!content) throw new Error('OpenAI returned no project names.');
  const parsed = JSON.parse(content);
  return [...new Set((parsed.names || []).map(x => String(x).trim()).filter(Boolean))];
}

const FALLBACK_PROJECT_NAMES = ['Aether','Hedgehog','Nimbus','Solace','Quill','Mosaic','Orbit','Ember','Harbor','Lumen','Cinder','Vertex','Meadow','Echo','Pioneer','Atlas','Clover','Sable','Nova','Drift'];

async function nextProjectName(userId) {
  const used = await pool.query('SELECT LOWER(title) AS title FROM ai_survey_bundles WHERE user_id=$1', [userId]);
  const usedSet = new Set(used.rows.map(r => String(r.title || '').toLowerCase()));
  let candidates = [];
  try { candidates = await generateAiProjectNames(8); } catch (e) { console.warn('AI project-name generation unavailable:', e.message); }
  candidates = [...candidates, ...FALLBACK_PROJECT_NAMES];
  const pick = candidates.find(name => !usedSet.has(String(name).toLowerCase()));
  return pick || `Project ${Date.now()}`;
}

async function ensureAiSurveyBundles(userId, minimum = AI_SURVEY_PREFETCH) {
  const existing = await pool.query(
    `SELECT COUNT(*)::int AS count FROM ai_survey_bundles
     WHERE user_id=$1 AND status IN ('available','in_progress')`, [userId]
  );
  if (Number(existing.rows[0].count) >= minimum) return;

  await ensureAiQuestionInventory(userId, Math.max(AI_QUESTION_PREFETCH, minimum * AI_SURVEY_SIZE));
  const used = await pool.query(
    `SELECT DISTINCT jsonb_array_elements_text(question_ids)::int AS question_id
     FROM ai_survey_bundles WHERE user_id=$1`, [userId]
  );
  const usedIds = used.rows.map(r => Number(r.question_id)).filter(Number.isFinite);
  const need = Math.max(0, (minimum - Number(existing.rows[0].count)) * AI_SURVEY_SIZE);
  const q = await pool.query(
    `SELECT id, category, reward FROM ai_questions
     WHERE active=TRUE ${usedIds.length ? 'AND id <> ALL($2::int[])' : ''}
     ORDER BY created_at ASC, id ASC LIMIT $1`,
    usedIds.length ? [need, usedIds] : [need]
  );

  for (let i = 0; i + AI_SURVEY_SIZE <= q.rows.length; i += AI_SURVEY_SIZE) {
    const chunk = q.rows.slice(i, i + AI_SURVEY_SIZE);
    const categories = [...new Set(chunk.map(x => x.category))];
    const category = categories.length === 1 ? categories[0] : 'Global Opinion';
    const rewardTotal = chunk.reduce((sum, x) => sum + Number(x.reward || AI_QUESTION_REWARD), 0);
    await pool.query(
      `INSERT INTO ai_survey_bundles (user_id,title,category,question_ids,reward_total)
       VALUES ($1,$2,$3,$4,$5)`,
      [userId, await nextProjectName(userId), category,
       JSON.stringify(chunk.map(x => Number(x.id))), rewardTotal]
    );
  }
}


function getNotificationEmailTransport() {
  if (!nodemailer) return null;
  const host=String(process.env.SMTP_HOST||'').trim();
  const user=String(process.env.SMTP_USER||'').trim();
  const pass=String(process.env.SMTP_PASS||'').trim();
  if(!host||!user||!pass) return null;
  return nodemailer.createTransport({host,port:Number(process.env.SMTP_PORT||587),secure:String(process.env.SMTP_SECURE||'false').toLowerCase()==='true',auth:{user,pass}});
}
function notificationFrom(){return String(process.env.NOTIFICATION_FROM||process.env.SMTP_USER||'notifications@liliantech.online').trim();}
async function sendNewSurveyNotifications(campaign, targetUserId=null) {
  const users=targetUserId
    ? await pool.query(`SELECT id,email,full_name FROM users WHERE id=$1 AND email IS NOT NULL`,[Number(targetUserId)])
    : await pool.query(`SELECT id,email,full_name FROM users WHERE email IS NOT NULL ORDER BY id`);
  const emailer=NOTIFICATION_EMAIL_ENABLED?getNotificationEmailTransport():null;
  const vapidPublic=String(process.env.VAPID_PUBLIC_KEY||'').trim();
  if(NOTIFICATION_PUSH_ENABLED && webpush && vapidPublic && process.env.VAPID_PRIVATE_KEY){
    try{webpush.setVapidDetails(String(process.env.VAPID_SUBJECT||'mailto:notifications@liliantech.online'),vapidPublic,String(process.env.VAPID_PRIVATE_KEY));}catch(e){console.warn('Push VAPID setup failed:',e.message);}
  }
  for(const u of users.rows){
    const subject=`New survey available: ${campaign.title}`;
    const text=`A new 10-question survey, ${campaign.title}, is now available on LilianTech. Reward: $${Number(campaign.reward_total).toFixed(3)}. Sign in to answer all 10 questions.`;
    if(emailer){try{await emailer.sendMail({from:notificationFrom(),to:u.email,subject,text,html:`<p>Hello ${String(u.full_name||'')},</p><p>A new 10-question survey, <strong>${campaign.title}</strong>, is now available on LilianTech.</p><p>Reward: <strong>$${Number(campaign.reward_total).toFixed(3)}</strong></p><p>Sign in to answer all 10 questions.</p><p><a href="https://liliantech.online/dashboard.html#surveys">Open LilianTech</a></p>`});await pool.query(`INSERT INTO notification_log(campaign_id,user_id,channel,status) VALUES($1,$2,'email','sent')`,[campaign.id,u.id]);}catch(e){await pool.query(`INSERT INTO notification_log(campaign_id,user_id,channel,status,detail) VALUES($1,$2,'email','failed',$3)`,[campaign.id,u.id,String(e.message).slice(0,500)]);}}
    if(NOTIFICATION_PUSH_ENABLED && webpush && vapidPublic && process.env.VAPID_PRIVATE_KEY){
      const subs=await pool.query(`SELECT id,endpoint,p256dh,auth FROM push_subscriptions WHERE user_id=$1`,[u.id]);
      for(const sub of subs.rows){try{await webpush.sendNotification({endpoint:sub.endpoint,keys:{p256dh:sub.p256dh,auth:sub.auth}},JSON.stringify({title:`New survey: ${campaign.title}`,body:`10 questions • Reward $${Number(campaign.reward_total).toFixed(3)}`,url:'/dashboard.html#surveys'}));await pool.query(`INSERT INTO notification_log(campaign_id,user_id,channel,status) VALUES($1,$2,'push','sent')`,[campaign.id,u.id]);}catch(e){if(e.statusCode===404||e.statusCode===410) await pool.query(`DELETE FROM push_subscriptions WHERE id=$1`,[sub.id]);}}
    }
  }
}
function broadcastSurveyEvent(payload){const data=`data: ${JSON.stringify(payload)}\n\n`;for(const res of notificationClients){try{res.write(data);}catch{notificationClients.delete(res);}}}
async function ensureGlobalSurveyBatch() {
  // Keep a healthy global seed of five surveys. Individual users receive a
  // fresh batch after completing their own five-survey batch; they do not wait
  // for 1,000 other people to finish the global inventory.
  const active = await pool.query(`SELECT COUNT(*)::int AS count FROM survey_campaigns WHERE status='active' AND owner_user_id IS NULL AND response_count < max_responses AND (expires_at IS NULL OR expires_at > NOW())`);
  if (Number(active.rows[0].count) < SURVEY_BATCH_SIZE) {
    await createSurveyCampaigns(SURVEY_BATCH_SIZE - Number(active.rows[0].count));
  }
}

async function getActiveCampaignsForUser(userId) {
  await assignAvailableCampaigns(userId, SURVEY_PREFETCH);
  const result=await pool.query(`SELECT c.id,c.title,c.category,c.reward_total,c.max_responses,c.response_count,c.status,c.created_at,a.status AS assignment_status,a.started_at,a.completed_at,
    jsonb_array_length(c.question_ids) AS question_count,
    COALESCE((SELECT COUNT(*) FROM jsonb_object_keys(COALESCE(a.answers,'{}'::jsonb))),0)::int AS answered_count
    FROM survey_assignments a JOIN survey_campaigns c ON c.id=a.campaign_id
    WHERE a.user_id=$1 AND a.status IN ('available','in_progress') AND c.status='active' AND (c.owner_user_id IS NULL OR c.owner_user_id=$1) AND (c.expires_at IS NULL OR c.expires_at>NOW())
    ORDER BY c.created_at ASC,c.id ASC`,[userId]);
  return result.rows.map(r=>({id:`campaign-${r.id}`,title:r.title,category:r.category,reward:Number(r.reward_total),questionCount:Number(r.question_count),answeredCount:Number(r.answered_count),remainingCount:Number(r.question_count)-Number(r.answered_count),status:r.assignment_status,startedAt:r.started_at,availableResponses:Math.max(0,Number(r.max_responses)-Number(r.response_count)),maxResponses:Number(r.max_responses),responseCount:Number(r.response_count),source:'ai'}));
}
async function assignAvailableCampaigns(userId, minimum=SURVEY_BATCH_SIZE){
  const uid=Number(userId);
  const userRow=await pool.query(`SELECT next_survey_batch_at FROM users WHERE id=$1::integer`,[uid]);
  if(!userRow.rows.length) return;
  const cooldown=userRow.rows[0].next_survey_batch_at;
  if(cooldown && new Date(cooldown).getTime()>Date.now()) return;

  const existing=await pool.query(`SELECT COUNT(*)::int AS count
    FROM survey_assignments a JOIN survey_campaigns c ON c.id=a.campaign_id
    WHERE a.user_id=$1::integer AND a.status IN ('available','in_progress')
      AND c.status='active' AND c.response_count<c.max_responses
      AND (c.expires_at IS NULL OR c.expires_at>NOW())
      AND (c.owner_user_id IS NULL OR c.owner_user_id=$1::integer)`,[uid]);
  const activeCount=Number(existing.rows[0].count);
  if (activeCount > 0) return;

  const completed=await pool.query(`SELECT COUNT(*)::int AS count FROM survey_assignments WHERE user_id=$1::integer AND status='completed'`,[uid]);
  const completedCount=Number(completed.rows[0].count);
  if (completedCount > 0 && completedCount % SURVEY_BATCH_SIZE !== 0) return;

  if (completedCount > 0) {
    // A completed batch must wait 30 minutes before the next five surveys are assigned.
    const due=await pool.query(`SELECT next_survey_batch_at FROM users WHERE id=$1::integer`,[uid]);
    if(due.rows[0]?.next_survey_batch_at && new Date(due.rows[0].next_survey_batch_at).getTime()>Date.now()) return;
    await createSurveyCampaigns(SURVEY_BATCH_SIZE, uid);
    await pool.query(`UPDATE users SET next_survey_batch_at=NULL WHERE id=$1::integer`,[uid]);
  } else {
    await ensureGlobalSurveyBatch();
  }

  const active=await pool.query(`SELECT c.id FROM survey_campaigns c
    WHERE c.status='active' AND c.response_count<c.max_responses
      AND (c.expires_at IS NULL OR c.expires_at>NOW())
      AND (c.owner_user_id IS NULL OR c.owner_user_id=$1::integer)
      AND NOT EXISTS(SELECT 1 FROM survey_assignments a WHERE a.campaign_id=c.id AND a.user_id=$1::integer)
    ORDER BY c.created_at ASC,c.id ASC LIMIT $2::integer`,[uid,Number(minimum)]);
  for(const r of active.rows){await pool.query(`INSERT INTO survey_assignments(campaign_id,user_id,status) VALUES($1::integer,$2::integer,'available') ON CONFLICT(campaign_id,user_id) DO NOTHING`,[Number(r.id),uid]);}
}
async function ensureUnusedSurveyQuestionInventory(requiredCount){
  const needed=Math.max(1,Number(requiredCount)||1);
  for(let attempt=0; attempt<6; attempt++){
    const unused=await pool.query(`
      SELECT COUNT(*)::int AS n
      FROM ai_questions q
      WHERE q.active=TRUE
        AND NOT EXISTS (
          SELECT 1 FROM survey_campaigns c
          CROSS JOIN LATERAL jsonb_array_elements_text(COALESCE(c.question_ids,'[]'::jsonb)) ids
          WHERE ids::int=q.id
        )
    `);
    if(Number(unused.rows[0]?.n||0)>=needed) return;
    const before=Number(unused.rows[0]?.n||0);
    const generated=await generateAiQuestionBatch();
    const after=await pool.query(`
      SELECT COUNT(*)::int AS n
      FROM ai_questions q
      WHERE q.active=TRUE
        AND NOT EXISTS (
          SELECT 1 FROM survey_campaigns c
          CROSS JOIN LATERAL jsonb_array_elements_text(COALESCE(c.question_ids,'[]'::jsonb)) ids
          WHERE ids::int=q.id
        )
    `);
    const available=Number(after.rows[0]?.n||0);
    if(generated<=0 && available<=before){
      throw new Error('Unable to generate enough new survey questions for the next survey batch.');
    }
  }
  throw new Error('Survey question inventory could not be replenished for the next batch.');
}

async function createSurveyCampaigns(count=1, notificationUserId=null){
  const needed=count*AI_SURVEY_SIZE;
  await ensureUnusedSurveyQuestionInventory(needed);
  const q=await pool.query(`
    SELECT q.id,q.category,q.reward
    FROM ai_questions q
    WHERE q.active=TRUE
      AND NOT EXISTS (
        SELECT 1 FROM survey_campaigns c
        CROSS JOIN LATERAL jsonb_array_elements_text(COALESCE(c.question_ids,'[]'::jsonb)) ids
        WHERE ids::int=q.id
      )
    ORDER BY q.created_at ASC,q.id ASC
    LIMIT $1
  `,[needed]);
  let made=[];
  for(let i=0;i+AI_SURVEY_SIZE<=q.rows.length && made.length<count;i+=AI_SURVEY_SIZE){
    const chunk=q.rows.slice(i,i+AI_SURVEY_SIZE);
    const cats=[...new Set(chunk.map(x=>x.category))];
    const category=cats.length===1?cats[0]:'Global Opinion';
    const rewardTotal=chunk.reduce((a,x)=>a+Number(x.reward||AI_QUESTION_REWARD),0);
    const title=await nextGlobalSurveyName();
    const ins=await pool.query(
      `INSERT INTO survey_campaigns(title,category,question_ids,reward_total,max_responses,status,owner_user_id)
       VALUES($1,$2,$3,$4,$5,'active',$6::integer)
       RETURNING id,title,category,reward_total,max_responses,response_count,owner_user_id`,
      [title,category,JSON.stringify(chunk.map(x=>Number(x.id))),rewardTotal,SURVEY_MAX_RESPONSES,notificationUserId?Number(notificationUserId):null]
    );
    made.push(ins.rows[0]);
    broadcastSurveyEvent({type:'new-survey',survey:{id:`campaign-${ins.rows[0].id}`,title:ins.rows[0].title}});
  }
  for(const c of made) sendNewSurveyNotifications(c,notificationUserId).catch(e=>console.warn('Notification dispatch failed:',e.message));
  return made;
}

function getWithdrawalMethods() {
  return [
    { id: 'PayPal', label: 'PayPal', currency: 'USD', mode: 'manual', speed: 'Administrator processing', fields: [
      { name: 'email', label: 'PayPal email', type: 'email', placeholder: 'you@example.com', required: true }
    ]},
    { id: 'Wise', label: 'Wise', currency: 'USD', mode: 'manual', speed: 'Administrator processing', fields: [
      { name: 'fullName', label: 'Name on Wise account', type: 'text', placeholder: 'Full name', required: true },
      { name: 'email', label: 'Wise account email', type: 'email', placeholder: 'you@example.com', required: true }
    ]},
    { id: 'Payoneer', label: 'Payoneer', currency: 'USD', mode: 'manual', speed: 'Administrator processing', fields: [
      { name: 'fullName', label: 'Name on Payoneer account', type: 'text', placeholder: 'Full name', required: true },
      { name: 'email', label: 'Payoneer account email', type: 'email', placeholder: 'you@example.com', required: true }
    ]},
    { id: 'Bank transfer', label: 'Bank transfer', currency: 'USD', mode: 'manual', speed: 'Administrator processing', fields: [
      { name: 'accountName', label: 'Account holder name', type: 'text', placeholder: 'Full name', required: true },
      { name: 'country', label: 'Bank country or region', type: 'text', placeholder: 'Country or region', required: true },
      { name: 'bankName', label: 'Bank name', type: 'text', placeholder: 'Bank name', required: true },
      { name: 'accountNumber', label: 'Account number / IBAN', type: 'text', placeholder: 'Account number or IBAN', required: true },
      { name: 'swift', label: 'SWIFT / BIC', type: 'text', placeholder: 'SWIFT or BIC', required: false },
      { name: 'currency', label: 'Payout currency', type: 'text', placeholder: 'e.g. USD, EUR, GBP', required: true }
    ]}
  ];
}

function parseDetails(details) { try { return JSON.parse(details); } catch { return { value: details }; } }

app.get('/api/earnings', requireAuth, async (req, res) => {
  try {
    const user = await getUserById(req.session.userId);
    if (!user) return res.status(401).json({error:'Account not found.'});
    const pending = await pool.query(`SELECT COALESCE(SUM(amount),0) AS amount FROM withdrawals WHERE user_id=$1 AND status IN ('pending','approved','processing')`, [req.session.userId]);
    const tx = await pool.query(`SELECT id,type,amount,description,reference_id,created_at FROM transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100`, [req.session.userId]);
    const completed = await pool.query(`SELECT COUNT(*)::int AS count FROM survey_assignments WHERE user_id=$1 AND status='completed'`, [req.session.userId]);
    const pendingAmount = Number(pending.rows[0].amount || 0);
    res.json({ total:Number(user.balance||0), pending:pendingAmount, available:Math.max(0,Number(user.balance||0)-pendingAmount), transactions:tx.rows, minimumWithdrawal:getMinimumWithdrawal(), completedSurveys:Number(completed.rows[0].count||0) });
  } catch(e) { console.error('Earnings error:',e); res.status(500).json({error:'Unable to load earnings.'}); }
});

app.get('/api/withdrawal-methods', requireAuth, async (req,res) => {
  res.set('Cache-Control','no-store');
  res.json({methods:getWithdrawalMethods(), minimumWithdrawal:getMinimumWithdrawal(), note:'Withdrawals are queued for administrator processing.'});
});

app.get('/api/withdrawals', requireAuth, async (req,res) => {
  try {
    const result=await pool.query(`SELECT id,amount,method,details,status,admin_note,provider_reference,payout_error,created_at,processed_at FROM withdrawals WHERE user_id=$1 ORDER BY created_at DESC`,[req.session.userId]);
    res.json({withdrawals:result.rows,minimumWithdrawal:getMinimumWithdrawal(),methods:getWithdrawalMethods()});
  } catch(e) { console.error('Withdrawals error:',e); res.status(500).json({error:'Unable to load withdrawals.'}); }
});

app.post('/api/withdrawals', requireAuth, async (req,res) => {
  const client=await pool.connect();
  try {
    const amount=Number(req.body.amount), method=String(req.body.method||'').trim();
    const detailsObj=req.body.details && typeof req.body.details==='object' ? req.body.details : {};
    const details=JSON.stringify(detailsObj), minimum=getMinimumWithdrawal();
    const methodConfig=getWithdrawalMethods().find(m=>m.id===method);
    if(!methodConfig) return res.status(400).json({error:'Select a supported withdrawal method.'});
    if(!Number.isFinite(amount)||amount<minimum) return res.status(400).json({error:`Minimum withdrawal is $${minimum.toFixed(2)}.`});
    for(const field of methodConfig.fields){ if(field.required && !String(detailsObj[field.name]||'').trim()) return res.status(400).json({error:`${field.label} is required.`}); }
    await client.query('BEGIN');
    const user=await client.query(`SELECT balance FROM users WHERE id=$1 FOR UPDATE`,[req.session.userId]);
    const pending=await client.query(`SELECT COALESCE(SUM(amount),0) AS amount FROM withdrawals WHERE user_id=$1 AND status IN ('pending','approved','processing')`,[req.session.userId]);
    const available=Number(user.rows[0]?.balance||0)-Number(pending.rows[0]?.amount||0);
    if(amount>available){await client.query('ROLLBACK');return res.status(400).json({error:'Insufficient available balance.'});}
    const result=await client.query(`INSERT INTO withdrawals(user_id,amount,method,details,status) VALUES($1,$2,$3,$4,'pending') RETURNING id,amount,method,details,status,created_at`,[req.session.userId,amount.toFixed(2),method,details]);
    await client.query('COMMIT');
    res.status(201).json({message:'Withdrawal request submitted and queued for administrator processing.',withdrawal:result.rows[0]});
  } catch(e){await client.query('ROLLBACK').catch(()=>{});console.error('Withdrawal submission error:',e);res.status(500).json({error:'Unable to submit withdrawal.'});}
  finally{client.release();}
});

app.put('/api/profile', requireAuth, async (req,res) => {
  try {
    const fullName=String(req.body.fullName||'').trim(), phone=String(req.body.phone||'').trim(), paymentMethod=String(req.body.paymentMethod||'').trim(), paymentDetails=String(req.body.paymentDetails||'').trim();
    if(!fullName) return res.status(400).json({error:'Full name is required.'});
    const current=await getUserById(req.session.userId);
    if(isDesignatedAdmin(current) && fullName !== current.full_name) return res.status(400).json({error:'Administrator name cannot be changed.'});
    const result=await pool.query(`UPDATE users SET full_name=$1,phone=$2,payment_method=$3,payment_details=$4 WHERE id=$5 RETURNING id,full_name,email,balance,role,phone,payment_method,payment_details,created_at`,[fullName,phone||null,paymentMethod||null,paymentDetails||null,req.session.userId]);
    res.json({message:'Profile updated.',user:result.rows[0]});
  } catch(e){console.error('Profile error:',e);res.status(500).json({error:'Unable to update profile.'});}
});

app.get('/api/admin/revenue', requireAdmin, async (req,res) => {
  try {
    const rewards=await pool.query(`SELECT COALESCE(SUM(amount),0) AS rewards FROM transactions WHERE type='earning'`);
    const pending=await pool.query(`SELECT COALESCE(SUM(amount),0) AS amount FROM withdrawals WHERE status IN ('pending','approved','processing')`);
    res.json({grossRevenue:0,memberRewards:Number(rewards.rows[0].rewards||0),platformMargin:0,providerEvents:0,pendingWithdrawalLiability:Number(pending.rows[0].amount||0),providers:[]});
  } catch(e){console.error('Admin revenue:',e);res.status(500).json({error:'Unable to load revenue dashboard.'});}
});

app.get('/api/admin/overview', requireAdmin, async (req,res) => {
  try {
    const [users,pending,surveys,rewards]=await Promise.all([
      pool.query(`SELECT COUNT(*)::int AS count FROM users`),
      pool.query(`SELECT COALESCE(SUM(amount),0) AS amount,COUNT(*)::int AS count FROM withdrawals WHERE status IN ('pending','approved','processing')`),
      pool.query(`SELECT COUNT(*)::int AS count FROM ai_survey_bundles WHERE status='completed'`),
      pool.query(`SELECT COALESCE(SUM(amount),0) AS amount FROM transactions WHERE type='earning'`)
    ]);
    res.json({users:users.rows[0].count,pendingWithdrawals:pending.rows[0].count,pendingAmount:Number(pending.rows[0].amount||0),completedSurveys:surveys.rows[0].count,providerSurveys:[],grossRevenue:0,memberRewards:Number(rewards.rows[0].amount||0),platformMargin:0});
  } catch(e){console.error('Admin overview:',e);res.status(500).json({error:'Unable to load admin overview.'});}
});

app.get('/api/admin/users', requireAdmin, async (req,res) => {
  try {
    const r=await pool.query(`
      SELECT
        u.id,u.full_name,u.email,u.balance,u.role,u.created_at,
        COALESCE((SELECT COUNT(*) FROM survey_assignments a WHERE a.user_id=u.id AND a.status='completed'),0)::int AS completed_surveys,
        COALESCE((SELECT SUM(t.amount) FROM transactions t WHERE t.user_id=u.id AND t.type='earning'),0) AS total_earnings,
        COALESCE((SELECT COUNT(*) FROM transactions t WHERE t.user_id=u.id AND t.type='earning'),0)::int AS earning_transactions,
        COALESCE((SELECT COUNT(*) FROM withdrawals w WHERE w.user_id=u.id),0)::int AS withdrawal_count
      FROM users u
      ORDER BY u.created_at DESC
      LIMIT 500
    `);
    res.json({users:r.rows.map(x=>({
      ...x,
      balance:Number(x.balance||0),
      completed_surveys:Number(x.completed_surveys||0),
      total_earnings:Number(x.total_earnings||0),
      earning_transactions:Number(x.earning_transactions||0),
      withdrawal_count:Number(x.withdrawal_count||0)
    }))});
  }
  catch(e){console.error('Admin users:',e);res.status(500).json({error:'Unable to load users.'});}
});

app.get('/api/admin/users/:id/activity', requireAdmin, async (req,res) => {
  try {
    const uid=Number(req.params.id);
    if(!Number.isInteger(uid)||uid<=0) return res.status(400).json({error:'Invalid user.'});
    const user=(await pool.query(`SELECT id,full_name,email,balance,role,created_at FROM users WHERE id=$1`,[uid])).rows[0];
    if(!user) return res.status(404).json({error:'User not found.'});
    const surveys=(await pool.query(`
      SELECT c.id,c.title,c.category,c.reward_total,a.status,a.started_at,a.completed_at
      FROM survey_assignments a JOIN survey_campaigns c ON c.id=a.campaign_id
      WHERE a.user_id=$1 ORDER BY COALESCE(a.completed_at,a.started_at,c.created_at) DESC
    `,[uid])).rows;
    const earnings=(await pool.query(`
      SELECT id,amount,description,reference_id,created_at
      FROM transactions WHERE user_id=$1 AND type='earning'
      ORDER BY created_at DESC
    `,[uid])).rows;
    res.json({user, surveys, earnings});
  } catch(e){console.error('Admin user activity:',e);res.status(500).json({error:'Unable to load user activity.'});}
});

app.get('/api/admin/withdrawals', requireAdmin, async (req,res) => {
  try { const r=await pool.query(`SELECT w.id,w.amount,w.method,w.details,w.status,w.admin_note,w.provider_reference,w.payout_error,w.created_at,w.processed_at,u.full_name,u.email FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY w.created_at DESC LIMIT 500`); res.json({withdrawals:r.rows}); }
  catch(e){console.error(e);res.status(500).json({error:'Unable to load withdrawals.'});}
});

app.post('/api/admin/withdrawals/:id/process', requireAdmin, async (req,res) => {
  const client=await pool.connect();
  try{
    const status=String(req.body.status||'').toLowerCase(),note=String(req.body.note||'').trim();
    if(!['approved','rejected','paid'].includes(status)) return res.status(400).json({error:'Status must be approved, rejected, or paid.'});
    await client.query('BEGIN');
    const wr=await client.query(`SELECT * FROM withdrawals WHERE id=$1 FOR UPDATE`,[req.params.id]);
    if(!wr.rows[0]){await client.query('ROLLBACK');return res.status(404).json({error:'Withdrawal not found.'});}
    const w=wr.rows[0];
    if(['paid','rejected'].includes(w.status)){await client.query('ROLLBACK');return res.status(400).json({error:'This withdrawal is already finalized.'});}
    if(status==='approved'&&w.status!=='pending'){await client.query('ROLLBACK');return res.status(400).json({error:'Only pending withdrawals can be approved.'});}
    if(status==='rejected'&&!['pending','approved'].includes(w.status)){await client.query('ROLLBACK');return res.status(400).json({error:'This withdrawal cannot be rejected in its current state.'});}
    if(status==='paid'&&!['approved','processing'].includes(w.status)){await client.query('ROLLBACK');return res.status(400).json({error:'A withdrawal must be approved before it can be marked paid.'});}
    if(status==='paid'){
      const user=await client.query(`SELECT balance FROM users WHERE id=$1 FOR UPDATE`,[w.user_id]);
      if(Number(user.rows[0].balance)<Number(w.amount)){await client.query('ROLLBACK');return res.status(400).json({error:'User no longer has enough balance to pay this withdrawal.'});}
      await client.query(`UPDATE users SET balance=balance-$1 WHERE id=$2`,[w.amount,w.user_id]);
      await client.query(`INSERT INTO transactions(user_id,type,amount,description,reference_id) VALUES($1,'withdrawal',$2,$3,$4)`,[w.user_id,-Number(w.amount),`Withdrawal paid via ${w.method}`,String(w.id)]);
    }
    await client.query(`UPDATE withdrawals SET status=$1,admin_note=$2,processed_at=NOW() WHERE id=$3`,[status,note||null,w.id]);
    await client.query('COMMIT');res.json({message:`Withdrawal marked ${status}.`});
  }catch(e){await client.query('ROLLBACK').catch(()=>{});console.error(e);res.status(500).json({error:'Unable to process withdrawal.'});}
  finally{client.release();}
});

async function releaseDueSurveyBatches(){
  const due=await pool.query(`
    SELECT id FROM users
    WHERE next_survey_batch_at IS NOT NULL AND next_survey_batch_at<=NOW()
    ORDER BY id
  `);
  for(const row of due.rows){
    const uid=Number(row.id);
    try{
      const active=await pool.query(`
        SELECT COUNT(*)::int AS count
        FROM survey_assignments a
        JOIN survey_campaigns c ON c.id=a.campaign_id
        WHERE a.user_id=$1::integer
          AND a.status IN ('available','in_progress')
          AND c.status='active'
          AND (c.expires_at IS NULL OR c.expires_at>NOW())
      `,[uid]);
      const completed=await pool.query(`
        SELECT COUNT(*)::int AS count FROM survey_assignments
        WHERE user_id=$1::integer AND status='completed'
      `,[uid]);
      if(Number(active.rows[0].count)>0 || Number(completed.rows[0].count)%SURVEY_BATCH_SIZE!==0) continue;

      const made=await createSurveyCampaigns(SURVEY_BATCH_SIZE,uid);
      if(made.length===SURVEY_BATCH_SIZE){
        await pool.query(`UPDATE users SET next_survey_batch_at=NULL WHERE id=$1::integer`,[uid]);
        console.log(`Released ${SURVEY_BATCH_SIZE} new surveys for user ${uid}.`);
      }else{
        console.warn(`Only ${made.length}/${SURVEY_BATCH_SIZE} surveys were created for user ${uid}; retrying on the next scheduler cycle.`);
      }
    }catch(e){
      console.warn(`Unable to release survey batch for user ${uid}:`,e.message);
    }
  }
}

app.get('/api/admin/provider-surveys', requireAdmin, async (req,res)=>res.json({surveys:[]}));
app.post('/api/admin/provider-surveys', requireAdmin, async (req,res)=>res.status(410).json({error:'External survey providers are disabled while LilianTech uses AI-generated surveys.'}));
app.get('/api/admin/providers', requireAdmin, async (req,res)=>res.json({providers:[]}));

app.get("/api/dashboard", requireAuth, async (req,res)=>{try{const user=await getUserById(req.session.userId);if(!user)return res.status(401).json({error:'Account not found.'});const rows=(await pool.query(`SELECT c.id,c.title,c.category,c.reward_total,c.status,c.created_at,c.expires_at,a.status AS assignment_status,a.started_at,a.completed_at FROM survey_assignments a JOIN survey_campaigns c ON c.id=a.campaign_id WHERE a.user_id=$1::integer ORDER BY c.created_at DESC`,[user.id])).rows;const active=rows.filter(x=>x.assignment_status!=='completed'&&x.status==='active');const available=active.filter(x=>x.assignment_status==='available').length;const inProgress=active.filter(x=>x.assignment_status==='in_progress').length;const completed=rows.filter(x=>x.assignment_status==='completed').length;res.set('Cache-Control','no-store');res.json({user:{...user,isAdmin:isDesignatedAdmin(user)},stats:{available,inProgress,completed,completedEarnings:rows.filter(x=>x.assignment_status==='completed').reduce((t,x)=>t+Number(x.reward_total||0),0)},activity:rows.map(x=>({survey_id:`campaign-${x.id}`,title:x.title,reward:Number(x.reward_total),status:x.assignment_status,started_at:x.started_at,completed_at:x.completed_at}))});}catch(e){console.error('Dashboard error:',e);res.status(500).json({error:'Unable to load dashboard.'});}});

app.post("/api/surveys/:surveyId/start", requireAuth, async (req,res)=>{
  try{const user=await getUserById(req.session.userId);const survey=await getSurveyById(req.params.surveyId,user,req);if(!survey)return res.status(404).json({error:'Survey not found.'});if(survey.status==='completed')return res.status(409).json({error:'This survey is already completed.'});await pool.query(`UPDATE survey_assignments SET status='in_progress',started_at=COALESCE(started_at,NOW()) WHERE campaign_id=$1::integer AND user_id=$2::integer`,[Number(String(req.params.surveyId).replace(/^campaign-/,'')),Number(user.id)]);survey.status='in_progress';res.json({message:'Survey opened.',...survey});}
  catch(e){console.error('Start survey error:',e);res.status(500).json({error:`Unable to open the survey. ${e.message||'Unknown server error.'}`});}
});
app.post("/api/surveys/:surveyId/submit", requireAuth, async (req,res)=>{
  const client=await pool.connect();
  try{
    const user=await getUserById(req.session.userId);const id=Number(String(req.params.surveyId).replace(/^campaign-/,''));if(!Number.isInteger(id)||id<=0)return res.status(400).json({error:'Invalid survey.'});
    const answers=req.body?.answers&&typeof req.body.answers==='object'?req.body.answers:{};
    await client.query('BEGIN');
    const c=await client.query(`SELECT c.*,a.status AS assignment_status,a.answers AS prior_answers FROM survey_campaigns c JOIN survey_assignments a ON a.campaign_id=c.id AND a.user_id=$2::integer WHERE c.id=$1::integer FOR UPDATE`,[id,user.id]);
    if(!c.rows.length){await client.query('ROLLBACK');return res.status(404).json({error:'Survey not found.'});}
    const row=c.rows[0];if(row.assignment_status==='completed'){await client.query('ROLLBACK');return res.status(409).json({error:'This survey has already been completed.'});}
    if(row.status!=='active' && row.assignment_status!=='in_progress'){await client.query('ROLLBACK');return res.status(409).json({error:'This survey is no longer available.'});}
    const ids=(Array.isArray(row.question_ids)?row.question_ids:JSON.parse(row.question_ids||'[]')).map(Number).filter(Number.isFinite);
    const qs=await client.query(`SELECT id,question,options,reward FROM ai_questions WHERE id=ANY($1::int[]) AND active=TRUE ORDER BY array_position($1::int[],id)`,[ids]);
    if(qs.rows.length!==ids.length){await client.query('ROLLBACK');return res.status(409).json({error:'This survey is incomplete and cannot be submitted.'});}
    const normalized={};let totalReward=0;
    for(const q of qs.rows){const a=String(answers[String(q.id)]??'').trim();const opts=Array.isArray(q.options)?q.options:JSON.parse(q.options||'[]');if(!a||!opts.includes(a)){await client.query('ROLLBACK');return res.status(400).json({error:`Please answer all ${ids.length} questions before submitting.`});}normalized[String(q.id)]=a;totalReward+=Number(q.reward||AI_QUESTION_REWARD);}
    if(Number(row.response_count)>=Number(row.max_responses)){await client.query('ROLLBACK');return res.status(409).json({error:'This survey has just reached its response limit. Please choose another survey.'});}
    await client.query(`UPDATE survey_assignments SET status='completed',answers=$1,completed_at=NOW() WHERE campaign_id=$2::integer AND user_id=$3::integer`,[JSON.stringify(normalized),id,Number(user.id)]);
    const updated=await client.query(`UPDATE survey_campaigns SET response_count=response_count+1,status=CASE WHEN response_count+1>=max_responses THEN 'closed' ELSE status END WHERE id=$1::integer RETURNING response_count,max_responses,status`,[id]);
    await client.query(`UPDATE users SET balance=balance+$1 WHERE id=$2`,[totalReward,user.id]);
    await client.query(`INSERT INTO transactions(user_id,type,amount,description,reference_id) VALUES($1,'earning',$2,$3,$4)`,[user.id,totalReward,`Completed ${row.title}`,`campaign-${id}`]);
    const batchProgress=await client.query(`SELECT COUNT(*)::int AS count FROM survey_assignments WHERE user_id=$1::integer AND status='completed'`,[Number(user.id)]);
    if(Number(batchProgress.rows[0].count)%SURVEY_BATCH_SIZE===0){
      await client.query(`UPDATE users SET next_survey_batch_at=NOW() + INTERVAL '30 minutes' WHERE id=$1::integer`,[Number(user.id)]);
    }
    await client.query('COMMIT');
    const u=updated.rows[0];broadcastSurveyEvent({type:'survey-updated',surveyId:`campaign-${id}`,responseCount:Number(u.response_count),maxResponses:Number(u.max_responses),closed:u.status==='closed'});
    res.json({message:'Survey completed successfully!',status:'survey_completed',reward:totalReward,remainingQuestions:0,surveyCompleted:true});
  }catch(e){await client.query('ROLLBACK').catch(()=>{});console.error('Submit survey error:',e);res.status(500).json({error:`Unable to submit the survey. ${e.message||'Unknown server error.'}`});}finally{client.release();}
});
app.get('/api/surveys/stream', requireAuth, async (req,res)=>{res.set({'Content-Type':'text/event-stream','Cache-Control':'no-cache, no-transform','Connection':'keep-alive'});res.flushHeaders?.();res.write(`data: ${JSON.stringify({type:'connected'})}\n\n`);notificationClients.add(res);const timer=setInterval(()=>{try{res.write(': ping\\n\\n')}catch{}},25000);req.on('close',()=>{clearInterval(timer);notificationClients.delete(res);});});
app.get('/api/notifications/config', requireAuth, (req,res)=>res.json({pushEnabled:Boolean(NOTIFICATION_PUSH_ENABLED&&webpush&&process.env.VAPID_PUBLIC_KEY&&process.env.VAPID_PRIVATE_KEY),publicKey:String(process.env.VAPID_PUBLIC_KEY||'')}));
app.post('/api/notifications/push/subscribe', requireAuth, async (req,res)=>{try{const s=req.body||{};if(!s.endpoint||!s.keys?.p256dh||!s.keys?.auth)return res.status(400).json({error:'Invalid push subscription.'});await pool.query(`INSERT INTO push_subscriptions(user_id,endpoint,p256dh,auth,updated_at) VALUES($1,$2,$3,$4,NOW()) ON CONFLICT(endpoint) DO UPDATE SET user_id=EXCLUDED.user_id,p256dh=EXCLUDED.p256dh,auth=EXCLUDED.auth,updated_at=NOW()`,[req.session.userId,s.endpoint,s.keys.p256dh,s.keys.auth]);res.json({message:'Push notifications enabled.'});}catch(e){console.error('Push subscribe:',e);res.status(500).json({error:'Unable to enable push notifications.'});}});
app.post('/api/notifications/push/unsubscribe', requireAuth, async (req,res)=>{try{if(req.body?.endpoint)await pool.query(`DELETE FROM push_subscriptions WHERE user_id=$1 AND endpoint=$2`,[req.session.userId,req.body.endpoint]);res.json({message:'Push notifications disabled.'});}catch(e){res.status(500).json({error:'Unable to disable push notifications.'});}});


(async () => {
  try {
    await initializeDatabase();
    releaseDueSurveyBatches().catch(e => console.warn('Initial survey batch release check:', e.message));
    setInterval(() => releaseDueSurveyBatches().catch(e => console.warn('Survey batch release check:', e.message)), 60 * 1000);
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`LilianTech listening on port ${PORT}`);
    });
  } catch (error) {
    console.error('Fatal startup error:', error);
    process.exit(1);
  }
})();
