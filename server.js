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
    const result = await pool.query('SELECT full_name, email, role FROM users WHERE id=$1', [req.session.userId]);
    if (!isDesignatedAdmin(result.rows[0])) {
      return res.status(403).send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access denied — LilianTech</title><link rel="stylesheet" href="/styles.css"></head><body><main class="section"><div class="container card feature" style="max-width:560px"><div class="brand">Lilian<span>Tech</span></div><h1>Access denied</h1><p class="muted">The administration area is restricted to the designated LilianTech administrator.</p><a class="button primary" href="/dashboard.html">Back to dashboard</a></div></main></body></html>`);
    }
    return res.sendFile(path.join(__dirname, "public", "admin.html"));
  } catch (error) {
    console.error("Admin page access check failed:", error);
    return res.status(500).send("Unable to verify administrator access.");
  }
});

app.use(express.static(path.join(__dirname, "public")));

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      full_name VARCHAR(120) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      balance NUMERIC(12,2) NOT NULL DEFAULT 0.00,
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
      reward NUMERIC(12,2) NOT NULL DEFAULT 0.00,
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
      reward NUMERIC(14,6) NOT NULL DEFAULT 0.005000,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
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
      amount NUMERIC(12,2) NOT NULL,
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
  await pool.query(`ALTER TABLE users ALTER COLUMN balance TYPE NUMERIC(14,6)`);
  await pool.query(`ALTER TABLE transactions ALTER COLUMN amount TYPE NUMERIC(14,6)`);
  await pool.query(`ALTER TABLE survey_activity ALTER COLUMN reward TYPE NUMERIC(14,6)`);

  // One-time cleanup of development/demo artifacts from earlier builds.
  await pool.query(`DELETE FROM provider_surveys WHERE LOWER(provider_id) IN ('demo','test','local','mock') OR LOWER(title) LIKE '%demo%' OR LOWER(title) LIKE '%test survey%'`);
  await pool.query(`DELETE FROM survey_activity WHERE LOWER(survey_id) LIKE 'demo-%' OR LOWER(survey_id) LIKE 'test-%' OR LOWER(survey_id) LIKE 'local-%' OR LOWER(title) LIKE '%demo%' OR LOWER(title) LIKE '%test survey%'`);
  await pool.query(`DELETE FROM transactions WHERE LOWER(description) LIKE '%demo%' OR LOWER(description) LIKE '%test earning%' OR LOWER(description) LIKE '%test survey%'`);
  await pool.query(`DELETE FROM withdrawals WHERE LOWER(details) LIKE '%demo%' OR LOWER(details) LIKE '%test%'`);
  await pool.query(`DELETE FROM provider_transactions WHERE LOWER(COALESCE(raw_payload::text,'')) LIKE '%demo%' OR LOWER(COALESCE(raw_payload::text,'')) LIKE '%test%'`);
  await pool.query(`UPDATE users u SET balance = COALESCE((SELECT SUM(t.amount) FROM transactions t WHERE t.user_id=u.id), 0)`);

  const { email: adminEmail, name: adminName } = getAdminIdentity();
  await pool.query(`UPDATE users SET role = CASE WHEN LOWER(email)=$1 AND full_name=$2 THEN 'admin' ELSE 'member' END`, [adminEmail, adminName]);
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
const AI_QUESTION_REWARD = Number(process.env.AI_QUESTION_REWARD || 0.005);
const AI_QUESTION_BATCH_SIZE = Math.max(5, Math.min(25, Number(process.env.AI_QUESTION_BATCH_SIZE || 15)));
const AI_QUESTION_PREFETCH = Math.max(5, Math.min(25, Number(process.env.AI_QUESTION_PREFETCH || 10)));

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
        { role: 'user', content: prompt }
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
      [hash, String(item.category || 'General').trim().slice(0,80), String(item.topic || 'General').trim().slice(0,180), String(item.region || 'Global').trim().slice(0,80), question, JSON.stringify(options), Number.isFinite(AI_QUESTION_REWARD) && AI_QUESTION_REWARD > 0 ? AI_QUESTION_REWARD : 0.005]
    );
    if (result.rows.length) created.push(result.rows[0].id);
  }
  return created.length;
}

async function ensureAiQuestionInventory(userId, minimum = AI_QUESTION_PREFETCH) {
  const count = await pool.query(`SELECT COUNT(*)::int AS count FROM ai_questions q WHERE q.active=TRUE AND NOT EXISTS (SELECT 1 FROM survey_activity a WHERE a.user_id=$1 AND a.survey_id=CONCAT('ai-', q.id))`, [userId]);
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

function getAdminIdentity() {
  return {
    name: String(process.env.ADMIN_NAME || "Bernard Wachira").trim(),
    email: String(process.env.ADMIN_EMAIL || "wachirabernard193@gmail.com").trim().toLowerCase()
  };
}

function isDesignatedAdmin(user) {
  const admin = getAdminIdentity();
  return Boolean(
    user &&
    user.role === "admin" &&
    user.full_name === admin.name &&
    String(user.email || "").toLowerCase() === admin.email
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

  return result.rows[0] || null;
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
    res.json(await getAllSurveyInventory(user, req));
  } catch (error) {
    console.error("Survey inventory error:", error);
    res.status(500).json({ error: "Unable to load surveys." });
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
    const adminIdentity = getAdminIdentity();
    if (normalizedEmail === adminIdentity.email && fullName.trim() !== adminIdentity.name) {
      return res.status(403).json({ error: "That administrator email is reserved for the designated administrator." });
    }
    if (normalizedEmail === adminIdentity.email) {
      return res.status(403).json({ error: "The designated administrator account must be provisioned separately." });
    }

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

    const result = await pool.query(
      `INSERT INTO users
       (full_name, email, password_hash, terms_accepted_at, privacy_accepted_at)
       VALUES ($1, $2, $3, NOW(), NOW())
       RETURNING id, full_name, email, balance, created_at`,
      [fullName.trim(), normalizedEmail, passwordHash]
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


async function getAllSurveyInventory(user = null, req = null) {
  if (!user) return [];
  try {
    return await getAiQuestionInventory(user.id, AI_QUESTION_PREFETCH);
  } catch (error) {
    console.error('AI question inventory:', error);
    return [];
  }
}

async function getSurveyById(surveyId, user = null, req = null) {
  if (!user) return null;
  return await getAiQuestionById(surveyId);
}

app.get("/api/dashboard", requireAuth, async (req, res) => {
  try {
    const user = await getUserById(req.session.userId);

    if (!user) {
      return res.status(401).json({ error: "Account not found." });
    }

    const activity = await pool.query(
      `SELECT survey_id, title, reward, status, started_at, completed_at
       FROM survey_activity
       WHERE user_id = $1
       ORDER BY COALESCE(completed_at, started_at) DESC`,
      [req.session.userId]
    );

    const completed = activity.rows.filter((item) => item.status === "completed");
    const inProgress = activity.rows.filter((item) => item.status === "in_progress");
    const completedEarnings = completed.reduce(
      (total, item) => total + Number(item.reward || 0),
      0
    );

    res.set("Cache-Control", "no-store");
    res.json({
      user,
      stats: {
        available: (await getAllSurveyInventory(user, req)).filter(
          (survey) => !activity.rows.some((item) => item.survey_id === survey.id)
        ).length,
        inProgress: inProgress.length,
        completed: completed.length,
        completedEarnings
      },
      activity: activity.rows
    });
  } catch (error) {
    console.error("Dashboard error:", error);
    res.status(500).json({ error: "Unable to load dashboard." });
  }
});

app.post("/api/surveys/:surveyId/start", requireAuth, async (req, res) => {
  try {
    const survey = await getSurveyById(req.params.surveyId, await getUserById(req.session.userId), req);
    if (!survey) return res.status(404).json({ error: "Question not found or no longer available." });

    const existing = await pool.query(`SELECT status FROM survey_activity WHERE user_id=$1 AND survey_id=$2`, [req.session.userId, survey.id]);
    if (existing.rows.length && existing.rows[0].status === 'completed') {
      return res.status(409).json({ error: "You have already answered this question." });
    }
    if (!existing.rows.length) {
      await pool.query(
        `INSERT INTO survey_activity (user_id, survey_id, title, reward, status) VALUES ($1,$2,$3,$4,'in_progress')`,
        [req.session.userId, survey.id, survey.title, survey.reward]
      );
    }

    res.status(201).json({
      message: "Question ready.",
      status: "in_progress",
      question: survey.question,
      options: survey.options,
      category: survey.category,
      topic: survey.topic,
      reward: survey.reward
    });
  } catch (error) {
    console.error("Start AI question error:", error);
    res.status(500).json({ error: "Unable to start the question." });
  }
});

app.post("/api/surveys/:surveyId/complete", requireAuth, async (req, res) => {
  const client = await pool.connect();
  try {
    const survey = await getSurveyById(req.params.surveyId, await getUserById(req.session.userId), req);
    if (!survey) return res.status(404).json({ error: "Question not found." });

    const answer = String(req.body?.answer || '').trim();
    if (!answer || !survey.options.includes(answer)) {
      return res.status(400).json({ error: "Please select one of the available answers." });
    }

    await client.query('BEGIN');
    const activity = await client.query(
      `SELECT id, reward, status FROM survey_activity WHERE user_id=$1 AND survey_id=$2 FOR UPDATE`,
      [req.session.userId, survey.id]
    );
    if (!activity.rows.length) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: "Start the question before answering it." });
    }
    if (activity.rows[0].status === 'completed') {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: "This question has already been answered." });
    }

    const reward = Number(activity.rows[0].reward || survey.reward || 0);
    await client.query(`UPDATE survey_activity SET status='completed', completed_at=NOW() WHERE id=$1`, [activity.rows[0].id]);
    await client.query(`UPDATE users SET balance=balance+$1 WHERE id=$2`, [reward, req.session.userId]);
    await client.query(
      `INSERT INTO transactions (user_id, type, amount, description, reference_id) VALUES ($1,'earning',$2,$3,$4)`,
      [req.session.userId, reward, `Answered ${survey.category}: ${survey.title}`, survey.id]
    );
    await client.query('COMMIT');

    res.json({ message: "Answer recorded and reward added.", status: "completed", reward, answer });
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    console.error("Complete AI question error:", error);
    res.status(500).json({ error: "Unable to record your answer." });
  } finally {
    client.release();
  }
});

// ---------- Provider callbacks ----------

// ---------- TheoremReach publisher integration ----------
// Rewards are credited only from a verified server-side callback. The entry URL is
// provider-configured and kept server-side so credentials and user identifiers are
// not exposed as application secrets in the frontend.
app.get('/api/providers/theoremreach/entry', requireAuth, async (req, res) => {
  const url = theoremReachEntryUrl(req.session.userId);
  if (!url) return res.status(503).json({ error: 'TheoremReach live survey entry is not configured yet.' });
  return res.redirect(url);
});

app.all('/api/providers/theoremreach/reward', async (req, res) => {
  try {
    if (String(req.query.debug || req.body?.debug || '') === 'true') return res.status(200).send('OK');
    if (!theoremReachHashValid(req)) return res.status(403).send('Invalid signature');

    const q = Object.assign({}, req.query || {}, req.body || {});
    const txId = String(q.tx_id || '').trim();
    const rawUserId = String(q.user_id || '').trim();
    const reversal = String(q.reversal || '').toLowerCase() === 'true';
    if (!txId || !rawUserId || !/^\d+$/.test(rawUserId)) return res.status(400).send('Missing transaction or user');

    const userId = Number(rawUserId);
    const appCurrencyReward = Number(q.reward || 0);
    const grossUsd = Number(q.currency || q.reward_amount_in_dollars || 0);
    const rewardUsd = Number((appCurrencyReward / getTheoremReachExchangeRate()).toFixed(2));
    const effectiveReward = reversal ? -Math.abs(rewardUsd) : rewardUsd;
    const publisherRevenue = Number.isFinite(grossUsd) ? grossUsd : 0;
    const margin = Number((publisherRevenue - rewardUsd).toFixed(2));
    const surveyId = String(q.offer_id || q.campaign_id || '').trim();

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const user = await client.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [userId]);
      if (!user.rows.length) { await client.query('ROLLBACK'); return res.status(404).send('Unknown user'); }

      const existing = await client.query(
        `SELECT id,status,user_reward FROM provider_transactions WHERE provider_id=$1 AND transaction_id=$2 FOR UPDATE`,
        ['theoremreach', txId]
      );
      if (existing.rows.length) {
        if (reversal && existing.rows[0].status !== 'reversed') {
          const prior = Number(existing.rows[0].user_reward || 0);
          await client.query(`UPDATE provider_transactions SET status='reversed', user_reward=0, margin=0, raw_payload=$1 WHERE id=$2`, [q, existing.rows[0].id]);
          if (prior > 0) {
            await client.query(`UPDATE users SET balance=GREATEST(0,balance-$1) WHERE id=$2`, [prior, userId]);
            await client.query(`INSERT INTO transactions (user_id,type,amount,description,reference_id) VALUES ($1,'reversal',$2,$3,$4)`, [userId, -prior, `TheoremReach survey reversal ${txId}`, txId]);
          }
        }
        await client.query('COMMIT');
        return res.status(200).send('OK');
      }

      const status = reversal ? 'reversed' : 'completed';
      await client.query(
        `INSERT INTO provider_transactions (provider_id,transaction_id,user_id,survey_id,status,amount,publisher_revenue,user_reward,margin,raw_payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        ['theoremreach', txId, userId, surveyId, status, Math.abs(effectiveReward), publisherRevenue, reversal ? 0 : rewardUsd, reversal ? 0 : margin, q]
      );
      if (!reversal && rewardUsd > 0) {
        await client.query(`UPDATE users SET balance=balance+$1 WHERE id=$2`, [rewardUsd, userId]);
        await client.query(`INSERT INTO transactions (user_id,type,amount,description,reference_id) VALUES ($1,'earning',$2,$3,$4)`, [userId, rewardUsd, `TheoremReach survey ${txId}`, txId]);
        if (surveyId) await client.query(`UPDATE survey_activity SET status='completed',completed_at=NOW(),reward=$1 WHERE user_id=$2 AND survey_id=$3 AND status <> 'completed'`, [rewardUsd, userId, `theoremreach-${surveyId}`]);
      }
      await client.query('COMMIT');
      return res.status(200).send('OK');
    } catch (e) {
      await client.query('ROLLBACK').catch(()=>{});
      throw e;
    } finally { client.release(); }
  } catch (error) {
    console.error('TheoremReach callback error:', error);
    return res.status(500).send('Callback processing failed');
  }
});

// CPX callback. Keep the provider secret server-side and require a valid signature
// before any wallet credit is created.
app.all('/api/providers/cpx/postback', async (req, res) => {
  try {
    if (!process.env.CPX_SECURE_HASH) return res.status(503).send('CPX secure hash not configured');
    const q = { ...req.query, ...req.body };
    const status = String(q.status || '').trim();
    const transactionId = String(q.trans_id || q.transaction_id || '').trim();
    const userId = String(q.user_id || q.subid || q.ext_user_id || '').trim();
    const publisherRevenue = Number(q.payout_publisher_usd ?? q.publisher_payout_usd ?? q.amount_usd ?? q.amount ?? 0);
    const explicitUserReward = Number(q.user_reward_usd ?? q.reward_usd ?? q.payout_usd);
    const calculatedReward = calculateUserReward('cpx', publisherRevenue, Number.isFinite(explicitUserReward) ? explicitUserReward : null);
    const secureHash = String(q.secure_hash || '').trim().toLowerCase();
    if (!transactionId || !userId || !/^\d+$/.test(userId) || !Number.isFinite(publisherRevenue) || publisherRevenue < 0 || !secureHash) return res.status(400).send('invalid');
    const expected = crypto.createHash('md5').update(`${transactionId}-${process.env.CPX_SECURE_HASH}`).digest('hex');
    if (secureHash.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(secureHash), Buffer.from(expected))) return res.status(403).send('invalid signature');
    const numericUserId = Number(userId);
    const user = await pool.query('SELECT id FROM users WHERE id=$1', [numericUserId]);
    if (!user.rows[0]) return res.status(404).send('user not found');
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const existing = await client.query(`SELECT id,status,COALESCE(user_reward,amount,0) AS user_reward FROM provider_transactions WHERE provider_id=$1 AND transaction_id=$2 FOR UPDATE`, ['cpx', transactionId]);
      if (existing.rows[0]) {
        const prior = existing.rows[0];
        if (status === '2' && prior.status !== '2') {
          const reversal = Number(prior.user_reward || 0);
          if (reversal > 0) {
            await client.query('UPDATE users SET balance=balance-$1 WHERE id=$2', [reversal, numericUserId]);
            await client.query(`INSERT INTO transactions (user_id,type,amount,description,reference_id) VALUES ($1,'adjustment',$2,$3,$4)`, [numericUserId, -reversal, `CPX Research reversal ${transactionId}`, transactionId]);
          }
          await client.query(`UPDATE provider_transactions SET status='2' WHERE id=$1`, [prior.id]);
        }
        await client.query('COMMIT');
        return res.status(200).send('ok');
      }
      const surveyId = String(q.offer_id || q.survey_id || '');
      const userReward = status === '1' ? calculatedReward : 0;
      const margin = Number((publisherRevenue - userReward).toFixed(2));
      await client.query(`INSERT INTO provider_transactions (provider_id,transaction_id,user_id,survey_id,status,amount,publisher_revenue,user_reward,margin,raw_payload) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, ['cpx', transactionId, numericUserId, surveyId, status, userReward, publisherRevenue, userReward, margin, q]);
      if (status === '1' && userReward > 0) {
        await client.query('UPDATE users SET balance=balance+$1 WHERE id=$2', [userReward, numericUserId]);
        if (surveyId) await client.query(`UPDATE survey_activity SET status='completed',completed_at=NOW(),reward=$1 WHERE user_id=$2 AND survey_id=$3 AND status <> 'completed'`, [userReward, numericUserId, `cpx-${surveyId}`]);
        await client.query(`INSERT INTO transactions (user_id,type,amount,description,reference_id) VALUES ($1,'earning',$2,$3,$4)`, [numericUserId, userReward, `CPX Research survey ${transactionId}`, transactionId]);
      }
      await client.query('COMMIT');
      return res.status(200).send('ok');
    } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; } finally { client.release(); }
  } catch (e) { console.error('CPX callback:', e); return res.status(500).send('error'); }
});

// BitLabs S2S callback. BitLabs documents an HMAC-SHA1 hash over the complete
// callback URL. Do not credit anything until the app secret is configured.
app.all('/api/providers/bitlabs/callback', async (req, res) => {
  try {
    const secret = process.env.BITLABS_APP_SECRET;
    if (!secret) return res.status(503).send('BitLabs callback secret not configured');

    const rawUrl = `${req.protocol}://${req.get('host')}${req.originalUrl}`;
    const unsignedUrl = rawUrl.replace(/([?&])hash=[^&]*/i, '$1').replace(/[?&]$/, '');
    const suppliedHash = String(req.query.hash || req.body?.hash || '').trim().toLowerCase();
    const expectedHash = crypto.createHmac('sha1', secret).update(unsignedUrl).digest('hex');
    if (!suppliedHash || suppliedHash.length !== expectedHash.length || !crypto.timingSafeEqual(Buffer.from(suppliedHash), Buffer.from(expectedHash))) {
      return res.status(403).send('invalid signature');
    }

    const userId = String(req.query.uid || req.body?.uid || '').trim();
    const transactionId = String(req.query.tx || req.query.transaction_id || req.body?.tx || req.body?.transaction_id || '').trim();
    const activityType = String(req.query.activity_type || req.body?.activity_type || '').toUpperCase();
    const publisherRevenue = Number(req.query.raw || req.query.revenue_usd || req.body?.raw || req.body?.revenue_usd || req.query.usd || req.body?.usd || 0);
    const explicitUserReward = Number(req.query.reward_usd || req.body?.reward_usd);
    const amountUsd = calculateUserReward('bitlabs', publisherRevenue, Number.isFinite(explicitUserReward) ? explicitUserReward : null);
    if (!/^\d+$/.test(userId) || !transactionId || !Number.isFinite(amountUsd) || amountUsd < 0) return res.status(400).send('invalid');

    const numericUserId = Number(userId);
    const user = await pool.query('SELECT id FROM users WHERE id=$1', [numericUserId]);
    if (!user.rows[0]) return res.status(404).send('user not found');

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const exists = await client.query(
        'SELECT id FROM provider_transactions WHERE provider_id=$1 AND transaction_id=$2 FOR UPDATE',
        ['bitlabs', transactionId]
      );
      if (exists.rows[0]) {
        if (['REVERSAL','CHARGEBACK','REJECTED'].includes(activityType) && exists.rows[0].status !== activityType) {
          const prior = await client.query(`SELECT COALESCE(user_reward,amount,0) AS user_reward FROM provider_transactions WHERE id=$1 FOR UPDATE`, [exists.rows[0].id]);
          const reversal = Number(prior.rows[0]?.user_reward || 0);
          if (reversal > 0) {
            await client.query('UPDATE users SET balance=balance-$1 WHERE id=$2', [reversal, numericUserId]);
            await client.query(`INSERT INTO transactions (user_id,type,amount,description,reference_id) VALUES ($1,'adjustment',$2,$3,$4)`, [numericUserId, -reversal, `BitLabs reversal ${transactionId}`, transactionId]);
          }
          await client.query(`UPDATE provider_transactions SET status=$1 WHERE id=$2`, [activityType, exists.rows[0].id]);
        }
        await client.query('COMMIT');
        return res.status(200).send('ok');
      }
      const userReward = (activityType === 'COMPLETE' || activityType === 'RECONCILIATION') ? amountUsd : 0;
      const margin = Number((publisherRevenue - userReward).toFixed(2));
      await client.query(
        `INSERT INTO provider_transactions (provider_id,transaction_id,user_id,survey_id,status,amount,publisher_revenue,user_reward,margin,raw_payload)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
        ['bitlabs', transactionId, numericUserId, String(req.query.survey_id || req.body?.survey_id || ''), activityType || 'UNKNOWN', userReward, publisherRevenue, userReward, margin, { query: req.query, body: req.body }]
      );
      if (userReward > 0) {
        await client.query('UPDATE users SET balance=balance+$1 WHERE id=$2', [userReward, numericUserId]);
        await client.query(
          `INSERT INTO transactions (user_id,type,amount,description,reference_id)
           VALUES ($1,'earning',$2,$3,$4)`,
          [numericUserId, amountUsd, `BitLabs survey ${transactionId}`, transactionId]
        );
      }
      await client.query('COMMIT');
      return res.status(200).send('ok');
    } catch (e) {
      await client.query('ROLLBACK').catch(() => {});
      throw e;
    } finally {
      client.release();
    }
  } catch (e) {
    console.error('BitLabs callback:', e);
    return res.status(500).send('error');
  }
});

// ---------- Payout providers ----------
function payoutMode(method) {
  if (method === 'PayPal') return process.env.PAYPAL_CLIENT_ID && process.env.PAYPAL_CLIENT_SECRET && process.env.PAYPAL_SENDER_EMAIL ? 'automatic' : 'manual';
  if (method === 'Wise') return process.env.WISE_API_TOKEN ? 'automatic' : 'manual';
  if (method === 'Payoneer') return process.env.PAYONEER_API_TOKEN ? 'automatic' : 'manual';
  return 'manual';
}

function getWithdrawalMethods() {
  return [
    { id: 'PayPal', label: 'PayPal', currency: 'USD', mode: payoutMode('PayPal'), speed: 'Fast', fields: [
      { name: 'email', label: 'PayPal email', type: 'email', placeholder: 'you@example.com', required: true }
    ]},
    { id: 'Wise', label: 'Wise', currency: 'USD', mode: payoutMode('Wise'), speed: 'Fast', fields: [
      { name: 'fullName', label: 'Name on Wise account', type: 'text', placeholder: 'Full name', required: true },
      { name: 'email', label: 'Wise account email', type: 'email', placeholder: 'you@example.com', required: true },
      { name: 'recipientId', label: 'Wise recipient or profile ID', type: 'text', placeholder: 'Optional', required: false }
    ]},
    { id: 'Payoneer', label: 'Payoneer', currency: 'USD', mode: payoutMode('Payoneer'), speed: 'Fast', fields: [
      { name: 'fullName', label: 'Name on Payoneer account', type: 'text', placeholder: 'Full name', required: true },
      { name: 'email', label: 'Payoneer account email', type: 'email', placeholder: 'you@example.com', required: true },
      { name: 'customerId', label: 'Payoneer customer ID', type: 'text', placeholder: 'Optional', required: false }
    ]},
    { id: 'Bank transfer', label: 'Bank transfer', currency: 'USD', mode: payoutMode('Bank transfer'), speed: 'Bank processing', fields: [
      { name: 'accountName', label: 'Account holder name', type: 'text', placeholder: 'Full name', required: true },
      { name: 'country', label: 'Bank country or region', type: 'text', placeholder: 'Country or region', required: true },
      { name: 'bankName', label: 'Bank name', type: 'text', placeholder: 'Bank name', required: true },
      { name: 'accountNumber', label: 'Account number / IBAN', type: 'text', placeholder: 'Account number or IBAN', required: true },
      { name: 'swift', label: 'SWIFT / BIC', type: 'text', placeholder: 'SWIFT or BIC', required: false },
      { name: 'currency', label: 'Payout currency', type: 'text', placeholder: 'e.g. USD, EUR, GBP', required: true }
    ]}
  ];
}

function parseDetails(details) {
  try { return JSON.parse(details); } catch { return { value: details }; }
}

async function paypalAccessToken() {
  const live = String(process.env.PAYPAL_ENV || 'sandbox').toLowerCase() === 'live';
  const base = live ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';
  const auth = Buffer.from(`${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_CLIENT_SECRET}`).toString('base64');
  const r = await fetch(`${base}/v1/oauth2/token`, {
    method: 'POST', headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=client_credentials', signal: AbortSignal.timeout(10000)
  });
  if (!r.ok) throw new Error(`PayPal authentication failed (${r.status})`);
  const d = await r.json();
  return { base, token: d.access_token };
}

async function sendPaypalPayout(amountUsd, details, withdrawalId) {
  const email = String(details.email || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error('Enter a valid PayPal email address.');
  const { base, token } = await paypalAccessToken();
  const batchId = `LT-${withdrawalId}-${Date.now()}`.slice(0, 30);
  const payload = {
    sender_batch_header: {
      sender_batch_id: batchId,
      email_subject: 'Your LilianTech withdrawal is on the way',
      email_message: 'Your LilianTech withdrawal has been submitted to PayPal.'
    },
    items: [{ recipient_type: 'EMAIL', amount: { value: Number(amountUsd).toFixed(2), currency: 'USD' }, receiver: email, note: `LilianTech withdrawal ${withdrawalId}`, sender_item_id: String(withdrawalId) }]
  };
  const r = await fetch(`${base}/v1/payments/payouts`, {
    method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(payload), signal: AbortSignal.timeout(15000)
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.message || 'PayPal payout request failed.');
  return d.batch_header?.payout_batch_id || batchId;
}

async function executeAutomaticPayout(method, amount, details, withdrawalId) {
  if (method === 'PayPal') return await sendPaypalPayout(amount, details, withdrawalId);
  if (method === 'Wise') throw new Error('Wise payout integration is not enabled yet.');
  if (method === 'Payoneer') throw new Error('Payoneer payout integration is not enabled yet.');
  return null;
}




// ---------- Earnings, withdrawals, profile and administration ----------
app.get("/api/earnings", requireAuth, async (req, res) => {
  try {
    const user = await getUserById(req.session.userId);
    const pending = await pool.query(`SELECT COALESCE(SUM(amount),0) AS amount FROM withdrawals WHERE user_id=$1 AND status IN ('pending','approved','processing')`, [req.session.userId]);
    const tx = await pool.query(`SELECT id, type, amount, description, reference_id, created_at FROM transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100`, [req.session.userId]);
    const pendingAmount = Number(pending.rows[0].amount || 0);
    res.json({ total: Number(user.balance || 0), pending: pendingAmount, available: Math.max(0, Number(user.balance || 0) - pendingAmount), transactions: tx.rows, minimumWithdrawal: getMinimumWithdrawal() });
  } catch (e) { console.error(e); res.status(500).json({ error: "Unable to load earnings." }); }
});

app.get("/api/withdrawal-methods", requireAuth, async (req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({ methods: getWithdrawalMethods(), minimumWithdrawal: getMinimumWithdrawal(), note: "Automatic payouts are available only when LilianTech has the required provider credentials configured. Otherwise the request is queued for administrator processing." });
});

app.get("/api/withdrawals", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`SELECT id, amount, method, details, status, admin_note, provider_reference, payout_error, created_at, processed_at FROM withdrawals WHERE user_id=$1 ORDER BY created_at DESC`, [req.session.userId]);
    res.json({ withdrawals: result.rows, minimumWithdrawal: getMinimumWithdrawal(), methods: getWithdrawalMethods() });
  } catch (e) { console.error(e); res.status(500).json({ error: "Unable to load withdrawals." }); }
});

app.post("/api/withdrawals", requireAuth, async (req, res) => {
  const client = await pool.connect();
  let withdrawal = null;
  try {
    const amount = Number(req.body.amount);
    const method = String(req.body.method || '').trim();
    const detailsObj = req.body.details && typeof req.body.details === 'object' ? req.body.details : {};
    const details = JSON.stringify(detailsObj);
    const minimum = getMinimumWithdrawal();
    const methods = getWithdrawalMethods();
    const methodConfig = methods.find(m => m.id === method);
    if (!methodConfig) return res.status(400).json({ error: "Select a supported withdrawal method." });
    if (!Number.isFinite(amount) || amount < minimum) return res.status(400).json({ error: `Minimum withdrawal is $${minimum.toFixed(2)}.` });
    for (const field of methodConfig.fields) {
      if (field.required && !String(detailsObj[field.name] || '').trim()) return res.status(400).json({ error: `${field.label} is required.` });
    }
    await client.query('BEGIN');
    const user = await client.query(`SELECT balance FROM users WHERE id=$1 FOR UPDATE`, [req.session.userId]);
    const pending = await client.query(`SELECT COALESCE(SUM(amount),0) AS amount FROM withdrawals WHERE user_id=$1 AND status IN ('pending','approved','processing')`, [req.session.userId]);
    const available = Number(user.rows[0]?.balance || 0) - Number(pending.rows[0]?.amount || 0);
    if (amount > available) { await client.query('ROLLBACK'); return res.status(400).json({ error: "Insufficient available balance." }); }
    const result = await client.query(`INSERT INTO withdrawals (user_id, amount, method, details, status) VALUES ($1,$2,$3,$4,'pending') RETURNING id, amount, method, details, status, created_at`, [req.session.userId, amount.toFixed(2), method, details]);
    withdrawal = result.rows[0];
    await client.query('COMMIT');
  } catch (e) { await client.query('ROLLBACK').catch(()=>{}); console.error(e); return res.status(500).json({ error: "Unable to submit withdrawal." }); } finally { client.release(); }

  // Try an actual provider payout only when credentials are present. Never mark a
  // withdrawal paid merely because the request was accepted by LilianTech.
  if (payoutMode(withdrawal.method) === 'automatic') {
    try {
      const reference = await executeAutomaticPayout(withdrawal.method, Number(withdrawal.amount), parseDetails(withdrawal.details), withdrawal.id);
      await pool.query(`UPDATE withdrawals SET status='processing', provider_reference=$1, processed_at=NOW(), payout_error=NULL WHERE id=$2`, [reference, withdrawal.id]);
      return res.status(201).json({ message: `Withdrawal submitted to ${withdrawal.method}. Provider confirmation is still required before it is marked paid.`, withdrawal: { ...withdrawal, status: 'processing', provider_reference: reference } });
    } catch (e) {
      console.error(`${withdrawal.method} payout error:`, e);
      await pool.query(`UPDATE withdrawals SET status='pending', payout_error=$1 WHERE id=$2`, [String(e.message || e).slice(0,500), withdrawal.id]);
      return res.status(202).json({ message: `Withdrawal saved, but the ${withdrawal.method} payout could not be submitted automatically. It remains pending for review.`, withdrawal: { ...withdrawal, status: 'pending' } });
    }
  }
  res.status(201).json({ message: "Withdrawal request submitted and queued for processing.", withdrawal });
});

app.put("/api/profile", requireAuth, async (req, res) => {
  try {
    const fullName = String(req.body.fullName || '').trim();
    const phone = String(req.body.phone || '').trim();
    const paymentMethod = String(req.body.paymentMethod || '').trim();
    const paymentDetails = String(req.body.paymentDetails || '').trim();
    if (!fullName) return res.status(400).json({ error: "Full name is required." });
    const current = await getUserById(req.session.userId);
    if (isDesignatedAdmin(current) && fullName !== getAdminIdentity().name) {
      return res.status(400).json({ error: "The designated administrator name cannot be changed." });
    }
    const result = await pool.query(`UPDATE users SET full_name=$1, phone=$2, payment_method=$3, payment_details=$4 WHERE id=$5 RETURNING id, full_name, email, balance, role, phone, payment_method, payment_details, created_at`, [fullName, phone || null, paymentMethod || null, paymentDetails || null, req.session.userId]);
    res.json({ message: "Profile updated.", user: result.rows[0] });
  } catch (e) { console.error(e); res.status(500).json({ error: "Unable to update profile." }); }
});

app.get("/api/admin/revenue", requireAdmin, async (req, res) => {
  try {
    const summary = await pool.query(`
      SELECT
        COALESCE(SUM(publisher_revenue),0) AS gross_revenue,
        COALESCE(SUM(user_reward),0) AS member_rewards,
        COALESCE(SUM(margin),0) AS platform_margin,
        COUNT(*)::int AS provider_events
      FROM provider_transactions
      WHERE status IN ('1','COMPLETE','RECONCILIATION','complete','reconciliation')
    `);
    const byProvider = await pool.query(`
      SELECT provider_id, COALESCE(SUM(publisher_revenue),0) AS gross_revenue,
             COALESCE(SUM(user_reward),0) AS member_rewards,
             COALESCE(SUM(margin),0) AS platform_margin, COUNT(*)::int AS events
      FROM provider_transactions
      WHERE status IN ('1','COMPLETE','RECONCILIATION','complete','reconciliation')
      GROUP BY provider_id ORDER BY provider_id
    `);
    const pendingLiability = await pool.query(`SELECT COALESCE(SUM(amount),0) AS amount FROM withdrawals WHERE status IN ('pending','approved','processing')`);
    const result = summary.rows[0];
    res.json({
      grossRevenue: Number(result.gross_revenue || 0),
      memberRewards: Number(result.member_rewards || 0),
      platformMargin: Number(result.platform_margin || 0),
      providerEvents: result.provider_events,
      pendingWithdrawalLiability: Number(pendingLiability.rows[0].amount || 0),
      providers: byProvider.rows.map(x => ({ providerId:x.provider_id, grossRevenue:Number(x.gross_revenue||0), memberRewards:Number(x.member_rewards||0), platformMargin:Number(x.platform_margin||0), events:x.events }))
    });
  } catch(e) { console.error(e); res.status(500).json({error:"Unable to load revenue dashboard."}); }
});

app.get("/api/admin/overview", requireAdmin, async (req, res) => {
  try {
    const [users, pending, surveys, providers, revenue] = await Promise.all([
      pool.query(`SELECT COUNT(*)::int AS count FROM users`),
      pool.query(`SELECT COALESCE(SUM(amount),0) AS amount, COUNT(*)::int AS count FROM withdrawals WHERE status IN ('pending','approved','processing')`),
      pool.query(`SELECT COUNT(*)::int AS count FROM survey_activity WHERE status='completed'`),
      pool.query(`SELECT provider_id, COUNT(*)::int AS count FROM provider_surveys GROUP BY provider_id ORDER BY provider_id`),
      pool.query(`SELECT COALESCE(SUM(publisher_revenue),0) AS gross, COALESCE(SUM(user_reward),0) AS rewards, COALESCE(SUM(margin),0) AS margin FROM provider_transactions WHERE status IN ('1','COMPLETE','RECONCILIATION','complete','reconciliation')`)
    ]);
    res.json({ users: users.rows[0].count, pendingWithdrawals: pending.rows[0].count, pendingAmount: pending.rows[0].amount, completedSurveys: surveys.rows[0].count, providerSurveys: providers.rows, grossRevenue: revenue.rows[0].gross, memberRewards: revenue.rows[0].rewards, platformMargin: revenue.rows[0].margin });
  } catch (e) { console.error(e); res.status(500).json({ error: "Unable to load admin overview." }); }
});

app.get("/api/admin/users", requireAdmin, async (req, res) => {
  try { const r = await pool.query(`SELECT id, full_name, email, balance, role, created_at FROM users ORDER BY created_at DESC LIMIT 500`); res.json({ users: r.rows }); }
  catch (e) { console.error(e); res.status(500).json({ error: "Unable to load users." }); }
});

app.get("/api/admin/withdrawals", requireAdmin, async (req, res) => {
  try { const r = await pool.query(`SELECT w.id,w.amount,w.method,w.details,w.status,w.admin_note,w.provider_reference,w.payout_error,w.created_at,w.processed_at,u.full_name,u.email FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY w.created_at DESC LIMIT 500`); res.json({ withdrawals: r.rows }); }
  catch (e) { console.error(e); res.status(500).json({ error: "Unable to load withdrawals." }); }
});

app.post("/api/admin/withdrawals/:id/process", requireAdmin, async (req, res) => {
  const client = await pool.connect();
  try {
    const status = String(req.body.status || '').toLowerCase();
    const note = String(req.body.note || '').trim();
    if (!['approved','rejected','paid'].includes(status)) return res.status(400).json({ error: "Status must be approved, rejected, or paid." });
    await client.query('BEGIN');
    const wr = await client.query(`SELECT * FROM withdrawals WHERE id=$1 FOR UPDATE`, [req.params.id]);
    if (!wr.rows[0]) { await client.query('ROLLBACK'); return res.status(404).json({ error: "Withdrawal not found." }); }
    const w = wr.rows[0];
    if (w.status === 'paid' || w.status === 'rejected') { await client.query('ROLLBACK'); return res.status(400).json({ error: "This withdrawal is already finalized." }); }
    if (status === 'approved' && w.status !== 'pending') { await client.query('ROLLBACK'); return res.status(400).json({ error: "Only pending withdrawals can be approved." }); }
    if (status === 'rejected' && w.status !== 'pending' && w.status !== 'approved') { await client.query('ROLLBACK'); return res.status(400).json({ error: "This withdrawal cannot be rejected in its current state." }); }
    if (status === 'paid' && !['approved','processing'].includes(w.status)) { await client.query('ROLLBACK'); return res.status(400).json({ error: "A withdrawal must be approved before it can be marked paid." }); }
    if (status === 'paid') {
      const user = await client.query(`SELECT balance FROM users WHERE id=$1 FOR UPDATE`, [w.user_id]);
      if (Number(user.rows[0].balance) < Number(w.amount)) { await client.query('ROLLBACK'); return res.status(400).json({ error: "User no longer has enough balance to pay this withdrawal." }); }
      await client.query(`UPDATE users SET balance=balance-$1 WHERE id=$2`, [w.amount,w.user_id]);
      await client.query(`INSERT INTO transactions (user_id,type,amount,description,reference_id) VALUES ($1,'withdrawal',$2,$3,$4)`, [w.user_id, -Number(w.amount), `Withdrawal paid via ${w.method}`, String(w.id)]);
    }
    await client.query(`UPDATE withdrawals SET status=$1, admin_note=$2, processed_at=NOW() WHERE id=$3`, [status,note||null,w.id]);
    await client.query('COMMIT');
    res.json({ message: `Withdrawal marked ${status}.` });
  } catch (e) { await client.query('ROLLBACK').catch(()=>{}); console.error(e); res.status(500).json({ error: "Unable to process withdrawal." }); } finally { client.release(); }
});

app.get("/api/admin/provider-surveys", requireAdmin, async (req,res)=>{
  try { const r=await pool.query(`SELECT id,provider_id,external_id,title,reward,minutes,country,status,created_at FROM provider_surveys ORDER BY created_at DESC`); res.json({surveys:r.rows}); }
  catch(e){console.error(e);res.status(500).json({error:"Unable to load provider surveys."});}
});

app.post("/api/admin/provider-surveys", requireAdmin, async (req,res)=>{
  try {
    const {providerId,externalId,title,reward,minutes,country,status='active'}=req.body;
    if(!providerId||!externalId||!title) return res.status(400).json({error:"Provider, external ID and title are required."});
    const r=await pool.query(`INSERT INTO provider_surveys (provider_id,external_id,title,reward,minutes,country,status) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(provider_id,external_id) DO UPDATE SET title=EXCLUDED.title,reward=EXCLUDED.reward,minutes=EXCLUDED.minutes,country=EXCLUDED.country,status=EXCLUDED.status RETURNING *`,[providerId,externalId,title,Number(reward)||0,Number(minutes)||10,country||'US',status]);
    res.status(201).json({message:"Provider survey saved.",survey:r.rows[0]});
  }catch(e){console.error(e);res.status(500).json({error:"Unable to save provider survey."});}
});

app.get("/api/admin/providers", requireAdmin, async (req,res)=>{
  try { res.json({providers: require(path.join(__dirname,'data','providers.json'))}); }
  catch(e){res.status(500).json({error:"Unable to load providers."});}
});

async function startServer() {
  try {
    if (isProduction && !process.env.DATABASE_URL) throw new Error("DATABASE_URL is required in production.");
    if (isProduction && !process.env.SESSION_SECRET) throw new Error("SESSION_SECRET is required in production.");
    await initializeDatabase();

    app.listen(PORT, () => {
      console.log(`LilianTech running on ${PORT}`);
    });
  } catch (error) {
    console.error("Database initialization failed:", error);
    process.exit(1);
  }
}

startServer();
