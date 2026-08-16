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
    CREATE TABLE IF NOT EXISTS ai_survey_bundles (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title VARCHAR(255) NOT NULL,
      category VARCHAR(80) NOT NULL DEFAULT 'Global Opinion',
      question_ids JSONB NOT NULL,
      reward_total NUMERIC(14,6) NOT NULL DEFAULT 0.050000,
      status VARCHAR(20) NOT NULL DEFAULT 'available',
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
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
const AI_QUESTION_BATCH_SIZE = Math.max(10, Math.min(50, Number(process.env.AI_QUESTION_BATCH_SIZE || 30)));
const AI_SURVEY_SIZE = 10;
const AI_SURVEY_PREFETCH = Math.max(2, Math.min(10, Number(process.env.AI_SURVEY_PREFETCH || 3)));
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
      [userId, `LilianTech ${category} Survey`, category,
       JSON.stringify(chunk.map(x => Number(x.id))), rewardTotal]
    );
  }
}

async function getAllSurveyInventory(user = null, req = null) {
  if (!user) return [];
  try {
    await ensureAiSurveyBundles(user.id);
    const result = await pool.query(
      `SELECT b.id,b.title,b.category,b.reward_total,b.status,b.started_at,b.completed_at,
              jsonb_array_length(b.question_ids) AS question_count,
              (SELECT COUNT(*) FROM survey_activity a
               WHERE a.user_id=b.user_id AND a.survey_id LIKE CONCAT('bundle-',b.id,'-q-%')
                 AND a.status='completed') AS answered_count
       FROM ai_survey_bundles b
       WHERE b.user_id=$1 AND b.status IN ('available','in_progress')
       ORDER BY b.id ASC`, [user.id]
    );
    return result.rows.map(b => ({
      id: `bundle-${b.id}`,
      title: b.title,
      category: b.category,
      reward: Number(b.reward_total),
      questionCount: Number(b.question_count),
      answeredCount: Number(b.answered_count),
      remainingCount: Number(b.question_count) - Number(b.answered_count),
      status: b.status,
      startedAt: b.started_at,
      provider: 'LilianTech AI',
      providerId: 'liliantech-ai',
      source: 'ai'
    }));
  } catch (error) {
    console.error('AI survey inventory:', error);
    return [];
  }
}

async function getSurveyById(surveyId, user = null, req = null) {
  if (!user) return null;
  const id = String(surveyId || '').replace(/^bundle-/, '');
  if (!/^\d+$/.test(id)) return null;
  const bundle = await pool.query(
    `SELECT id,title,category,reward_total,status,question_ids
     FROM ai_survey_bundles WHERE id=$1 AND user_id=$2`, [Number(id), user.id]
  );
  const b = bundle.rows[0];
  if (!b) return null;
  const ids = Array.isArray(b.question_ids) ? b.question_ids : JSON.parse(b.question_ids || '[]');
  const questions = await pool.query(
    `SELECT id,category,topic,region,question,options,reward
     FROM ai_questions WHERE id=ANY($1::int[]) AND active=TRUE ORDER BY array_position($1::int[],id)`, [ids]
  );
  const answered = await pool.query(
    `SELECT survey_id FROM survey_activity
     WHERE user_id=$1 AND survey_id LIKE CONCAT('bundle-', $2, '-q-%') AND status='completed'`,
    [user.id, Number(id)]
  );
  const answeredIds = new Set(answered.rows.map(r => String(r.survey_id).split('-q-')[1]));
  return {
    id:`bundle-${b.id}`, title:b.title, category:b.category, reward:Number(b.reward_total),
    status:b.status, questions:questions.rows.map(q => ({
      id:`bundle-${b.id}-q-${q.id}`, questionId:q.id, category:q.category, topic:q.topic,
      region:q.region, question:q.question, options:Array.isArray(q.options)?q.options:JSON.parse(q.options||'[]'),
      reward:Number(q.reward), answered:answeredIds.has(String(q.id))
    })).filter(q=>!q.answered)
  };
}

app.get("/api/dashboard", requireAuth, async (req, res) => {
  try {
    const user = await getUserById(req.session.userId);
    if (!user) return res.status(401).json({ error: "Account not found." });

    await ensureAiSurveyBundles(user.id);
    const bundles = await pool.query(
      `SELECT b.id,b.title,b.category,b.reward_total,b.status,b.started_at,b.completed_at,
              jsonb_array_length(b.question_ids) AS question_count,
              (SELECT COUNT(*) FROM survey_activity a WHERE a.user_id=b.user_id
               AND a.survey_id LIKE CONCAT('bundle-',b.id,'-q-%') AND a.status='completed') AS answered_count
       FROM ai_survey_bundles b WHERE b.user_id=$1 ORDER BY b.created_at DESC`, [user.id]
    );
    const rows = bundles.rows;
    const available = rows.filter(b => b.status === 'available').length;
    const inProgress = rows.filter(b => b.status === 'in_progress').length;
    const completed = rows.filter(b => b.status === 'completed').length;
    const activity = rows.map(b => ({
      survey_id:`bundle-${b.id}`, title:b.title, reward:Number(b.reward_total),
      status:b.status, started_at:b.started_at, completed_at:b.completed_at,
      question_count:Number(b.question_count), answered_count:Number(b.answered_count)
    }));
    res.set("Cache-Control", "no-store");
    res.json({
      user,
      stats:{available,inProgress,completed,
        completedEarnings:rows.filter(b=>b.status==='completed').reduce((t,b)=>t+Number(b.reward_total||0),0)},
      activity
    });
  } catch (error) {
    console.error("Dashboard error:", error);
    res.status(500).json({ error: "Unable to load dashboard." });
  }
});

app.post("/api/surveys/:surveyId/start", requireAuth, async (req, res) => {
  try {
    const user = await getUserById(req.session.userId);
    const survey = await getSurveyById(req.params.surveyId, user, req);
    if (!survey) return res.status(404).json({ error: "Survey not found." });
    if (survey.status === 'completed') return res.status(409).json({ error: "This survey is already completed." });
    await pool.query(
      `UPDATE ai_survey_bundles SET status='in_progress', started_at=COALESCE(started_at,NOW()) WHERE id=$1 AND user_id=$2`,
      [Number(String(req.params.surveyId).replace('bundle-','')), user.id]
    );
    res.status(201).json({message:"Survey opened.", ...survey});
  } catch (error) {
    console.error("Start AI survey error:", error);
    res.status(500).json({ error: "Unable to open the survey." });
  }
});

app.post("/api/surveys/:surveyId/complete", requireAuth, async (req, res) => {
  const client = await pool.connect();
  try {
    const user = await getUserById(req.session.userId);
    const match = String(req.params.surveyId).match(/^bundle-(\d+)-q-(\d+)$/);
    if (!match) return res.status(400).json({error:"Invalid question."});
    const bundleId=Number(match[1]), questionId=Number(match[2]);
    const answer=String(req.body?.answer||'').trim();
    const q=await client.query(`SELECT q.id,q.question,q.options,q.reward,b.status,b.question_ids
      FROM ai_questions q JOIN ai_survey_bundles b ON q.id=ANY(SELECT jsonb_array_elements_text(b.question_ids)::int)
      WHERE q.id=$1 AND b.id=$2 AND b.user_id=$3 AND q.active=TRUE`,[questionId,bundleId,user.id]);
    if(!q.rows.length) return res.status(404).json({error:"Question not found."});
    const row=q.rows[0], options=Array.isArray(row.options)?row.options:JSON.parse(row.options||'[]');
    if(!options.includes(answer)) return res.status(400).json({error:"Please select one of the available answers."});
    await client.query('BEGIN');
    const sid=`bundle-${bundleId}-q-${questionId}`;
    const existing=await client.query(`SELECT id,status FROM survey_activity WHERE user_id=$1 AND survey_id=$2 FOR UPDATE`,[user.id,sid]);
    if(existing.rows[0]?.status==='completed'){await client.query('ROLLBACK');return res.status(409).json({error:"This question has already been answered."});}
    await client.query(`INSERT INTO survey_activity(user_id,survey_id,title,reward,status) VALUES($1,$2,$3,$4,'completed')
      ON CONFLICT(user_id,survey_id) DO UPDATE SET status='completed',completed_at=NOW(),reward=EXCLUDED.reward`,
      [user.id,sid,row.question,Number(row.reward||AI_QUESTION_REWARD)]);
    const reward=Number(row.reward||AI_QUESTION_REWARD);
    await client.query(`UPDATE users SET balance=balance+$1 WHERE id=$2`,[reward,user.id]);
    await client.query(`INSERT INTO transactions(user_id,type,amount,description,reference_id) VALUES($1,'earning',$2,$3,$4)`,
      [user.id,reward,`Answered LilianTech survey question: ${row.question}`,sid]);
    const count=await client.query(`SELECT COUNT(*)::int AS n FROM survey_activity WHERE user_id=$1 AND survey_id LIKE CONCAT('bundle-', $2, '-q-%') AND status='completed'`,
      [user.id,bundleId]);
    const total=Array.isArray(row.question_ids)?row.question_ids.length:JSON.parse(row.question_ids||'[]').length;
    const finished=count.rows[0].n>=total;
    if(finished) await client.query(`UPDATE ai_survey_bundles SET status='completed',completed_at=NOW() WHERE id=$1 AND user_id=$2`,[bundleId,user.id]);
    else await client.query(`UPDATE ai_survey_bundles SET status='in_progress',started_at=COALESCE(started_at,NOW()) WHERE id=$1 AND user_id=$2`,[bundleId,user.id]);
    await client.query('COMMIT');
    res.json({message:finished?"Survey completed!":"Answer recorded.",status:finished?'survey_completed':'question_completed',
      reward,remainingQuestions:Math.max(0,total-count.rows[0].n),surveyCompleted:finished});
  } catch(error){await client.query('ROLLBACK').catch(()=>{});console.error("Complete AI question error:",error);res.status(500).json({error:"Unable to record your answer."});}
  finally{client.release();}
});



(async () => {
  try {
    await initializeDatabase();
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`LilianTech listening on port ${PORT}`);
    });
  } catch (error) {
    console.error('Fatal startup error:', error);
    process.exit(1);
  }
})();
