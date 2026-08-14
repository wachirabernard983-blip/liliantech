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

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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
  `);

  await pool.query(`
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
  `);

  // Safe migrations for databases created by earlier LilianTech versions.
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) NOT NULL DEFAULT 'member'`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(40)`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS payment_method VARCHAR(40)`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS payment_details TEXT`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS withdrawals (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      amount NUMERIC(12,2) NOT NULL CHECK (amount > 0),
      method VARCHAR(40) NOT NULL,
      details TEXT NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      admin_note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      processed_at TIMESTAMPTZ
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type VARCHAR(30) NOT NULL,
      amount NUMERIC(12,2) NOT NULL,
      description VARCHAR(255) NOT NULL,
      reference_id VARCHAR(120),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
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
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS provider_transactions (
      id SERIAL PRIMARY KEY,
      provider_id VARCHAR(80) NOT NULL,
      transaction_id VARCHAR(180) NOT NULL,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      survey_id VARCHAR(160),
      status VARCHAR(30) NOT NULL,
      amount NUMERIC(12,2) NOT NULL DEFAULT 0,
      raw_payload JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(provider_id, transaction_id)
    );
  `);

  // Optional deployment convenience: set ADMIN_EMAILS=email1,email2 in production.
  const adminEmail = String(process.env.ADMIN_EMAIL || 'wachirabernard193@gmail.com').trim().toLowerCase();
  const adminName = String(process.env.ADMIN_NAME || 'Bernard Wachira').trim();
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

function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "Authentication required." });
  pool.query('SELECT full_name, email, role FROM users WHERE id = $1', [req.session.userId])
    .then(result => {
      const u = result.rows[0];
      const adminEmail = String(process.env.ADMIN_EMAIL || 'wachirabernard193@gmail.com').trim().toLowerCase();
      const adminName = String(process.env.ADMIN_NAME || 'Bernard Wachira').trim();
      if (!u || u.role !== 'admin' || u.full_name !== adminName || String(u.email).toLowerCase() !== adminEmail) return res.status(403).json({ error: "Administrator access required." });
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

app.get("/api/providers", (req, res) => {
  res.sendFile(
    path.join(__dirname, "data", "providers.json")
  );
});

app.post("/api/register", async (req, res) => {
  try {
    const { fullName, email, password } = req.body;

    if (!fullName || !email || !password) {
      return res.status(400).json({
        error: "Full name, email and password are required."
      });
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

    const result = await pool.query(
      `INSERT INTO users
       (full_name, email, password_hash)
       VALUES ($1, $2, $3)
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

app.post("/api/login", async (req, res) => {
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


function getSurveyInventory() {
  return require(path.join(__dirname, "data", "surveys.json"));
}

async function getAllSurveyInventory(user = null, req = null) {
  const local = getSurveyInventory();
  const imported = await pool.query(`SELECT id, provider_id, external_id, title, reward, minutes, country, status FROM provider_surveys WHERE status='active'`);
  const dbInventory = imported.rows.map(row => ({
    id: `provider-${row.id}`, title: row.title, minutes: row.minutes,
    reward: `$${Number(row.reward || 0).toFixed(2)}`, provider: row.provider_id,
    externalId: row.external_id, country: row.country, source: 'imported'
  }));
  const live = user && req ? await getLiveProviderSurveys(user, req).catch(err => { console.error('Provider survey fetch:', err); return []; }) : [];
  return [...local, ...dbInventory, ...live];
}

async function getLiveProviderSurveys(user, req) {
  const surveys = [];
  const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim().replace('::ffff:','');
  const ua = String(req.headers['user-agent'] || '');

  // CPX Research: user-based API. App ID is public; secure hash stays server-side.
  const cpxAppId = process.env.CPX_APP_ID || '35372';
  if (cpxAppId) {
    const q = new URLSearchParams({
      app_id: cpxAppId, ext_user_id: String(user.id), output_method: 'api',
      ip_user: ip || '0.0.0.0', user_agent: ua, limit: '12'
    });
    if (process.env.CPX_SECURE_HASH) q.set('secure_hash', crypto.createHash('md5').update(`${user.id}-${process.env.CPX_SECURE_HASH}`).digest('hex'));
    const r = await fetch(`https://live-api.cpx-research.com/api/get-surveys.php?${q}`);
    if (r.ok) {
      const data = await r.json();
      if (data.status === 'success') {
        for (const x of (data.surveys || [])) surveys.push({
          id: `cpx-${x.id}`, externalId: String(x.id), title: `CPX Research survey`,
          minutes: Number(x.loi || 0), reward: `$${Number(x.payout_publisher_usd ?? x.payout ?? 0).toFixed(2)}`,
          provider: 'CPX Research', providerId: 'cpx', href: x.href_new || x.href,
          source: 'live', live: true
        });
      }
    }
  }

  // BitLabs: user-based Survey API. The token is never exposed to the browser.
  if (process.env.BITLABS_API_TOKEN) {
    const r = await fetch('https://api.bitlabs.ai/v2/client/surveys?platform=WEB&sdk=CUSTOM', {
      headers: { 'X-Api-Token': process.env.BITLABS_API_TOKEN, accept: 'application/json' }
    });
    if (r.ok) {
      const data = await r.json();
      for (const x of (data.surveys || [])) surveys.push({
        id: `bitlabs-${x.id || x.survey_id}`, externalId: String(x.id || x.survey_id),
        title: x.title || 'BitLabs survey', minutes: Number(x.loi || x.length_of_interview || 0),
        reward: `$${Number(x.reward || x.payout || 0).toFixed(2)}`, provider: 'BitLabs',
        providerId: 'bitlabs', href: x.click_url || x.clickUrl, source: 'live', live: true
      });
    }
  }

  // Cint and Dynata are credential/signature based. The adapters are intentionally
  // gated until approved credentials are supplied, so no fake inventory is shown.
  return surveys.filter(x => x.href);
}

async function getSurveyById(surveyId) {
  const local = getSurveyInventory().find((survey) => survey.id === surveyId);
  if (local) return local;
  if (String(surveyId).startsWith('provider-')) {
    const id = Number(String(surveyId).replace('provider-', ''));
    if (Number.isInteger(id)) {
      const r = await pool.query(`SELECT id, provider_id, external_id, title, reward, minutes, country FROM provider_surveys WHERE id=$1 AND status='active'`, [id]);
      if (r.rows[0]) return { id: `provider-${r.rows[0].id}`, title: r.rows[0].title, minutes: r.rows[0].minutes, reward: `$${Number(r.rows[0].reward || 0).toFixed(2)}`, provider: r.rows[0].provider_id, externalId: r.rows[0].external_id, country: r.rows[0].country };
    }
  }
  return null;
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
    const survey = await getSurveyById(req.params.surveyId);

    if (!survey) {
      return res.status(404).json({ error: "Survey not found." });
    }

    const existing = await pool.query(
      `SELECT status FROM survey_activity
       WHERE user_id = $1 AND survey_id = $2`,
      [req.session.userId, survey.id]
    );

    if (existing.rows.length > 0) {
      return res.json({
        message: "Survey already started.",
        status: existing.rows[0].status
      });
    }

    const reward = Number(String(survey.reward).replace(/[^0-9.]/g, "")) || 0;

    if (survey.live && survey.href) {
      await pool.query(
        `INSERT INTO survey_activity (user_id, survey_id, title, reward, status) VALUES ($1,$2,$3,$4,'in_progress')`,
        [req.session.userId, survey.id, survey.title, reward]
      );
      return res.status(201).json({ message: "Survey opened. Completion is confirmed by the provider.", status: "in_progress", redirectUrl: survey.href, provider: survey.provider });
    }

    await pool.query(
      `INSERT INTO survey_activity
       (user_id, survey_id, title, reward, status)
       VALUES ($1, $2, $3, $4, 'in_progress')`,
      [req.session.userId, survey.id, survey.title, reward]
    );

    res.status(201).json({
      message: "Survey started.",
      status: "in_progress"
    });
  } catch (error) {
    console.error("Start survey error:", error);
    res.status(500).json({ error: "Unable to start survey." });
  }
});

app.post("/api/surveys/:surveyId/complete", requireAuth, async (req, res) => {
  const client = await pool.connect();

  try {
    const survey = await getSurveyById(req.params.surveyId);

    if (!survey) {
      return res.status(404).json({ error: "Survey not found." });
    }

    await client.query("BEGIN");

    const activity = await client.query(
      `SELECT id, reward, status
       FROM survey_activity
       WHERE user_id = $1 AND survey_id = $2
       FOR UPDATE`,
      [req.session.userId, survey.id]
    );

    if (activity.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Start the survey before completing it." });
    }

    if (activity.rows[0].status === "completed") {
      await client.query("ROLLBACK");
      return res.json({ message: "Survey already completed.", status: "completed" });
    }

    const reward = Number(activity.rows[0].reward || 0);
    if (String(survey.id).startsWith('cpx-') || String(survey.id).startsWith('bitlabs-')) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Provider surveys are completed and credited by the provider callback." });
    }

    await client.query(
      `UPDATE survey_activity
       SET status = 'completed', completed_at = NOW()
       WHERE id = $1`,
      [activity.rows[0].id]
    );

    await client.query(
      `UPDATE users
       SET balance = balance + $1
       WHERE id = $2`,
      [reward, req.session.userId]
    );

    await client.query(
      `INSERT INTO transactions (user_id, type, amount, description, reference_id)
       VALUES ($1, 'earning', $2, $3, $4)`,
      [req.session.userId, reward, `Completed ${survey.title}`, survey.id]
    );

    await client.query("COMMIT");

    res.json({
      message: "Survey completed and reward added.",
      status: "completed",
      reward
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Complete survey error:", error);
    res.status(500).json({ error: "Unable to complete survey." });
  } finally {
    client.release();
  }
});

// ---------- Provider callbacks ----------\n// CPX postback: credit only verified, idempotent transactions. Configure the exact\n// callback URL in CPX as https://liliantech.online/api/providers/cpx/postback.\napp.all('/api/providers/cpx/postback', async (req, res) => {\n  try {\n    const q = { ...req.query, ...req.body };\n    const status = String(q.status || '');\n    const transactionId = String(q.trans_id || q.transaction_id || '');\n    const userId = String(q.user_id || q.subid || '');\n    const amount = Number(q.amount_usd || q.amount_local || 0);\n    const secureHash = String(q.secure_hash || '');\n    if (!transactionId || !userId || !Number.isFinite(amount)) return res.status(400).send('invalid');\n    if (process.env.CPX_SECURE_HASH) {\n      const expected = crypto.createHash('md5').update(`${transactionId}-${process.env.CPX_SECURE_HASH}`).digest('hex');\n      if (secureHash.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(secureHash), Buffer.from(expected))) return res.status(403).send('invalid signature');\n    } else {\n      return res.status(503).send('CPX secure hash not configured');\n    }\n    const user = await pool.query('SELECT id FROM users WHERE id=$1', [Number(userId)]);\n    if (!user.rows[0]) return res.status(404).send('user not found');\n    const client = await pool.connect();\n    try {\n      await client.query('BEGIN');\n      const exists = await client.query('SELECT id,status FROM provider_transactions WHERE provider_id=$1 AND transaction_id=$2 FOR UPDATE', ['cpx', transactionId]);\n      if (exists.rows[0]) { await client.query('COMMIT'); return res.status(200).send('ok'); }\n      await client.query(`INSERT INTO provider_transactions (provider_id,transaction_id,user_id,survey_id,status,amount,raw_payload) VALUES ($1,$2,$3,$4,$5,$6,$7)`, ['cpx', transactionId, Number(userId), String(q.offer_id || q.survey_id || ''), status, amount, q]);\n      if (status === '1' && amount > 0) {\n        await client.query(`UPDATE users SET balance=balance+$1 WHERE id=$2`, [amount, Number(userId)]);\n        await client.query(`UPDATE survey_activity SET status='completed', completed_at=NOW(), reward=$1 WHERE user_id=$2 AND survey_id=$3`, [amount, Number(userId), `cpx-${q.offer_id || q.survey_id || ''}`]);\n        await client.query(`INSERT INTO transactions (user_id,type,amount,description,reference_id) VALUES ($1,'earning',$2,$3,$4)`, [Number(userId), amount, `CPX Research survey ${transactionId}`, transactionId]);\n      } else if (status === '2' && amount > 0) {\n        await client.query(`UPDATE users SET balance=GREATEST(0,balance-$1) WHERE id=$2`, [amount, Number(userId)]);\n        await client.query(`INSERT INTO transactions (user_id,type,amount,description,reference_id) VALUES ($1,'adjustment',$2,$3,$4)`, [Number(userId), -amount, `CPX Research reversal ${transactionId}`, transactionId]);\n      }\n      await client.query('COMMIT');\n      res.status(200).send('ok');\n    } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }\n  } catch (e) { console.error('CPX callback:', e); res.status(500).send('error'); }\n});\n\n// BitLabs callback endpoint. Configure the callback/signature fields from the\n// BitLabs publisher dashboard before enabling reward crediting.\napp.post('/api/providers/bitlabs/callback', express.json(), async (req, res) => {\n  // Kept intentionally non-crediting until the BitLabs callback secret/configuration\n  // supplied by BitLabs is installed. This prevents forged reward requests.\n  if (!process.env.BITLABS_API_TOKEN) return res.status(503).send('BitLabs not configured');\n  res.status(202).json({ received: true, message: 'Callback endpoint ready; configure BitLabs callback verification before crediting.' });\n});\n\n// ---------- Earnings, withdrawals, profile and administration ----------
app.get("/api/earnings", requireAuth, async (req, res) => {
  try {
    const user = await getUserById(req.session.userId);
    const pending = await pool.query(`SELECT COALESCE(SUM(amount),0) AS amount FROM withdrawals WHERE user_id=$1 AND status='pending'`, [req.session.userId]);
    const tx = await pool.query(`SELECT id, type, amount, description, reference_id, created_at FROM transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100`, [req.session.userId]);
    const pendingAmount = Number(pending.rows[0].amount || 0);
    res.json({ total: Number(user.balance || 0), pending: pendingAmount, available: Math.max(0, Number(user.balance || 0) - pendingAmount), transactions: tx.rows, minimumWithdrawal: getMinimumWithdrawal() });
  } catch (e) { console.error(e); res.status(500).json({ error: "Unable to load earnings." }); }
});

app.get("/api/withdrawals", requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`SELECT id, amount, method, details, status, admin_note, created_at, processed_at FROM withdrawals WHERE user_id=$1 ORDER BY created_at DESC`, [req.session.userId]);
    res.json({ withdrawals: result.rows, minimumWithdrawal: getMinimumWithdrawal() });
  } catch (e) { console.error(e); res.status(500).json({ error: "Unable to load withdrawals." }); }
});

app.post("/api/withdrawals", requireAuth, async (req, res) => {
  const client = await pool.connect();
  try {
    const amount = Number(req.body.amount);
    const method = String(req.body.method || '').trim();
    const details = String(req.body.details || '').trim();
    const minimum = getMinimumWithdrawal();
    if (!Number.isFinite(amount) || amount < minimum) return res.status(400).json({ error: `Minimum withdrawal is $${minimum.toFixed(2)}.` });
    if (!method || !details) return res.status(400).json({ error: "Payment method and payment details are required." });
    await client.query('BEGIN');
    const user = await client.query(`SELECT balance FROM users WHERE id=$1 FOR UPDATE`, [req.session.userId]);
    const pending = await client.query(`SELECT COALESCE(SUM(amount),0) AS amount FROM withdrawals WHERE user_id=$1 AND status='pending'`, [req.session.userId]);
    const available = Number(user.rows[0]?.balance || 0) - Number(pending.rows[0]?.amount || 0);
    if (amount > available) { await client.query('ROLLBACK'); return res.status(400).json({ error: "Insufficient available balance." }); }
    const result = await client.query(`INSERT INTO withdrawals (user_id, amount, method, details) VALUES ($1,$2,$3,$4) RETURNING id, amount, method, status, created_at`, [req.session.userId, amount.toFixed(2), method, details]);
    await client.query('COMMIT');
    res.status(201).json({ message: "Withdrawal request submitted.", withdrawal: result.rows[0] });
  } catch (e) { await client.query('ROLLBACK').catch(()=>{}); console.error(e); res.status(500).json({ error: "Unable to submit withdrawal." }); } finally { client.release(); }
});

app.put("/api/profile", requireAuth, async (req, res) => {
  try {
    const fullName = String(req.body.fullName || '').trim();
    const phone = String(req.body.phone || '').trim();
    const paymentMethod = String(req.body.paymentMethod || '').trim();
    const paymentDetails = String(req.body.paymentDetails || '').trim();
    if (!fullName) return res.status(400).json({ error: "Full name is required." });
    const result = await pool.query(`UPDATE users SET full_name=$1, phone=$2, payment_method=$3, payment_details=$4 WHERE id=$5 RETURNING id, full_name, email, balance, role, phone, payment_method, payment_details, created_at`, [fullName, phone || null, paymentMethod || null, paymentDetails || null, req.session.userId]);
    res.json({ message: "Profile updated.", user: result.rows[0] });
  } catch (e) { console.error(e); res.status(500).json({ error: "Unable to update profile." }); }
});

app.get("/api/admin/overview", requireAdmin, async (req, res) => {
  try {
    const [users, pending, surveys, providers] = await Promise.all([
      pool.query(`SELECT COUNT(*)::int AS count FROM users`),
      pool.query(`SELECT COALESCE(SUM(amount),0) AS amount, COUNT(*)::int AS count FROM withdrawals WHERE status='pending'`),
      pool.query(`SELECT COUNT(*)::int AS count FROM survey_activity WHERE status='completed'`),
      pool.query(`SELECT provider_id, COUNT(*)::int AS count FROM provider_surveys GROUP BY provider_id ORDER BY provider_id`)
    ]);
    res.json({ users: users.rows[0].count, pendingWithdrawals: pending.rows[0].count, pendingAmount: pending.rows[0].amount, completedSurveys: surveys.rows[0].count, providerSurveys: providers.rows });
  } catch (e) { console.error(e); res.status(500).json({ error: "Unable to load admin overview." }); }
});

app.get("/api/admin/users", requireAdmin, async (req, res) => {
  try { const r = await pool.query(`SELECT id, full_name, email, balance, role, created_at FROM users ORDER BY created_at DESC LIMIT 500`); res.json({ users: r.rows }); }
  catch (e) { console.error(e); res.status(500).json({ error: "Unable to load users." }); }
});

app.get("/api/admin/withdrawals", requireAdmin, async (req, res) => {
  try { const r = await pool.query(`SELECT w.id,w.amount,w.method,w.details,w.status,w.admin_note,w.created_at,w.processed_at,u.full_name,u.email FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY w.created_at DESC LIMIT 500`); res.json({ withdrawals: r.rows }); }
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
    if (status === 'approved') {
      // Approval reserves the request but does not remove funds. Funds are removed only when marked paid.
    }
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
