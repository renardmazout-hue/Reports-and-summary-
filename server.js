// ══════════════════════════════════════════════
//  Reports & Summary — Backend Railway
//  Routes : POST /api/login  |  POST /api/analyze  |  GET /api/usage
//  Rate limiting : SQLite (par IP + par UID, reset quotidien)
// ══════════════════════════════════════════════
require("dotenv").config();
const express     = require("express");
const cors        = require("cors");
const jwt         = require("jsonwebtoken");
const fetch       = require("node-fetch");
const Database    = require("better-sqlite3");
const path        = require("path");
const bcrypt      = require("bcryptjs");
const crypto      = require("crypto");

const app  = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

// ── Variables d'environnement (définies dans Railway)
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || "";
const JWT_SECRET        = process.env.JWT_SECRET        || "changez-ce-secret";
const ADMIN_EMAIL       = process.env.ADMIN_EMAIL       || "admin@texturno.com";
const ADMIN_PASSWORD    = process.env.ADMIN_PASSWORD    || "";
const PORT               = process.env.PORT              || 3000;

// Limite IP — filet anti-abus générique (pas lié au plan)
const RATE_LIMIT_PER_IP = parseInt(process.env.RATE_LIMIT_PER_IP || "300", 10);

// Limites par plan — DOIT rester synchronisé avec l'objet PLANS du frontend
// (reqPerDay). C'est la seule source de vérité côté serveur.
const PLAN_LIMITS = {
  starter: 20,
  basic:   40,
  pro:     100,
  premium: 250,
};
function limitForPlan(plan) {
  return PLAN_LIMITS[plan] || PLAN_LIMITS.starter;
}

// Chemin DB — IMPORTANT : doit pointer vers un volume persistant Railway
// (Railway → Settings → Volumes → mount path ex: /data)
const DB_PATH = process.env.SQLITE_PATH || path.join(__dirname, "rate-limits.db");

// ── Vérification au démarrage
if (!ANTHROPIC_API_KEY) console.warn("⚠️  ANTHROPIC_API_KEY manquante !");
if (!ADMIN_PASSWORD)    console.warn("⚠️  ADMIN_PASSWORD manquante !");

// ══════════════════════════════════════════════
//  SQLite — init
// ══════════════════════════════════════════════
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS rate_limits (
    identifier TEXT NOT NULL,
    type       TEXT NOT NULL CHECK(type IN ('ip','uid')),
    date       TEXT NOT NULL,
    count      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (identifier, type, date)
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    uid           TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    name          TEXT,
    plan          TEXT NOT NULL DEFAULT 'starter',
    created_at    TEXT NOT NULL
  );
`);

const findUserByEmailStmt = db.prepare(`SELECT * FROM users WHERE email = ?`);
const findUserByUidStmt   = db.prepare(`SELECT * FROM users WHERE uid = ?`);
const insertUserStmt      = db.prepare(
  `INSERT INTO users (uid, email, password_hash, name, plan, created_at) VALUES (?, ?, ?, ?, 'starter', ?)`
);
const updateUserPlanStmt  = db.prepare(`UPDATE users SET plan = ? WHERE uid = ?`);

function generateUid() {
  return "U-" + crypto.randomBytes(5).toString("hex").toUpperCase().slice(0, 8);
}

// Nettoyage léger : on ne garde que les 7 derniers jours de compteurs
db.prepare(`DELETE FROM rate_limits WHERE date < date('now', '-7 days')`).run();

const selectStmt = db.prepare(
  `SELECT count FROM rate_limits WHERE identifier = ? AND type = ? AND date = ?`
);
const insertStmt = db.prepare(
  `INSERT INTO rate_limits (identifier, type, date, count) VALUES (?, ?, ?, 1)`
);
const incrementStmt = db.prepare(
  `UPDATE rate_limits SET count = count + 1 WHERE identifier = ? AND type = ? AND date = ?`
);

function todayUTC() {
  return new Date().toISOString().slice(0, 10); // YYYY-MM-DD
}

// Vérifie + incrémente atomiquement le compteur. Retourne { allowed, count, limit }
function checkAndIncrement(identifier, type, limit) {
  const date = todayUTC();
  const run = db.transaction(() => {
    const row = selectStmt.get(identifier, type, date);
    if (!row) {
      insertStmt.run(identifier, type, date);
      return { allowed: true, count: 1, limit };
    }
    if (row.count >= limit) {
      return { allowed: false, count: row.count, limit };
    }
    incrementStmt.run(identifier, type, date);
    return { allowed: true, count: row.count + 1, limit };
  });
  return run();
}

function getCurrentCount(identifier, type) {
  const row = selectStmt.get(identifier, type, todayUTC());
  return row ? row.count : 0;
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) return forwarded.split(",")[0].trim();
  return req.socket.remoteAddress;
}

// ── Middleware JWT
function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token  = header.replace("Bearer ", "").trim();
  if (!token) return res.status(401).json({ error: "Token manquant." });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Session expirée — reconnectez-vous." });
  }
}

// ── Middleware rate limit (IP puis UID selon le plan réel, reset quotidien)
function rateLimitMiddleware(req, res, next) {
  const ip = getClientIp(req);

  const ipResult = checkAndIncrement(ip, "ip", RATE_LIMIT_PER_IP);
  if (!ipResult.allowed) {
    return res.status(429).json({
      error: "Limite quotidienne par IP atteinte.",
      type: "ip",
      identifier: ip,
      count: ipResult.count,
      limit: ipResult.limit,
    });
  }

  // L'admin n'est pas soumis au quota par plan
  if (req.user?.role === "admin") return next();

  const uid = req.user?.uid;
  if (!uid) return res.status(401).json({ error: "Compte invalide." });

  const userRow = findUserByUidStmt.get(uid);
  const plan = userRow?.plan || "starter";
  const limit = limitForPlan(plan);

  const uidResult = checkAndIncrement(uid, "uid", limit);
  if (!uidResult.allowed) {
    return res.status(429).json({
      error: `Limite quotidienne atteinte pour le plan ${plan} (${limit} requêtes/jour).`,
      type: "uid",
      identifier: uid,
      plan,
      count: uidResult.count,
      limit: uidResult.limit,
    });
  }

  next();
}

// ══════════════════════════════════════════════
//  POST /api/login
// ══════════════════════════════════════════════
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: "Email et mot de passe requis." });

  const normEmail = email.trim().toLowerCase();

  // 1. Compte admin (identifiants fixes en variables d'env)
  if (normEmail === ADMIN_EMAIL.toLowerCase() && password === ADMIN_PASSWORD) {
    const token = jwt.sign(
      { email: ADMIN_EMAIL, role: "admin" },
      JWT_SECRET,
      { expiresIn: "12h" }
    );
    return res.json({ token, user: { email: ADMIN_EMAIL, role: "admin", name: "Administratrice" } });
  }

  // 2. Compte client (table users)
  const userRow = findUserByEmailStmt.get(normEmail);
  if (userRow && (await bcrypt.compare(password, userRow.password_hash))) {
    const token = jwt.sign(
      { uid: userRow.uid, email: userRow.email, role: "user" },
      JWT_SECRET,
      { expiresIn: "30d" }
    );
    return res.json({
      token,
      user: { uid: userRow.uid, email: userRow.email, name: userRow.name, role: "user", plan: userRow.plan },
    });
  }

  return res.status(401).json({ error: "Email ou mot de passe incorrect." });
});

// ══════════════════════════════════════════════
//  POST /api/register  — création de compte client
// ══════════════════════════════════════════════
app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password)
    return res.status(400).json({ error: "Nom, email et mot de passe requis." });
  if (password.length < 6)
    return res.status(400).json({ error: "Le mot de passe doit comporter au moins 6 caractères." });

  const normEmail = email.trim().toLowerCase();
  if (normEmail === ADMIN_EMAIL.toLowerCase())
    return res.status(400).json({ error: "Cet email est réservé." });
  if (findUserByEmailStmt.get(normEmail))
    return res.status(409).json({ error: "Un compte existe déjà avec cet email." });

  const uid = generateUid();
  const passwordHash = await bcrypt.hash(password, 10);
  insertUserStmt.run(uid, normEmail, passwordHash, name.trim(), new Date().toISOString());

  const token = jwt.sign({ uid, email: normEmail, role: "user" }, JWT_SECRET, { expiresIn: "30d" });
  return res.json({
    token,
    user: { uid, email: normEmail, name: name.trim(), role: "user", plan: "starter" },
  });
});

// ══════════════════════════════════════════════
//  GET /api/me — relit le plan à jour depuis la DB
// ══════════════════════════════════════════════
app.get("/api/me", requireAuth, (req, res) => {
  if (req.user.role === "admin")
    return res.json({ email: ADMIN_EMAIL, role: "admin", name: "Administratrice" });

  const userRow = findUserByUidStmt.get(req.user.uid);
  if (!userRow) return res.status(404).json({ error: "Compte introuvable." });
  return res.json({ uid: userRow.uid, email: userRow.email, name: userRow.name, role: "user", plan: userRow.plan });
});

// ══════════════════════════════════════════════
//  POST /api/admin/set-plan — admin uniquement
//  Appelé quand l'admin valide un paiement et change le plan d'un client
// ══════════════════════════════════════════════
app.post("/api/admin/set-plan", requireAuth, (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "Accès réservé à l'administrateur." });

  const { uid, plan } = req.body || {};
  if (!uid || !PLAN_LIMITS[plan])
    return res.status(400).json({ error: "uid et plan (starter|basic|pro|premium) requis." });

  const userRow = findUserByUidStmt.get(uid);
  if (!userRow) return res.status(404).json({ error: "Utilisateur introuvable." });

  updateUserPlanStmt.run(plan, uid);
  return res.json({ ok: true, uid, plan });
});

// ══════════════════════════════════════════════
//  GET /api/usage  (protégé JWT) — quota restant du jour
// ══════════════════════════════════════════════
app.get("/api/usage", requireAuth, (req, res) => {
  const ip = getClientIp(req);
  const ipUsage = { count: getCurrentCount(ip, "ip"), limit: RATE_LIMIT_PER_IP };

  if (req.user.role === "admin") {
    return res.json({ ip: ipUsage, uid: { count: 0, limit: null, plan: null, unlimited: true } });
  }

  const userRow = findUserByUidStmt.get(req.user.uid);
  const plan = userRow?.plan || "starter";
  const limit = limitForPlan(plan);

  res.json({
    ip: ipUsage,
    uid: { count: getCurrentCount(req.user.uid, "uid"), limit, plan },
  });
});

// ══════════════════════════════════════════════
//  POST /api/analyze  (protégé JWT + rate limit)
// ══════════════════════════════════════════════
app.post("/api/analyze", requireAuth, rateLimitMiddleware, async (req, res) => {
  const body = req.body || {};

  if (!ANTHROPIC_API_KEY)
    return res.status(500).json({ error: "Clé API Anthropic non configurée sur le serveur." });

  try {
    const isStream = !!body.stream;
    const upstream = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type":       "application/json",
        "x-api-key":          ANTHROPIC_API_KEY,
        "anthropic-version":  "2023-06-01",
        "anthropic-beta":     "prompt-caching-2024-07-31",
      },
      body: JSON.stringify(body),
    });

    if (isStream) {
      res.setHeader("Content-Type", "text/event-stream");
      res.setHeader("Cache-Control", "no-cache");
      upstream.body.pipe(res);
      return;
    }

    const data = await upstream.json();
    if (data.error) return res.status(upstream.status).json({ error: data.error.message });
    return res.json(data);

  } catch (err) {
    console.error("Erreur /api/analyze :", err.message);
    return res.status(500).json({ error: "Erreur serveur : " + err.message });
  }
});


// ══════════════════════════════════════════════
//  TABLE payments — init
// ══════════════════════════════════════════════
db.exec(`
  CREATE TABLE IF NOT EXISTS payments (
    id          TEXT PRIMARY KEY,
    uid         TEXT NOT NULL,
    email       TEXT NOT NULL,
    name        TEXT,
    plan        TEXT NOT NULL,
    amount      INTEGER NOT NULL,
    method      TEXT NOT NULL,
    phone       TEXT,
    status      TEXT NOT NULL DEFAULT 'pending',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
  );
`);

const insertPaymentStmt = db.prepare(
  `INSERT INTO payments (id, uid, email, name, plan, amount, method, phone, status, created_at, updated_at)
   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`
);
const getPaymentsStmt      = db.prepare(`SELECT * FROM payments ORDER BY created_at DESC`);
const getPaymentByIdStmt   = db.prepare(`SELECT * FROM payments WHERE id = ?`);
const updatePaymentStmt    = db.prepare(
  `UPDATE payments SET status = ?, updated_at = ? WHERE id = ?`
);

// ══════════════════════════════════════════════
//  POST /api/payment — client soumet un paiement
// ══════════════════════════════════════════════
app.post("/api/payment", requireAuth, (req, res) => {
  if (req.user.role === "admin")
    return res.status(400).json({ error: "L'admin ne peut pas soumettre un paiement." });

  const { plan, amount, method, phone } = req.body || {};
  if (!plan || !amount || !method)
    return res.status(400).json({ error: "plan, amount et method requis." });
  if (!PLAN_LIMITS[plan])
    return res.status(400).json({ error: "Plan invalide." });

  const userRow = findUserByUidStmt.get(req.user.uid);
  if (!userRow) return res.status(404).json({ error: "Compte introuvable." });

  const id  = "PAY-" + crypto.randomBytes(4).toString("hex").toUpperCase();
  const now = new Date().toISOString();
  insertPaymentStmt.run(id, userRow.uid, userRow.email, userRow.name, plan, amount, method, phone || null, now, now);

  return res.json({ ok: true, id, status: "pending" });
});

// ══════════════════════════════════════════════
//  GET /api/admin/payments — admin uniquement
// ══════════════════════════════════════════════
app.get("/api/admin/payments", requireAuth, (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "Accès réservé à l'administrateur." });

  const payments = getPaymentsStmt.all();
  return res.json({ payments });
});

// ══════════════════════════════════════════════
//  PATCH /api/admin/payment/:id — valider ou rejeter
// ══════════════════════════════════════════════
app.patch("/api/admin/payment/:id", requireAuth, (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "Accès réservé à l'administrateur." });

  const { id } = req.params;
  const { status } = req.body || {};
  if (!["approved", "rejected"].includes(status))
    return res.status(400).json({ error: "status doit être 'approved' ou 'rejected'." });

  const payment = getPaymentByIdStmt.get(id);
  if (!payment) return res.status(404).json({ error: "Paiement introuvable." });

  const now = new Date().toISOString();
  updatePaymentStmt.run(status, now, id);

  // Si approuvé → upgrade le plan du client automatiquement
  if (status === "approved") {
    updateUserPlanStmt.run(payment.plan, payment.uid);
  }

  return res.json({ ok: true, id, status });
});

// ══════════════════════════════════════════════
//  GET /api/admin/users — liste tous les clients
// ══════════════════════════════════════════════
app.get("/api/admin/users", requireAuth, (req, res) => {
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "Accès réservé à l'administrateur." });

  const users = db.prepare(`SELECT uid, email, name, plan, created_at FROM users ORDER BY created_at DESC`).all();
  return res.json({ users });
});

// ── Ping (utilisé par le frontend pour vérifier que le backend est joignable)
app.get("/api/ping", (req, res) => res.json({ ok: true }));

// ── Health check
app.get("/", (req, res) => res.json({ status: "ok", app: "TEXTURNO Backend" }));

app.listen(PORT, () => console.log(`✅ Serveur démarré sur le port ${PORT}`));
