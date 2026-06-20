// v2
// ══════════════════════════════════════════════
//  Reports & Summary — Backend Railway
//  Routes : POST /api/login  |  POST /api/analyze
// ══════════════════════════════════════════════
require("dotenv").config();
const express    = require("express");
const cors       = require("cors");
const jwt        = require("jsonwebtoken");
const fetch      = require("node-fetch");

const app  = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

// ── Variables d'environnement (définies dans Railway)
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || "";
const JWT_SECRET        = process.env.JWT_SECRET        || "changez-ce-secret";
const ADMIN_EMAIL       = process.env.ADMIN_EMAIL       || "admin@texturno.com";
const ADMIN_PASSWORD    = process.env.ADMIN_PASSWORD    || "";
const PORT              = process.env.PORT              || 3000;

// ── Vérification au démarrage
if (!ANTHROPIC_API_KEY) console.warn("⚠️  ANTHROPIC_API_KEY manquante !");
if (!ADMIN_PASSWORD)    console.warn("⚠️  ADMIN_PASSWORD manquante !");

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

// ══════════════════════════════════════════════
//  POST /api/login
// ══════════════════════════════════════════════
app.post("/api/login", (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: "Email et mot de passe requis." });

  if (
    email.trim().toLowerCase() === ADMIN_EMAIL.toLowerCase() &&
    password === ADMIN_PASSWORD
  ) {
    const token = jwt.sign(
      { email: ADMIN_EMAIL, role: "admin" },
      JWT_SECRET,
      { expiresIn: "12h" }
    );
    return res.json({ token, user: { email: ADMIN_EMAIL, role: "admin", name: "Administratrice" } });
  }

  return res.status(401).json({ error: "Email ou mot de passe incorrect." });
});

// ══════════════════════════════════════════════
//  POST /api/analyze  (protégé JWT)
// ══════════════════════════════════════════════
app.post("/api/analyze", requireAuth, async (req, res) => {
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

// ── Health check
app.get("/", (req, res) => res.json({ status: "ok", app: "TEXTURNO Backend" }));

app.listen(PORT, () => console.log(`✅ Serveur démarré sur le port ${PORT}`)
