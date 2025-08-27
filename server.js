import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { db, initDb } from "./db.js";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";

app.use(cors());
app.use(helmet());
app.use(express.json({ limit: "5mb" }));
app.use(morgan("dev"));

initDb();

// --- helpers ---
function makeToken(user) {
  const payload = { id: user.id, role: user.role, name: user.name, email: user.email };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });
}
function auth(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}
function requireRole(role) { return requireRoles([role]); }
function requireRoles(roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user?.role)) return res.status(403).json({ error: "Forbidden" });
    next();
  };
}

// --- auth ---
app.post("/auth/register", (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password || !role) return res.status(400).json({ error: "Missing fields" });
  if (!["customer", "contractor", "agent"].includes(role)) return res.status(400).json({ error: "Invalid role" });
  const exists = db.prepare("SELECT id FROM users WHERE email = ?").get(email.toLowerCase());
  if (exists) return res.status(409).json({ error: "Email already used" });
  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare("INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)")
                .run(name, email.toLowerCase(), hash, role);
  const user = db.prepare("SELECT id, name, email, role FROM users WHERE id = ?").get(info.lastInsertRowid);
  res.json({ user, token: makeToken(user) });
});

app.post("/auth/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Missing fields" });
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email.toLowerCase());
  if (!user) return res.status(401).json({ error: "Invalid credentials" });
  const ok = bcrypt.compareSync(password, user.password_hash || "");
  if (!ok) return res.status(401).json({ error: "Invalid credentials" });
  const publicUser = { id: user.id, name: user.name, email: user.email, role: user.role };
  res.json({ user: publicUser, token: makeToken(publicUser) });
});

// --- users (agents only) ---
app.get("/users", auth, requireRoles(["agent"]), (req, res) => {
  const { role, q } = req.query;
  let sql = "SELECT id, name, email, role FROM users WHERE 1=1";
  const params = [];
  if (role) { sql += " AND role = ?"; params.push(role); }
  if (q) { sql += " AND (name LIKE ? OR email LIKE ?)"; params.push(`%${q}%`, `%${q}%`); }
  res.json(db.prepare(sql).all(...params));
});

// --- jobs ---
app.post("/jobs", auth, requireRoles(["customer", "agent"]), (req, res) => {
  const { title, description, budgetMin, budgetMax, location, customerId, customerEmail, commissionPct } = req.body;
  if (!title) return res.status(400).json({ error: "Title required" });

  let ownerId = req.user.id;
  let agentId = null;
  let commission = 0;
  if (req.user.role === "agent") {
    agentId = req.user.id;
    commission = Number(commissionPct || 0);
    if (customerId) ownerId = customerId;
    else if (customerEmail) {
      const found = db.prepare("SELECT id FROM users WHERE email = ? AND role = 'customer'")
                     .get(String(customerEmail).toLowerCase());
      if (!found) return res.status(400).json({ error: "Customer not found by email" });
      ownerId = found.id;
    }
  }

  const info = db.prepare(`
    INSERT INTO jobs (customer_id, agent_id, commission_pct, title, description, budget_min, budget_max, location, status, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  `).run(ownerId, agentId, commission, title, description || "", budgetMin || 0, budgetMax || 0, location || "");
  const job = db.prepare("SELECT * FROM jobs WHERE id = ?").get(info.lastInsertRowid);
  res.json({ job });
});

app.get("/jobs", auth, (req, res) => {
  const { status } = req.query;
  let rows;
  if (req.user.role === "agent") {
    rows = status ? db.prepare("SELECT * FROM jobs WHERE status = ? ORDER BY id DESC").all(status)
                  : db.prepare("SELECT * FROM jobs ORDER BY id DESC").all();
  } else if (req.user.role === "contractor") {
    rows = status ? db.prepare("SELECT * FROM jobs WHERE status = ? ORDER BY id DESC").all(status)
                  : db.prepare("SELECT * FROM jobs WHERE status = 'open' ORDER BY id DESC").all();
  } else {
    rows = status ? db.prepare("SELECT * FROM jobs WHERE customer_id = ? AND status = ? ORDER BY id DESC").all(req.user.id, status)
                  : db.prepare("SELECT * FROM jobs WHERE customer_id = ? ORDER BY id DESC").all(req.user.id);
  }
  res.json(rows);
});

app.get("/jobs/:id", auth, (req, res) => {
  const job = db.prepare("SELECT * FROM jobs WHERE id = ?").get(req.params.id);
  if (!job) return res.status(404).json({ error: "Not found" });
  if (req.user.role === "agent") return res.json(job);
  if (req.user.role === "customer" && job.customer_id !== req.user.id) return res.status(403).json({ error: "Forbidden" });
  res.json(job);
});

// --- bids ---
app.post("/jobs/:id/bids", auth, requireRoles(["contractor"]), (req, res) => {
  const job = db.prepare("SELECT * FROM jobs WHERE id = ?").get(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found" });
  if (job.status !== "open") return res.status(400).json({ error: "Job not open for bids" });
  const { amount, durationDays, message } = req.body;
  const info = db.prepare(`
    INSERT INTO bids (job_id, contractor_id, amount, duration_days, message, status, created_at)
    VALUES (?, ?, ?, ?, ?, 'pending', strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  `).run(job.id, req.user.id, amount || 0, durationDays || 0, message || "");
  const bid = db.prepare("SELECT * FROM bids WHERE id = ?").get(info.lastInsertRowid);
  res.json({ bid });
});

app.get("/jobs/:id/bids", auth, (req, res) => {
  const job = db.prepare("SELECT * FROM jobs WHERE id = ?").get(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found" });
  if (req.user.role === "customer" && job.customer_id !== req.user.id) return res.status(403).json({ error: "Forbidden" });
  const bids = db.prepare(`
    SELECT b.*, u.name as contractor_name
    FROM bids b LEFT JOIN users u ON u.id = b.contractor_id
    WHERE job_id = ? ORDER BY b.id DESC
  `).all(job.id);
  res.json(bids);
});

app.post("/bids/:id/accept", auth, requireRoles(["customer","agent"]), (req, res) => {
  const bid = db.prepare("SELECT * FROM bids WHERE id = ?").get(req.params.id);
  if (!bid) return res.status(404).json({ error: "Bid not found" });
  const job = db.prepare("SELECT * FROM jobs WHERE id = ?").get(bid.job_id);
  if (!job) return res.status(404).json({ error: "Job not found" });
  if (!(req.user.role === "agent" || job.customer_id === req.user.id)) return res.status(403).json({ error: "Forbidden" });

  const tx = db.transaction(() => {
    db.prepare("UPDATE bids SET status = 'accepted' WHERE id = ?").run(bid.id);
    db.prepare("UPDATE bids SET status = 'rejected' WHERE job_id = ? AND id != ?").run(job.id, bid.id);
    db.prepare("UPDATE jobs SET status = 'in_progress', contractor_id = ? WHERE id = ?").run(bid.contractor_id, job.id);
  });
  tx();

  const updatedBid = db.prepare("SELECT * FROM bids WHERE id = ?").get(bid.id);
  const updatedJob = db.prepare("SELECT * FROM jobs WHERE id = ?").get(job.id);
  res.json({ bid: updatedBid, job: updatedJob });
});

// --- milestones ---
app.post("/jobs/:id/milestones", auth, (req, res) => {
  const job = db.prepare("SELECT * FROM jobs WHERE id = ?").get(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found" });
  const isOwner = req.user.role === "customer" && job.customer_id === req.user.id;
  const isAssigned = req.user.role === "contractor" && job.contractor_id === req.user.id;
  const isAgent = req.user.role === "agent";
  if (!isOwner && !isAssigned && !isAgent) return res.status(403).json({ error: "Forbidden" });

  const { title, amount, dueDate } = req.body;
  const info = db.prepare(`
    INSERT INTO milestones (job_id, title, amount, status, due_date)
    VALUES (?, ?, ?, 'pending', ?)
  `).run(job.id, title || "", amount || 0, dueDate || null);
  const ms = db.prepare("SELECT * FROM milestones WHERE id = ?").get(info.lastInsertRowid);
  res.json({ milestone: ms });
});

app.get("/jobs/:id/milestones", auth, (req, res) => {
  const job = db.prepare("SELECT * FROM jobs WHERE id = ?").get(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found" });
  const isOwner = req.user.role === "customer" && job.customer_id === req.user.id;
  const isAssigned = req.user.role === "contractor" && job.contractor_id === req.user.id;
  const isAgent = req.user.role === "agent";
  if (!isOwner && !isAssigned && !isAgent) return res.status(403).json({ error: "Forbidden" });

  const ms = db.prepare("SELECT * FROM milestones WHERE job_id = ? ORDER BY id ASC").all(job.id);
  res.json(ms);
});

app.patch("/milestones/:id/complete", auth, (req, res) => {
  const ms = db.prepare("SELECT * FROM milestones WHERE id = ?").get(req.params.id);
  if (!ms) return res.status(404).json({ error: "Milestone not found" });
  const job = db.prepare("SELECT * FROM jobs WHERE id = ?").get(ms.job_id);
  const isOwner = req.user.role === "customer" && job.customer_id === req.user.id;
  const isAssigned = req.user.role === "contractor" && job.contractor_id === req.user.id;
  const isAgent = req.user.role === "agent";
  if (!isOwner && !isAssigned && !isAgent) return res.status(403).json({ error: "Forbidden" });

  db.prepare("UPDATE milestones SET status = 'completed' WHERE id = ?").run(ms.id);
  const updated = db.prepare("SELECT * FROM milestones WHERE id = ?").get(ms.id);
  res.json(updated);
});

// --- agent assignment ---
app.post("/jobs/:id/assign-agent", auth, requireRoles(["agent"]), (req, res) => {
  const { id } = req.params;
  const { agentId, commissionPct } = req.body;
  const job = db.prepare("SELECT * FROM jobs WHERE id = ?").get(id);
  if (!job) return res.status(404).json({ error: "Job not found" });
  const targetAgentId = agentId || req.user.id;
  db.prepare("UPDATE jobs SET agent_id = ?, commission_pct = ? WHERE id = ?")
    .run(targetAgentId, Number(commissionPct || 0), id);
  const updated = db.prepare("SELECT * FROM jobs WHERE id = ?").get(id);
  res.json(updated);
});

// --- health ---
app.get("/", (req, res) => res.json({ ok: true, service: "BuildEasy Backend" }));

app.listen(PORT, () => console.log(`✅ Backend on http://localhost:${PORT}`));
