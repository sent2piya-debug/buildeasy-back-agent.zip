import Database from "better-sqlite3";
import path from "path";
import url from "url";

const __dirname = path.dirname(url.fileURLToPath(import.meta.url));
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "buildeasy.db");

export const db = new Database(DB_PATH);

export function initDb() {
  const schema = `
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT CHECK(role IN ('customer','contractor','agent')) NOT NULL
  );

  CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER NOT NULL,
    contractor_id INTEGER,
    agent_id INTEGER,
    commission_pct REAL DEFAULT 0,
    title TEXT NOT NULL,
    description TEXT,
    budget_min REAL,
    budget_max REAL,
    location TEXT,
    status TEXT CHECK(status IN ('open','in_progress','completed','cancelled')) NOT NULL DEFAULT 'open',
    created_at TEXT,
    FOREIGN KEY(customer_id) REFERENCES users(id),
    FOREIGN KEY(contractor_id) REFERENCES users(id),
    FOREIGN KEY(agent_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS bids (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    contractor_id INTEGER NOT NULL,
    amount REAL,
    duration_days INTEGER,
    message TEXT,
    status TEXT CHECK(status IN ('pending','accepted','rejected')) NOT NULL DEFAULT 'pending',
    created_at TEXT,
    FOREIGN KEY(job_id) REFERENCES jobs(id),
    FOREIGN KEY(contractor_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS milestones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    title TEXT,
    amount REAL,
    status TEXT CHECK(status IN ('pending','completed')) NOT NULL DEFAULT 'pending',
    due_date TEXT,
    FOREIGN KEY(job_id) REFERENCES jobs(id)
  );
  `;
  db.exec(schema);
}
