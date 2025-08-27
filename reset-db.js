import { db, initDb } from "./db.js";
import bcrypt from "bcryptjs";

initDb();

db.exec(`
DROP TABLE IF EXISTS milestones;
DROP TABLE IF EXISTS bids;
DROP TABLE IF EXISTS jobs;
DROP TABLE IF EXISTS users;
`);

import("./db.js").then(({ initDb }) => {
  initDb();

  const pw1 = bcrypt.hashSync("customer123", 10);
  const pw2 = bcrypt.hashSync("contractor123", 10);
  const pw3 = bcrypt.hashSync("agent123", 10);

  const insertUser = db.prepare("INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)");
  const customerId = insertUser.run("Khun Customer", "customer@example.com", pw1, "customer").lastInsertRowid;
  const contractorId = insertUser.run("Somsak Contractor", "contractor@example.com", pw2, "contractor").lastInsertRowid;
  const agentId = insertUser.run("BuildEasy Agent", "agent@example.com", pw3, "agent").lastInsertRowid;

  const insertJob = db.prepare(`
    INSERT INTO jobs (customer_id, agent_id, commission_pct, title, description, budget_min, budget_max, location, status, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  `);
  insertJob.run(
    customerId, agentId, 7.5,
    "Kitchen Renovation (Bangkok Condo)",
    "Replace cabinets, countertops, and lighting.",
    50000, 80000, "Bangkok"
  );

  console.log("✅ Database reset & seeded.");
  process.exit(0);
});
