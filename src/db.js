const crypto = require("crypto");
const initSqlJs = require("sql.js");

// Hash password dengan scrypt + salt acak
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64);

  return `${salt.toString("hex")}:${hash.toString("hex")}`;
}

// Verifikasi password
function verifyPassword(password, storedPassword) {
  const [saltHex, hashHex] = storedPassword.split(":");

  if (!saltHex || !hashHex) {
    return false;
  }

  const salt = Buffer.from(saltHex, "hex");
  const storedHash = Buffer.from(hashHex, "hex");

  const derivedHash = crypto.scryptSync(password, salt, 64);

  return (
    derivedHash.length === storedHash.length &&
    crypto.timingSafeEqual(derivedHash, storedHash)
  );
}

// Membuat database SQLite in-memory berisi data contoh
async function createDb() {
  const SQL = await initSqlJs();
  const db = new SQL.Database();

  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY,
      username TEXT UNIQUE,
      password_hash TEXT,
      full_name TEXT,
      role TEXT,
      balance INTEGER
    )
  `);

  const seed = [
    ["admin", "Admin#2024", "Administrator SecurePay", "admin", 0],
    ["budi", "budi123", "Budi Santoso", "customer", 5000000],
    ["sari", "sari123", "Sari Wulandari", "customer", 7500000],
    ["andi", "andi123", "Andi Pratama", "customer", 2500000],
  ];

  const stmt = db.prepare(
    "INSERT INTO users (username, password_hash, full_name, role, balance) VALUES (?, ?, ?, ?, ?)",
  );

  for (const [u, p, name, role, bal] of seed) {
    stmt.run([u, hashPassword(p), name, role, bal]);
  }

  stmt.free();

  return db;
}

// Helper SELECT
function all(db, sql) {
  const result = db.exec(sql);

  if (result.length === 0) return [];

  const { columns, values } = result[0];

  return values.map((row) =>
    Object.fromEntries(row.map((v, i) => [columns[i], v])),
  );
}

// Helper SELECT dengan parameter
function allBound(db, sql, params) {
  const stmt = db.prepare(sql);
  stmt.bind(params);

  const rows = [];

  while (stmt.step()) {
    rows.push(stmt.getAsObject());
  }

  stmt.free();

  return rows;
}

module.exports = {
  createDb,
  hashPassword,
  verifyPassword,
  all,
  allBound,
};
