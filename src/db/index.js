const path = require('node:path');
const fs = require('node:fs');
const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  throw new Error(
    'Missing DATABASE_URL. Set it to a PostgreSQL connection string in .env — see .env.example.'
  );
}

// Hosted Postgres providers (Render, Neon, Supabase, etc.) require SSL but
// commonly use certificates that Node's default trust store won't validate
// automatically. `rejectUnauthorized: false` still encrypts the connection
// (protecting credentials/queries in transit) — it just skips CA validation,
// which is the standard, documented approach these providers themselves
// recommend for this exact setup. Local Postgres (no sslmode in the URL)
// skips SSL entirely, since a same-machine connection has nothing to protect
// in transit and most local installs don't have SSL configured at all.
const useSsl = /sslmode=require/.test(process.env.DATABASE_URL) || process.env.PGSSL === 'true';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: useSsl ? { rejectUnauthorized: false } : false,
});

pool.on('error', (err) => {
  // A background/idle client emitting an error should not crash the whole
  // process — log it and let the pool recover the connection.
  console.error('Unexpected error on idle Postgres client:', err);
});

async function initDb() {
  const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  await pool.query(schema);
}

module.exports = { pool, initDb };
