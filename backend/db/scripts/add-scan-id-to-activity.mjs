#!/usr/bin/env node
import pg from 'pg';

const { Client } = pg;

async function main() {
  const url = process.env.DATABASE_URL;
  if (!url) {
    console.error('DATABASE_URL not set. Aborting.');
    process.exit(1);
  }

  const client = new Client({ connectionString: url });
  await client.connect();

  try {
    console.log('Adding scan_id column to activity table (if missing)...');
    await client.query(`ALTER TABLE activity ADD COLUMN IF NOT EXISTS scan_id integer;`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_activity_scan_id ON activity(scan_id);`);
    console.log('Done.');
  } catch (err) {
    console.error('Migration failed:', err);
    process.exitCode = 2;
  } finally {
    await client.end();
  }
}

main();
