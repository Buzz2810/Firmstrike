import "dotenv/config";
import pg from "pg";

const { Client } = pg;

const client = new Client({
  connectionString: process.env.DATABASE_URL,
});

async function migrate() {
  console.log("Adding UNIQUE constraint for scan_id on ai_reports and sbom_reports...");
  await client.connect();

  try {
    await client.query(`ALTER TABLE "ai_reports" ADD CONSTRAINT "ai_reports_scan_id_unique" UNIQUE ("scan_id");`);
  } catch (err) {
    console.log("ai_reports scan_id unique constraint note:", err.message);
  }

  try {
    await client.query(`ALTER TABLE "sbom_reports" ADD CONSTRAINT "sbom_reports_scan_id_unique" UNIQUE ("scan_id");`);
  } catch (err) {
    console.log("sbom_reports scan_id unique constraint note:", err.message);
  }

  await client.end();
  console.log("Constraints updated.");
  process.exit(0);
}

migrate().catch(err => {
  console.error(err);
  process.exit(1);
});
