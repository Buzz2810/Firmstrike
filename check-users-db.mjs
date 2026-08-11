import pg from "pg";
import dotenv from "dotenv";

dotenv.config({
  path: "../../.env",
});

const { Client } = pg;

const client = new Client({
  connectionString: process.env.DATABASE_URL,
});

async function main() {
  try {
    console.log("Connecting to database...");

    await client.connect();

    console.log("Connected successfully.\n");

    // --------------------------------------------------
    // USERS COLUMNS
    // --------------------------------------------------

    console.log("========== USERS COLUMNS ==========");

    const columns = await client.query(`
      SELECT
        column_name,
        data_type,
        udt_name,
        column_default,
        is_nullable
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'users'
      ORDER BY ordinal_position;
    `);

    console.table(columns.rows);

    // --------------------------------------------------
    // USERS CONSTRAINTS
    // --------------------------------------------------

    console.log("\n========== USERS CONSTRAINTS ==========");

    const constraints = await client.query(`
      SELECT
        tc.constraint_name,
        tc.constraint_type,
        kcu.column_name
      FROM information_schema.table_constraints tc
      LEFT JOIN information_schema.key_column_usage kcu
        ON tc.constraint_name = kcu.constraint_name
        AND tc.table_schema = kcu.table_schema
      WHERE tc.table_schema = 'public'
        AND tc.table_name = 'users'
      ORDER BY tc.constraint_name;
    `);

    console.table(constraints.rows);

    // --------------------------------------------------
    // EXISTING USER
    // --------------------------------------------------

    console.log("\n========== CHECK TEST EMAIL ==========");

    const existing = await client.query(`
      SELECT id, username, email, role
      FROM users
      WHERE email = 'sujal@gmail.com';
    `);

    console.table(existing.rows);

    // --------------------------------------------------
    // TEST INSERT
    // --------------------------------------------------

    console.log("\n========== TEST INSERT ==========");

    try {
      const test = await client.query(`
        INSERT INTO users
          (username, email, password, role)
        VALUES
          (
            '__firmstrike_test__',
            '__firmstrike_test__@example.com',
            'test-password',
            'analyst'
          )
        RETURNING
          id,
          username,
          email,
          role;
      `);

      console.log("TEST INSERT SUCCESS:");
      console.table(test.rows);

      await client.query(`
        DELETE FROM users
        WHERE email = '__firmstrike_test__@example.com';
      `);

      console.log("Test row deleted.");
    } catch (error) {
      console.log("\n========== TEST INSERT ERROR ==========");
      console.log("MESSAGE:", error.message);
      console.log("CODE:", error.code);
      console.log("DETAIL:", error.detail);
      console.log("HINT:", error.hint);
      console.log("TABLE:", error.table);
      console.log("COLUMN:", error.column);
      console.log("CONSTRAINT:", error.constraint);
    }
  } catch (error) {
    console.error("\n========== DATABASE ERROR ==========");
    console.error(error);
  } finally {
    await client.end();
  }
}

main();