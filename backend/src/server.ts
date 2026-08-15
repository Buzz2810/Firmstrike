import dotenv from "dotenv";
import path from "node:path";

// Load .env first
dotenv.config({
  path: path.resolve(process.cwd(), ".env"),
});
// Environment loaded; avoid logging DATABASE_URL or other secrets here.

// Import the app only after .env has been loaded
const { default: app } = await import("./app");
const { logger } = await import("./lib/logger");

const rawPort = process.env.PORT;

if (!rawPort) {
  throw new Error("PORT environment variable is required but was not provided.");
}

const port = Number(rawPort);

if (Number.isNaN(port) || port <= 0) {
  throw new Error(`Invalid PORT value: "${rawPort}"`);
}

app.listen(port, (err) => {
  if (err) {
    logger.error({ err }, "Error listening on port");
    process.exit(1);
  }

  logger.info({ port }, "Server listening");
});