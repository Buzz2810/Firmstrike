"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var drizzle_kit_1 = require("drizzle-kit");
var path_1 = require("path");
if (!process.env.DATABASE_URL) {
    throw new Error("DATABASE_URL, ensure the database is provisioned");
}
exports.default = (0, drizzle_kit_1.defineConfig)({
    schema: path_1.default.join(__dirname, "./src/schema/index.ts").split(path_1.default.sep).join("/"),
    dialect: "postgresql",
    dbCredentials: {
        url: process.env.DATABASE_URL,
    },
});
