import { Router, type IRouter } from "express";
import { db, usersTable } from "@workspace/db";
import { eq } from "drizzle-orm";
import crypto from "crypto";
import { and } from "drizzle-orm";

const otpStore = new Map<string, { code: string; expires: Date }>();

const router: IRouter = Router();

function hashPassword(password: string): string {
  return crypto.createHash("sha256").update(password + "viv_salt").digest("hex");
}

function generateToken(userId: number): string {
  return Buffer.from(`${userId}:${Date.now()}:viv_token`).toString("base64");
}

function verifyToken(token: string): number | null {
  try {
    const decoded = Buffer.from(token, "base64").toString("utf8");
    const parts = decoded.split(":");
    const id = Number(parts[0]);
    if (!Number.isNaN(id)) return id;
  } catch (e) {}
  return null;
}

function generateOtp(): string {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

router.post("/auth/register", async (req, res): Promise<void> => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    res.status(400).json({ error: "Missing required fields" });
    return;
  }
  const existing = await db.select({
    id: usersTable.id,
    username: usersTable.username,
    email: usersTable.email,
    password: usersTable.password,
    role: usersTable.role,
    createdAt: usersTable.createdAt,
  }).from(usersTable).where(eq(usersTable.email, email));
  if (existing.length > 0) {
    res.status(400).json({ error: "Email already registered" });
    return;
  }
  const [user] = await db.insert(usersTable).values({
    username,
    email,
    password: hashPassword(password),
    role: "analyst",
  }).returning();
  // Generate initial OTP for verification (stored in-memory until DB migration)
  const otp = generateOtp();
  const expires = new Date(Date.now() + 5 * 60 * 1000);
  otpStore.set(user.email, { code: otp, expires });
  // In production, send OTP via email/SMS. For now return it for testing.
  res.status(201).json({
    message: "Registered - verify OTP",
    otp,
    expires: expires.toISOString(),
    user: { id: user.id, username: user.username, email: user.email, role: user.role, createdAt: user.createdAt.toISOString() },
  });
});

router.post("/auth/login", async (req, res): Promise<void> => {
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400).json({ error: "Missing required fields" });
    return;
  }
  const [user] = await db.select({
    id: usersTable.id,
    username: usersTable.username,
    email: usersTable.email,
    password: usersTable.password,
    role: usersTable.role,
    createdAt: usersTable.createdAt,
  }).from(usersTable).where(eq(usersTable.email, email));
  if (!user || user.password !== hashPassword(password)) {
    res.status(401).json({ error: "Invalid credentials" });
    return;
  }
  // On successful password check, require OTP verification before issuing token
  const otp = generateOtp();
  const expires = new Date(Date.now() + 5 * 60 * 1000);
  otpStore.set(user.email, { code: otp, expires });
  // In production, send OTP to user's email. Return OTP for dev/testing.
  res.json({
    message: "OTP sent",
    otp,
    expires: expires.toISOString(),
    user: { id: user.id, username: user.username, email: user.email, role: user.role, createdAt: user.createdAt.toISOString() },
  });
});

router.post("/auth/request-otp", async (req, res): Promise<void> => {
  const { email } = req.body;
  if (!email) {
    res.status(400).json({ error: "Missing email" });
    return;
  }
  const [user] = await db.select({
    id: usersTable.id,
    username: usersTable.username,
    email: usersTable.email,
    password: usersTable.password,
    role: usersTable.role,
    createdAt: usersTable.createdAt,
  }).from(usersTable).where(eq(usersTable.email, email));
  if (!user) {
    res.status(404).json({ error: "User not found" });
    return;
  }
  const otp = generateOtp();
  const expires = new Date(Date.now() + 5 * 60 * 1000);
  otpStore.set(user.email, { code: otp, expires });
  res.json({ message: "OTP generated", otp, expires: expires.toISOString() });
});

router.post("/auth/verify-otp", async (req, res): Promise<void> => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    res.status(400).json({ error: "Missing fields" });
    return;
  }
  const [user] = await db.select({
    id: usersTable.id,
    username: usersTable.username,
    email: usersTable.email,
    password: usersTable.password,
    role: usersTable.role,
    createdAt: usersTable.createdAt,
  }).from(usersTable).where(eq(usersTable.email, email));
  if (!user) {
    res.status(404).json({ error: "User not found" });
    return;
  }
  const stored = otpStore.get(user.email);
  if (!stored || stored.code !== otp || stored.expires < new Date()) {
    res.status(400).json({ error: "Invalid or expired OTP" });
    return;
  }
  otpStore.delete(user.email);
  const token = generateToken(user.id);
  res.json({ token, user: { id: user.id, username: user.username, email: user.email, role: user.role, createdAt: user.createdAt.toISOString() } });
});

router.get("/auth/me", async (req, res): Promise<void> => {
  const auth = req.headers.authorization;
  if (!auth) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const id = verifyToken(auth.replace(/Bearer\s+/i, ""));
  if (!id) {
    res.status(401).json({ error: "Invalid token" });
    return;
  }
  const [user] = await db.select({
    id: usersTable.id,
    username: usersTable.username,
    email: usersTable.email,
    password: usersTable.password,
    role: usersTable.role,
    createdAt: usersTable.createdAt,
  }).from(usersTable).where(eq(usersTable.id, id));
  if (!user) {
    res.status(404).json({ error: "User not found" });
    return;
  }
  res.json({ id: user.id, username: user.username, email: user.email, role: user.role, createdAt: user.createdAt.toISOString() });
});

export default router;
