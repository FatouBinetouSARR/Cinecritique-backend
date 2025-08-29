const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
dotenv.config();
const mongoose = require("mongoose");
const User = require("./models/User");
const Review = require("./models/Review");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || "development";
const isProduction = NODE_ENV === "production";

// FRONTEND_ORIGIN doit être sans slash final
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "https://cinecritique-projet.vercel.app";

app.use(cors({
  origin: FRONTEND_ORIGIN,
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());

// Static serving for uploaded files
const uploadsRoot = path.join(__dirname, "uploads");
const avatarsDir = path.join(uploadsRoot, "avatars");
if (!fs.existsSync(uploadsRoot)) fs.mkdirSync(uploadsRoot);
if (!fs.existsSync(avatarsDir)) fs.mkdirSync(avatarsDir);
app.use("/uploads", express.static(uploadsRoot));

const JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || "dev_access_secret";
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || "dev_refresh_secret";
const ACCESS_TOKEN_EXPIRES_IN = process.env.ACCESS_TOKEN_EXPIRES_IN || "15m";
const REFRESH_TOKEN_EXPIRES_IN = process.env.REFRESH_TOKEN_EXPIRES_IN || "7d";

const reviewRoutes = require("./routes/reviewRoutes.js");
app.use("/api", reviewRoutes);

const refreshTokensStore = new Map();

// Token helpers
function signAccessToken(payload) {
  return jwt.sign(payload, JWT_ACCESS_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRES_IN });
}

function signRefreshToken(payload) {
  return jwt.sign(payload, JWT_REFRESH_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRES_IN });
}

function setRefreshTokenCookie(res, refreshToken) {
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: isProduction, // HTTPS obligatoire pour production
    sameSite: "none",     // 🔑 pour cross-site cookie
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}

function clearRefreshTokenCookie(res) {
  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: isProduction,
    sameSite: "none",
  });
}

function generateTokens(user) {
  const accessToken = signAccessToken({ userId: user._id, email: user.email });
  const refreshToken = signRefreshToken({ userId: user._id });
  return { accessToken, refreshToken };
}

// Auth middleware
async function authenticateAccessToken(req, res, next) {
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Token d'accès manquant" });
  try {
    const payload = jwt.verify(token, JWT_ACCESS_SECRET);
    req.userId = payload.userId;
    next();
  } catch {
    res.status(401).json({ message: "Token invalide ou expiré" });
  }
}

// MongoDB connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Connecté à MongoDB Atlas"))
  .catch(err => console.error("❌ Erreur MongoDB :", err));

// Routes
app.get("/", (_req, res) => res.send("Bienvenue sur l'API CineCritique 🎬"));

// Register
app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ message: "Email et mot de passe requis" });

  const normalizedEmail = email.toLowerCase().trim();
  if (await User.findOne({ email: normalizedEmail })) {
    return res.status(409).json({ message: "Utilisateur déjà existant" });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = await User.create({ email: normalizedEmail, passwordHash });

    const { accessToken, refreshToken } = generateTokens(newUser);
    refreshTokensStore.set(refreshToken, { userId: newUser._id });
    setRefreshTokenCookie(res, refreshToken);

    res.status(201).json({
      user: { id: newUser._id, email: normalizedEmail },
      accessToken
    });
  } catch (err) {
    console.error("❌ Erreur lors de l'inscription :", err);
    res.status(500).json({ message: "Erreur lors de l'inscription" });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ message: "Email et mot de passe requis" });

  const normalizedEmail = email.toLowerCase().trim();
  const user = await User.findOne({ email: normalizedEmail });
  if (!user) return res.status(401).json({ message: "Identifiants invalides" });

  const isValid = await bcrypt.compare(password, user.passwordHash);
  if (!isValid) return res.status(401).json({ message: "Identifiants invalides" });

  const { accessToken, refreshToken } = generateTokens(user);
  refreshTokensStore.set(refreshToken, { userId: user._id });
  setRefreshTokenCookie(res, refreshToken);

  res.status(200).json({
    user: { id: user._id, email: user.email },
    accessToken
  });
});

// Refresh
app.post("/api/auth/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.cookies || {};
    if (!refreshToken) return res.status(401).json({ message: "Refresh token manquant" });

    const payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
    const stored = refreshTokensStore.get(refreshToken);
    if (!stored || stored.userId !== payload.userId)
      return res.status(401).json({ message: "Refresh token invalide" });

    const user = await User.findById(payload.userId);
    if (!user) return res.status(404).json({ message: "Utilisateur non trouvé" });

    const { accessToken, refreshToken: newRefreshToken } = generateTokens(user);
    refreshTokensStore.delete(refreshToken);
    refreshTokensStore.set(newRefreshToken, { userId: user._id });
    setRefreshTokenCookie(res, newRefreshToken);

    res.status(200).json({ user: { id: user._id, email: user.email }, accessToken });
  } catch {
    return res.status(401).json({ message: "Refresh token invalide ou expiré" });
  }
});

// Logout
app.post("/api/auth/logout", (req, res) => {
  const { refreshToken } = req.cookies || {};
  if (refreshToken) refreshTokensStore.delete(refreshToken);
  clearRefreshTokenCookie(res);
  res.status(200).json({ message: "Déconnecté" });
});

app.listen(PORT, () => console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`));
