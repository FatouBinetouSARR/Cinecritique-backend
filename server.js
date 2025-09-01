// cinecritique-backend/server.js
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const mongoose = require("mongoose");
const path = require("path");
const fs = require("fs");

dotenv.config();

// Import modèles et routes
const User = require("./models/User");
const Review = require("./models/Review");
const RefreshToken = require("./models/RefreshToken");
const reviewRoutes = require("./routes/reviewRoutes");

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || "development";
const isProduction = NODE_ENV === "production";

// ===============================
// 🔹 FRONTEND_ORIGIN / CORS
// ===============================
const devOrigins = ["http://localhost:5173", "http://localhost:5174", "http://localhost:3000"];
const allowedOrigins = isProduction
  ? [process.env.FRONTEND_ORIGIN].filter(Boolean) // Prod = une seule origine définie dans .env
  : devOrigins; // Dev = plusieurs localhost

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        console.log("❌ Origin non autorisée :", origin);
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true, // nécessaire pour cookies (refresh token)
  })
);

// ===============================
// 🔹 Middlewares
// ===============================
app.use(express.json());
app.use(cookieParser());

// ===============================
// 🔹 Static files (avatars/uploads)
// ===============================
const uploadsRoot = path.join(__dirname, "uploads");
const avatarsDir = path.join(uploadsRoot, "avatars");
if (!fs.existsSync(uploadsRoot)) fs.mkdirSync(uploadsRoot);
if (!fs.existsSync(avatarsDir)) fs.mkdirSync(avatarsDir);
app.use("/uploads", express.static(uploadsRoot));

// ===============================
// 🔹 JWT Config
// ===============================
const JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || "dev_access_secret";
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || "dev_refresh_secret";
const ACCESS_TOKEN_EXPIRES_IN = process.env.ACCESS_TOKEN_EXPIRES_IN || "15m";
const REFRESH_TOKEN_EXPIRES_IN = process.env.REFRESH_TOKEN_EXPIRES_IN || "7d";

// ===============================
// 🔹 Helpers Tokens
// ===============================
function signAccessToken(payload) {
  return jwt.sign(payload, JWT_ACCESS_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRES_IN });
}

function signRefreshToken(payload) {
  return jwt.sign(payload, JWT_REFRESH_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRES_IN });
}

function setRefreshTokenCookie(res, refreshToken) {
  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? "none" : "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 jours
  });
}

function clearRefreshTokenCookie(res) {
  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? "none" : "lax",
  });
}

async function generateTokens(user) {
  const accessToken = signAccessToken({ userId: user._id, email: user.email });
  const refreshToken = signRefreshToken({ userId: user._id });

  await RefreshToken.create({ userId: user._id, token: refreshToken });

  return { accessToken, refreshToken };
}

// ===============================
// 🔹 Connexion MongoDB
// ===============================
mongoose
  .connect(process.env.MONGO_URI, { dbName: "cinecritique" })
  .then(() => console.log("✅ Connecté à MongoDB Atlas"))
  .catch((err) => console.error("❌ Erreur MongoDB :", err));

// ===============================
// 🔹 Middleware d'authentification
// ===============================
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Token d'accès manquant ou invalide" });
    }

    const token = authHeader.split(" ")[1];
    const payload = jwt.verify(token, JWT_ACCESS_SECRET);

    const user = await User.findById(payload.userId);
    if (!user) return res.status(404).json({ message: "Utilisateur non trouvé" });

    req.user = user;
    next();
  } catch (err) {
    console.error("Erreur d'authentification :", err);
    return res.status(401).json({ message: "Session expirée ou invalide" });
  }
};

// ===============================
// 🔹 Routes
// ===============================
app.get("/", (_req, res) => res.send("🎬 Bienvenue sur l'API CineCritique 🚀"));

// Reviews
app.use("/api", reviewRoutes);

// Profil utilisateur
app.get("/api/profile", authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select("-passwordHash");
    if (!user) return res.status(404).json({ message: "Utilisateur non trouvé" });
    res.status(200).json(user);
  } catch (err) {
    console.error("Erreur lors de la récupération du profil :", err);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

app.put("/api/profile", authenticate, async (req, res) => {
  try {
    const { username, bio } = req.body;
    const updates = {};
    if (username !== undefined) updates.username = username;
    if (bio !== undefined) updates.bio = bio;

    const user = await User.findByIdAndUpdate(
      req.user._id,
      { $set: updates },
      { new: true, runValidators: true }
    ).select("-passwordHash");

    res.status(200).json(user);
  } catch (err) {
    console.error("Erreur lors de la mise à jour du profil :", err);
    res.status(500).json({ message: "Erreur lors de la mise à jour du profil" });
  }
});

// ===============================
// 🔹 Auth (Register/Login/Refresh/Logout)
// ===============================
app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ message: "Email et mot de passe requis" });

  const normalizedEmail = email.toLowerCase().trim();
  if (await User.findOne({ email: normalizedEmail }))
    return res.status(409).json({ message: "Utilisateur déjà existant" });

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = await User.create({ email: normalizedEmail, passwordHash });

    const { accessToken, refreshToken } = await generateTokens(newUser);
    setRefreshTokenCookie(res, refreshToken);

    res.status(201).json({
      user: { id: newUser._id, email: normalizedEmail },
      accessToken,
    });
  } catch (err) {
    console.error("❌ Erreur register :", err);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// --- Login
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ message: "Email et mot de passe requis" });

  const normalizedEmail = email.toLowerCase().trim();
  const user = await User.findOne({ email: normalizedEmail });
  if (!user) return res.status(401).json({ message: "Identifiants invalides" });

  const isValid = await bcrypt.compare(password, user.passwordHash);
  if (!isValid) return res.status(401).json({ message: "Identifiants invalides" });

  const { accessToken, refreshToken } = await generateTokens(user);
  setRefreshTokenCookie(res, refreshToken);

  res.status(200).json({ user: { id: user._id, email: user.email }, accessToken });
});

// --- Refresh
app.post("/api/auth/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.cookies || {};
    if (!refreshToken)
      return res.status(401).json({ message: "Refresh token manquant" });

    const payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
    const storedToken = await RefreshToken.findOne({
      token: refreshToken,
      userId: payload.userId,
    });
    if (!storedToken)
      return res.status(401).json({ message: "Refresh token invalide" });

    const user = await User.findById(payload.userId);
    if (!user) return res.status(404).json({ message: "Utilisateur non trouvé" });

    const { accessToken, refreshToken: newRefreshToken } = await generateTokens(user);
    await RefreshToken.deleteOne({ token: refreshToken });
    setRefreshTokenCookie(res, newRefreshToken);

    res.status(200).json({ user: { id: user._id, email: user.email }, accessToken });
  } catch (err) {
    console.error("❌ Refresh error:", err);
    res.status(401).json({ message: "Refresh token invalide ou expiré" });
  }
});

// --- Logout
app.post("/api/auth/logout", async (req, res) => {
  const { refreshToken } = req.cookies || {};
  if (refreshToken) await RefreshToken.deleteOne({ token: refreshToken });
  clearRefreshTokenCookie(res);
  res.status(200).json({ message: "Déconnecté" });
});

// ===============================
// 🔹 Start Server
// ===============================
app.listen(PORT, () =>
  console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`)
);
