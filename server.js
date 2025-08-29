  const express = require("express");
  const cors = require("cors");
  const cookieParser = require("cookie-parser");
  const bcrypt = require("bcryptjs");
  const jwt = require("jsonwebtoken");
  const dotenv = require("dotenv");
  dotenv.config();
  const mongoose = require("mongoose");
  const User = require("./models/User");
  const Review = require("./models/Review"); // ensure model is registered so collection exists
  const multer = require("multer");
  const path = require("path");
  const fs = require("fs");

  const app = express();
  const PORT = process.env.PORT || 3000;
  const NODE_ENV = process.env.NODE_ENV || "development";
  const isProduction = NODE_ENV === "production";
  const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "http://localhost:5173";

  app.use(cors({ origin: FRONTEND_ORIGIN, credentials: true }));
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
      sameSite: "strict",
      path: "/api/auth/refresh",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
  }

  function clearRefreshTokenCookie(res) {
    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: isProduction,
      sameSite: "strict",
      path: "/api/auth/refresh",
    });
  }

  function generateTokens(user) {
    const accessToken = signAccessToken({ userId: user._id, email: user.email });
    const refreshToken = signRefreshToken({ userId: user._id });
    return { accessToken, refreshToken };
  }

  // Middleware d'authentification
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

  // Connexion à MongoDB Atlas
  mongoose.connect(process.env.MONGO_URI)
    .then(async () => {
      console.log("✅ Connecté à MongoDB Atlas");
      // Drop legacy unique index on reviews to allow multiple reviews per user/movie
      try {
        const collection = Review.collection; // use model-bound collection
        const indexes = await collection.indexes();
        if (process.env.NODE_ENV !== "production") {
          console.log("ℹ️ Indexes (avant nettoyage):", indexes);
        }
        const toDrop = indexes.filter((i) => {
          const key = i.key || {};
          const hasCompound = (key.movieId === 1 && key.user === 1) || (key.filmId === 1 && key.userId === 1);
          const hasMovieOnly = (key.movieId === 1 && Object.keys(key).length === 1) || (key.filmId === 1 && Object.keys(key).length === 1);
          const hasUserOnly = (key.user === 1 && Object.keys(key).length === 1) || (key.userId === 1 && Object.keys(key).length === 1);
          return (hasCompound || hasMovieOnly || hasUserOnly) && (i.unique === true);
        });
        for (const idx of toDrop) {
          await collection.dropIndex(idx.name);
          console.log(`🧹 Index unique supprimé: ${idx.name}`);
        }
        // Fallback: en dev, s'il reste encore un index bloquant, on supprime tous les index
        if (process.env.NODE_ENV !== "production") {
          const afterCheck = await collection.indexes();
          const stillHas = afterCheck.some(i => {
            const k = i.key || {};
            const hasCompound = (k.movieId === 1 && k.user === 1) || (k.filmId === 1 && k.userId === 1);
            const hasMovieOnly = (k.movieId === 1 && Object.keys(k).length === 1) || (k.filmId === 1 && Object.keys(k).length === 1);
            const hasUserOnly = (k.user === 1 && Object.keys(k).length === 1) || (k.userId === 1 && Object.keys(k).length === 1);
            return (hasCompound || hasMovieOnly || hasUserOnly) && i.unique === true;
          });
          if (stillHas) {
            await collection.dropIndexes();
            console.log("🧨 Tous les index de 'reviews' ont été supprimés en développement (fallback)");
          }
          const finalIndexes = await collection.indexes();
          console.log("ℹ️ Indexes (après nettoyage):", finalIndexes);
        }
      } catch (e) {
        // ignore if index not found or collection missing
        if (process.env.NODE_ENV !== "production") {
          console.warn("(Info) Impossible de supprimer l'index unique reviews:", e.message);
        }
      }
    })
    .catch(err => console.error("❌ Erreur MongoDB :", err));

  // Routes
  app.get("/", (req, res) => res.send("Bienvenue sur l'API CineCritique 🎬"));

  // Inscription
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

  // Connexion
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

  // Profile
  app.get("/api/profile", authenticateAccessToken, async (req, res) => {
    const user = await User.findById(req.userId).select("-passwordHash");
    if (!user) return res.status(404).json({ message: "Utilisateur non trouvé" });
    res.status(200).json(user);
  });

  // Mise à jour du profil (username, bio)
  app.put("/api/profile", authenticateAccessToken, async (req, res) => {
    try {
      const { username, bio } = req.body || {};
      const update = {};
      if (typeof username === "string") update.username = username;
      if (typeof bio === "string") update.bio = bio;

      const user = await User.findByIdAndUpdate(
        req.userId,
        { $set: update },
        { new: true, select: "-passwordHash" }
      );
      if (!user) return res.status(404).json({ message: "Utilisateur non trouvé" });
      res.status(200).json(user);
    } catch (e) {
      res.status(500).json({ message: "Erreur lors de la mise à jour du profil" });
    }
  });

  // Configuration Multer pour avatar
  const storage = multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, avatarsDir),
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname) || ".png";
      const base = path.basename(file.originalname, ext).replace(/[^a-z0-9_-]/gi, "").slice(0, 32) || "avatar";
      const unique = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
      cb(null, `${base}-${unique}${ext}`);
    },
  });
  const upload = multer({ storage });

  // Upload d'avatar
  app.put("/api/profile/avatar", authenticateAccessToken, upload.single("avatar"), async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ message: "Aucun fichier fourni" });
      const relativeUrl = `/uploads/avatars/${req.file.filename}`;
      const user = await User.findByIdAndUpdate(
        req.userId,
        { $set: { avatarUrl: relativeUrl } },
        { new: true, select: "-passwordHash" }
      );
      if (!user) return res.status(404).json({ message: "Utilisateur non trouvé" });
      res.status(200).json({ avatarUrl: relativeUrl, user });
    } catch (e) {
      res.status(500).json({ message: "Erreur lors du téléversement de l'avatar" });
    }
  });

  // Rafraîchissement du token
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

  // Déconnexion
  app.post("/api/auth/logout", (req, res) => {
    const { refreshToken } = req.cookies || {};
    if (refreshToken) refreshTokensStore.delete(refreshToken);
    clearRefreshTokenCookie(res);
    res.status(200).json({ message: "Déconnecté" });
  });

  app.listen(PORT, () => console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`));
