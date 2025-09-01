// cinecritique-backend/models/RefreshToken.js
const mongoose = require("mongoose");

const refreshTokenSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, unique: true }, // 🔹 unique par utilisateur
  token: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: "7d" } // TTL: auto-supprimé après 7 jours
});

module.exports = mongoose.model("RefreshToken", refreshTokenSchema);
