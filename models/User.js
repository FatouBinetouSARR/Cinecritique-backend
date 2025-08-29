const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  username: { type: String, default: "" },
  bio: { type: String, default: "" },
  avatarUrl: { type: String, default: "" },
});

module.exports = mongoose.model("User", userSchema);
