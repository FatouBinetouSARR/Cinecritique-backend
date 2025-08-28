// backend/src/middlewares/authenticate.js
const jwt = require("jsonwebtoken");

module.exports = function authenticate(req, res, next) {
  const auth = req.headers.authorization; // "Bearer <token>"
  if (!auth?.startsWith("Bearer ")) return res.status(401).json({ message: "Unauthorized" });

  const token = auth.split(" ")[1];
  try {
    const secret = process.env.JWT_ACCESS_SECRET || "dev_access_secret";
    const payload = jwt.verify(token, secret);
    // Tokens are signed with { userId, email } in server.js
    req.user = { id: payload.userId };
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
};
