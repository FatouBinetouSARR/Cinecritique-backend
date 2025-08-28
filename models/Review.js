const mongoose = require("mongoose");

const reviewSchema = new mongoose.Schema(
  {
    movieId: { type: String, required: true }, // id TMDb ou interne
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    rating: { type: Number, min: 1, max: 5, required: true },
    comment: { type: String, trim: true, maxlength: 3000 },
    likes: { type: Number, default: 0 },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Review", reviewSchema);
