const mongoose = require("mongoose");

const reviewSchema = new mongoose.Schema(
  {
    movieId: { type: String, required: true }, // id TMDb ou interne
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    rating: { type: Number, min: 1, max: 5, required: true },
    comment: { type: String, trim: true, maxlength: 3000 },
    likes: { type: Number, default: 0 },
    likedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
  },
  { timestamps: true }
);

// Index pour optimiser les recherches de likes
reviewSchema.index({ movieId: 1, 'likedBy': 1 });

module.exports = mongoose.model("Review", reviewSchema);
