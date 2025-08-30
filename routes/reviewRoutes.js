const express = require("express");
const authenticate = require("../middlewares/authenticate");
const {
  getReviewsByMovie,
  createReview,
  updateReview,
  deleteReview,
  getMyReviews,
  getTopRatedMovies,
  toggleLikeReview,
  checkUserLike,
  getPopularReviews,
  getTopCritics,
} = require("../controllers/reviewController");

const router = express.Router();

// Film → toutes les critiques
router.get("/movies/:movieId/reviews", getReviewsByMovie);

// Actions utilisateur (protégées)
router.post("/movies/:movieId/reviews", authenticate, createReview);
router.put("/movies/:movieId/reviews/:id", authenticate, updateReview);
router.delete("/movies/:movieId/reviews/:id", authenticate, deleteReview);

// (optionnel) Mes critiques
router.get("/reviews/mine", authenticate, getMyReviews);

// Classement des films les mieux notés (agrégés depuis les critiques)
router.get("/reviews/top-rated", getTopRatedMovies);

// Gestion des likes
router.post("/reviews/:id/like", authenticate, toggleLikeReview);
router.get("/reviews/:id/like", authenticate, checkUserLike);

// Nouvelles routes pour la page d'accueil
router.get("/reviews/popular", getPopularReviews);
router.get("/users/top-critics", getTopCritics);

module.exports = router;
