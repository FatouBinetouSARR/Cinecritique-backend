const Review = require("../models/Review");

// GET /api/movies/:movieId/reviews
async function getReviewsByMovie(req, res) {
  try {
    const { movieId } = req.params;
    const reviews = await Review.find({ movieId }).populate("user", "username email");
    res.json(reviews);
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
}

// POST /api/movies/:movieId/reviews
async function createReview(req, res) {
  try {
    const { movieId } = req.params;
    const { rating, comment } = req.body;

    if (!rating || rating < 1 || rating > 5)
      return res.status(400).json({ message: "rating doit être entre 1 et 5" });

    const review = await Review.create({
      movieId,
      user: req.user.id,
      rating,
      comment,
    });

    const populated = await review.populate("user", "username email");
    res.status(201).json(populated);
  } catch (e) {
    if (e.code === 11000) {
      return res.status(400).json({ message: "Vous avez déjà laissé une critique pour ce film" });
    }
    res.status(500).json({ message: e.message });
  }
}

// PUT /api/movies/:movieId/reviews/:id
async function updateReview(req, res) {
  try {
    const { id } = req.params;
    const { rating, comment } = req.body;

    const review = await Review.findOne({ _id: id, user: req.user.id });
    if (!review) return res.status(404).json({ message: "Critique non trouvée" });

    if (rating !== undefined) {
      if (rating < 1 || rating > 5)
        return res.status(400).json({ message: "rating doit être entre 1 et 5" });
      review.rating = rating;
    }
    if (comment !== undefined) review.comment = comment;

    await review.save();
    const populated = await review.populate("user", "username email");
    res.json(populated);
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
}

// DELETE /api/movies/:movieId/reviews/:id
async function deleteReview(req, res) {
  try {
    const { id } = req.params;

    const review = await Review.findOneAndDelete({ _id: id, user: req.user.id });
    if (!review) return res.status(404).json({ message: "Critique non trouvée" });

    res.json({ message: "Critique supprimée" });
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
}

// (optionnel) GET /api/reviews/mine
async function getMyReviews(req, res) {
  try {
    const reviews = await Review.find({ user: req.user.id }).sort({ createdAt: -1 });
    res.json(reviews);
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
}

// GET /api/reviews/top-rated
async function getTopRatedMovies(req, res) {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 20, 100);
    const minCount = parseInt(req.query.minCount, 10) || 1;

    const results = await Review.aggregate([
      {
        $group: {
          _id: "$movieId",
          avgRating: { $avg: "$rating" },
          reviewCount: { $sum: 1 },
        },
      },
      { $match: { reviewCount: { $gte: minCount } } },
      { $sort: { avgRating: -1, reviewCount: -1 } },
      { $limit: limit },
    ]);

    const payload = results.map((r) => ({
      movieId: r._id,
      avgRating: Number(r.avgRating.toFixed(2)),
      reviewCount: r.reviewCount,
    }));

    res.json(payload);
  } catch (e) {
    res.status(500).json({ message: e.message });
  }
}

// GET /api/reviews/popular - Récupérer les avis populaires triés par likes
async function getPopularReviews(req, res) {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 10, 50);
    
    const reviews = await Review.find()
      .populate("user", "username email")
      .sort({ likes: -1 })
      .limit(limit);
    
    res.json(reviews);
  } catch (error) {
    console.error('Erreur lors de la récupération des avis populaires:', error);
    res.status(500).json({ message: 'Erreur lors de la récupération des avis populaires' });
  }
}

// GET /api/users/top-critics - Récupérer les critiqueurs populaires
async function getTopCritics(req, res) {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 3, 10);
    
    const topCritics = await Review.aggregate([
      {
        $group: {
          _id: "$user",
          reviewCount: { $sum: 1 },
          totalLikes: { $sum: "$likes" }
        }
      },
      { $sort: { reviewCount: -1, totalLikes: -1 } },
      { $limit: limit },
      {
        $lookup: {
          from: "users",
          localField: "_id",
          foreignField: "_id",
          as: "userInfo"
        }
      },
      {
        $project: {
          _id: 1,
          reviewCount: 1,
          totalLikes: 1,
          user: { $arrayElemAt: ["$userInfo", 0] }
        }
      }
    ]);
    
    res.json(topCritics);
  } catch (error) {
    console.error('Erreur lors de la récupération des critiqueurs populaires:', error);
    res.status(500).json({ message: 'Erreur lors de la récupération des critiqueurs populaires' });
  }
}

module.exports = {
  // Like/Unlike une critique
  async toggleLikeReview(req, res) {
    try {
      const { id } = req.params;
      const userId = req.user.id;

      const review = await Review.findById(id);
      if (!review) {
        return res.status(404).json({ message: 'Critique non trouvée' });
      }

      // Vérifier si l'utilisateur a déjà liké
      const userIndex = review.likedBy.findIndex(id => id.toString() === userId.toString());
      let isLiked;

      if (userIndex === -1) {
        // Ajouter le like
        review.likedBy.push(userId);
        review.likes += 1;
        isLiked = true;
      } else {
        // Retirer le like
        review.likedBy.splice(userIndex, 1);
        review.likes = Math.max(0, review.likes - 1);
        isLiked = false;
      }

      await review.save();
      
      res.json({ 
        message: isLiked ? 'Critique likée avec succès' : 'Like retiré avec succès',
        likes: review.likes,
        isLiked
      });
    } catch (error) {
      console.error('Erreur lors du like:', error);
      res.status(500).json({ message: 'Erreur lors du traitement du like', error: error.message });
    }
  },

  // Vérifier si l'utilisateur a liké une critique
  async checkUserLike(req, res) {
    try {
      const { id } = req.params;
      const userId = req.user.id;

      const review = await Review.findById(id);
      if (!review) {
        return res.status(404).json({ message: 'Critique non trouvée' });
      }

      const isLiked = review.likedBy.some(id => id.toString() === userId.toString());
      res.json({ isLiked });
    } catch (error) {
      console.error('Erreur lors de la vérification du like:', error);
      res.status(500).json({ 
        message: 'Erreur lors de la vérification du like',
        error: error.message 
      });
    }
  },

  getReviewsByMovie,
  createReview,
  updateReview,
  deleteReview,
  getMyReviews,
  getTopRatedMovies,
  getPopularReviews,
  getTopCritics,
};
