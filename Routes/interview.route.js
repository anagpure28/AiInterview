// routes/interview.js (a protected route)
const express = require('express');
const router = express.Router();
const verifyToken = require('../middleware/auth');

// Protected endpoint
router.get('/protected', verifyToken, (req, res) => {
  // Accessible only with a valid token
  res.json({ message: 'This is a protected route' });
});

module.exports = router;
