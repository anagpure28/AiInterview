// middleware/auth.js
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const User = require('../models/User');
dotenv.config();

const verifyToken = async (req, res, next) => {
  const accessToken = req.header('Authorization');
  const refreshToken = req.header('Refresh-Token');

  if (!accessToken && !refreshToken) {
    return res.status(401).json({ message: 'Access denied' });
  }

  jwt.verify(accessToken, process.env.JWT_SECRET, async (err, user) => {
    if (err) {
      // Access token has expired; try to refresh it with the refresh token
      jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, async (refreshErr, refreshUser) => {
        if (refreshErr) {
          return res.status(403).json({ message: 'Invalid tokens' });
        }

        const dbUser = await User.findById(refreshUser.userId);

        if (!dbUser || dbUser.refreshToken !== refreshToken) {
          return res.status(403).json({ message: 'Invalid tokens' });
        }

        // Generate a new access token
        const newAccessToken = jwt.sign({ userId: refreshUser.userId }, process.env.JWT_SECRET, {
          expiresIn: '15m', // New token expires in 15 minutes
        });

        // Set the new access token in the request header
        req.headers['Authorization'] = newAccessToken;

        // Continue to the protected route
        next();
      });
    } else {
      // Access token is valid; continue to the protected route
      req.user = user;
      next();
    }
  });
};

module.exports = verifyToken;
