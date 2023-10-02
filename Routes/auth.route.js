// routes/auth.js
const express = require('express');
const authRouter = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer')
const User = require('../Models/user.model');
require('dotenv').config()

// Registration endpoint
authRouter.post('/register', async (req, res) => {
  try {
    const { name, mobile, email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const user = new User({
      name,
      mobile,
      email,
      password: hashedPassword,
    });

    // Save the user to the database
    await user.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

authRouter.post("/login",async(req,res)=>{
    try{
        const {email, password} = req.body;

        const user = await User.findOne({email});
        if(!user){
            return res.status(401).json({message:"Invalid credentials"})
        }

        //Compare provided password with the stored hash password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if(!isPasswordValid){
            return res.status(401).json({message:"Invalid credentials"})
        }
        
        //Generate an access Token
        const accessToken = jwt.sign({userId: user._id}, process.env.JWT_SECRET, {
            expireIn : '15m',
        })

        // Generate a refresh token
        const refreshToken = jwt.sign({ userId: user._id }, process.env.REFRESH_TOKEN_SECRET);

        // Store the refresh token in the database
        user.refreshToken = refreshToken;
        await user.save();

        // Send the tokens in the response
        res.json({ accessToken, refreshToken });

    } catch(err){
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
})

authRouter.post('/refresh-token', async (req, res) => {
    const { refreshToken } = req.body;
  
    if (!refreshToken) {
      return res.status(400).json({ message: 'Refresh token is required' });
    }
  
    // Verify the refresh token
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, async (err, user) => {
      if (err) {
        return res.status(403).json({ message: 'Invalid refresh token' });
      }
  
      // Check if the user exists and has the same refresh token
      const dbUser = await User.findById(user.userId);
  
      if (!dbUser || dbUser.refreshToken !== refreshToken) {
        return res.status(403).json({ message: 'Invalid refresh token' });
      }
  
      // Generate a new access token
      const newAccessToken = jwt.sign({ userId: user.userId }, process.env.JWT_SECRET, {
        expiresIn: '15m', // New token expires in 15 minutes
      });
  
      res.json({ accessToken: newAccessToken });
    });
});

authRouter.post('/forgot-password', async (req, res) => {
    try {
      const { email } = req.body;
  
      // Check if the user with the provided email exists
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      // Generate a password reset token
      const resetToken = jwt.sign({ userId: user._id }, process.env.RESET_TOKEN_SECRET, {
        expiresIn: '1h', // Token expires in 1 hour
      });
  
      // Send a password reset link via email
      const resetLink = `https://yourwebsite.com/reset-password?token=${resetToken}`;
  
      // Create a nodemailer transporter (configure your email provider)
      const transporter = nodemailer.createTransport({
        service: 'YourEmailProvider',
        auth: {
          user: 'your@email.com',
          pass: 'your-password',
        },
      });
  
      // Email content
      const mailOptions = {
        from: 'your@email.com',
        to: user.email,
        subject: 'Password Reset',
        text: `Click the link below to reset your password:\n${resetLink}`,
      };
  
      // Send the email
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error(error);
          return res.status(500).json({ message: 'Failed to send reset email' });
        }
  
        console.log('Reset email sent:', info.response);
        res.json({ message: 'Reset email sent' });
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Server error' });
    }
});

module.exports = authRouter ;
