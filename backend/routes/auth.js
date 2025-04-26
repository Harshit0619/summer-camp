const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const User = require('../models/User');

const router = express.Router();

const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

router.post('/register', async (req, res) => {
  const { email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const verificationToken = crypto.randomBytes(32).toString('hex');
  const user = new User({ email, password: hashed, verificationToken });
  await user.save();

  const url = `http://localhost:3000/verify/${verificationToken}`;
  await transporter.sendMail({
    to: email,
    subject: 'Verify your email for Summer Camp',
    html: `Click <a href="${url}">here</a> to verify your email.`
  });

  res.json({ message: 'Registration successful! Please check your email to verify your account.' });
});

router.get('/verify/:token', async (req, res) => {
  const user = await User.findOne({ verificationToken: req.params.token });
  if (!user) return res.status(400).send('Invalid token');
  user.isVerified = true;
  user.verificationToken = undefined;
  await user.save();
  res.send('Email verified! You can now log in.');
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !await bcrypt.compare(password, user.password))
    return res.status(400).json({ message: 'Invalid credentials' });
  if (!user.isVerified)
    return res.status(400).json({ message: 'Please verify your email first.' });
  // Generate JWT or session here
  res.json({ message: 'Login successful!' });
});

module.exports = router; 