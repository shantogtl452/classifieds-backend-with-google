const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error(err));

// User Schema
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
});
const User = mongoose.model('User', UserSchema);

// Ad Schema
const AdSchema = new mongoose.Schema({
  title: String,
  description: String,
  location: String,
  userId: mongoose.Schema.Types.ObjectId,
  createdAt: { type: Date, default: Date.now }
});
const Ad = mongoose.model('Ad', AdSchema);

// Auth middleware
function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Routes
app.post('/auth/signup', async (req, res) => {
  const { email, password } = req.body;
  const existingUser = await User.findOne({ email });
  if (existingUser) return res.status(400).json({ error: 'User already exists' });
  const passwordHash = await bcrypt.hash(password, 10);
  const newUser = new User({ email, passwordHash });
  await newUser.save();
  res.status(201).json({ message: 'User created' });
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });
  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.status(400).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
  res.json({ token });
});

app.post('/ads', authenticateToken, async (req, res) => {
  const { title, description, location } = req.body;
  const ad = new Ad({ title, description, location, userId: req.user.id });
  await ad.save();
  res.status(201).json(ad);
});

app.get('/ads', async (req, res) => {
  const query = {};
  if (req.query.city) query.location = req.query.city;
  const ads = await Ad.find(query).sort({ createdAt: -1 });
  res.json(ads);
});

app.get('/me/ads', authenticateToken, async (req, res) => {
  const ads = await Ad.find({ userId: req.user.id });
  res.json(ads);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));


// Google Login Support
const { OAuth2Client } = require('google-auth-library');
const googleClient = new OAuth2Client();

app.post('/auth/google', async (req, res) => {
  const { token } = req.body;

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const email = payload.email;

    let user = await User.findOne({ email });
    if (!user) {
      user = new User({
        email,
        passwordHash: 'google-oauth', // placeholder (not used)
      });
      await user.save();
    }

    const jwtToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    res.json({ token: jwtToken });
  } catch (err) {
    console.error(err);
    res.status(403).json({ error: 'Invalid Google token' });
  }
});
