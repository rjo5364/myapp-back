// Dependencies
const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const session = require('express-session');
const bodyParser = require('body-parser');
const axios = require('axios');
const path = require('path');
const cors = require('cors');

// Environment variables configuration
if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

// Import Google OAuth strategy
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express(); // Initializing the Express app

// Middleware
app.use(bodyParser.json()); // Parses incoming JSON requests

// Allow CORS for your frontend URL
app.use(cors({ 
  origin: 'https://myapp-front-69q2.onrender.com', 
  credentials: true 
})); // Enables CORS with the frontend URL

// Session management configuration
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true }, // Set to true for production with HTTPS
  })
);
app.use(passport.initialize());
app.use(passport.session());

// MongoDB connection
const dbUri = process.env.MONGODB_URI;

if (!dbUri) {
  console.error('MONGODB_URI is not defined in environment variables.');
  process.exit(1);
}

mongoose
  .connect(dbUri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log('Connected to MongoDB Atlas'))
  .catch((err) => console.error('Failed to connect to MongoDB:', err));

// User schema and model
const userSchema = new mongoose.Schema({
  socialId: String,
  name: String,
  email: String,
  platform: String,
  profilePicture: String,
});

const User = mongoose.model('User', userSchema);

// Google OAuth strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: 'https://myapp-backend-0125.onrender.com/auth/google/callback', 
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ socialId: profile.id });
        if (!user) {
          user = new User({
            socialId: profile.id,
            name: profile.displayName,
            email: profile.emails[0].value,
            platform: 'google',
            profilePicture: profile.photos[0]?.value || '',
          });
          await user.save();
        }
        return done(null, user);
      } catch (err) {
        console.error('Error saving user:', err);
        return done(err, null);
      }
    }
  )
);

// Serialize and deserialize user
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Google authentication routes
app.get(
  '/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    res.redirect('https://myapp-front-69q2.onrender.com/profile'); // Redirect to frontend after login
  }
);

// LinkedIn authentication routes
app.get('/auth/linkedin', (req, res) => {
  const linkedinAuthURL = `https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=${process.env.LINKEDIN_CLIENT_ID}&redirect_uri=${process.env.LINKEDIN_REDIRECT_URI}&scope=openid%20profile%20email`;
  res.redirect(linkedinAuthURL);
});

app.get('/auth/linkedin/callback', async (req, res) => {
  try {
    const code = req.query.code;

    const tokenResponse = await axios.post(
      'https://www.linkedin.com/oauth/v2/accessToken',
      null,
      {
        params: {
          grant_type: 'authorization_code',
          code: code,
          redirect_uri: process.env.LINKEDIN_REDIRECT_URI,
          client_id: process.env.LINKEDIN_CLIENT_ID,
          client_secret: process.env.LINKEDIN_CLIENT_SECRET,
        },
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }
    );

    const accessToken = tokenResponse.data.access_token;

    const profileResponse = await axios.get(
      'https://api.linkedin.com/v2/userinfo',
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      }
    );

    const { sub, name, email, picture } = profileResponse.data;

    let user = await User.findOne({ socialId: sub });

    if (!user) {
      user = new User({
        socialId: sub,
        name: name,
        email: email || 'No email provided',
        platform: 'linkedin',
        profilePicture: picture || '',
      });
      await user.save();
    }

    req.login(user, (err) => {
      if (err) {
        console.error('Login error:', err);
        return res.redirect('/');
      }
      res.redirect('https://myapp-front-69q2.onrender.com/profile'); // Redirect to frontend after login
    });
  } catch (err) {
    console.error('LinkedIn authentication error:', err);
    res.redirect('/');
  }
});

// Profile route
app.get('/profile', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  res.json({
    name: req.user.name,
    email: req.user.email,
    profilePicture: req.user.profilePicture,
  });
});

// Serve React frontend
app.use(express.static(path.join(__dirname, '../myapp/build')));

// Logout route
app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ error: 'Logout error' });
    }
    req.session.destroy((destroyErr) => {
      if (destroyErr) {
        console.error('Session destroy error:', destroyErr);
        return res.status(500).json({ error: 'Session destroy error' });
      }
      res.clearCookie('connect.sid', { path: '/' });
      return res.status(200).json({ message: 'Logged out successfully' });
    });
  });
});

// Wildcard route for React frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../myapp/build', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something went wrong!');
});

// Start the server
app.listen(5000, () => {
  console.log(`Server is running on http://localhost:5000`);
});
