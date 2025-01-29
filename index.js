const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bodyParser = require('body-parser');
const axios = require('axios');
const path = require('path');
const cors = require('cors');
require('dotenv').config();

const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();

// Important: Add trust proxy setting for Render.com
app.set('trust proxy', 1);

// Middleware
app.use(bodyParser.json());
app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization']
  })
);

// Set up MongoDB connection with event listeners
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log('Connected to MongoDB Atlas'))
  .catch((err) => console.error('Failed to connect to MongoDB Atlas:', err));

mongoose.connection.on('connected', () => {
  console.log('MongoDB connection established successfully');
});

mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('MongoDB connection disconnected');
});

// Initialize MongoDB session store
const sessionStore = MongoStore.create({
  mongoUrl: process.env.MONGODB_URI,
  collectionName: 'sessions',
  ttl: 24 * 60 * 60,
  autoRemove: 'native',
  stringify: false,
  autoRemove: 'native'
});

sessionStore.on('error', function(error) {
  console.error('Session Store Error:', error);
});

// Session configuration
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    proxy: true,
    store: sessionStore,
    cookie: { 
      secure: true,
      sameSite: 'none',
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
      domain: process.env.COOKIE_DOMAIN
    }
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Enhanced session debugging middleware
app.use((req, res, next) => {
  console.log('Session Debug:', {
    sessionID: req.sessionID,
    hasSession: !!req.session,
    isAuthenticated: req.isAuthenticated?.(),
    user: req.user,
    cookie: req.session?.cookie,
    store: req.session?.store?.constructor.name,
    linkedInState: req.session?.linkedInState
  });
  next();
});

// User schema
const userSchema = new mongoose.Schema({
  socialId: String,
  name: String,
  email: String,
  platform: String,
  profilePicture: String,
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date
});

const User = mongoose.model('User', userSchema);

// Google Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.BASE_URL}/auth/google/callback`,
      proxy: true
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        console.log('Google profile:', profile);
        let user = await User.findOne({ socialId: profile.id });

        if (!user) {
          user = new User({
            socialId: profile.id,
            name: profile.displayName,
            email: profile.emails[0].value,
            platform: 'google',
            profilePicture: profile.photos[0]?.value || '',
            lastLogin: new Date()
          });
        } else {
          user.lastLogin = new Date();
        }

        await user.save();
        return done(null, user);
      } catch (err) {
        console.error('Error saving user:', err);
        return done(err, null);
      }
    }
  )
);

// Serialize and deserialize user
passport.serializeUser((user, done) => {
  console.log('Serializing user:', user);
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    console.log('Deserialized user:', user);
    done(null, user);
  } catch (err) {
    console.error('Deserialize error:', err);
    done(err, null);
  }
});

// Routes
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy' });
});

// Google Routes
app.get(
  '/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get(
  '/auth/google/callback',
  passport.authenticate('google', { 
    failureRedirect: '/',
    failureMessage: true 
  }),
  (req, res) => {
    console.log('Google authentication successful');
    console.log('Session after auth:', req.session);
    console.log('User after auth:', req.user);
    
    req.session.save((err) => {
      if (err) {
        console.error('Session save error:', err);
        return res.redirect(`${process.env.FRONTEND_URL}?error=session_error`);
      }
      res.redirect(`${process.env.FRONTEND_URL}/profile`);
    });
  }
);

// LinkedIn Routes
app.get('/auth/linkedin', async (req, res) => {
  try {
    const state = Math.random().toString(36).substring(7);
    req.session.linkedInState = state;

    // Wait for session to be saved
    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    const queryParams = new URLSearchParams({
      response_type: 'code',
      client_id: process.env.LINKEDIN_CLIENT_ID,
      redirect_uri: process.env.LINKEDIN_REDIRECT_URI,
      state: state,
      scope: 'openid profile email'
    });

    const authURL = `https://www.linkedin.com/oauth/v2/authorization?${queryParams}`;
    console.log('Redirecting to LinkedIn:', {
      url: authURL,
      state: state,
      sessionState: req.session.linkedInState
    });
    res.redirect(authURL);
  } catch (err) {
    console.error('LinkedIn auth error:', err);
    res.redirect(`${process.env.FRONTEND_URL}?error=auth_init_failed`);
  }
});

app.get('/auth/linkedin/callback', async (req, res) => {
  try {
    console.log('LinkedIn callback received:', {
      query: req.query,
      sessionState: req.session?.linkedInState,
      sessionID: req.sessionID
    });

    const { code, state, error } = req.query;

    if (error) {
      console.error('LinkedIn OAuth error:', error);
      return res.redirect(`${process.env.FRONTEND_URL}?error=linkedin_auth_failed`);
    }

    if (!req.session) {
      console.error('No session found in LinkedIn callback');
      return res.redirect(`${process.env.FRONTEND_URL}?error=no_session`);
    }

    if (state !== req.session.linkedInState) {
      console.error('State mismatch:', { 
        received: state, 
        stored: req.session.linkedInState,
        sessionID: req.sessionID 
      });
      return res.redirect(`${process.env.FRONTEND_URL}?error=invalid_state`);
    }

    // Exchange code for access token
    const tokenResponse = await axios({
      method: 'POST',
      url: 'https://www.linkedin.com/oauth/v2/accessToken',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      data: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: process.env.LINKEDIN_REDIRECT_URI,
        client_id: process.env.LINKEDIN_CLIENT_ID,
        client_secret: process.env.LINKEDIN_CLIENT_SECRET
      }).toString()
    });

    console.log('LinkedIn token response:', tokenResponse.data);
    const accessToken = tokenResponse.data.access_token;

    // Get user info using the userinfo endpoint
    const userInfoResponse = await axios.get('https://api.linkedin.com/v2/userinfo', {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    });

    const profileData = userInfoResponse.data;
    console.log('LinkedIn user info:', profileData);

    // Create or update user
    let user = await User.findOne({ 
      socialId: profileData.sub,
      platform: 'linkedin'
    });

    if (!user) {
      user = new User({
        socialId: profileData.sub,
        name: profileData.name,
        email: profileData.email,
        platform: 'linkedin',
        profilePicture: profileData.picture || '',
        lastLogin: new Date()
      });
    } else {
      user.lastLogin = new Date();
      user.name = profileData.name;
      user.email = profileData.email;
      user.profilePicture = profileData.picture || user.profilePicture;
    }

    await user.save();
    console.log('User saved:', user);
    
    req.login(user, (err) => {
      if (err) {
        console.error('Login error:', err);
        return res.redirect(`${process.env.FRONTEND_URL}?error=login_failed`);
      }
      
      req.session.save((err) => {
        if (err) {
          console.error('Session save error:', err);
          return res.redirect(`${process.env.FRONTEND_URL}?error=session_error`);
        }
        console.log('LinkedIn authentication successful');
        res.redirect(`${process.env.FRONTEND_URL}/profile`);
      });
    });

  } catch (err) {
    console.error('LinkedIn authentication error:', {
      message: err.message,
      response: err.response?.data,
      status: err.response?.status,
      headers: err.response?.headers
    });
    res.redirect(
      `${process.env.FRONTEND_URL}?error=auth_failed&reason=${encodeURIComponent(err.message)}`
    );
  }
});

app.get('/profile', (req, res) => {
  console.log('Profile request received. Authenticated:', req.isAuthenticated());
  console.log('User:', req.user);
  
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  res.json({
    name: req.user.name,
    email: req.user.email,
    profilePicture: req.user.profilePicture,
    platform: req.user.platform,
    lastLogin: req.user.lastLogin
  });
});

app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      console.error('Error during logout:', err);
      return res.status(500).json({ error: 'Logout error' });
    }
    req.session.destroy((destroyErr) => {
      if (destroyErr) {
        console.error('Error destroying session:', destroyErr);
        return res.status(500).json({ error: 'Session destroy error' });
      }
      res.clearCookie('connect.sid', { 
        path: '/',
        domain: process.env.COOKIE_DOMAIN,
        secure: true,
        sameSite: 'none'
      });
      res.status(200).json({ message: 'Logged out successfully' });
    });
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ 
    error: 'Something went wrong!',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  console.log(`Frontend URL: ${process.env.FRONTEND_URL}`);
  console.log(`Base URL: ${process.env.BASE_URL}`);
});