const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bodyParser = require('body-parser');
const axios = require('axios');
const cors = require('cors');
require('dotenv').config();

const GoogleStrategy = require('passport-google-oauth20').Strategy;

const app = express();

// Important: Add trust proxy setting for Render.com
app.set('trust proxy', 1);

// Comprehensive CORS Configuration
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    // List of allowed origins
    const allowedOrigins = [
      process.env.FRONTEND_URL,
      'https://your-frontend-domain.com', // Add any additional domains
      /\.yourdomain\.com$/ // Regex for subdomains if needed
    ];
    
    const isAllowed = allowedOrigins.some(allowed => 
      (typeof allowed === 'string' && origin === allowed) || 
      (allowed instanceof RegExp && allowed.test(origin))
    );
    
    if (isAllowed) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept']
};

// Middleware
app.use(cors(corsOptions));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

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

// MongoDB Connection with Enhanced Error Handling
const connectWithRetry = () => {
  mongoose
    .connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 10000, // Timeout after 10 seconds
      socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
    })
    .then(() => {
      console.log('Connected to MongoDB Atlas');
      // Setup session store after successful connection
      setupSessionStore();
    })
    .catch((err) => {
      console.error('Failed to connect to MongoDB Atlas:', err);
      // Retry connection after 5 seconds
      setTimeout(connectWithRetry, 5000);
    });
};

// Session Store Setup
let sessionStore;
function setupSessionStore() {
  sessionStore = MongoStore.create({
    clientPromise: mongoose.connection.getClient(),
    dbName: mongoose.connection.db.namespace,
    collectionName: 'sessions',
    ttl: 24 * 60 * 60, // 24 hours
    autoRemove: 'interval',
    autoRemoveInterval: 10, // Remove expired sessions every 10 minutes
    touchAfter: 24 * 3600 // only update session if it hasn't been modified for 24 hours
  });

  // Enhanced Session Store Error Handling
  sessionStore.on('error', (error) => {
    console.error('Session Store Error:', error);
  });

  // Configure session middleware after store is created
  configureSessionMiddleware();
}

// Session Configuration Function
function configureSessionMiddleware() {
  app.use(
    session({
      secret: process.env.SESSION_SECRET,
      resave: false, // Only save session if modified
      saveUninitialized: false, // Don't create session until something stored
      store: sessionStore,
      name: 'sessionId',
      cookie: { 
        secure: true, // Requires HTTPS
        sameSite: 'none', // For cross-site tracking
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        domain: process.env.COOKIE_DOMAIN,
        path: '/'
      }
    })
  );

  // Initialize Passport after session middleware
  app.use(passport.initialize());
  app.use(passport.session());
}

// Start the connection
connectWithRetry();

// Google Strategy with Enhanced Logging and Error Handling
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.BASE_URL}/auth/google/callback`,
      proxy: true,
      passReqToCallback: true // Pass the request to the verify callback
    },
    async (req, accessToken, refreshToken, profile, done) => {
      try {
        console.log('Google Authentication Details:', {
          profileId: profile.id,
          displayName: profile.displayName,
          emails: profile.emails,
          // Be cautious about logging tokens in production
        });

        let user = await User.findOne({ 
          socialId: profile.id, 
          platform: 'google' 
        });

        const userData = {
          socialId: profile.id,
          name: profile.displayName,
          email: profile.emails[0]?.value,
          platform: 'google',
          profilePicture: profile.photos[0]?.value || '',
          lastLogin: new Date()
        };

        if (!user) {
          user = new User(userData);
        } else {
          // Update existing user's information
          Object.assign(user, userData);
        }

        await user.save();
        return done(null, user);
      } catch (err) {
        console.error('Google Strategy Error:', {
          message: err.message,
          stack: err.stack
        });
        return done(err, null);
      }
    }
  )
);

// Enhanced Serialization and Deserialization
passport.serializeUser((user, done) => {
  console.log('Serializing User - Full Object:', user);
  console.log('Serializing User - ID:', user.id);
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    console.log('Deserializing user with ID:', id);
    const user = await User.findById(id);
    
    if (!user) {
      console.error('No user found during deserialization for ID:', id);
      return done(null, false);
    }
    
    console.log('Deserialized user:', user);
    done(null, user);
  } catch (err) {
    console.error('Deserialization Error:', {
      message: err.message,
      stack: err.stack
    });
    done(err, null);
  }
});

// Debugging Middleware
app.use((req, res, next) => {
  console.log('Request Debug:', {
    path: req.path,
    method: req.method,
    headers: req.headers,
    sessionID: req.sessionID,
    isAuthenticated: req.isAuthenticated(),
    user: req.user,
    sessionData: req.session
  });
  next();
});

// Routes
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy' });
});

// Test session route
app.get('/test-session', (req, res) => {
  req.session.testData = 'test';
  req.session.save((err) => {
    if (err) {
      console.error('Session save error:', err);
      return res.status(500).json({ error: 'Session save failed' });
    }
    res.json({ 
      sessionID: req.sessionID,
      sessionData: req.session,
      store: req.session.store?.constructor.name
    });
  });
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

// LinkedIn Authentication Routes
app.get('/auth/linkedin', async (req, res) => {
  try {
    const state = Math.random().toString(36).substring(7);
    req.session.linkedInState = state;

    // Wait for session to be saved
    await new Promise((resolve, reject) => {
      req.session.save(async (err) => {
        if (err) {
          console.error('Session save error:', err);
          reject(err);
        } else {
          // Add a small delay after save
          await new Promise(resolve => setTimeout(resolve, 500));
          resolve();
        }
      });
    });

    // Verify the state was saved
    const verifySession = await sessionStore.get(req.sessionID);
    console.log('Verified session state:', {
      sessionID: req.sessionID,
      linkedInState: verifySession?.linkedInState,
      state: state
    });

    const queryParams = new URLSearchParams({
      response_type: 'code',
      client_id: process.env.LINKEDIN_CLIENT_ID,
      redirect_uri: process.env.LINKEDIN_REDIRECT_URI,
      state: state,
      scope: 'openid profile email'
    });

    const authURL = `https://www.linkedin.com/oauth/v2/authorization?${queryParams}`;
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

// Profile Route
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
      res.clearCookie('sessionId', { 
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