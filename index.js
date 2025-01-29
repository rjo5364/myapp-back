const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const session = require('express-session');
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

// Session configuration
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    proxy: true,
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

// Session debugging middleware
app.use((req, res, next) => {
  console.log('Session:', {
    id: req.sessionID,
    cookie: req.session.cookie,
    authenticated: req.isAuthenticated(),
    user: req.user
  });
  next();
});

// MongoDB Atlas connection
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log('Connected to MongoDB Atlas'))
  .catch((err) => console.error('Failed to connect to MongoDB Atlas:', err));

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
    
    // Add a small delay to ensure session is saved
    setTimeout(() => {
      res.redirect(`${process.env.FRONTEND_URL}/profile`);
    }, 100);
  }
);

app.get('/auth/linkedin', (req, res) => {
  const state = Math.random().toString(36).substring(7);
  req.session.linkedInState = state;  // Save state in session
  
  const scope = ['openid', 'profile', 'email', 'r_liteprofile', 'r_emailaddress'].join(' ');
  
  const queryParams = new URLSearchParams({
    response_type: 'code',
    client_id: process.env.LINKEDIN_CLIENT_ID,
    redirect_uri: process.env.LINKEDIN_REDIRECT_URI,
    state: state,
    scope: scope
  });

  const authURL = `https://www.linkedin.com/oauth/v2/authorization?${queryParams.toString()}`;
  console.log('Redirecting to LinkedIn:', authURL);
  res.redirect(authURL);
});

app.get('/auth/linkedin/callback', async (req, res) => {
  try {
    const { code, state, error } = req.query;
    
    if (error) {
      console.error('LinkedIn OAuth error:', error);
      return res.redirect(`${process.env.FRONTEND_URL}?error=linkedin_auth_failed`);
    }

    // Validate state parameter
    if (state !== req.session.linkedInState) {
      console.error('State mismatch in LinkedIn callback');
      return res.redirect(`${process.env.FRONTEND_URL}?error=invalid_state`);
    }

    if (!code) {
      console.error('No code received from LinkedIn');
      return res.redirect(`${process.env.FRONTEND_URL}?error=no_code`);
    }

    console.log('LinkedIn callback received. Code:', code, 'State:', state);

    // Exchange code for token
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

    // Get user profile
    const [profileRes, emailRes] = await Promise.all([
      axios.get('https://api.linkedin.com/v2/me', {
        headers: { 
          'Authorization': `Bearer ${accessToken}`,
          'X-Restli-Protocol-Version': '2.0.0'
        }
      }),
      axios.get('https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))', {
        headers: { 
          'Authorization': `Bearer ${accessToken}`,
          'X-Restli-Protocol-Version': '2.0.0'
        }
      })
    ]);

    console.log('LinkedIn profile response:', profileRes.data);
    console.log('LinkedIn email response:', emailRes.data);

    const profileData = profileRes.data;
    const email = emailRes.data.elements?.[0]?.['handle~']?.emailAddress;

    // Create or update user
    let user = await User.findOne({ 
      socialId: profileData.id,
      platform: 'linkedin'
    });

    if (!user) {
      user = new User({
        socialId: profileData.id,
        name: `${profileData.localizedFirstName} ${profileData.localizedLastName}`,
        email: email || 'No email provided',
        platform: 'linkedin',
        profilePicture: profileData.profilePicture?.['displayImage~']?.elements?.[0]?.identifiers?.[0]?.identifier || '',
        lastLogin: new Date()
      });
    } else {
      user.lastLogin = new Date();
    }

    await user.save();
    console.log('User saved:', user);
    
    req.login(user, (err) => {
      if (err) {
        console.error('Login error:', err);
        return res.redirect(`${process.env.FRONTEND_URL}?error=login_failed`);
      }
      console.log('LinkedIn authentication successful');
      res.redirect(`${process.env.FRONTEND_URL}/profile`);
    });

  } catch (err) {
    console.error('LinkedIn authentication error:', {
      message: err.message,
      response: err.response?.data,
      status: err.response?.status,
      headers: err.response?.headers
    });
    res.redirect(`${process.env.FRONTEND_URL}?error=auth_failed&reason=${encodeURIComponent(err.message)}`);
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