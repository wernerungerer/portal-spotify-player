require('dotenv').config();
const express = require('express');
const session = require('express-session');
const axios = require('axios');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

const SPOTIFY_CLIENT_ID = process.env.SPOTIFY_CLIENT_ID;
const SPOTIFY_CLIENT_SECRET = process.env.SPOTIFY_CLIENT_SECRET;
const SPOTIFY_REDIRECT_URI = process.env.SPOTIFY_REDIRECT_URI;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

const SPOTIFY_AUTH_URL = 'https://accounts.spotify.com/authorize';
const SPOTIFY_TOKEN_URL = 'https://accounts.spotify.com/api/token';
const SPOTIFY_API_BASE = 'https://api.spotify.com/v1';

const SCOPES = [
  'streaming',
  'user-read-email',
  'user-read-private',
  'user-read-playback-state',
  'user-modify-playback-state',
  'user-read-currently-playing',
  'user-read-recently-played',
  'playlist-read-private',
  'playlist-read-collaborative'
].join(' ');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 3600000
  }
}));

// --- Auth Routes ---

app.get('/auth/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  req.session.authState = state;
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: SPOTIFY_CLIENT_ID,
    scope: SCOPES,
    redirect_uri: SPOTIFY_REDIRECT_URI,
    state
  });
  res.redirect(`${SPOTIFY_AUTH_URL}?${params.toString()}`);
});

app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.redirect('/?error=' + encodeURIComponent(error));
  }

  if (state !== req.session.authState) {
    return res.redirect('/?error=state_mismatch');
  }

  try {
    const response = await axios.post(SPOTIFY_TOKEN_URL, new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: SPOTIFY_REDIRECT_URI
    }).toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + Buffer.from(`${SPOTIFY_CLIENT_ID}:${SPOTIFY_CLIENT_SECRET}`).toString('base64')
      }
    });

    req.session.accessToken = response.data.access_token;
    req.session.refreshToken = response.data.refresh_token;
    req.session.tokenExpiry = Date.now() + (response.data.expires_in * 1000);

    res.redirect('/');
  } catch (err) {
    console.error('Token exchange error:', err.response?.data || err.message);
    res.redirect('/?error=token_exchange_failed');
  }
});

app.get('/auth/token', async (req, res) => {
  if (!req.session.accessToken) {
    return res.json({ authenticated: false });
  }

  // Refresh if expiring within 5 minutes
  if (req.session.tokenExpiry && Date.now() > req.session.tokenExpiry - 300000) {
    try {
      const response = await axios.post(SPOTIFY_TOKEN_URL, new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: req.session.refreshToken
      }).toString(), {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': 'Basic ' + Buffer.from(`${SPOTIFY_CLIENT_ID}:${SPOTIFY_CLIENT_SECRET}`).toString('base64')
        }
      });

      req.session.accessToken = response.data.access_token;
      req.session.tokenExpiry = Date.now() + (response.data.expires_in * 1000);
      if (response.data.refresh_token) {
        req.session.refreshToken = response.data.refresh_token;
      }
    } catch (err) {
      console.error('Token refresh error:', err.response?.data || err.message);
      return res.json({ authenticated: false });
    }
  }

  res.json({
    authenticated: true,
    accessToken: req.session.accessToken
  });
});

app.post('/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// --- Spotify API Proxy ---

async function getToken(req) {
  if (!req.session.accessToken) return null;

  if (req.session.tokenExpiry && Date.now() > req.session.tokenExpiry - 300000) {
    try {
      const response = await axios.post(SPOTIFY_TOKEN_URL, new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: req.session.refreshToken
      }).toString(), {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': 'Basic ' + Buffer.from(`${SPOTIFY_CLIENT_ID}:${SPOTIFY_CLIENT_SECRET}`).toString('base64')
        }
      });
      req.session.accessToken = response.data.access_token;
      req.session.tokenExpiry = Date.now() + (response.data.expires_in * 1000);
      if (response.data.refresh_token) {
        req.session.refreshToken = response.data.refresh_token;
      }
    } catch {
      return null;
    }
  }

  return req.session.accessToken;
}

function requireAuth(req, res, next) {
  if (!req.session.accessToken) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
}

app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const token = await getToken(req);
    const response = await axios.get(`${SPOTIFY_API_BASE}/me`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    res.json(response.data);
  } catch (err) {
    res.status(err.response?.status || 500).json({ error: err.message });
  }
});

app.get('/api/player', requireAuth, async (req, res) => {
  try {
    const token = await getToken(req);
    const response = await axios.get(`${SPOTIFY_API_BASE}/me/player`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    res.json(response.data || {});
  } catch (err) {
    if (err.response?.status === 204) return res.json({});
    res.status(err.response?.status || 500).json({ error: err.message });
  }
});

app.put('/api/player/play', requireAuth, async (req, res) => {
  try {
    const token = await getToken(req);
    const params = req.query.device_id ? `?device_id=${req.query.device_id}` : '';
    await axios.put(`${SPOTIFY_API_BASE}/me/player/play${params}`, req.body || {}, {
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }
    });
    res.json({ success: true });
  } catch (err) {
    res.status(err.response?.status || 500).json({ error: err.message });
  }
});

app.put('/api/player/pause', requireAuth, async (req, res) => {
  try {
    const token = await getToken(req);
    await axios.put(`${SPOTIFY_API_BASE}/me/player/pause`, {}, {
      headers: { Authorization: `Bearer ${token}` }
    });
    res.json({ success: true });
  } catch (err) {
    res.status(err.response?.status || 500).json({ error: err.message });
  }
});

app.post('/api/player/next', requireAuth, async (req, res) => {
  try {
    const token = await getToken(req);
    await axios.post(`${SPOTIFY_API_BASE}/me/player/next`, {}, {
      headers: { Authorization: `Bearer ${token}` }
    });
    res.json({ success: true });
  } catch (err) {
    res.status(err.response?.status || 500).json({ error: err.message });
  }
});

app.post('/api/player/previous', requireAuth, async (req, res) => {
  try {
    const token = await getToken(req);
    await axios.post(`${SPOTIFY_API_BASE}/me/player/previous`, {}, {
      headers: { Authorization: `Bearer ${token}` }
    });
    res.json({ success: true });
  } catch (err) {
    res.status(err.response?.status || 500).json({ error: err.message });
  }
});

app.put('/api/player/shuffle', requireAuth, async (req, res) => {
  try {
    const token = await getToken(req);
    await axios.put(`${SPOTIFY_API_BASE}/me/player/shuffle?state=${req.query.state}`, {}, {
      headers: { Authorization: `Bearer ${token}` }
    });
    res.json({ success: true });
  } catch (err) {
    res.status(err.response?.status || 500).json({ error: err.message });
  }
});

app.put('/api/player/repeat', requireAuth, async (req, res) => {
  try {
    const token = await getToken(req);
    await axios.put(`${SPOTIFY_API_BASE}/me/player/repeat?state=${req.query.state}`, {}, {
      headers: { Authorization: `Bearer ${token}` }
    });
    res.json({ success: true });
  } catch (err) {
    res.status(err.response?.status || 500).json({ error: err.message });
  }
});

app.put('/api/player/seek', requireAuth, async (req, res) => {
  try {
    const token = await getToken(req);
    await axios.put(`${SPOTIFY_API_BASE}/me/player/seek?position_ms=${req.query.position_ms}`, {}, {
      headers: { Authorization: `Bearer ${token}` }
    });
    res.json({ success: true });
  } catch (err) {
    res.status(err.response?.status || 500).json({ error: err.message });
  }
});

app.put('/api/player/volume', requireAuth, async (req, res) => {
  try {
    const token = await getToken(req);
    await axios.put(`${SPOTIFY_API_BASE}/me/player/volume?volume_percent=${req.query.volume_percent}`, {}, {
      headers: { Authorization: `Bearer ${token}` }
    });
    res.json({ success: true });
  } catch (err) {
    res.status(err.response?.status || 500).json({ error: err.message });
  }
});

app.get('/api/playlists', requireAuth, async (req, res) => {
  try {
    const token = await getToken(req);
    const limit = req.query.limit || 50;
    const offset = req.query.offset || 0;
    const response = await axios.get(`${SPOTIFY_API_BASE}/me/playlists?limit=${limit}&offset=${offset}`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    res.json(response.data);
  } catch (err) {
    res.status(err.response?.status || 500).json({ error: err.message });
  }
});

app.get('/api/playlists/:id', requireAuth, async (req, res) => {
  try {
    const token = await getToken(req);
    const response = await axios.get(`${SPOTIFY_API_BASE}/playlists/${req.params.id}`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    res.json(response.data);
  } catch (err) {
    res.status(err.response?.status || 500).json({ error: err.message });
  }
});

app.get('/api/player/queue', requireAuth, async (req, res) => {
  try {
    const token = await getToken(req);
    const response = await axios.get(`${SPOTIFY_API_BASE}/me/player/queue`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    res.json(response.data);
  } catch (err) {
    if (err.response?.status === 204) return res.json({ queue: [] });
    res.status(err.response?.status || 500).json({ error: err.message });
  }
});

app.get('/api/recently-played', requireAuth, async (req, res) => {
  try {
    const token = await getToken(req);
    const limit = req.query.limit || 50;
    const response = await axios.get(`${SPOTIFY_API_BASE}/me/player/recently-played?limit=${limit}`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    res.json(response.data);
  } catch (err) {
    res.status(err.response?.status || 500).json({ error: err.message });
  }
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Portal Spotify Player running on port ${PORT}`);
});
