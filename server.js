require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const { expressjwt: expressJwt } = require('express-jwt');

// Validate environment variables first
const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;
const PORT = process.env.PORT || 3000;

if (!JWT_SECRET || !REFRESH_SECRET) {
  console.error('FATAL ERROR: JWT_SECRET or REFRESH_SECRET not defined in environment variables');
  process.exit(1);
}

const app = express();
app.use(bodyParser.json());

// Mock database
let posts = ['Early bird catches the worm'];
const users = [
  { id: 1, username: 'admin', password: 'adminpass', role: 'admin' },
  { id: 2, username: 'user', password: 'userpass', role: 'user' }
];
let refreshTokens = [];

// Configure JWT middleware
const authenticateJwt = expressJwt({
  secret: JWT_SECRET,
  algorithms: ['HS256'],
  requestProperty: 'auth',
  credentialsRequired: true
});

// Role checking middleware
const requireRole = (role) => (req, res, next) => {
  if (req.auth?.role !== role) return res.sendStatus(403);
  next();
};

// Routes
app.post('/signin', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);
  
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const accessToken = jwt.sign(
    { userId: user.id, role: user.role },
    JWT_SECRET,
    { expiresIn: '15m' }
  );

  const refreshToken = jwt.sign(
    { userId: user.id },
    REFRESH_SECRET,
    { expiresIn: '7d' }
  );

  refreshTokens.push(refreshToken);
  res.json({ accessToken, refreshToken });
});

app.post('/refresh', (req, res) => {
  const { refreshToken } = req.body;
  
  if (!refreshToken || !refreshTokens.includes(refreshToken)) {
    return res.status(403).json({ error: 'Invalid refresh token' });
  }

  jwt.verify(refreshToken, REFRESH_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    
    const user = users.find(u => u.id === decoded.userId);
    if (!user) return res.status(403).json({ error: 'User not found' });

    const newAccessToken = jwt.sign(
      { userId: user.id, role: user.role },
      JWT_SECRET,
      { expiresIn: '15m' }
    );

    res.json({ accessToken: newAccessToken });
  });
});

app.post('/logout', (req, res) => {
  const { refreshToken } = req.body;
  refreshTokens = refreshTokens.filter(token => token !== refreshToken);
  res.sendStatus(204);
});

app.get('/posts', authenticateJwt, (req, res) => {
  res.json(posts);
});

app.post('/posts', authenticateJwt, requireRole('admin'), (req, res) => {
  const { message } = req.body;
  if (!message?.trim()) return res.status(400).json({ error: 'Message is required' });
  
  posts.push(message.trim());
  res.status(201).json(posts);
});

// Error handling
app.use((err, req, res, next) => {
  if (err.name === 'UnauthorizedError') {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});