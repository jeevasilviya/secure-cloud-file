/**
 * =====================================================================
 * SecureScrapbook - Express Application Entry Point
 * =====================================================================
 * Hardened with:
 *   - Helmet security headers
 *   - Strict CORS origin whitelisting (Vercel HTTPS only)
 *   - Rate limiting for brute-force / DDoS mitigation
 *   - Global security audit logging & CloudWatch streaming
 */

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { auditMiddleware } = require('./services/auditLogger');
const authRoutes = require('./routes/auth');
const scrapbookRoutes = require('./routes/scrapbooks');

const app = express();

// 1. HTTP Security Headers via Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      upgradeInsecureRequests: []
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// 2. Strict CORS Policy (Permits only Vercel Frontend Domain over HTTPS)
const allowedOrigins = [
  process.env.VERCEL_FRONTEND_URL,
  'https://securescrapbook.vercel.app'
].filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    // Allow non-browser requests or verified Vercel HTTPS domain
    if (!origin || allowedOrigins.includes(origin) || process.env.NODE_ENV === 'development') {
      callback(null, true);
    } else {
      callback(new Error(`Blocked by CORS policy: Origin ${origin} not permitted.`));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  credentials: true
}));

// 3. Global & Sensitive Endpoint Rate Limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 300, // 300 requests per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too Many Requests', message: 'Rate limit exceeded. Please try again later.' }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // 20 login/register attempts per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too Many Requests', message: 'Too many authentication attempts. Please try again later.' }
});

app.use(generalLimiter);
app.use('/api/auth', authLimiter);

// 4. Request Body Parsers (Payload limit enforced to prevent memory exhaustion)
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// 5. Global Auditing & Monitoring Middleware
app.use(auditMiddleware());

// 6. Health & Readiness Probe
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'UP', service: 'SecureScrapbook API', timestamp: new Date() });
});

// 7. Mount Core API Routes
app.use('/api/auth', authRoutes);
app.use('/api/scrapbooks', scrapbookRoutes);

// 8. 404 Route Handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not Found', message: `Cannot ${req.method} ${req.originalUrl}` });
});

// 9. Centralized Error Handler
app.use((err, req, res, next) => {
  console.error('[Unhandled Server Exception]:', err.stack);
  res.status(500).json({
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'production' ? 'An unexpected error occurred.' : err.message
  });
});

const PORT = process.env.PORT || 5000;
if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    console.log(`[SecureScrapbook API] Running on port ${PORT} (Environment: ${process.env.NODE_ENV || 'development'})`);
  });
}

module.exports = app;
