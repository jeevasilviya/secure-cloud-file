/**
 * =====================================================================
 * SecureScrapbook - JWT Authentication Middleware
 * =====================================================================
 * Verifies Bearer tokens, resolves user identity, and attaches `req.user`.
 */

const jwt = require('jsonwebtoken');
const { logAuditEvent } = require('../services/auditLogger');

const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret_super_secure_key_2026_change_in_prod';

function authenticateJWT(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';

  if (!token) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Access token is missing or malformed.'
    });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      logAuditEvent({
        userId: null,
        userEmail: 'invalid_token',
        ipAddress: clientIp,
        userAgent: req.headers['user-agent'] || 'unknown',
        action: 'INVALID_TOKEN_ATTEMPT',
        resourceType: 'AUTH',
        resourceId: null,
        status: 'UNAUTHORIZED',
        httpMethod: req.method,
        requestUri: req.originalUrl,
        details: { tokenError: err.message },
        riskScore: 65
      });

      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid or expired access token.'
      });
    }

    req.user = {
      id: decoded.id,
      email: decoded.email?.toLowerCase(),
      fullName: decoded.fullName
    };

    next();
  });
}

module.exports = {
  authenticateJWT
};
