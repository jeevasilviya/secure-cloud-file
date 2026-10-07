/**
 * =====================================================================
 * SecureScrapbook - Authentication Routes (bcrypt & JWT)
 * =====================================================================
 * Implements bcrypt (cost factor 12), account lockouts on repeated failures,
 * and structured audit logging for all authentication attempts.
 */

const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../db');
const { logAuditEvent } = require('../services/auditLogger');

const BCRYPT_SALT_ROUNDS = 12;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret_super_secure_key_2026_change_in_prod';
const JWT_EXPIRES_IN = '8h';

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user account with bcrypt password hashing
 */
router.post('/register', async (req, res) => {
  const { email, password, fullName } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!email || !password || !fullName) {
    return res.status(400).json({ error: 'Validation Error', message: 'All fields are required.' });
  }

  if (password.length < 10) {
    return res.status(400).json({ error: 'Validation Error', message: 'Password must be at least 10 characters long.' });
  }

  try {
    const normalizedEmail = email.trim().toLowerCase();

    // Check duplicate
    const existing = await db.query('SELECT id FROM users WHERE LOWER(email) = $1', [normalizedEmail]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'Conflict', message: 'An account with this email already exists.' });
    }

    // Hash password with bcrypt (Cost Factor 12)
    const salt = await bcrypt.genSalt(BCRYPT_SALT_ROUNDS);
    const passwordHash = await bcrypt.hash(password, salt);

    const insertUser = `
      INSERT INTO users (email, password_hash, full_name)
      VALUES ($1, $2, $3)
      RETURNING id, email, full_name, created_at
    `;
    const result = await db.query(insertUser, [normalizedEmail, passwordHash, fullName]);
    const newUser = result.rows[0];

    // Audit log account creation
    await logAuditEvent({
      userId: newUser.id,
      userEmail: newUser.email,
      ipAddress: clientIp,
      userAgent: req.headers['user-agent'],
      action: 'USER_REGISTER_SUCCESS',
      resourceType: 'AUTH',
      resourceId: newUser.id,
      status: 'SUCCESS'
    });

    return res.status(201).json({
      message: 'User registered successfully.',
      user: { id: newUser.id, email: newUser.email, fullName: newUser.full_name }
    });
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ error: 'Server Error', message: 'Registration failed.' });
  }
});

/**
 * @route   POST /api/auth/login
 * @desc    Authenticate credentials, issue JWT, log audit events
 */
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const userAgent = req.headers['user-agent'];

  if (!email || !password) {
    return res.status(400).json({ error: 'Validation Error', message: 'Email and password are required.' });
  }

  const normalizedEmail = email.trim().toLowerCase();

  try {
    const userResult = await db.query('SELECT * FROM users WHERE LOWER(email) = $1', [normalizedEmail]);
    const user = userResult.rows[0];

    // Account does not exist or password mismatch
    if (!user) {
      await logAuditEvent({
        userId: null,
        userEmail: normalizedEmail,
        ipAddress: clientIp,
        userAgent,
        action: 'AUTH_LOGIN_FAILED_NONEXISTENT_USER',
        resourceType: 'AUTH',
        status: 'UNAUTHORIZED',
        riskScore: 50,
        details: { reason: 'User not found' }
      });
      return res.status(401).json({ error: 'Unauthorized', message: 'Invalid credentials.' });
    }

    // Check account lockout
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      await logAuditEvent({
        userId: user.id,
        userEmail: user.email,
        ipAddress: clientIp,
        userAgent,
        action: 'AUTH_LOGIN_BLOCKED_LOCKED_ACCOUNT',
        resourceType: 'AUTH',
        status: 'UNAUTHORIZED',
        riskScore: 70
      });
      return res.status(403).json({ error: 'Account Locked', message: 'Account is temporarily locked. Try again later.' });
    }

    // Verify bcrypt password
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      const newAttempts = user.failed_login_attempts + 1;
      let lockQuery = 'UPDATE users SET failed_login_attempts = $1 WHERE id = $2';
      let lockParams = [newAttempts, user.id];

      // Lock account after 5 consecutive failures for 15 minutes
      if (newAttempts >= 5) {
        const lockoutTime = new Date(Date.now() + 15 * 60 * 1000);
        lockQuery = 'UPDATE users SET failed_login_attempts = $1, locked_until = $2 WHERE id = $3';
        lockParams = [newAttempts, lockoutTime, user.id];
      }

      await db.query(lockQuery, lockParams);

      await logAuditEvent({
        userId: user.id,
        userEmail: user.email,
        ipAddress: clientIp,
        userAgent,
        action: 'AUTH_LOGIN_FAILED_BAD_PASSWORD',
        resourceType: 'AUTH',
        resourceId: user.id,
        status: 'UNAUTHORIZED',
        riskScore: newAttempts >= 5 ? 85 : 40,
        details: { failedAttempts: newAttempts }
      });

      return res.status(401).json({ error: 'Unauthorized', message: 'Invalid credentials.' });
    }

    // Reset failed attempts & update last login
    await db.query(
      'UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login_at = NOW() WHERE id = $1',
      [user.id]
    );

    // Issue JWT
    const token = jwt.sign(
      { id: user.id, email: user.email, fullName: user.full_name },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    await logAuditEvent({
      userId: user.id,
      userEmail: user.email,
      ipAddress: clientIp,
      userAgent,
      action: 'AUTH_LOGIN_SUCCESS',
      resourceType: 'AUTH',
      resourceId: user.id,
      status: 'SUCCESS'
    });

    return res.json({
      message: 'Login successful.',
      token,
      user: { id: user.id, email: user.email, fullName: user.full_name }
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'Server Error', message: 'Authentication processing error.' });
  }
});

module.exports = router;
