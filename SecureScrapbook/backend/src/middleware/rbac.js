/**
 * =====================================================================
 * SecureScrapbook - Role-Based Access Control (RBAC) Authorization Middleware
 * =====================================================================
 * Supports 3 hierarchical roles mapped via user email & account ID:
 *   - 'Owner'  (Level 3): Full control (delete, manage collaborators/sharing, edit, view)
 *   - 'Editor' (Level 2): Can modify and create scrapbook pages, upload media, view
 *   - 'Viewer' (Level 1): Read-only access to scrapbook and pages
 *
 * Enforces zero-trust application-layer blocking with automated security audit logging.
 */

const { logAuditEvent } = require('../services/auditLogger');
const db = require('../db'); // Database pool connection

// Numeric hierarchy for permission evaluation
const ROLE_LEVELS = {
  Viewer: 1,
  Editor: 2,
  Owner: 3
};

/**
 * Normalizes email strings for case-insensitive permission comparison.
 * @param {string} email
 * @returns {string}
 */
const normalizeEmail = (email) => (email ? email.trim().toLowerCase() : '');

/**
 * Resolves the effective permission role of a user for a given scrapbook.
 * Checks primary ownership first, then falls back to email-mapped collaborator permissions.
 *
 * @param {string} scrapbookId - UUID of the target scrapbook
 * @param {object} user - Authenticated user object ({ id, email })
 * @returns {Promise<{ role: 'Owner' | 'Editor' | 'Viewer' | null, scrapbook: object | null }>}
 */
async function resolveUserScrapbookRole(scrapbookId, user) {
  if (!scrapbookId || !user || !user.email) {
    return { role: null, scrapbook: null };
  }

  // 1. Fetch scrapbook metadata and verify primary owner
  const scrapbookQuery = `
    SELECT id, owner_id, cover_image_key, created_at, updated_at
    FROM scrapbooks
    WHERE id = $1 AND is_archived = FALSE
  `;
  const scrapbookResult = await db.query(scrapbookQuery, [scrapbookId]);

  if (scrapbookResult.rows.length === 0) {
    return { role: null, scrapbook: null, notFound: true };
  }

  const scrapbook = scrapbookResult.rows[0];

  // If the authenticated user is the primary owner of the scrapbook
  if (scrapbook.owner_id === user.id) {
    return { role: 'Owner', scrapbook, isPrimaryOwner: true };
  }

  // 2. Query email-based collaboration permissions in scrapbook_permissions table
  const permissionQuery = `
    SELECT role, granted_by, created_at
    FROM scrapbook_permissions
    WHERE scrapbook_id = $1 AND LOWER(user_email) = LOWER($2)
  `;
  const permissionResult = await db.query(permissionQuery, [scrapbookId, normalizeEmail(user.email)]);

  if (permissionResult.rows.length > 0) {
    const grantedRole = permissionResult.rows[0].role;
    return { role: grantedRole, scrapbook, isPrimaryOwner: false };
  }

  // No matching ownership or collaborator permission found
  return { role: null, scrapbook, isPrimaryOwner: false };
}

/**
 * Express Middleware factory to enforce required RBAC role on a scrapbook resource.
 *
 * @param {'Owner' | 'Editor' | 'Viewer'} minimumRequiredRole
 * @param {object} options
 * @param {string} [options.paramName='scrapbookId'] - Route parameter holding scrapbook UUID
 * @returns {import('express').RequestHandler}
 */
function requireScrapbookRole(minimumRequiredRole, options = {}) {
  const paramName = options.paramName || 'scrapbookId';
  const minRequiredLevel = ROLE_LEVELS[minimumRequiredRole];

  if (!minRequiredLevel) {
    throw new Error(`[RBAC Config Error] Invalid role specified: "${minimumRequiredRole}"`);
  }

  return async (req, res, next) => {
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';

    // 1. Authentication Check
    if (!req.user || !req.user.id || !req.user.email) {
      await logAuditEvent({
        userId: null,
        userEmail: req.user?.email || 'unauthenticated',
        ipAddress: clientIp,
        userAgent,
        action: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        resourceType: 'SCRAPBOOK',
        resourceId: req.params[paramName] || req.body?.scrapbookId || 'unknown',
        status: 'UNAUTHORIZED',
        httpMethod: req.method,
        requestUri: req.originalUrl,
        details: { reason: 'Missing or expired authentication token', requiredRole: minimumRequiredRole },
        riskScore: 60
      });

      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Authentication token is required to access this resource.'
      });
    }

    // 2. Resolve Scrapbook Target UUID from URL params, query, or body
    const scrapbookId = req.params[paramName] || req.params.id || req.body?.scrapbookId || req.query?.scrapbookId;

    if (!scrapbookId) {
      return res.status(400).json({
        error: 'Bad Request',
        message: `Missing required scrapbook identifier parameter (${paramName}).`
      });
    }

    try {
      // 3. Resolve role mapped via email & ownership
      const { role, scrapbook, notFound, isPrimaryOwner } = await resolveUserScrapbookRole(scrapbookId, req.user);

      if (notFound) {
        return res.status(404).json({
          error: 'Not Found',
          message: 'Requested scrapbook does not exist or has been archived.'
        });
      }

      const userRoleLevel = role ? ROLE_LEVELS[role] : 0;

      // 4. Evaluate RBAC Hierarchy
      if (!role || userRoleLevel < minRequiredLevel) {
        // High-risk security event: Permission breach attempt
        await logAuditEvent({
          userId: req.user.id,
          userEmail: req.user.email,
          ipAddress: clientIp,
          userAgent,
          action: 'RBAC_PERMISSION_DENIED',
          resourceType: 'SCRAPBOOK',
          resourceId: scrapbookId,
          status: 'FORBIDDEN',
          httpMethod: req.method,
          requestUri: req.originalUrl,
          details: {
            userEmail: req.user.email,
            assignedRole: role || 'None',
            requiredRole: minimumRequiredRole,
            requiredLevel: minRequiredLevel,
            currentLevel: userRoleLevel
          },
          riskScore: 80
        });

        return res.status(403).json({
          error: 'Forbidden',
          message: `Access denied. Requires '${minimumRequiredRole}' permission. Your assigned role for this scrapbook is '${role || 'None'}'.`
        });
      }

      // 5. Attach authorized context to request object for downstream controllers
      req.scrapbook = scrapbook;
      req.scrapbookPermission = {
        role,
        isPrimaryOwner,
        level: userRoleLevel
      };

      return next();
    } catch (error) {
      console.error('[RBAC Middleware] Error evaluating access control:', error);

      await logAuditEvent({
        userId: req.user?.id,
        userEmail: req.user?.email,
        ipAddress: clientIp,
        userAgent,
        action: 'RBAC_EVALUATION_ERROR',
        resourceType: 'SCRAPBOOK',
        resourceId: scrapbookId,
        status: 'FAILURE',
        httpMethod: req.method,
        requestUri: req.originalUrl,
        details: { errorMessage: error.message },
        riskScore: 50
      });

      return res.status(500).json({
        error: 'Internal Server Error',
        message: 'An error occurred while evaluating access permissions.'
      });
    }
  };
}

/**
 * Express Middleware factory to resolve permission when accessing a scrapbook page directly (/pages/:pageId)
 * First resolves the parent scrapbook ID from the page record, then validates RBAC role.
 *
 * @param {'Owner' | 'Editor' | 'Viewer'} minimumRequiredRole
 * @returns {import('express').RequestHandler}
 */
function requirePageRole(minimumRequiredRole) {
  return async (req, res, next) => {
    const pageId = req.params.pageId || req.params.id;

    if (!pageId) {
      return res.status(400).json({ error: 'Bad Request', message: 'Missing page ID parameter.' });
    }

    try {
      const pageQuery = `
        SELECT id, scrapbook_id, page_number
        FROM scrapbook_pages
        WHERE id = $1
      `;
      const pageResult = await db.query(pageQuery, [pageId]);

      if (pageResult.rows.length === 0) {
        return res.status(404).json({ error: 'Not Found', message: 'Scrapbook page not found.' });
      }

      const page = pageResult.rows[0];
      req.scrapbookPage = page;

      // Delegate evaluation to requireScrapbookRole with scrapbook_id injected
      req.params.scrapbookId = page.scrapbook_id;
      return requireScrapbookRole(minimumRequiredRole)(req, res, next);
    } catch (error) {
      console.error('[RBAC Page Middleware] Error:', error);
      return res.status(500).json({ error: 'Internal Server Error', message: 'Failed to authorize page access.' });
    }
  };
}

module.exports = {
  ROLE_LEVELS,
  resolveUserScrapbookRole,
  requireScrapbookRole,
  requirePageRole,
  // Convenient pre-configured middleware exports
  requireViewer: (options) => requireScrapbookRole('Viewer', options),
  requireEditor: (options) => requireScrapbookRole('Editor', options),
  requireOwner: (options) => requireScrapbookRole('Owner', options),
  requirePageViewer: () => requirePageRole('Viewer'),
  requirePageEditor: () => requirePageRole('Editor'),
  requirePageOwner: () => requirePageRole('Owner')
};
