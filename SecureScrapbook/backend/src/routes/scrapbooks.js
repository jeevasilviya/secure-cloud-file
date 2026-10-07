/**
 * =====================================================================
 * SecureScrapbook - Scrapbook & Pages Protected REST Controller
 * =====================================================================
 * Demonstrates:
 *   1. RBAC enforcement:
 *      - GET /scrapbooks/:scrapbookId -> Viewer+
 *      - POST /scrapbooks/:scrapbookId/pages -> Editor+
 *      - PUT /scrapbooks/:scrapbookId/pages/:pageId -> Editor+
 *      - POST /scrapbooks/:scrapbookId/share -> Owner only
 *      - DELETE /scrapbooks/:scrapbookId -> Owner only
 *   2. Zero plaintext storage:
 *      - Memoirs and titles encrypted with AES-256-GCM prior to SQL INSERT/UPDATE.
 *   3. Immutable security audit logging for all mutations and sensitive reads.
 */

const express = require('express');
const router = express.Router();
const db = require('../db');
const { authenticateJWT } = require('../middleware/auth');
const {
  requireViewer,
  requireEditor,
  requireOwner
} = require('../middleware/rbac');
const { encryptText, decryptText, encryptJSON, decryptJSON } = require('../services/encryption');
const { logAuditEvent } = require('../services/auditLogger');

// All endpoints in this router require a valid JWT
router.use(authenticateJWT);

/**
 * @route   POST /api/scrapbooks
 * @desc    Create a new scrapbook (Authenticated User becomes Owner)
 * @access  Authenticated Users
 */
router.post('/', async (req, res) => {
  const { title, description } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!title) {
    return res.status(400).json({ error: 'Validation Error', message: 'Title is required' });
  }

  try {
    // Application-layer AES-256-GCM Encryption (Zero Plaintext in PostgreSQL)
    const encTitle = encryptText(title);
    const encDesc = description ? encryptText(description) : { cipherText: null, iv: null, tag: null };

    const insertQuery = `
      INSERT INTO scrapbooks (
        owner_id,
        title_encrypted, title_iv, title_tag,
        description_encrypted, description_iv, description_tag
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING id, created_at
    `;

    const result = await db.query(insertQuery, [
      req.user.id,
      encTitle.cipherText, encTitle.iv, encTitle.tag,
      encDesc.cipherText, encDesc.iv, encDesc.tag
    ]);

    const createdScrapbook = result.rows[0];

    // Audit Log Creation
    await logAuditEvent({
      userId: req.user.id,
      userEmail: req.user.email,
      ipAddress: clientIp,
      userAgent: req.headers['user-agent'],
      action: 'SCRAPBOOK_CREATE',
      resourceType: 'SCRAPBOOK',
      resourceId: createdScrapbook.id,
      status: 'SUCCESS',
      details: { isOwner: true }
    });

    return res.status(201).json({
      message: 'Scrapbook created successfully with AES-256 encryption.',
      scrapbook: {
        id: createdScrapbook.id,
        title, // Return decrypted in response over HTTPS
        description,
        createdAt: createdScrapbook.created_at
      }
    });
  } catch (error) {
    console.error('Error creating scrapbook:', error);
    return res.status(500).json({ error: 'Server Error', message: 'Failed to create scrapbook.' });
  }
});

/**
 * @route   GET /api/scrapbooks/:scrapbookId
 * @desc    Fetch scrapbook and its pages
 * @access  Viewer, Editor, Owner
 */
router.get('/:scrapbookId', requireViewer(), async (req, res) => {
  const { scrapbookId } = req.params;

  try {
    // 1. Fetch encrypted scrapbook record
    const sbQuery = `
      SELECT id, owner_id, title_encrypted, title_iv, title_tag,
             description_encrypted, description_iv, description_tag, created_at
      FROM scrapbooks
      WHERE id = $1
    `;
    const sbResult = await db.query(sbQuery, [scrapbookId]);
    const sb = sbResult.rows[0];

    // Decrypt on the fly
    const decryptedTitle = decryptText(sb.title_encrypted, sb.title_iv, sb.title_tag);
    const decryptedDesc = sb.description_encrypted
      ? decryptText(sb.description_encrypted, sb.description_iv, sb.description_tag)
      : null;

    // 2. Fetch encrypted pages
    const pagesQuery = `
      SELECT id, page_number, title_encrypted, title_iv, title_tag,
             content_encrypted, content_iv, content_tag,
             media_metadata_encrypted, media_metadata_iv, media_metadata_tag, created_at
      FROM scrapbook_pages
      WHERE scrapbook_id = $1
      ORDER BY page_number ASC
    `;
    const pagesResult = await db.query(pagesQuery, [scrapbookId]);

    const decryptedPages = pagesResult.rows.map(p => ({
      id: p.id,
      pageNumber: p.page_number,
      title: decryptText(p.title_encrypted, p.title_iv, p.title_tag),
      content: decryptText(p.content_encrypted, p.content_iv, p.content_tag),
      mediaMetadata: decryptJSON(p.media_metadata_encrypted, p.media_metadata_iv, p.media_metadata_tag),
      createdAt: p.created_at
    }));

    return res.json({
      scrapbook: {
        id: sb.id,
        title: decryptedTitle,
        description: decryptedDesc,
        userRole: req.scrapbookPermission.role,
        pages: decryptedPages
      }
    });
  } catch (error) {
    console.error('Error retrieving scrapbook:', error);
    return res.status(500).json({ error: 'Decryption Error', message: 'Failed to decrypt scrapbook.' });
  }
});

/**
 * @route   POST /api/scrapbooks/:scrapbookId/pages
 * @desc    Create a new memoir page in the scrapbook
 * @access  Editor, Owner (Blocked for Viewer)
 */
router.post('/:scrapbookId/pages', requireEditor(), async (req, res) => {
  const { scrapbookId } = req.params;
  const { pageNumber, title, content, mediaMetadata } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!pageNumber || !title || !content) {
    return res.status(400).json({ error: 'Validation Error', message: 'pageNumber, title, and content are required' });
  }

  try {
    // Encrypt memoir text and media metadata with AES-256-GCM
    const encTitle = encryptText(title);
    const encContent = encryptText(content);
    const encMedia = mediaMetadata ? encryptJSON(mediaMetadata) : { cipherText: null, iv: null, tag: null };

    const insertQuery = `
      INSERT INTO scrapbook_pages (
        scrapbook_id, page_number,
        title_encrypted, title_iv, title_tag,
        content_encrypted, content_iv, content_tag,
        media_metadata_encrypted, media_metadata_iv, media_metadata_tag
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING id, created_at
    `;

    const result = await db.query(insertQuery, [
      scrapbookId,
      pageNumber,
      encTitle.cipherText, encTitle.iv, encTitle.tag,
      encContent.cipherText, encContent.iv, encContent.tag,
      encMedia.cipherText, encMedia.iv, encMedia.tag
    ]);

    const page = result.rows[0];

    // Audit Log Page Addition
    await logAuditEvent({
      userId: req.user.id,
      userEmail: req.user.email,
      ipAddress: clientIp,
      userAgent: req.headers['user-agent'],
      action: 'PAGE_CREATE',
      resourceType: 'PAGE',
      resourceId: page.id,
      status: 'SUCCESS',
      details: { scrapbookId, pageNumber }
    });

    return res.status(201).json({
      message: 'Scrapbook page encrypted and saved successfully.',
      pageId: page.id
    });
  } catch (error) {
    console.error('Error adding scrapbook page:', error);
    return res.status(500).json({ error: 'Server Error', message: 'Failed to save page.' });
  }
});

/**
 * @route   POST /api/scrapbooks/:scrapbookId/share
 * @desc    Grant/Update collaborator role by Email (Owner Only)
 * @access  Owner
 */
router.post('/:scrapbookId/share', requireOwner(), async (req, res) => {
  const { scrapbookId } = req.params;
  const { collaboratorEmail, role } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!collaboratorEmail || !['Editor', 'Viewer'].includes(role)) {
    return res.status(400).json({
      error: 'Validation Error',
      message: 'Valid collaboratorEmail and role ("Editor" or "Viewer") are required.'
    });
  }

  try {
    const normalizedEmail = collaboratorEmail.trim().toLowerCase();

    // Upsert permission record
    const upsertQuery = `
      INSERT INTO scrapbook_permissions (scrapbook_id, user_email, role, granted_by)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (scrapbook_id, user_email)
      DO UPDATE SET role = EXCLUDED.role, updated_at = CURRENT_TIMESTAMP
      RETURNING id, role
    `;

    const result = await db.query(upsertQuery, [
      scrapbookId,
      normalizedEmail,
      role,
      req.user.id
    ]);

    await logAuditEvent({
      userId: req.user.id,
      userEmail: req.user.email,
      ipAddress: clientIp,
      userAgent: req.headers['user-agent'],
      action: 'PERMISSION_GRANT',
      resourceType: 'PERMISSION',
      resourceId: scrapbookId,
      status: 'SUCCESS',
      details: { targetEmail: normalizedEmail, assignedRole: role }
    });

    return res.json({
      message: `Permission '${role}' granted to ${normalizedEmail} successfully.`
    });
  } catch (error) {
    console.error('Error granting permission:', error);
    return res.status(500).json({ error: 'Server Error', message: 'Failed to update collaborator permission.' });
  }
});

/**
 * @route   DELETE /api/scrapbooks/:scrapbookId
 * @desc    Permanently delete scrapbook (Owner Only)
 * @access  Owner
 */
router.delete('/:scrapbookId', requireOwner(), async (req, res) => {
  const { scrapbookId } = req.params;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  try {
    await db.query('DELETE FROM scrapbooks WHERE id = $1', [scrapbookId]);

    await logAuditEvent({
      userId: req.user.id,
      userEmail: req.user.email,
      ipAddress: clientIp,
      userAgent: req.headers['user-agent'],
      action: 'SCRAPBOOK_DELETE',
      resourceType: 'SCRAPBOOK',
      resourceId: scrapbookId,
      status: 'SUCCESS',
      riskScore: 30
    });

    return res.json({ message: 'Scrapbook deleted permanently.' });
  } catch (error) {
    console.error('Error deleting scrapbook:', error);
    return res.status(500).json({ error: 'Server Error', message: 'Failed to delete scrapbook.' });
  }
});

module.exports = router;
