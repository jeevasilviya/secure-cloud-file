/**
 * =====================================================================
 * SecureScrapbook - Application-Layer Cryptography Service
 * =====================================================================
 * Algorithm: AES-256-GCM (Authenticated Encryption with Associated Data)
 * Standards:
 *   - 256-bit Key derived from APP_ENCRYPTION_KEY / AWS KMS
 *   - 96-bit (12-byte) cryptographically secure random IV per ciphertext
 *   - 128-bit (16-byte) Authentication Tag ensuring data integrity & tamper-proofing
 *
 * Guarantees zero plaintext storage of memoirs, titles, and metadata in PostgreSQL.
 */

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH_BYTES = 12; // Standard 96-bit IV recommended for GCM
const AUTH_TAG_LENGTH_BYTES = 16; // 128-bit GCM authentication tag

/**
 * Derives a consistent 32-byte (256-bit) buffer from the master key string or buffer.
 * In production AWS EC2 environments, this key is retrieved from AWS Secrets Manager / KMS.
 * @returns {Buffer}
 */
function getMasterKey() {
  const secret = process.env.APP_ENCRYPTION_KEY || 'default_32_byte_development_key_secure_scrapbook_2026!';
  return crypto.createHash('sha256').update(secret).digest();
}

/**
 * Encrypts a plaintext UTF-8 string using AES-256-GCM.
 *
 * @param {string} plainText - The sensitive user content or memoir text
 * @param {string|Buffer} [associatedData] - Optional AAD (e.g. scrapbook UUID) to prevent ciphertext relocation
 * @returns {{ cipherText: string, iv: string, tag: string }} Hex-encoded components for DB storage
 */
function encryptText(plainText, associatedData = '') {
  if (plainText === null || plainText === undefined) {
    return { cipherText: null, iv: null, tag: null };
  }

  const key = getMasterKey();
  const iv = crypto.randomBytes(IV_LENGTH_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  if (associatedData) {
    cipher.setAAD(Buffer.from(String(associatedData), 'utf8'));
  }

  let encrypted = cipher.update(String(plainText), 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const tag = cipher.getAuthTag();

  return {
    cipherText: encrypted,
    iv: iv.toString('hex'),
    tag: tag.toString('hex')
  };
}

/**
 * Decrypts an AES-256-GCM ciphertext verifying the integrity tag.
 *
 * @param {string} cipherText - Hex-encoded encrypted data
 * @param {string} ivHex - Hex-encoded IV
 * @param {string} tagHex - Hex-encoded authentication tag
 * @param {string|Buffer} [associatedData] - Associated Authenticated Data used during encryption
 * @returns {string} Plaintext UTF-8 string
 * @throws {Error} If authentication tag verification fails (ciphertext was tampered with)
 */
function decryptText(cipherText, ivHex, tagHex, associatedData = '') {
  if (!cipherText || !ivHex || !tagHex) {
    return null;
  }

  const key = getMasterKey();
  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);

  if (associatedData) {
    decipher.setAAD(Buffer.from(String(associatedData), 'utf8'));
  }

  let decrypted = decipher.update(cipherText, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

/**
 * Encrypts arbitrary JSON metadata (photos, coordinates, layout settings).
 *
 * @param {object} jsonObject
 * @param {string} [associatedData]
 * @returns {{ cipherText: string, iv: string, tag: string }}
 */
function encryptJSON(jsonObject, associatedData = '') {
  if (!jsonObject) return { cipherText: null, iv: null, tag: null };
  const serialized = JSON.stringify(jsonObject);
  return encryptText(serialized, associatedData);
}

/**
 * Decrypts and parses JSON metadata.
 *
 * @param {string} cipherText
 * @param {string} ivHex
 * @param {string} tagHex
 * @param {string} [associatedData]
 * @returns {object|null}
 */
function decryptJSON(cipherText, ivHex, tagHex, associatedData = '') {
  const plainText = decryptText(cipherText, ivHex, tagHex, associatedData);
  if (!plainText) return null;
  return JSON.parse(plainText);
}

module.exports = {
  encryptText,
  decryptText,
  encryptJSON,
  decryptJSON
};
