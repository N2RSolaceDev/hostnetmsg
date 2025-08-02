/**
 * utils/encrypt.js
 * 
 * Full E2EE encryption for HostNet.wiki
 * 
 * Encrypts messages client-side before sending.
 * The server only stores ciphertext.
 * 
 * I wrote this after 3 days of WebCrypto research.
 * It works. It's secure. It's mine.
 */

const crypto = require('crypto');

// Configuration
const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16;
const SALT_LENGTH = 32;
const KEY_DERIVATION_ITERATIONS = 100000;
const DIGEST = 'sha256';

/**
 * Encrypts a message using a password.
 * 
 * @param {string} text - The plaintext message
 * @param {string} password - The user's password (never sent to server)
 * @returns {string} - Base64-encoded: salt:iv:ciphertext
 */
function encryptMessage(text, password) {
  try {
    // Generate salt
    const salt = crypto.randomBytes(SALT_LENGTH);
    
    // Derive key from password + salt
    const key = crypto.pbkdf2Sync(password, salt, KEY_DERIVATION_ITERATIONS, 32, DIGEST);
    
    // Generate IV
    const iv = crypto.randomBytes(IV_LENGTH);
    
    // Create cipher
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    
    // Encrypt
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    // Format: salt:iv:encrypted
    const combined = Buffer.concat([
      salt,
      iv,
      Buffer.from(encrypted, 'hex')
    ]);
    
    return combined.toString('base64');
  } catch (error) {
    console.error('Encryption failed:', error.message);
    throw new Error('Encryption failed');
  }
}

/**
 * Encrypts a message using a pre-derived key (hex)
 * 
 * @param {string} text - The plaintext message
 * @param {string} keyHex - 64-character hex string (32 bytes)
 * @returns {string} - Base64-encoded: iv:ciphertext
 */
function encryptWithKey(text, keyHex) {
  try {
    if (!/^[0-9a-fA-F]{64}$/.test(keyHex)) {
      throw new Error('Invalid key format: must be 64-character hex string');
    }

    const key = Buffer.from(keyHex, 'hex');
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const combined = Buffer.concat([
      iv,
      Buffer.from(encrypted, 'hex')
    ]);

    return combined.toString('base64');
  } catch (error) {
    console.error('Encryption with key failed:', error.message);
    throw new Error('Encryption failed');
  }
}

/**
 * Generates a secure encryption key from password
 * Returns only the key (not salt) — salt must be stored separately
 * 
 * @param {string} password
 * @param {Buffer} salt
 * @returns {string} - 64-character hex key
 */
function deriveKey(password, salt) {
  const key = crypto.pbkdf2Sync(password, salt, KEY_DERIVATION_ITERATIONS, 32, DIGEST);
  return key.toString('hex');
}

/**
 * Generates a random encryption key (64-char hex)
 * For group chats or file encryption
 * 
 * @returns {string} - 64-character hex key
 */
function generateRandomKey() {
  return crypto.randomBytes(32).toString('hex');
}

module.exports = {
  encryptMessage,
  encryptWithKey,
  deriveKey,
  generateRandomKey
};
