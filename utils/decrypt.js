/**
 * utils/decrypt.js
 * 
 * Full E2EE decryption for HostNet.wiki
 * 
 * Decrypts messages client-side after receiving.
 * The server never handles plaintext.
 * 
 * This is real privacy.
 * Not a promise. Not a policy.
 * Code.
 */

const crypto = require('crypto');

// Configuration (must match encrypt.js)
const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16;
const SALT_LENGTH = 32;
const KEY_DERIVATION_ITERATIONS = 100000;
const DIGEST = 'sha256';

/**
 * Decrypts a message using a password.
 * 
 * @param {string} encryptedData - Base64-encoded: salt:iv:ciphertext
 * @param {string} password - The user's password
 * @returns {string} - Decrypted plaintext
 */
function decryptMessage(encryptedData, password) {
  try {
    // Decode base64
    const buffer = Buffer.from(encryptedData, 'base64');
    
    // Extract salt, iv, and ciphertext
    const salt = buffer.subarray(0, SALT_LENGTH);
    const iv = buffer.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
    const ciphertext = buffer.subarray(SALT_LENGTH + IV_LENGTH);
    
    // Derive key
    const key = crypto.pbkdf2Sync(password, salt, KEY_DERIVATION_ITERATIONS, 32, DIGEST);
    
    // Create decipher
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    
    // Decrypt
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    console.error('Decryption failed:', error.message);
    throw new Error('Decryption failed. Wrong password or corrupted data.');
  }
}

/**
 * Decrypts a message using a pre-derived key (hex)
 * 
 * @param {string} encryptedData - Base64-encoded: iv:ciphertext
 * @param {string} keyHex - 64-character hex string
 * @returns {string} - Decrypted plaintext
 */
function decryptWithKey(encryptedData, keyHex) {
  try {
    if (!/^[0-9a-fA-F]{64}$/.test(keyHex)) {
      throw new Error('Invalid key format: must be 64-character hex string');
    }

    const buffer = Buffer.from(encryptedData, 'base64');
    const iv = buffer.subarray(0, IV_LENGTH);
    const ciphertext = buffer.subarray(IV_LENGTH);
    const key = Buffer.from(keyHex, 'hex');

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  } catch (error) {
    console.error('Decryption with key failed:', error.message);
    throw new Error('Decryption failed');
  }
}

/**
 * Validates if encrypted data is properly formatted
 * 
 * @param {string} encryptedData - Base64 string
 * @returns {boolean} - True if valid format
 */
function isValidEncryptedData(encryptedData) {
  try {
    const buffer = Buffer.from(encryptedData, 'base64');
    return buffer.length > IV_LENGTH + SALT_LENGTH;
  } catch {
    return false;
  }
}

/**
 * Extracts salt from encrypted data (for debugging or key derivation)
 * 
 * @param {string} encryptedData - Base64-encoded
 * @returns {Buffer|null} - Salt buffer
 */
function extractSalt(encryptedData) {
  try {
    const buffer = Buffer.from(encryptedData, 'base64');
    if (buffer.length <= SALT_LENGTH) return null;
    return buffer.subarray(0, SALT_LENGTH);
  } catch {
    return null;
  }
}

module.exports = {
  decryptMessage,
  decryptWithKey,
  isValidEncryptedData,
  extractSalt
};
