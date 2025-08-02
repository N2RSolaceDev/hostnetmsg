/**
 * utils/sendEmail.js
 * 
 * Sends verification emails via the unfiltereduk.co.uk API.
 * 
 * Uses:
 *   API_KEY=ukapi_5bf9cafbd354a61380addcbcbaeadb57b8d251f91b56866e66afa6e00d6fd5e5
 *   BASE_URL=https://unfiltereduk.onrender.com
 * 
 * This is not SMTP. This is direct API integration.
 * No email client. No transport. Just HTTP.
 * 
 * I built this so the system speaks to itself.
 * Like I do, when no one’s listening.
 */

const axios = require('axios');

// API Configuration
const API_KEY = 'ukapi_5bf9cafbd354a61380addcbcbaeadb57b8d251f91b56866e66afa6e00d6fd5e5';
const BASE_URL = 'https://unfiltereduk.onrender.com';

// Initialize axios instance
const api = axios.create({
  baseURL: BASE_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json'
  }
});

/**
 * Sends a verification email to the user
 * 
 * @param {string} to - User's email (e.g. user@unfiltereduk.co.uk)
 * @param {string} token - JWT or verification token
 * @returns {Promise<{ success: boolean, messageId?: string, error?: string }>}
 */
async function sendVerificationEmail(to, token) {
  const verificationLink = `${BASE_URL}/verify?token=${token}`;

  const subject = '🔐 Verify Your HostNet Account';
  const body = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
      <h2 style="color: #000;">Welcome to HostNet</h2>
      <p>You've created an account with <strong>HostNet.wiki</strong>, the British communication network.</p>
      <p>To complete your registration, please verify your email address:</p>
      <div style="text-align: center; margin: 30px 0;">
        <a href="${verificationLink}" 
           style="background: #000; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold;">
           Verify Email Address
        </a>
      </div>
      <p>This link expires in 24 hours.</p>
      <p>If you didn't create this account, please ignore this email.</p>
      <hr>
      <p><small>This email was sent securely via the unfiltereduk.co.uk network.<br>
         No tracking. No ads. No compromise.</small></p>
    </div>
  `;

  try {
    const response = await api.post('/api/automated-send', {
      key: API_KEY,
      to,
      subject,
      body
    });

    if (response.status === 200) {
      console.log(`📧 Verification email sent to ${to}`);
      return { success: true, messageId: response.data.from };
    } else {
      console.warn('📧 API responded with non-OK status:', response.status, response.data);
      return { success: false, error: 'Failed to send email (API error)' };
    }
  } catch (error) {
    if (error.response) {
      console.error('📧 API Error:', error.response.status, error.response.data);
      return { 
        success: false, 
        error: `API error: ${error.response.data.error || 'Unknown error'}` 
      };
    } else if (error.request) {
      console.error('📧 No response received:', error.request);
      return { success: false, error: 'No response from email service' };
    } else {
      console.error('📧 Request setup error:', error.message);
      return { success: false, error: 'Email request failed' };
    }
  }
}

/**
 * Sends a password reset verification email
 * 
 * @param {string} to - User's email
 * @param {string} token - Reset token
 * @returns {Promise<{ success: boolean, error?: string }>}
 */
async function sendPasswordResetEmail(to, token) {
  const resetLink = `${BASE_URL}/reset-password?token=${token}`;

  const subject = '🔐 Reset Your HostNet Password';
  const body = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px;">
      <h2>Password Reset Request</h2>
      <p>You requested to reset your password for <strong>HostNet.wiki</strong>.</p>
      <p>If this was you, click the link below:</p>
      <div style="text-align: center; margin: 30px 0;">
        <a href="${resetLink}" 
           style="background: #000; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold;">
           Reset Password
        </a>
      </div>
      <p>This link expires in 1 hour.</p>
      <p>If you didn't request this, please ignore this email.</p>
      <hr>
      <p><small>Secured by unfiltereduk.co.uk • No tracking • No logging</small></p>
    </div>
  `;

  try {
    const response = await api.post('/api/automated-send', {
      key: API_KEY,
      to,
      subject,
      body
    });

    if (response.status === 200) {
      console.log(`📧 Password reset email sent to ${to}`);
      return { success: true };
    } else {
      return { success: false, error: 'Failed to send reset email' };
    }
  } catch (error) {
    console.error('📧 Failed to send password reset email:', error.message);
    return { success: false, error: 'Could not send reset email' };
  }
}

/**
 * Test function: Sends a test verification email
 * Only for dev/debugging
 */
async function sendTestEmail(to) {
  const testToken = 'testtoken_abc123';
  return await sendVerificationEmail(to, testToken);
}

module.exports = {
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendTestEmail
};
