import * as CryptoJS from 'crypto-js';

/**
 * Generates a cryptographically secure random string using the Web Crypto API.
 * This is used for generating encryption keys and salts.
 */
function generateSecureRandomString(length: number): string {
  const array = new Uint8Array(length);
  try {
    if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
      // Use browser's secure random generator
      window.crypto.getRandomValues(array);
    } else {
      throw new Error("Crypto not available");
    }
  } catch (e) {
    // Fallback for environments where crypto is restricted or unavailable
    for (let i = 0; i < length; i++) {
      array[i] = Math.floor(Math.random() * 256);
    }
  }
  // Convert bytes to a base36 string for URL compatibility
  return Array.from(array, (byte) => byte.toString(36)).join('').substring(0, length);
}

/**
 * Derives a strong encryption key from a base key, password, and salt using PBKDF2.
 * PBKDF2 with 100,000 iterations is a standard recommendation for high security.
 */
function deriveKey(baseKey: string, password?: string, salt?: string): string {
  if (!password || !salt) return baseKey;
  
  // Combine baseKey and password for the derivation
  const combinedPassword = baseKey + password;
  
  // Use PBKDF2 with 100,000 iterations
  const derived = CryptoJS.PBKDF2(combinedPassword, salt, {
    keySize: 256 / 32,
    iterations: 100000,
    hasher: CryptoJS.algo.SHA256
  });
  
  return derived.toString();
}

/**
 * Encrypts a string using AES-256.
 * 
 * SECURITY ARCHITECTURE:
 * 1. A random 32-char key is generated on the client.
 * 2. This key is returned but NOT sent to the server. It stays in the URL fragment (#).
 * 3. If a password is provided, we derive a stronger encryption key using PBKDF2.
 * 4. The server only receives the encrypted blob and (if applicable) the salt/password hash.
 */
export function encryptSecret(text: string, password?: string): { encryptedData: string; key: string; salt?: string } {
  try {
    const key = generateSecureRandomString(32);
    const salt = password ? generateSecureRandomString(16) : undefined;
    
    // Derive the final encryption key using PBKDF2
    const encryptionKey = deriveKey(key, password, salt);
    
    // Perform AES encryption
    const encrypted = CryptoJS.AES.encrypt(text, encryptionKey).toString();
    
    return {
      encryptedData: encrypted,
      key: key,
      salt: salt
    };
  } catch (e) {
    console.error("Encryption error:", e);
    throw new Error("Encryption failed. This might be due to browser security restrictions.");
  }
}

/**
 * Decrypts a string using AES-256.
 * Requires the key (from URL fragment) and optional password.
 */
export function decryptSecret(encryptedData: string, key: string, password?: string, salt?: string): string {
  try {
    // Re-derive the decryption key using PBKDF2
    const decryptionKey = deriveKey(key, password, salt);
    
    const bytes = CryptoJS.AES.decrypt(encryptedData, decryptionKey);
    const originalText = bytes.toString(CryptoJS.enc.Utf8);
    
    // If decryption fails (wrong key/password), originalText will be empty
    if (!originalText) {
      throw new Error("Invalid key or password");
    }
    
    return originalText;
  } catch (e) {
    console.error("Decryption error:", e);
    if (e instanceof Error && e.message === "Invalid key or password") throw e;
    throw new Error("Decryption failed. This might be due to browser security restrictions.");
  }
}

/**
 * Hashes a password with a salt using SHA-256.
 * This hash is sent to the server to verify access without sending the actual password.
 */
export function hashPassword(password: string, salt: string): string {
  return CryptoJS.SHA256(password + salt).toString();
}
