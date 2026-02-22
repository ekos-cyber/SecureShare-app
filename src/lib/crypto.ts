/**
 * Web Crypto API Implementation
 * Uses native browser cryptography for maximum security and performance.
 * Algorithms: AES-GCM (Authenticated Encryption), PBKDF2 (Key Derivation), SHA-256 (Hashing).
 */

// Helper to convert ArrayBuffer to Base64
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

// Helper to convert Base64 to Uint8Array
function base64ToUint8Array(base64: string): Uint8Array {
  const binary_string = window.atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes;
}

// Helper to convert string to Uint8Array
function stringToUint8Array(str: string): Uint8Array {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}

/**
 * Generates a cryptographically secure random string.
 */
function generateSecureRandomString(length: number): string {
  const array = new Uint8Array(length);
  window.crypto.getRandomValues(array);
  return Array.from(array, (byte) => byte.toString(36)).join('').substring(0, length);
}

/**
 * Derives a strong encryption key using PBKDF2.
 */
async function deriveKey(baseKey: string, password?: string, salt?: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  
  // 1. Import the base key material
  const keyMaterial = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(baseKey + (password || "")),
    { name: "PBKDF2" },
    false,
    ["deriveBits", "deriveKey"]
  );

  // 2. Derive the actual AES-GCM key
  // If no salt is provided (no password case), we use a fixed salt or the baseKey itself as salt?
  // Actually, for the no-password case, we can just import the baseKey directly as AES-GCM?
  // But to keep it uniform, let's use PBKDF2 always.
  // If salt is missing, we use an empty salt (not ideal but consistent with legacy logic if any).
  // However, the caller should provide a salt if password is used.
  
  const saltBuffer = salt ? enc.encode(salt) : new Uint8Array(16); // Default salt if none (should not happen for password case)

  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBuffer,
      iterations: 100000,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypts a string using AES-GCM.
 */
export async function encryptSecret(text: string, password?: string): Promise<{ encryptedData: string; key: string; salt?: string }> {
  const key = generateSecureRandomString(32);
  const salt = password ? generateSecureRandomString(16) : undefined;
  
  // Derive key
  const cryptoKey = await deriveKey(key, password, salt);
  
  // Generate IV (12 bytes for GCM)
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  
  // Encrypt
  const encodedText = new TextEncoder().encode(text);
  const encryptedBuffer = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    cryptoKey,
    encodedText
  );
  
  // Combine IV + Ciphertext
  const combined = new Uint8Array(iv.length + encryptedBuffer.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encryptedBuffer), iv.length);
  
  return {
    encryptedData: arrayBufferToBase64(combined.buffer),
    key: key,
    salt: salt
  };
}

/**
 * Decrypts a string using AES-GCM.
 */
export async function decryptSecret(encryptedData: string, key: string, password?: string, salt?: string): Promise<string> {
  try {
    // Decode base64
    const combined = base64ToUint8Array(encryptedData);
    
    // Extract IV (first 12 bytes)
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    
    // Derive key
    const cryptoKey = await deriveKey(key, password, salt);
    
    // Decrypt
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv
      },
      cryptoKey,
      ciphertext
    );
    
    return new TextDecoder().decode(decryptedBuffer);
  } catch (e) {
    console.error("Decryption error:", e);
    throw new Error("Invalid key or password");
  }
}

/**
 * Hashes a password with a salt using SHA-256.
 */
export async function hashPassword(password: string, salt: string): Promise<string> {
  const msgBuffer = new TextEncoder().encode(password + salt);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', msgBuffer);
  return arrayBufferToBase64(hashBuffer);
}
