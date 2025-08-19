import CryptoJS from 'crypto-js';

// Generate a random salt
export const generateSalt = (): string => {
  return CryptoJS.lib.WordArray.random(128 / 8).toString();
};

// Hash password with PBKDF2 (FIPS-compliant)
export const hashPassword = (password: string, salt: string): string => {
  const iterations = 10000;
  const keySize = 256 / 32;
  
  const hash = CryptoJS.PBKDF2(password, salt, {
    keySize,
    iterations,
    hasher: CryptoJS.algo.SHA256,
  });
  
  return hash.toString();
};

// Encrypt data for transmission
export const encryptData = async (data: string): Promise<string> => {
  // In production, this should use the server's public key
  // For now, we'll use a simple hash
  const salt = generateSalt();
  const hashed = hashPassword(data, salt);
  return `${salt}:${hashed}`;
};

// Generate secure random string
export const generateSecureRandom = (length: number = 32): string => {
  const array = new Uint8Array(length);
  window.crypto.getRandomValues(array);
  return Array.from(array, (byte) => byte.toString(16).padStart(2, '0')).join('');
};

// Validate password strength
export const validatePasswordStrength = (password: string): {
  isValid: boolean;
  errors: string[];
} => {
  const errors: string[] = [];
  
  if (password.length < 12) {
    errors.push('Password must be at least 12 characters long');
  }
  
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  
  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }
  
  return {
    isValid: errors.length === 0,
    errors,
  };
};

// Clear sensitive data from memory
export const clearSensitiveData = (data: any): void => {
  if (typeof data === 'string') {
    // For strings, we can't directly clear memory in JavaScript
    // But we can at least remove references
    data = null;
  } else if (data instanceof Uint8Array) {
    // For typed arrays, we can overwrite the data
    data.fill(0);
  } else if (typeof data === 'object' && data !== null) {
    // For objects, clear all properties
    Object.keys(data).forEach(key => {
      data[key] = null;
    });
  }
};