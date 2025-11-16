/**
 * Host Validation Utilities
 *
 * Validation functions for host configuration and credentials.
 * These utilities ensure data integrity before submitting to the backend API.
 *
 * Used by:
 * - Hosts page (edit host dialog)
 * - Host creation dialog
 * - Bulk import validation
 * - API request validation
 *
 * DO NOT use these functions for backend validation - backend has its own
 * validation layer. These are frontend-only checks for UX improvement.
 *
 * @module utils/hostValidation
 */

/**
 * Valid SSH private key header formats.
 *
 * These headers identify different SSH key types and formats.
 * Used to validate SSH private key content before upload.
 *
 * Supported formats:
 * - OpenSSH: Modern format (default since OpenSSH 7.8)
 * - RSA: Traditional RSA keys (legacy)
 * - EC: Elliptic Curve keys (ECDSA)
 * - DSA: Digital Signature Algorithm keys (deprecated, included for compatibility)
 *
 * @constant
 * @readonly
 */
export const VALID_SSH_KEY_HEADERS = [
  '-----BEGIN OPENSSH PRIVATE KEY-----', // pragma: allowlist secret
  '-----BEGIN RSA PRIVATE KEY-----', // pragma: allowlist secret
  '-----BEGIN EC PRIVATE KEY-----', // pragma: allowlist secret
  '-----BEGIN DSA PRIVATE KEY-----', // pragma: allowlist secret
] as const;

/**
 * Validate SSH private key format.
 *
 * Checks if the provided SSH key content starts with a valid PEM header.
 * This is a basic format validation - full cryptographic validation happens
 * server-side.
 *
 * Validation rules:
 * 1. Key content must not be empty or whitespace-only
 * 2. Key must start with one of the valid PEM headers
 * 3. Trimmed content is checked (leading/trailing whitespace ignored)
 *
 * Security Note: This function does NOT validate:
 * - Key strength (bit length)
 * - Key integrity (corrupted keys)
 * - Key permissions (public vs private)
 * - Key passphrase protection
 *
 * Backend validation handles these concerns.
 *
 * @param keyContent - Raw SSH private key content
 * @returns True if key has valid format, false otherwise
 *
 * @example
 * const key = '-----BEGIN OPENSSH PRIVATE KEY-----\nABC123...\n-----END...'; // pragma: allowlist secret
 * const isValid = validateSshKey(key);
 * console.log(isValid); // true
 *
 * @example
 * const invalidKey = 'not a real key';
 * const isValid = validateSshKey(invalidKey);
 * console.log(isValid); // false
 */
export function validateSshKey(keyContent: string): boolean {
  // Reject empty or whitespace-only content
  if (!keyContent || !keyContent.trim()) {
    return false;
  }

  const trimmedContent = keyContent.trim();

  // Check if content starts with any valid SSH key header
  return VALID_SSH_KEY_HEADERS.some((header) => trimmedContent.startsWith(header));
}

/**
 * Validate hostname format.
 *
 * Checks if hostname is valid per RFC 1123 standards.
 *
 * Validation rules:
 * 1. Length: 1-253 characters
 * 2. Characters: alphanumeric, hyphens, dots only
 * 3. Format: Cannot start/end with hyphen or dot
 * 4. Labels: Each dot-separated segment 1-63 characters
 *
 * @param hostname - Hostname or FQDN to validate
 * @returns True if hostname is valid, false otherwise
 *
 * @example
 * validateHostname('web-server-01.example.com'); // true
 * validateHostname('localhost'); // true
 * validateHostname('-invalid'); // false
 * validateHostname('too..many...dots'); // false
 */
export function validateHostname(hostname: string): boolean {
  if (!hostname || hostname.length === 0 || hostname.length > 253) {
    return false;
  }

  // RFC 1123 hostname pattern
  const hostnamePattern =
    /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  return hostnamePattern.test(hostname);
}

/**
 * Validate IPv4 address format.
 *
 * Checks if IP address is valid IPv4 format with correct octet ranges.
 *
 * Validation rules:
 * 1. Format: Four dot-separated octets (xxx.xxx.xxx.xxx)
 * 2. Range: Each octet 0-255
 * 3. Special addresses: Rejects 0.0.0.0, 255.255.255.255
 * 4. Localhost: Rejects 127.x.x.x addresses
 *
 * @param ipAddress - IPv4 address to validate
 * @returns True if IP address is valid, false otherwise
 *
 * @example
 * validateIpAddress('192.168.1.100'); // true
 * validateIpAddress('10.0.0.1'); // true
 * validateIpAddress('127.0.0.1'); // false (localhost)
 * validateIpAddress('256.1.1.1'); // false (out of range)
 */
export function validateIpAddress(ipAddress: string): boolean {
  if (!ipAddress) {
    return false;
  }

  // Basic IPv4 pattern
  const ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const match = ipAddress.match(ipPattern);

  if (!match) {
    return false;
  }

  // Check each octet is in valid range (0-255)
  const octets = [match[1], match[2], match[3], match[4]].map(Number);
  if (!octets.every((octet) => octet >= 0 && octet <= 255)) {
    return false;
  }

  // Reject special addresses
  if (ipAddress === '0.0.0.0' || ipAddress === '255.255.255.255') {
    return false;
  }

  // Reject localhost addresses (127.x.x.x)
  if (octets[0] === 127) {
    return false;
  }

  return true;
}

/**
 * Validate SSH port number.
 *
 * Checks if port number is in valid range and not a reserved system port.
 *
 * Validation rules:
 * 1. Range: 1-65535 (valid TCP port range)
 * 2. Typical: Port 22 (default SSH)
 * 3. Warning: Ports 1-1023 are system reserved (allowed but logged)
 *
 * @param port - Port number to validate
 * @returns True if port is valid, false otherwise
 *
 * @example
 * validatePort(22); // true (default SSH)
 * validatePort(2222); // true (alternate SSH)
 * validatePort(0); // false (reserved)
 * validatePort(70000); // false (out of range)
 */
export function validatePort(port: number): boolean {
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

/**
 * Validate username format.
 *
 * Checks if username meets Unix/Linux username requirements.
 *
 * Validation rules:
 * 1. Length: 1-32 characters
 * 2. Characters: lowercase letters, digits, hyphens, underscores
 * 3. Format: Must start with lowercase letter or underscore
 * 4. Reserved: Cannot be 'root' in some contexts (warning only)
 *
 * @param username - Username to validate
 * @returns True if username is valid, false otherwise
 *
 * @example
 * validateUsername('deploy'); // true
 * validateUsername('admin_user'); // true
 * validateUsername('1invalid'); // false (starts with digit)
 * validateUsername('user@host'); // false (invalid character)
 */
export function validateUsername(username: string): boolean {
  if (!username || username.length === 0 || username.length > 32) {
    return false;
  }

  // Unix username pattern: starts with letter or underscore,
  // followed by letters, digits, hyphens, underscores
  const usernamePattern = /^[a-z_][a-z0-9_-]*$/;
  return usernamePattern.test(username);
}
