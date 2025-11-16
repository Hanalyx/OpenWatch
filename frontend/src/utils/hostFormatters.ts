/**
 * Host Data Formatters
 *
 * Formatting utilities for displaying host-related data in user-friendly formats.
 * Includes date/time formatting, metric formatting, and text transformation.
 *
 * Used by:
 * - Hosts page (data display)
 * - Host detail page (metrics, timestamps)
 * - Dashboard (summaries, aggregations)
 * - Reports (data export)
 *
 * @module utils/hostFormatters
 */

/**
 * Format ISO 8601 timestamp to localized date/time string.
 *
 * Converts ISO timestamp to human-readable format using browser locale.
 * Returns fallback text for null/invalid timestamps.
 *
 * Format: "MM/DD/YYYY, HH:MM:SS AM/PM" (US locale)
 * Examples: "11/14/2025, 2:30:45 PM", "Never", "Unknown"
 *
 * @param isoTimestamp - ISO 8601 timestamp string or null
 * @param fallback - Text to display if timestamp is null (default: "Never")
 * @returns Formatted date/time string
 *
 * @example
 * formatTimestamp('2025-11-14T14:30:45Z'); // "11/14/2025, 2:30:45 PM"
 * formatTimestamp(null); // "Never"
 * formatTimestamp(null, 'Not Available'); // "Not Available"
 */
export function formatTimestamp(isoTimestamp: string | null, fallback: string = 'Never'): string {
  if (!isoTimestamp) {
    return fallback;
  }

  try {
    const date = new Date(isoTimestamp);
    if (isNaN(date.getTime())) {
      return fallback;
    }
    return date.toLocaleString();
  } catch (error) {
    return fallback;
  }
}

/**
 * Format timestamp as relative time (e.g., "2 hours ago").
 *
 * Converts timestamp to human-friendly relative time description.
 * Uses browser's Intl.RelativeTimeFormat for localization.
 *
 * Examples:
 * - "just now" (< 1 minute)
 * - "5 minutes ago"
 * - "2 hours ago"
 * - "3 days ago"
 * - "2 weeks ago"
 *
 * @param isoTimestamp - ISO 8601 timestamp string or null
 * @param fallback - Text to display if timestamp is null (default: "Never")
 * @returns Relative time string
 *
 * @example
 * // If current time is 2025-11-14 15:00:00
 * formatRelativeTime('2025-11-14T14:55:00Z'); // "5 minutes ago"
 * formatRelativeTime('2025-11-12T14:00:00Z'); // "2 days ago"
 * formatRelativeTime(null); // "Never"
 */
export function formatRelativeTime(
  isoTimestamp: string | null,
  fallback: string = 'Never'
): string {
  if (!isoTimestamp) {
    return fallback;
  }

  try {
    const date = new Date(isoTimestamp);
    if (isNaN(date.getTime())) {
      return fallback;
    }

    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffSec = Math.floor(diffMs / 1000);
    const diffMin = Math.floor(diffSec / 60);
    const diffHour = Math.floor(diffMin / 60);
    const diffDay = Math.floor(diffHour / 24);

    // Less than 1 minute
    if (diffSec < 60) {
      return 'just now';
    }

    // Less than 1 hour
    if (diffMin < 60) {
      return `${diffMin} minute${diffMin > 1 ? 's' : ''} ago`;
    }

    // Less than 1 day
    if (diffHour < 24) {
      return `${diffHour} hour${diffHour > 1 ? 's' : ''} ago`;
    }

    // Less than 1 week
    if (diffDay < 7) {
      return `${diffDay} day${diffDay > 1 ? 's' : ''} ago`;
    }

    // Less than 1 month
    if (diffDay < 30) {
      const weeks = Math.floor(diffDay / 7);
      return `${weeks} week${weeks > 1 ? 's' : ''} ago`;
    }

    // More than 1 month - show absolute date
    return formatTimestamp(isoTimestamp, fallback);
  } catch (error) {
    return fallback;
  }
}

/**
 * Format percentage value to fixed decimal places.
 *
 * Formats numeric percentage for consistent display across the application.
 * Handles null values and out-of-range values gracefully.
 *
 * @param value - Percentage value (0-100) or null
 * @param decimals - Number of decimal places (default: 1)
 * @param fallback - Text to display if value is null (default: "N/A")
 * @returns Formatted percentage string with % symbol
 *
 * @example
 * formatPercentage(87.543, 1); // "87.5%"
 * formatPercentage(95, 0); // "95%"
 * formatPercentage(null); // "N/A"
 */
export function formatPercentage(
  value: number | null,
  decimals: number = 1,
  fallback: string = 'N/A'
): string {
  if (value === null || value === undefined) {
    return fallback;
  }

  if (isNaN(value)) {
    return fallback;
  }

  return `${value.toFixed(decimals)}%`;
}

/**
 * Format byte size to human-readable string (KB, MB, GB).
 *
 * Converts byte count to appropriate unit with automatic scaling.
 * Uses binary units (1024 bytes = 1 KB).
 *
 * @param bytes - Size in bytes or null
 * @param decimals - Number of decimal places (default: 1)
 * @param fallback - Text to display if bytes is null (default: "N/A")
 * @returns Formatted size string with unit
 *
 * @example
 * formatByteSize(1024); // "1.0 KB"
 * formatByteSize(1536, 2); // "1.50 KB"
 * formatByteSize(1048576); // "1.0 MB"
 * formatByteSize(null); // "N/A"
 */
export function formatByteSize(
  bytes: number | null,
  decimals: number = 1,
  fallback: string = 'N/A'
): string {
  if (bytes === null || bytes === undefined || isNaN(bytes)) {
    return fallback;
  }

  if (bytes === 0) {
    return '0 Bytes';
  }

  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return `${(bytes / Math.pow(k, i)).toFixed(decimals)} ${sizes[i]}`;
}

/**
 * Format uptime duration to human-readable string.
 *
 * Converts uptime in seconds to friendly duration format.
 * Shows most significant units (days, hours, minutes).
 *
 * @param uptimeSeconds - Uptime in seconds or null
 * @param fallback - Text to display if uptime is null (default: "Unknown")
 * @returns Formatted uptime string
 *
 * @example
 * formatUptime(3665); // "1h 1m"
 * formatUptime(86400); // "1d 0h"
 * formatUptime(172800); // "2d 0h"
 * formatUptime(null); // "Unknown"
 */
export function formatUptime(uptimeSeconds: number | null, fallback: string = 'Unknown'): string {
  if (uptimeSeconds === null || uptimeSeconds === undefined || isNaN(uptimeSeconds)) {
    return fallback;
  }

  const days = Math.floor(uptimeSeconds / 86400);
  const hours = Math.floor((uptimeSeconds % 86400) / 3600);
  const minutes = Math.floor((uptimeSeconds % 3600) / 60);

  if (days > 0) {
    return `${days}d ${hours}h`;
  }

  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }

  return `${minutes}m`;
}

/**
 * Capitalize first letter of string.
 *
 * Simple text transformation for consistent formatting.
 * Handles empty strings and null values gracefully.
 *
 * @param text - String to capitalize or null
 * @param fallback - Text to return if input is null (default: empty string)
 * @returns Capitalized string
 *
 * @example
 * capitalize('hello'); // "Hello"
 * capitalize('WORLD'); // "WORLD" (only first letter affected)
 * capitalize(''); // ""
 * capitalize(null); // ""
 */
export function capitalize(text: string | null, fallback: string = ''): string {
  if (!text) {
    return fallback;
  }

  return text.charAt(0).toUpperCase() + text.slice(1);
}

/**
 * Truncate long text with ellipsis.
 *
 * Shortens text to maximum length and adds ellipsis if truncated.
 * Preserves full text if already within length limit.
 *
 * @param text - Text to truncate or null
 * @param maxLength - Maximum length before truncation (default: 50)
 * @param ellipsis - Ellipsis string to append (default: "...")
 * @returns Truncated text with ellipsis if needed
 *
 * @example
 * truncate('This is a very long hostname', 15); // "This is a ve..."
 * truncate('Short', 15); // "Short"
 * truncate(null, 15); // ""
 */
export function truncate(
  text: string | null,
  maxLength: number = 50,
  ellipsis: string = '...'
): string {
  if (!text) {
    return '';
  }

  if (text.length <= maxLength) {
    return text;
  }

  return text.substring(0, maxLength - ellipsis.length) + ellipsis;
}

/**
 * Format number with thousand separators.
 *
 * Adds commas (or locale-specific separators) to large numbers for readability.
 *
 * @param value - Number to format or null
 * @param fallback - Text to display if value is null (default: "0")
 * @returns Formatted number string
 *
 * @example
 * formatNumber(1000); // "1,000"
 * formatNumber(1234567); // "1,234,567"
 * formatNumber(null); // "0"
 */
export function formatNumber(value: number | null, fallback: string = '0'): string {
  if (value === null || value === undefined || isNaN(value)) {
    return fallback;
  }

  return value.toLocaleString();
}
