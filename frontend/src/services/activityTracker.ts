/**
 * Activity Tracker Service
 *
 * Tracks user activity (mouse, keyboard, touch) to implement
 * inactivity-based session timeout.
 *
 * Default: 15 minutes of inactivity triggers session expiry warning.
 */

import { store } from '../store';
import { logout } from '../store/slices/authSlice';

// Default inactivity timeout in minutes
const DEFAULT_INACTIVITY_TIMEOUT_MINUTES = 15;

// Storage key for admin-configured timeout
const TIMEOUT_STORAGE_KEY = 'session_inactivity_timeout_minutes';

// Activity events to track
const ACTIVITY_EVENTS = [
  'mousedown',
  'mousemove',
  'keydown',
  'scroll',
  'touchstart',
  'click',
  'wheel',
] as const;

// Throttle activity updates to avoid excessive processing
const ACTIVITY_THROTTLE_MS = 1000;

class ActivityTracker {
  private lastActivityTime: number = Date.now();
  private inactivityTimeoutMinutes: number = DEFAULT_INACTIVITY_TIMEOUT_MINUTES;
  private checkInterval: NodeJS.Timeout | null = null;
  private isTracking: boolean = false;
  private lastThrottledUpdate: number = 0;
  private boundActivityHandler: () => void;
  private onInactivityWarning: ((timeLeftSeconds: number) => void) | null = null;
  private onInactivityLogout: (() => void) | null = null;
  private warningShown: boolean = false;

  constructor() {
    this.boundActivityHandler = this.handleActivity.bind(this);
    this.loadTimeoutSetting();
  }

  /**
   * Load timeout setting from localStorage (local cache)
   */
  private loadTimeoutSetting(): void {
    try {
      const stored = localStorage.getItem(TIMEOUT_STORAGE_KEY);
      if (stored) {
        const parsed = parseInt(stored, 10);
        if (!isNaN(parsed) && parsed >= 1 && parsed <= 480) {
          this.inactivityTimeoutMinutes = parsed;
        }
      }
    } catch {
      // Use default if storage fails
    }
  }

  /**
   * Fetch timeout setting from backend API and cache locally
   * This is called once when tracking starts to sync with admin-configured value
   */
  async fetchTimeoutFromBackend(): Promise<void> {
    try {
      const token = localStorage.getItem('auth_token');
      if (!token) {
        return; // Not authenticated, skip fetch
      }

      const response = await fetch('/api/system/session-timeout', {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        if (data.timeout_minutes && data.timeout_minutes >= 1 && data.timeout_minutes <= 480) {
          this.inactivityTimeoutMinutes = data.timeout_minutes;
          // Cache locally for faster subsequent loads
          try {
            localStorage.setItem(TIMEOUT_STORAGE_KEY, data.timeout_minutes.toString());
          } catch {
            // Ignore storage errors
          }
        }
      }
    } catch {
      // Silently fail - use local cache or default
    }
  }

  /**
   * Save timeout setting to localStorage
   */
  saveTimeoutSetting(minutes: number): void {
    if (minutes >= 1 && minutes <= 480) {
      this.inactivityTimeoutMinutes = minutes;
      try {
        localStorage.setItem(TIMEOUT_STORAGE_KEY, minutes.toString());
      } catch {
        // Ignore storage errors
      }
    }
  }

  /**
   * Get current timeout setting in minutes
   */
  getTimeoutMinutes(): number {
    return this.inactivityTimeoutMinutes;
  }

  /**
   * Get time remaining until inactivity timeout (in seconds)
   */
  getTimeRemainingSeconds(): number {
    const elapsed = Date.now() - this.lastActivityTime;
    const timeoutMs = this.inactivityTimeoutMinutes * 60 * 1000;
    const remaining = Math.max(0, timeoutMs - elapsed);
    return Math.floor(remaining / 1000);
  }

  /**
   * Check if user is currently inactive (past timeout threshold)
   */
  isInactive(): boolean {
    return this.getTimeRemainingSeconds() <= 0;
  }

  /**
   * Check if user is approaching inactivity timeout (within warning period)
   * Warning period: 5 minutes before timeout
   */
  isApproachingTimeout(): boolean {
    const remaining = this.getTimeRemainingSeconds();
    return remaining > 0 && remaining <= 5 * 60;
  }

  /**
   * Handle user activity event
   */
  private handleActivity(): void {
    const now = Date.now();

    // Throttle updates to avoid excessive processing
    if (now - this.lastThrottledUpdate < ACTIVITY_THROTTLE_MS) {
      return;
    }

    this.lastThrottledUpdate = now;
    this.lastActivityTime = now;

    // Reset warning state when user becomes active
    if (this.warningShown) {
      this.warningShown = false;
    }
  }

  /**
   * Reset activity timer (e.g., after extending session)
   */
  resetActivity(): void {
    this.lastActivityTime = Date.now();
    this.warningShown = false;
  }

  /**
   * Start tracking user activity
   */
  start(onWarning?: (timeLeftSeconds: number) => void, onLogout?: () => void): void {
    if (this.isTracking) {
      return;
    }

    this.onInactivityWarning = onWarning || null;
    this.onInactivityLogout = onLogout || null;
    this.lastActivityTime = Date.now();
    this.warningShown = false;
    this.isTracking = true;

    // Add activity event listeners
    ACTIVITY_EVENTS.forEach((event) => {
      window.addEventListener(event, this.boundActivityHandler, { passive: true });
    });

    // Check for inactivity every 10 seconds
    this.checkInterval = setInterval(() => {
      this.checkInactivity();
    }, 10000);
  }

  /**
   * Stop tracking user activity
   */
  stop(): void {
    if (!this.isTracking) {
      return;
    }

    this.isTracking = false;

    // Remove activity event listeners
    ACTIVITY_EVENTS.forEach((event) => {
      window.removeEventListener(event, this.boundActivityHandler);
    });

    // Clear check interval
    if (this.checkInterval) {
      clearInterval(this.checkInterval);
      this.checkInterval = null;
    }

    this.onInactivityWarning = null;
    this.onInactivityLogout = null;
  }

  /**
   * Check for inactivity and trigger callbacks
   */
  private checkInactivity(): void {
    const state = store.getState().auth;

    // Only check if user is authenticated
    if (!state.isAuthenticated) {
      return;
    }

    const timeRemainingSeconds = this.getTimeRemainingSeconds();

    if (timeRemainingSeconds <= 0) {
      // User has been inactive past the timeout
      if (this.onInactivityLogout) {
        this.onInactivityLogout();
      } else {
        // Default behavior: logout
        store.dispatch(logout());
      }
    } else if (timeRemainingSeconds <= 5 * 60 && !this.warningShown) {
      // Approaching timeout (within 5 minutes), show warning
      this.warningShown = true;
      if (this.onInactivityWarning) {
        this.onInactivityWarning(timeRemainingSeconds);
      }
    }
  }

  /**
   * Get last activity timestamp
   */
  getLastActivityTime(): number {
    return this.lastActivityTime;
  }
}

// Singleton instance
export const activityTracker = new ActivityTracker();
export default activityTracker;
