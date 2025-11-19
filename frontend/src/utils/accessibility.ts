/**
 * Accessibility utilities for WCAG 2.1 AA compliance
 * Provides helpers for focus management, screen reader support, and color contrast
 */

// ARIA live region announcer for screen readers
class LiveRegionAnnouncer {
  private static instance: LiveRegionAnnouncer;
  private politeRegion: HTMLElement | null = null;
  private assertiveRegion: HTMLElement | null = null;

  static getInstance(): LiveRegionAnnouncer {
    if (!LiveRegionAnnouncer.instance) {
      LiveRegionAnnouncer.instance = new LiveRegionAnnouncer();
    }
    return LiveRegionAnnouncer.instance;
  }

  private constructor() {
    this.createLiveRegions();
  }

  private createLiveRegions(): void {
    if (typeof window === 'undefined') return;

    // Create polite live region
    this.politeRegion = document.createElement('div');
    this.politeRegion.setAttribute('aria-live', 'polite');
    this.politeRegion.setAttribute('aria-atomic', 'true');
    this.politeRegion.style.position = 'absolute';
    this.politeRegion.style.left = '-10000px';
    this.politeRegion.style.width = '1px';
    this.politeRegion.style.height = '1px';
    this.politeRegion.style.overflow = 'hidden';
    document.body.appendChild(this.politeRegion);

    // Create assertive live region
    this.assertiveRegion = document.createElement('div');
    this.assertiveRegion.setAttribute('aria-live', 'assertive');
    this.assertiveRegion.setAttribute('aria-atomic', 'true');
    this.assertiveRegion.style.position = 'absolute';
    this.assertiveRegion.style.left = '-10000px';
    this.assertiveRegion.style.width = '1px';
    this.assertiveRegion.style.height = '1px';
    this.assertiveRegion.style.overflow = 'hidden';
    document.body.appendChild(this.assertiveRegion);
  }

  announce(message: string, priority: 'polite' | 'assertive' = 'polite'): void {
    const region = priority === 'assertive' ? this.assertiveRegion : this.politeRegion;
    if (region) {
      region.textContent = message;
      // Clear after announcement to ensure repeated messages are announced
      setTimeout(() => {
        region.textContent = '';
      }, 1000);
    }
  }
}

export const announcer = LiveRegionAnnouncer.getInstance();

/**
 * Focus management utilities
 */
export const focusManagement = {
  /**
   * Trap focus within a container element
   */
  trapFocus(container: HTMLElement): () => void {
    const focusableElements = container.querySelectorAll(
      'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
    );

    const firstElement = focusableElements[0] as HTMLElement;
    const lastElement = focusableElements[focusableElements.length - 1] as HTMLElement;

    const handleTabKey = (event: KeyboardEvent) => {
      if (event.key !== 'Tab') return;

      if (event.shiftKey) {
        if (document.activeElement === firstElement) {
          event.preventDefault();
          lastElement.focus();
        }
      } else {
        if (document.activeElement === lastElement) {
          event.preventDefault();
          firstElement.focus();
        }
      }
    };

    container.addEventListener('keydown', handleTabKey);

    // Return cleanup function
    return () => {
      container.removeEventListener('keydown', handleTabKey);
    };
  },

  /**
   * Find the first focusable element in a container
   */
  findFirstFocusable(container: HTMLElement): HTMLElement | null {
    const focusableElements = container.querySelectorAll(
      'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
    );
    return (focusableElements[0] as HTMLElement) || null;
  },

  /**
   * Store and restore focus
   */
  createFocusStore() {
    let storedElement: HTMLElement | null = null;

    return {
      store() {
        storedElement = document.activeElement as HTMLElement;
      },
      restore() {
        if (storedElement && typeof storedElement.focus === 'function') {
          storedElement.focus();
        }
      },
    };
  },
};

/**
 * Color contrast utilities for WCAG AA compliance
 */
export const colorContrast = {
  /**
   * Calculate relative luminance of a color
   */
  getLuminance(hex: string): number {
    const rgb = this.hexToRgb(hex);
    if (!rgb) return 0;

    const [r, g, b] = rgb.map((c) => {
      c = c / 255;
      return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
    });

    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  },

  /**
   * Calculate contrast ratio between two colors
   */
  getContrastRatio(color1: string, color2: string): number {
    const l1 = this.getLuminance(color1);
    const l2 = this.getLuminance(color2);

    const lighter = Math.max(l1, l2);
    const darker = Math.min(l1, l2);

    return (lighter + 0.05) / (darker + 0.05);
  },

  /**
   * Check if contrast ratio meets WCAG AA standard (4.5:1)
   */
  meetsWCAGAA(foreground: string, background: string): boolean {
    return this.getContrastRatio(foreground, background) >= 4.5;
  },

  /**
   * Check if contrast ratio meets WCAG AAA standard (7:1)
   */
  meetsWCAGAAA(foreground: string, background: string): boolean {
    return this.getContrastRatio(foreground, background) >= 7;
  },

  /**
   * Convert hex color to RGB
   */
  hexToRgb(hex: string): [number, number, number] | null {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return result
      ? [parseInt(result[1], 16), parseInt(result[2], 16), parseInt(result[3], 16)]
      : null;
  },
};

/**
 * Screen reader utilities
 */
export const screenReader = {
  /**
   * Create descriptive text for complex UI elements
   * State object can contain any serializable UI state data (progress, counts, messages, etc.)
   */
  createDescription(type: string, state?: Record<string, unknown>): string {
    const descriptions: Record<string, string> = {
      loading: 'Loading content, please wait',
      error: 'An error occurred',
      success: 'Action completed successfully',
      warning: 'Warning: please review',
      empty: 'No items to display',
      searching: 'Searching for results',
      uploading: 'File upload in progress',
      processing: 'Processing request',
    };

    let baseDescription = descriptions[type] || '';

    if (state) {
      if (state.count !== undefined) {
        baseDescription += `, ${state.count} items`;
      }
      if (state.percentage !== undefined) {
        baseDescription += `, ${state.percentage}% complete`;
      }
      if (state.error) {
        baseDescription += `: ${state.error}`;
      }
    }

    return baseDescription;
  },

  /**
   * Create skip link for navigation
   */
  createSkipLink(targetId: string, text: string = 'Skip to main content'): HTMLAnchorElement {
    const skipLink = document.createElement('a');
    skipLink.href = `#${targetId}`;
    skipLink.textContent = text;
    skipLink.className = 'skip-link';
    skipLink.style.cssText = `
      position: absolute;
      top: -40px;
      left: 6px;
      background: #000;
      color: #fff;
      padding: 8px;
      text-decoration: none;
      z-index: 10000;
      border-radius: 4px;
      transition: top 0.3s;
    `;

    skipLink.addEventListener('focus', () => {
      skipLink.style.top = '6px';
    });

    skipLink.addEventListener('blur', () => {
      skipLink.style.top = '-40px';
    });

    return skipLink;
  },
};

/**
 * Keyboard navigation utilities
 */
export const keyboardNavigation = {
  /**
   * Handle roving tabindex pattern for lists and grids
   */
  createRovingTabindex(
    container: HTMLElement,
    selector: string = '[role="option"], [role="gridcell"], button, a'
  ) {
    const items = Array.from(container.querySelectorAll(selector)) as HTMLElement[];
    let currentIndex = 0;

    // Set initial tabindex
    items.forEach((item, index) => {
      item.tabIndex = index === 0 ? 0 : -1;
    });

    const handleKeyDown = (event: KeyboardEvent) => {
      const { key } = event;
      let newIndex = currentIndex;

      switch (key) {
        case 'ArrowDown':
        case 'ArrowRight':
          event.preventDefault();
          newIndex = (currentIndex + 1) % items.length;
          break;
        case 'ArrowUp':
        case 'ArrowLeft':
          event.preventDefault();
          newIndex = currentIndex > 0 ? currentIndex - 1 : items.length - 1;
          break;
        case 'Home':
          event.preventDefault();
          newIndex = 0;
          break;
        case 'End':
          event.preventDefault();
          newIndex = items.length - 1;
          break;
        default:
          return;
      }

      // Update tabindex and focus
      items[currentIndex].tabIndex = -1;
      items[newIndex].tabIndex = 0;
      items[newIndex].focus();
      currentIndex = newIndex;
    };

    container.addEventListener('keydown', handleKeyDown);

    return () => {
      container.removeEventListener('keydown', handleKeyDown);
    };
  },

  /**
   * Handle escape key for modals and dropdowns
   */
  onEscape(callback: () => void): () => void {
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        callback();
      }
    };

    document.addEventListener('keydown', handleEscape);

    return () => {
      document.removeEventListener('keydown', handleEscape);
    };
  },
};

/**
 * Form validation with accessible error handling
 */
export const accessibleValidation = {
  /**
   * Create accessible error messages
   */
  createErrorMessage(fieldId: string, message: string): HTMLElement {
    const errorElement = document.createElement('div');
    errorElement.id = `${fieldId}-error`;
    errorElement.setAttribute('role', 'alert');
    errorElement.setAttribute('aria-live', 'polite');
    errorElement.className = 'error-message';
    errorElement.textContent = message;

    return errorElement;
  },

  /**
   * Associate error with form field
   */
  associateError(fieldElement: HTMLElement, errorElement: HTMLElement): void {
    const existingDescribedBy = fieldElement.getAttribute('aria-describedby') || '';
    const errorId = errorElement.id;

    if (!existingDescribedBy.includes(errorId)) {
      fieldElement.setAttribute(
        'aria-describedby',
        existingDescribedBy ? `${existingDescribedBy} ${errorId}` : errorId
      );
    }

    fieldElement.setAttribute('aria-invalid', 'true');
  },

  /**
   * Clear error association
   */
  clearError(fieldElement: HTMLElement, errorElementId: string): void {
    const describedBy = fieldElement.getAttribute('aria-describedby') || '';
    const updatedDescribedBy = describedBy
      .split(' ')
      .filter((id) => id !== errorElementId)
      .join(' ');

    if (updatedDescribedBy) {
      fieldElement.setAttribute('aria-describedby', updatedDescribedBy);
    } else {
      fieldElement.removeAttribute('aria-describedby');
    }

    fieldElement.setAttribute('aria-invalid', 'false');
  },
};

/**
 * High-level accessibility checker
 */
export const accessibilityChecker = {
  /**
   * Run basic accessibility checks on a component
   */
  checkComponent(element: HTMLElement): Array<{ type: 'error' | 'warning'; message: string }> {
    const issues: Array<{ type: 'error' | 'warning'; message: string }> = [];

    // Check for missing alt text on images
    const images = element.querySelectorAll('img');
    images.forEach((img) => {
      if (!img.alt && !img.getAttribute('aria-label')) {
        issues.push({
          type: 'error',
          message: 'Image missing alt text or aria-label',
        });
      }
    });

    // Check for buttons without accessible names
    const buttons = element.querySelectorAll('button');
    buttons.forEach((button) => {
      const hasText = button.textContent?.trim();
      const hasAriaLabel = button.getAttribute('aria-label');
      const hasAriaLabelledBy = button.getAttribute('aria-labelledby');

      if (!hasText && !hasAriaLabel && !hasAriaLabelledBy) {
        issues.push({
          type: 'error',
          message: 'Button missing accessible name',
        });
      }
    });

    // Check for proper heading hierarchy
    const headings = element.querySelectorAll('h1, h2, h3, h4, h5, h6');
    let previousLevel = 0;
    headings.forEach((heading) => {
      const level = parseInt(heading.tagName.charAt(1));
      if (level > previousLevel + 1) {
        issues.push({
          type: 'warning',
          message: `Heading level skipped from h${previousLevel} to h${level}`,
        });
      }
      previousLevel = level;
    });

    return issues;
  },
};

export default {
  announcer,
  focusManagement,
  colorContrast,
  screenReader,
  keyboardNavigation,
  accessibleValidation,
  accessibilityChecker,
};
