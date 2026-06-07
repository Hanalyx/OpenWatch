import { Component, type ReactNode } from 'react';

// Global error boundary for the route subtree.
//
// Spec: frontend-foundation C-08, AC-10. Catches uncaught render
// errors in any child route, renders a recoverable fallback, keeps
// the shell visible.
//
// The scrub list (C-11): error messages that LITERALLY contain field
// names from the deny list are redacted before console.error to avoid
// leaking secrets in browser DevTools.

const SCRUB_FIELDS = ['evidence', 'token', 'password', 'secret', 'private_key'];

function scrub(message: string): string {
  let out = message;
  for (const field of SCRUB_FIELDS) {
    const re = new RegExp(`("?${field}"?\\s*[:=]\\s*)[^,}\\s]+`, 'gi');
    out = out.replace(re, '$1[REDACTED]');
  }
  return out;
}

interface State {
  error: Error | null;
}

interface Props {
  children: ReactNode;
}

export class ErrorBoundary extends Component<Props, State> {
  override state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  override componentDidCatch(error: Error, info: { componentStack?: string }) {
    if (import.meta.env.DEV) {
      console.error('frontend error boundary:', scrub(error.message), info);
    }
  }

  handleReload = () => {
    this.setState({ error: null });
  };

  override render() {
    if (this.state.error) {
      return (
        <div
          role="alert"
          style={{
            padding: '28px',
            color: 'var(--ow-fg-1)',
          }}
        >
          <h2 style={{ marginTop: 0 }}>Something went wrong</h2>
          <p>The page failed to render. The shell is still available.</p>
          <button
            type="button"
            onClick={this.handleReload}
            style={{
              height: 32,
              padding: '0 12px',
              border: '1px solid var(--ow-info)',
              background: 'var(--ow-info)',
              color: 'var(--ow-info-on)',
              fontFamily: 'inherit',
              fontWeight: 600,
              fontSize: 13,
              borderRadius: 6,
              cursor: 'pointer',
            }}
          >
            Reload
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
