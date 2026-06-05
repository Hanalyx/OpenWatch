// 403 / authz.permission_denied page.
//
// Spec: frontend-foundation C-07, AC-09.

export function ForbiddenPage() {
  return (
    <div
      role="alert"
      style={{ padding: 28, color: 'var(--ow-fg-1)' }}
    >
      <title>Access denied — OpenWatch</title>
      <h1 style={{ marginTop: 0 }}>Access denied</h1>
      <p>
        Your account does not have permission to view this page (
        <code
          style={{ fontFamily: 'var(--ow-font-mono)', fontSize: 12 }}
        >
          authz.permission_denied
        </code>
        ). Contact an administrator if you believe this is in error.
      </p>
    </div>
  );
}
