// Placeholder home page. The real dashboard depends on backend slices
// that haven't shipped (fleet rollup endpoint). Tracked in the project
// roadmap (app/docs/openwatch_roadmap.md) and BACKLOG.

export function HomePlaceholderPage() {
  return (
    <div style={{ padding: 28, color: 'var(--ow-fg-1)' }}>
      <title>Dashboard — OpenWatch</title>
      <h1 style={{ marginTop: 0 }}>Welcome to OpenWatch</h1>
      <p>
        The dashboard is implemented page-by-page as backend slices unblock.
        Use the sidebar to navigate to Hosts.
      </p>
    </div>
  );
}
