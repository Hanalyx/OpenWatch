// Shared inline styles for the bulk-import wizard. Kept colocated so the
// three step components stay visually consistent without pulling in a CSS
// module just for a handful of declarations.

import type React from 'react';

export const card: React.CSSProperties = {
  background: 'var(--ow-bg-1)',
  border: '1px solid var(--ow-line)',
  borderRadius: 'var(--ow-radius)',
  marginBottom: 14,
};

export const cardHeader: React.CSSProperties = {
  padding: '12px 16px',
  borderBottom: '1px solid var(--ow-line)',
  fontSize: 13,
  fontWeight: 600,
};

export const cardBody: React.CSSProperties = { padding: 16 };

export const labelText: React.CSSProperties = {
  fontSize: 12,
  color: 'var(--ow-fg-1)',
  marginBottom: 4,
};

export const primaryBtn: React.CSSProperties = {
  height: 32,
  padding: '0 16px',
  background: 'var(--ow-info)',
  color: 'var(--ow-info-on)',
  border: 0,
  borderRadius: 6,
  fontFamily: 'inherit',
  fontWeight: 600,
  fontSize: 13,
  cursor: 'pointer',
};

export const secondaryBtn: React.CSSProperties = {
  height: 32,
  padding: '0 16px',
  background: 'var(--ow-bg-2)',
  color: 'var(--ow-fg-0)',
  border: '1px solid var(--ow-line)',
  borderRadius: 6,
  fontFamily: 'inherit',
  fontWeight: 500,
  fontSize: 13,
  cursor: 'pointer',
};

export const ghostBtn: React.CSSProperties = {
  ...secondaryBtn,
  background: 'transparent',
};

export const errorPanel: React.CSSProperties = {
  padding: '10px 12px',
  margin: '12px 0',
  background: 'var(--ow-crit-bg)',
  border: '1px solid var(--ow-crit)',
  borderRadius: 6,
  color: 'var(--ow-crit)',
  fontSize: 13,
};

export const infoPanel: React.CSSProperties = {
  padding: '10px 12px',
  margin: '12px 0',
  background: 'var(--ow-bg-2)',
  border: '1px solid var(--ow-line)',
  borderRadius: 6,
  color: 'var(--ow-fg-1)',
  fontSize: 12,
};

export const th: React.CSSProperties = {
  textAlign: 'left',
  padding: '8px 12px',
  fontSize: 11,
  fontWeight: 600,
  color: 'var(--ow-fg-2)',
  textTransform: 'uppercase',
  letterSpacing: '0.04em',
};

export const td: React.CSSProperties = {
  padding: '8px 12px',
  color: 'var(--ow-fg-1)',
  verticalAlign: 'top',
};

export const select: React.CSSProperties = {
  height: 30,
  padding: '0 8px',
  background: 'var(--ow-bg-2)',
  border: '1px solid var(--ow-line)',
  borderRadius: 6,
  color: 'var(--ow-fg-0)',
  fontFamily: 'inherit',
  fontSize: 12,
};
