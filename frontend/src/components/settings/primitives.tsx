import type { ReactNode, ChangeEvent } from 'react';
import { Minus, Plus } from 'lucide-react';

// Settings primitives — direct ports of the prototype's
// .setting-card / .setting-row / .toggle / .stepper / .field /
// .section / .page-head structures.
//
// All visual properties are scaled to the --ow-* token contract so
// the dark/light scheme switches without per-component overrides.

export function PageHead({
  title,
  description,
  actions,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <header
      style={{
        display: 'flex',
        alignItems: 'flex-end',
        justifyContent: 'space-between',
        gap: 20,
        paddingBottom: 16,
        borderBottom: '1px solid var(--ow-line)',
        marginBottom: 24,
      }}
    >
      <div>
        <h1
          style={{
            margin: '0 0 4px',
            fontSize: 22,
            fontWeight: 600,
            letterSpacing: '-0.01em',
          }}
        >
          {title}
        </h1>
        {description && (
          <p style={{ margin: 0, color: 'var(--ow-fg-2)', fontSize: 13, maxWidth: 720 }}>
            {description}
          </p>
        )}
      </div>
      {actions && <div style={{ display: 'flex', gap: 8 }}>{actions}</div>}
    </header>
  );
}

export function Section({
  title,
  badge,
  badgeTier = 'ok',
  description,
  children,
}: {
  title?: string;
  badge?: string;
  badgeTier?: 'ok' | 'warn' | 'crit';
  description?: string;
  children: ReactNode;
}) {
  const badgeColor =
    badgeTier === 'crit'
      ? 'var(--ow-crit)'
      : badgeTier === 'warn'
      ? 'var(--ow-warn)'
      : 'var(--ow-ok)';
  const badgeBg =
    badgeTier === 'crit'
      ? 'var(--ow-crit-bg)'
      : badgeTier === 'warn'
      ? 'var(--ow-warn-bg)'
      : 'var(--ow-ok-bg)';
  return (
    <section style={{ marginBottom: 32 }}>
      {title && (
        <h2
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            margin: '0 0 4px',
            fontSize: 16,
            fontWeight: 600,
          }}
        >
          {title}
          {badge && (
            <span
              style={{
                background: badgeBg,
                color: badgeColor,
                fontSize: 10,
                fontWeight: 700,
                padding: '2px 8px',
                borderRadius: 'var(--ow-radius-full)',
                letterSpacing: '0.04em',
                textTransform: 'uppercase',
              }}
            >
              {badge}
            </span>
          )}
        </h2>
      )}
      {description && (
        <p style={{ margin: '0 0 16px', color: 'var(--ow-fg-2)', fontSize: 13, maxWidth: 720 }}>
          {description}
        </p>
      )}
      {children}
    </section>
  );
}

export function SettingCard({ children }: { children: ReactNode }) {
  return (
    <div
      style={{
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        overflow: 'hidden',
      }}
    >
      {children}
    </div>
  );
}

export function SettingRow({
  name,
  description,
  control,
}: {
  name: ReactNode;
  description?: ReactNode;
  control: ReactNode;
}) {
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '1fr minmax(180px, auto)',
        gap: 20,
        alignItems: 'center',
        padding: '16px 20px',
        borderTop: '1px solid var(--ow-line)',
      }}
    >
      <div>
        <div
          style={{
            fontWeight: 500,
            color: 'var(--ow-fg-0)',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
        >
          {name}
        </div>
        {description && (
          <div style={{ color: 'var(--ow-fg-2)', fontSize: 12, marginTop: 4, lineHeight: 1.5 }}>
            {description}
          </div>
        )}
      </div>
      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>{control}</div>
    </div>
  );
}

// Inline first-row variant — no top border (matches prototype
// `.setting-row:first-child { border-top: 0 }`). Apply manually
// to the first row in a card.
export function FirstSettingRow(props: Parameters<typeof SettingRow>[0]) {
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: '1fr minmax(180px, auto)',
        gap: 20,
        alignItems: 'center',
        padding: '16px 20px',
      }}
    >
      <div>
        <div
          style={{
            fontWeight: 500,
            color: 'var(--ow-fg-0)',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
        >
          {props.name}
        </div>
        {props.description && (
          <div style={{ color: 'var(--ow-fg-2)', fontSize: 12, marginTop: 4, lineHeight: 1.5 }}>
            {props.description}
          </div>
        )}
      </div>
      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>{props.control}</div>
    </div>
  );
}

export function Toggle({
  value,
  onChange,
  ariaLabel,
  disabled,
}: {
  value: boolean;
  onChange: (next: boolean) => void;
  ariaLabel?: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={value}
      aria-label={ariaLabel}
      disabled={disabled}
      onClick={() => onChange(!value)}
      style={{
        width: 36,
        height: 20,
        background: value ? 'var(--ow-info)' : 'var(--ow-bg-3)',
        borderRadius: 'var(--ow-radius-full)',
        position: 'relative',
        cursor: disabled ? 'not-allowed' : 'pointer',
        border: `1px solid ${value ? 'var(--ow-info)' : 'var(--ow-line-2)'}`,
        transition: 'background 160ms, border-color 160ms',
        padding: 0,
        opacity: disabled ? 0.6 : 1,
      }}
    >
      <span
        style={{
          position: 'absolute',
          top: 2,
          left: value ? 17 : 2,
          width: 14,
          height: 14,
          background: value ? 'white' : 'var(--ow-fg-2)',
          borderRadius: '50%',
          transition: 'left 160ms, background 160ms',
        }}
      />
    </button>
  );
}

export function Stepper({
  value,
  min = 0,
  max = 999,
  step = 1,
  unit,
  onChange,
  disabled,
}: {
  value: number;
  min?: number;
  max?: number;
  step?: number;
  unit?: string;
  onChange: (v: number) => void;
  disabled?: boolean;
}) {
  const clamp = (v: number) => Math.max(min, Math.min(max, v));
  return (
    <div
      style={{
        display: 'inline-flex',
        alignItems: 'stretch',
        background: 'var(--ow-bg-2)',
        border: '1px solid var(--ow-line)',
        borderRadius: 6,
        overflow: 'hidden',
        height: 32,
      }}
    >
      <button
        type="button"
        aria-label="Decrease"
        disabled={disabled}
        onClick={() => onChange(clamp(value - step))}
        style={stepperBtn}
      >
        <Minus size={12} />
      </button>
      <input
        type="number"
        value={value}
        disabled={disabled}
        min={min}
        max={max}
        step={step}
        onChange={(e) => onChange(clamp(Number(e.target.value) || 0))}
        style={{
          width: 56,
          border: 0,
          background: 'transparent',
          color: 'var(--ow-fg-0)',
          textAlign: 'center',
          fontFamily: 'var(--ow-font-mono)',
          fontSize: 13,
          outline: 0,
        }}
      />
      <button
        type="button"
        aria-label="Increase"
        disabled={disabled}
        onClick={() => onChange(clamp(value + step))}
        style={stepperBtn}
      >
        <Plus size={12} />
      </button>
      {unit && (
        <span
          style={{
            padding: '0 10px',
            color: 'var(--ow-fg-2)',
            alignSelf: 'center',
            fontSize: 12,
            borderLeft: '1px solid var(--ow-line)',
          }}
        >
          {unit}
        </span>
      )}
    </div>
  );
}

const stepperBtn: React.CSSProperties = {
  width: 28,
  border: 0,
  background: 'transparent',
  color: 'var(--ow-fg-2)',
  cursor: 'pointer',
  fontSize: 14,
  display: 'inline-grid',
  placeItems: 'center',
};

export function Field({
  value,
  onChange,
  type = 'text',
  placeholder,
  ariaLabel,
  disabled,
  hint,
  width,
}: {
  value: string;
  onChange?: (v: string) => void;
  type?: 'text' | 'email' | 'password' | 'tel';
  placeholder?: string;
  ariaLabel?: string;
  disabled?: boolean;
  hint?: string;
  width?: number | string;
}) {
  return (
    <>
      <input
        type={type}
        value={value}
        placeholder={placeholder}
        aria-label={ariaLabel}
        disabled={disabled}
        onChange={(e: ChangeEvent<HTMLInputElement>) => onChange?.(e.target.value)}
        style={{
          background: 'var(--ow-bg-2)',
          border: '1px solid var(--ow-line)',
          borderRadius: 6,
          color: 'var(--ow-fg-0)',
          fontFamily: 'inherit',
          fontSize: 13,
          padding: '0 10px',
          height: 32,
          outline: 0,
          width: width ?? '100%',
        }}
      />
      {hint && (
        <div style={{ fontSize: 11, color: 'var(--ow-fg-3)', marginTop: 4 }}>{hint}</div>
      )}
    </>
  );
}

export function Select({
  value,
  onChange,
  options,
  ariaLabel,
  width,
}: {
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
  ariaLabel?: string;
  width?: number | string;
}) {
  return (
    <select
      value={value}
      aria-label={ariaLabel}
      onChange={(e) => onChange(e.target.value)}
      style={{
        height: 32,
        background: 'var(--ow-bg-2)',
        border: '1px solid var(--ow-line)',
        borderRadius: 6,
        color: 'var(--ow-fg-0)',
        fontFamily: 'inherit',
        fontSize: 13,
        padding: '0 28px 0 10px',
        cursor: 'pointer',
        appearance: 'none',
        width: width ?? 'auto',
        minWidth: 160,
        backgroundImage:
          'url("data:image/svg+xml;utf8,<svg xmlns=\'http://www.w3.org/2000/svg\' width=\'12\' height=\'12\' viewBox=\'0 0 24 24\' fill=\'none\' stroke=\'%238a93a3\' stroke-width=\'2\' stroke-linecap=\'round\' stroke-linejoin=\'round\'><path d=\'m6 9 6 6 6-6\'/></svg>")',
        backgroundRepeat: 'no-repeat',
        backgroundPosition: 'right 8px center',
      }}
    >
      {options.map((opt) => (
        <option key={opt.value} value={opt.value}>
          {opt.label}
        </option>
      ))}
    </select>
  );
}

export function Segmented<T extends string>({
  value,
  options,
  onChange,
  ariaLabel,
}: {
  value: T;
  options: { value: T; label: string }[];
  onChange: (v: T) => void;
  ariaLabel?: string;
}) {
  return (
    <div
      role="radiogroup"
      aria-label={ariaLabel}
      style={{
        display: 'inline-flex',
        background: 'var(--ow-bg-2)',
        border: '1px solid var(--ow-line)',
        borderRadius: 6,
        padding: 3,
      }}
    >
      {options.map((opt) => {
        const isActive = opt.value === value;
        return (
          <button
            key={opt.value}
            type="button"
            role="radio"
            aria-checked={isActive}
            onClick={() => onChange(opt.value)}
            style={{
              border: 0,
              background: isActive ? 'var(--ow-bg-3)' : 'transparent',
              color: isActive ? 'var(--ow-fg-0)' : 'var(--ow-fg-2)',
              fontFamily: 'inherit',
              fontSize: 12,
              fontWeight: 500,
              padding: '5px 12px',
              borderRadius: 4,
              cursor: 'pointer',
            }}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}

export function Btn({
  children,
  onClick,
  variant = 'secondary',
  size = 'md',
  disabled,
  type = 'button',
  ariaLabel,
}: {
  children: ReactNode;
  onClick?: () => void;
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger';
  size?: 'sm' | 'md';
  disabled?: boolean;
  type?: 'button' | 'submit';
  ariaLabel?: string;
}) {
  const h = size === 'sm' ? 28 : 34;
  const fs = size === 'sm' ? 12 : 13;
  const pad = size === 'sm' ? '0 10px' : '0 14px';
  let bg = 'var(--ow-bg-1)';
  let color = 'var(--ow-fg-0)';
  let border = '1px solid var(--ow-line)';
  if (variant === 'primary') {
    bg = 'var(--ow-info)';
    color = 'var(--ow-info-on)';
    border = '1px solid var(--ow-info)';
  } else if (variant === 'ghost') {
    bg = 'transparent';
    border = '1px solid transparent';
  } else if (variant === 'danger') {
    color = 'var(--ow-crit)';
    border = '1px solid color-mix(in oklab, var(--ow-crit) 30%, var(--ow-line))';
  }
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      aria-label={ariaLabel}
      style={{
        height: h,
        borderRadius: 'var(--ow-radius-sm)',
        border,
        background: bg,
        color,
        fontFamily: 'inherit',
        fontWeight: variant === 'primary' ? 600 : 500,
        fontSize: fs,
        padding: pad,
        cursor: disabled ? 'not-allowed' : 'pointer',
        display: 'inline-flex',
        alignItems: 'center',
        gap: 8,
        transition: 'background 120ms, border-color 120ms',
        opacity: disabled ? 0.6 : 1,
      }}
    >
      {children}
    </button>
  );
}

export function StatusPill({
  tier,
  children,
}: {
  tier: 'ok' | 'warn' | 'crit';
  children: ReactNode;
}) {
  const color =
    tier === 'crit'
      ? 'var(--ow-crit)'
      : tier === 'warn'
      ? 'var(--ow-warn)'
      : 'var(--ow-ok)';
  const bg =
    tier === 'crit'
      ? 'var(--ow-crit-bg)'
      : tier === 'warn'
      ? 'var(--ow-warn-bg)'
      : 'var(--ow-ok-bg)';
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        height: 22,
        padding: '0 10px',
        background: bg,
        borderRadius: 'var(--ow-radius-full)',
        fontSize: 11,
        color,
        fontWeight: 600,
        letterSpacing: '0.02em',
      }}
    >
      <span
        style={{
          width: 6,
          height: 6,
          borderRadius: '50%',
          background: color,
          boxShadow: `0 0 0 3px color-mix(in oklab, ${color} 30%, transparent)`,
        }}
      />
      {children}
    </span>
  );
}

// Modal — themed dialog scoped to the --ow-* token contract. Renders
// nothing when !open. Click on the scrim or Escape close via onClose.
export function Modal({
  open,
  onClose,
  title,
  children,
  footer,
  width = 480,
  preventClose = false,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  width?: number;
  preventClose?: boolean;
}) {
  if (!open) return null;
  return (
    <div
      role="presentation"
      onClick={(e) => {
        if (!preventClose && e.target === e.currentTarget) onClose();
      }}
      onKeyDown={(e) => {
        if (!preventClose && e.key === 'Escape') onClose();
      }}
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.55)',
        backdropFilter: 'blur(2px)',
        display: 'grid',
        placeItems: 'center',
        zIndex: 60,
        padding: 20,
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
        style={{
          background: 'var(--ow-bg-1)',
          border: '1px solid var(--ow-line)',
          borderRadius: 'var(--ow-radius)',
          boxShadow: 'var(--ow-shadow-lg)',
          width: '100%',
          maxWidth: width,
          maxHeight: 'calc(100vh - 40px)',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            padding: '16px 20px',
            borderBottom: '1px solid var(--ow-line)',
            fontSize: 15,
            fontWeight: 600,
            color: 'var(--ow-fg-0)',
          }}
          id="modal-title"
        >
          {title}
        </div>
        <div
          style={{
            padding: 20,
            overflowY: 'auto',
            flex: 1,
          }}
        >
          {children}
        </div>
        {footer && (
          <div
            style={{
              padding: '14px 20px',
              borderTop: '1px solid var(--ow-line)',
              display: 'flex',
              gap: 8,
              justifyContent: 'flex-end',
              background: 'var(--ow-bg-2)',
            }}
          >
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}

export function FormField({
  label,
  hint,
  error,
  children,
}: {
  label: string;
  hint?: string;
  error?: string;
  children: ReactNode;
}) {
  return (
    <label style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 12 }}>
      <span style={{ fontSize: 12, color: 'var(--ow-fg-1)', fontWeight: 500 }}>{label}</span>
      {children}
      {hint && !error && (
        <span style={{ fontSize: 11, color: 'var(--ow-fg-3)' }}>{hint}</span>
      )}
      {error && (
        <span role="alert" style={{ fontSize: 12, color: 'var(--ow-crit)' }}>
          {error}
        </span>
      )}
    </label>
  );
}

export function StatMini({
  label,
  value,
  unit,
  hint,
  tier = 'neutral',
}: {
  label: string;
  value: ReactNode;
  unit?: ReactNode;
  hint?: string;
  tier?: 'crit' | 'warn' | 'ok' | 'neutral';
}) {
  const tierColor =
    tier === 'crit'
      ? 'var(--ow-crit)'
      : tier === 'warn'
      ? 'var(--ow-warn)'
      : tier === 'ok'
      ? 'var(--ow-ok)'
      : 'var(--ow-fg-0)';
  return (
    <div
      style={{
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        padding: '12px 14px',
      }}
    >
      <div
        style={{
          color: 'var(--ow-fg-2)',
          fontSize: 11,
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
          fontWeight: 500,
        }}
      >
        {label}
      </div>
      <div
        style={{
          fontSize: 22,
          fontWeight: 600,
          letterSpacing: '-0.01em',
          marginTop: 4,
          lineHeight: 1,
          fontVariantNumeric: 'tabular-nums',
          color: tierColor,
        }}
      >
        {value}
        {unit && (
          <span style={{ fontSize: 13, color: 'var(--ow-fg-3)', fontWeight: 500, marginLeft: 2 }}>
            {unit}
          </span>
        )}
      </div>
      {hint && (
        <div style={{ color: 'var(--ow-fg-3)', fontSize: 11, marginTop: 4 }}>{hint}</div>
      )}
    </div>
  );
}

export function StatMiniRow({ children }: { children: ReactNode }) {
  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(3, 1fr)',
        gap: 12,
        marginBottom: 14,
      }}
    >
      {children}
    </div>
  );
}

export function Callout({
  tier = 'info',
  children,
}: {
  tier?: 'info' | 'warn' | 'crit';
  children: ReactNode;
}) {
  const color =
    tier === 'crit'
      ? 'var(--ow-crit)'
      : tier === 'warn'
      ? 'var(--ow-warn)'
      : 'var(--ow-info)';
  const bg =
    tier === 'crit'
      ? 'var(--ow-crit-bg)'
      : tier === 'warn'
      ? 'var(--ow-warn-bg)'
      : 'var(--ow-info-bg)';
  return (
    <div
      role="note"
      style={{
        display: 'flex',
        gap: 12,
        alignItems: 'flex-start',
        padding: '12px 14px',
        background: bg,
        border: `1px solid color-mix(in oklab, ${color} 30%, var(--ow-line))`,
        borderLeft: `3px solid ${color}`,
        borderRadius: 'var(--ow-radius)',
        color: 'var(--ow-fg-1)',
        fontSize: 12,
        lineHeight: 1.5,
      }}
    >
      <div style={{ color, flexShrink: 0, marginTop: 1 }}>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
          <circle cx="12" cy="12" r="10" />
          <path d="M12 8v4M12 16h.01" />
        </svg>
      </div>
      <div style={{ flex: 1 }}>{children}</div>
    </div>
  );
}

export function SchedSummary({
  icon,
  iconTier = 'info',
  title,
  subtitle,
  rightLabel,
  rightValue,
  toggleValue,
  onToggleChange,
}: {
  icon: ReactNode;
  iconTier?: 'info' | 'ok' | 'warn';
  title: string;
  subtitle: string;
  rightLabel: string;
  rightValue: ReactNode;
  toggleValue: boolean;
  onToggleChange: (next: boolean) => void;
}) {
  const iconColor =
    iconTier === 'ok'
      ? 'var(--ow-ok)'
      : iconTier === 'warn'
      ? 'var(--ow-warn)'
      : 'var(--ow-info)';
  const iconBg =
    iconTier === 'ok'
      ? 'var(--ow-ok-bg)'
      : iconTier === 'warn'
      ? 'var(--ow-warn-bg)'
      : 'var(--ow-info-bg)';
  return (
    <div
      style={{
        background: 'var(--ow-bg-1)',
        border: '1px solid var(--ow-line)',
        borderRadius: 'var(--ow-radius)',
        padding: '18px 20px',
        marginBottom: 14,
        display: 'grid',
        gridTemplateColumns: '1fr auto',
        gap: 20,
        alignItems: 'center',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <div
          style={{
            width: 36,
            height: 36,
            borderRadius: 8,
            background: iconBg,
            color: iconColor,
            display: 'grid',
            placeItems: 'center',
            flexShrink: 0,
          }}
        >
          {icon}
        </div>
        <div>
          <div style={{ fontWeight: 600, fontSize: 15 }}>{title}</div>
          <div style={{ color: 'var(--ow-fg-2)', fontSize: 12, marginTop: 2 }}>
            {subtitle}
          </div>
        </div>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        <div style={{ textAlign: 'right', color: 'var(--ow-fg-2)', fontSize: 12 }}>
          <div>{rightLabel}</div>
          <div style={{ color: 'var(--ow-fg-1)', fontFamily: 'var(--ow-font-mono)' }}>
            {rightValue}
          </div>
        </div>
        <Toggle value={toggleValue} onChange={onToggleChange} ariaLabel={`${title} enabled`} />
      </div>
    </div>
  );
}

export function AdvancedDisclosure({
  label,
  open,
  onToggle,
  children,
}: {
  label: string;
  open: boolean;
  onToggle: () => void;
  children?: ReactNode;
}) {
  return (
    <div style={{ marginTop: 14 }}>
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 6,
          color: 'var(--ow-info)',
          fontSize: 13,
          background: 'transparent',
          border: 0,
          cursor: 'pointer',
          padding: 0,
          fontWeight: 500,
        }}
      >
        <svg
          width="12"
          height="12"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          style={{
            transform: open ? 'rotate(90deg)' : 'rotate(0deg)',
            transition: 'transform var(--ow-motion-fast) ease',
          }}
        >
          <path d="m9 18 6-6-6-6" />
        </svg>
        {label}
      </button>
      {open && <div style={{ marginTop: 12 }}>{children}</div>}
    </div>
  );
}

export function BackendPendingBanner({
  slice,
  text,
}: {
  slice: string;
  text?: string;
}) {
  return (
    <div
      role="status"
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 12,
        padding: '12px 16px',
        background: 'var(--ow-warn-bg)',
        border: '1px solid color-mix(in oklab, var(--ow-warn) 30%, var(--ow-line))',
        borderLeft: '3px solid var(--ow-warn)',
        borderRadius: 'var(--ow-radius)',
        marginBottom: 20,
        color: 'var(--ow-fg-1)',
        fontSize: 13,
      }}
    >
      <strong style={{ color: 'var(--ow-warn)' }}>Backend pending — {slice}</strong>
      {text && <span style={{ color: 'var(--ow-fg-2)' }}>· {text}</span>}
    </div>
  );
}
