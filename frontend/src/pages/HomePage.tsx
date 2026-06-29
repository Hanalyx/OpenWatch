import { Link } from '@tanstack/react-router';
import { RadarField } from '@/components/RadarField';
import { useVersion } from '@/hooks/useVersion';
import owIcon from '@/assets/openwatch-icon.png';

// HomePage — the public, non-login landing surface at "/". Renders the
// Radar "Eyrie" hero and routes visitors to the console via /login. It
// does NOT mount AppFrame and carries no authenticated data; the
// telemetry readout is static demo art (a public page must not expose
// real fleet numbers).
//
// Spec: frontend-homepage. Hero concept A (Radar), ported from
// docs/engineering/prototypes/openwatch-v1/home/Eyrie - Radar.html.

const SCAN = 'rgb(96,212,228)';

export function HomePage() {
  const version = useVersion();
  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        overflow: 'hidden',
        background: 'var(--ow-bg-0)',
        color: 'var(--ow-fg-0)',
      }}
    >
      <title>OpenWatch · Infrastructure compliance, watched</title>
      <style>{`
        @keyframes ow-pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }
        @media (prefers-reduced-motion: reduce) { .ow-pulse { animation: none !important; } }
      `}</style>

      <RadarField />

      {/* vignette + scanlines — pure decoration */}
      <div
        aria-hidden="true"
        style={{
          position: 'fixed',
          inset: 0,
          pointerEvents: 'none',
          zIndex: 2,
          background:
            'radial-gradient(ellipse 80% 70% at 60% 45%, transparent 40%, rgba(3,5,9,0.55) 78%, rgba(3,5,9,0.92) 100%)',
        }}
      />
      <div
        aria-hidden="true"
        style={{
          position: 'fixed',
          inset: 0,
          pointerEvents: 'none',
          zIndex: 3,
          opacity: 0.35,
          mixBlendMode: 'multiply',
          background:
            'repeating-linear-gradient(to bottom, transparent 0 2px, rgba(0,0,0,0.18) 2px 3px)',
        }}
      />

      {/* UI layer */}
      <div
        style={{
          position: 'fixed',
          inset: 0,
          zIndex: 5,
          display: 'flex',
          flexDirection: 'column',
          padding: '34px 44px',
        }}
      >
        <header style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div
              aria-hidden="true"
              style={{
                width: 34,
                height: 34,
                borderRadius: 9,
                background: '#fff',
                display: 'grid',
                placeItems: 'center',
                overflow: 'hidden',
                boxShadow: '0 0 0 1px rgba(255,255,255,0.10), 0 4px 16px rgba(0,0,0,0.35)',
              }}
            >
              <img
                src={owIcon}
                alt=""
                style={{ width: '84%', height: '84%', objectFit: 'contain', display: 'block' }}
              />
            </div>
            <span style={{ fontWeight: 700, letterSpacing: '0.02em', fontSize: 16 }}>
              OpenWatch
            </span>
          </div>
          <span
            style={{
              fontSize: 11.5,
              color: 'var(--ow-fg-2)',
              border: '1px solid var(--ow-line)',
              borderRadius: 999,
              padding: '5px 11px',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 7,
              background: 'rgba(10,14,20,0.5)',
            }}
          >
            <span
              className="ow-pulse"
              aria-hidden="true"
              style={{
                width: 6,
                height: 6,
                borderRadius: '50%',
                background: SCAN,
                boxShadow: `0 0 8px ${SCAN}`,
                animation: 'ow-pulse 1.8s ease-in-out infinite',
              }}
            />
            <span style={{ color: 'var(--ow-fg-1)', fontWeight: 600 }}>Eyrie</span>
            {version && <span>· v{version}</span>}
          </span>
        </header>

        <div
          style={{
            flex: 1,
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'center',
            maxWidth: 680,
          }}
        >
          <div
            style={{
              fontFamily: 'var(--ow-font-mono, monospace)',
              fontSize: 12,
              letterSpacing: '0.42em',
              textTransform: 'uppercase',
              color: SCAN,
              marginBottom: 22,
            }}
          >
            Infrastructure compliance, watched
          </div>
          <h1
            style={{
              fontSize: 'clamp(48px, 8vw, 104px)',
              lineHeight: 0.94,
              letterSpacing: '-0.035em',
              fontWeight: 800,
              margin: 0,
            }}
          >
            <span style={{ display: 'block' }}>It sees</span>
            <span
              style={{
                display: 'block',
                backgroundImage: `linear-gradient(100deg, ${SCAN}, var(--ow-info) 60%, var(--ow-brand-2))`,
                WebkitBackgroundClip: 'text',
                backgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                color: 'transparent',
              }}
            >
              everything.
            </span>
          </h1>
          <p
            style={{
              marginTop: 26,
              fontSize: 18,
              lineHeight: 1.55,
              color: 'var(--ow-fg-1)',
              maxWidth: 500,
            }}
          >
            From the high vantage of the <b style={{ color: 'var(--ow-fg-0)' }}>Eyrie</b>, OpenWatch
            sweeps every host in your fleet. Scanning, scoring, and remediating against CIS, STIG
            and NIST in one continuous pass.
          </p>
          <div style={{ marginTop: 38 }}>
            <Link
              to="/login"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 11,
                height: 50,
                padding: '0 26px',
                borderRadius: 10,
                background: 'var(--ow-info)',
                color: 'var(--ow-info-on)',
                fontWeight: 700,
                fontSize: 15,
                textDecoration: 'none',
              }}
            >
              Enter console
              <svg
                width="17"
                height="17"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2.4"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <path d="M5 12h14M13 6l6 6-6 6" />
              </svg>
            </Link>
          </div>
        </div>
      </div>

      {/* static demo telemetry readout — NOT live fleet data */}
      <div
        aria-hidden="true"
        style={{
          position: 'fixed',
          right: 44,
          bottom: 34,
          zIndex: 5,
          textAlign: 'right',
          fontFamily: 'var(--ow-font-mono, monospace)',
          fontSize: 11.5,
          color: 'var(--ow-fg-2)',
          lineHeight: 1.9,
        }}
      >
        <div>
          fleet sweep <span style={{ color: SCAN }}>active</span>
        </div>
        <div>
          hosts acquired <span style={{ color: SCAN }}>7</span>
        </div>
        <div>
          reachable <span style={{ color: SCAN }}>1</span>
        </div>
        <div>
          flagged <span style={{ color: 'rgb(229,72,77)' }}>6</span>
        </div>
        <div>
          avg compliance <span style={{ color: 'rgb(230,162,60)' }}>24%</span>
        </div>
      </div>

      <div
        aria-hidden="true"
        style={{
          position: 'fixed',
          left: 44,
          bottom: 34,
          zIndex: 5,
          fontFamily: 'var(--ow-font-mono, monospace)',
          fontSize: 11,
          color: 'var(--ow-fg-3)',
          letterSpacing: '0.08em',
        }}
      >
        EYRIE // ORBITAL VANTAGE // 47.6N 122.3W
      </div>
    </div>
  );
}
