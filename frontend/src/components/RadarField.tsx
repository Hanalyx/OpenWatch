import { useEffect, useRef } from 'react';

// RadarField — the animated "Eyrie" radar backdrop shared by the public
// homepage hero and the login page. A sweep beam rotates from a vantage
// origin and lights host nodes as it passes, echoing OpenWatch sweeping
// a fleet. Ported from docs/engineering/prototypes/openwatch-v1
// (home/Eyrie - Radar.html + login.html backdrop).
//
// Spec: frontend-homepage (hero), frontend-auth-login (backdrop).
//
// Pure decoration: the canvas carries aria-hidden and the readout values
// are static demo art, never live fleet data (a public surface must not
// expose real numbers). Honors prefers-reduced-motion by drawing a
// single static frame instead of animating.

interface RadarFieldProps {
  // dim renders the backdrop variant (login) — lower opacity, centered
  // origin, no node labels. Default false is the hero variant.
  dim?: boolean;
}

interface Node {
  ang: number;
  x: number;
  y: number;
  s: 'crit' | 'warn' | 'ok';
  label: string;
  lit: number;
  last: number;
}

// Demo fleet seed — angle, radius fraction, status, label. Static art.
const SEED: { a: number; r: number; s: Node['s']; l: string }[] = [
  { a: 0.3, r: 0.42, s: 'crit', l: 'owas-rhn01' },
  { a: 0.62, r: 0.55, s: 'crit', l: 'owas-hrm01' },
  { a: 1.05, r: 0.34, s: 'warn', l: 'owas-tst01' },
  { a: 1.55, r: 0.62, s: 'warn', l: 'owas-tst02' },
  { a: 2.1, r: 0.3, s: 'ok', l: 'owas-ub5s2' },
  { a: 2.55, r: 0.5, s: 'warn', l: 'owas-ub4m2' },
  { a: 3.0, r: 0.4, s: 'crit', l: '192.168.1.212' },
  { a: 3.55, r: 0.58, s: 'warn', l: '·' },
  { a: 3.95, r: 0.33, s: 'crit', l: '·' },
  { a: 4.35, r: 0.66, s: 'warn', l: '·' },
  { a: 4.85, r: 0.44, s: 'ok', l: '·' },
  { a: 5.25, r: 0.56, s: 'crit', l: '·' },
  { a: 5.7, r: 0.36, s: 'warn', l: '·' },
  { a: 6.05, r: 0.6, s: 'crit', l: '·' },
];

// Portable rgba (not oklch) so the canvas renders identically across the
// SPA's target browsers. Alpha is supplied per draw.
const COLOR: Record<Node['s'], (a: number) => string> = {
  crit: (a) => `rgba(229,72,77,${a})`,
  warn: (a) => `rgba(230,162,60,${a})`,
  ok: (a) => `rgba(48,192,138,${a})`,
};
const scan = (a: number) => `rgba(96,212,228,${a})`;

export function RadarField({ dim = false }: RadarFieldProps) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const intensity = dim ? 0.55 : 1;
    const showLabels = !dim;
    let W = 0;
    let H = 0;
    let DPR = 1;
    let cx = 0;
    let cy = 0;
    let R = 0;
    const nodes: Node[] = [];

    function resize() {
      DPR = Math.min(window.devicePixelRatio || 1, 2);
      W = canvas!.width = window.innerWidth * DPR;
      H = canvas!.height = window.innerHeight * DPR;
      canvas!.style.width = window.innerWidth + 'px';
      canvas!.style.height = window.innerHeight + 'px';
      // Hero sweeps from an upper-right "watchtower" vantage; the dimmed
      // login backdrop is centered.
      cx = dim ? W * 0.5 : W * 0.66;
      cy = dim ? H * 0.5 : H * 0.46;
      R = Math.hypot(Math.max(cx, W - cx), Math.max(cy, H - cy)) * 1.02;
      buildNodes();
    }

    function buildNodes() {
      nodes.length = 0;
      SEED.forEach((n) => {
        nodes.push({
          ang: n.a,
          x: cx + Math.cos(n.a) * R * n.r,
          y: cy + Math.sin(n.a) * R * n.r * 0.82,
          s: n.s,
          label: n.l,
          lit: 0,
          last: -10,
        });
      });
    }

    function norm(a: number) {
      a %= Math.PI * 2;
      return a < 0 ? a + Math.PI * 2 : a;
    }

    let sweep = -1.2;
    let t = 0;

    function drawFrame(animate: boolean) {
      if (animate) {
        t += 1;
        sweep += 0.0125;
      }
      const sw = norm(sweep);
      ctx!.clearRect(0, 0, W, H);

      // faint range rings
      ctx!.lineWidth = DPR;
      for (let i = 1; i <= 6; i++) {
        ctx!.beginPath();
        ctx!.strokeStyle = scan((0.05 + (i === 3 ? 0.04 : 0)) * intensity);
        for (let k = 0; k <= 64; k++) {
          const a = (k / 64) * Math.PI * 2;
          const x = cx + Math.cos(a) * R * (i / 6);
          const y = cy + Math.sin(a) * R * (i / 6) * 0.82;
          if (k) ctx!.lineTo(x, y);
          else ctx!.moveTo(x, y);
        }
        ctx!.stroke();
      }
      // radial spokes
      for (let i = 0; i < 12; i++) {
        const a = (i / 12) * Math.PI * 2;
        ctx!.beginPath();
        ctx!.strokeStyle = scan(0.04 * intensity);
        ctx!.moveTo(cx, cy);
        ctx!.lineTo(cx + Math.cos(a) * R, cy + Math.sin(a) * R * 0.82);
        ctx!.stroke();
      }

      // sweep beam — gradient wedge trailing the leading edge
      const steps = 38;
      for (let i = 0; i < steps; i++) {
        const a = sw - (i / steps) * 0.34 * 2.4;
        const alpha = (1 - i / steps) * 0.16 * intensity;
        ctx!.beginPath();
        ctx!.moveTo(cx, cy);
        ctx!.lineTo(cx + Math.cos(a) * R, cy + Math.sin(a) * R * 0.82);
        ctx!.lineTo(cx + Math.cos(a - 0.03) * R, cy + Math.sin(a - 0.03) * R * 0.82);
        ctx!.closePath();
        ctx!.fillStyle = scan(alpha);
        ctx!.fill();
      }
      // leading edge
      ctx!.beginPath();
      ctx!.moveTo(cx, cy);
      ctx!.lineTo(cx + Math.cos(sw) * R, cy + Math.sin(sw) * R * 0.82);
      ctx!.strokeStyle = scan(0.55 * intensity);
      ctx!.lineWidth = 2 * DPR;
      ctx!.stroke();

      // origin glow
      const og = ctx!.createRadialGradient(cx, cy, 0, cx, cy, 60 * DPR);
      og.addColorStop(0, scan(0.5 * intensity));
      og.addColorStop(1, 'transparent');
      ctx!.fillStyle = og;
      ctx!.beginPath();
      ctx!.arc(cx, cy, 60 * DPR, 0, Math.PI * 2);
      ctx!.fill();

      // nodes
      nodes.forEach((n) => {
        const na = norm(n.ang);
        let d = Math.abs(sw - na);
        if (d > Math.PI) d = Math.PI * 2 - d;
        if (animate && d < 0.06 && t - n.last > 60) {
          n.lit = 1;
          n.last = t;
        }
        if (animate) n.lit *= 0.975;
        const base = (0.22 + n.lit * 0.78) * intensity;
        if (n.lit > 0.05) {
          const rr = (1 - n.lit) * 46 * DPR + 6 * DPR;
          ctx!.beginPath();
          ctx!.arc(n.x, n.y, rr, 0, Math.PI * 2);
          ctx!.strokeStyle = COLOR[n.s](n.lit * 0.5 * intensity);
          ctx!.lineWidth = 1.5 * DPR;
          ctx!.stroke();
        }
        if (n.lit > 0.1) {
          const g = ctx!.createRadialGradient(n.x, n.y, 0, n.x, n.y, 26 * DPR);
          g.addColorStop(0, COLOR[n.s](n.lit * 0.5 * intensity));
          g.addColorStop(1, 'transparent');
          ctx!.fillStyle = g;
          ctx!.beginPath();
          ctx!.arc(n.x, n.y, 26 * DPR, 0, Math.PI * 2);
          ctx!.fill();
        }
        ctx!.beginPath();
        ctx!.arc(n.x, n.y, (2.2 + n.lit * 2) * DPR, 0, Math.PI * 2);
        ctx!.fillStyle = COLOR[n.s](base);
        ctx!.fill();
        if (showLabels && n.lit > 0.35 && n.label !== '·') {
          ctx!.font = 11 * DPR + "px 'JetBrains Mono', monospace";
          ctx!.fillStyle = `rgba(225,238,240,${n.lit * 0.9})`;
          ctx!.textAlign = 'left';
          ctx!.fillText(n.label, n.x + 10 * DPR, n.y - 8 * DPR);
          ctx!.fillStyle = COLOR[n.s](n.lit * 0.7);
          ctx!.fillText(
            n.s === 'ok' ? 'compliant' : n.s === 'warn' ? 'paused' : 'flagged',
            n.x + 10 * DPR,
            n.y + 6 * DPR,
          );
        }
      });
    }

    const reduced =
      typeof window.matchMedia === 'function' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    let raf = 0;
    function loop() {
      drawFrame(true);
      raf = window.requestAnimationFrame(loop);
    }

    resize();
    window.addEventListener('resize', resize);
    if (reduced) {
      // Static single frame — no motion for users who opt out.
      sweep = 0.6;
      drawFrame(false);
    } else {
      loop();
    }

    return () => {
      window.removeEventListener('resize', resize);
      if (raf) window.cancelAnimationFrame(raf);
    };
  }, [dim]);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden="true"
      style={{ position: 'fixed', inset: 0, width: '100vw', height: '100vh', display: 'block' }}
    />
  );
}
