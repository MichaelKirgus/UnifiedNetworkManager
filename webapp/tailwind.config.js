/** @type {import('tailwindcss').Config} */
export default {
  // Dark mode is driven by a `.dark` class on <html>. It is set before first
  // paint by the inline script in index.html (no flash) and kept in sync by
  // src/theme/useTheme.ts. The palette itself lives as CSS variables in
  // src/index.css — adding a new theme only requires another variable block.
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        // Semantic tokens (values in src/index.css). All use the
        // `rgb(var(--x) / <alpha-value>)` form so opacity modifiers work.
        background: 'rgb(var(--background) / <alpha-value>)',
        foreground: 'rgb(var(--foreground) / <alpha-value>)',
        card: 'rgb(var(--card) / <alpha-value>)',
        muted: {
          DEFAULT: 'rgb(var(--muted) / <alpha-value>)',
          foreground: 'rgb(var(--muted-foreground) / <alpha-value>)',
        },
        border: 'rgb(var(--border) / <alpha-value>)',
        secondary: 'rgb(var(--secondary) / <alpha-value>)',
        faint: 'rgb(var(--faint) / <alpha-value>)',
        primary: {
          DEFAULT: 'rgb(var(--primary) / <alpha-value>)',
          hover: 'rgb(var(--primary-hover) / <alpha-value>)',
        },
        success: {
          DEFAULT: 'rgb(var(--success) / <alpha-value>)',
          fg: 'rgb(var(--success-fg) / <alpha-value>)',
          border: 'rgb(var(--success-border) / <alpha-value>)',
        },
        warning: {
          DEFAULT: 'rgb(var(--warning) / <alpha-value>)',
          fg: 'rgb(var(--warning-fg) / <alpha-value>)',
          border: 'rgb(var(--warning-border) / <alpha-value>)',
        },
        danger: {
          DEFAULT: 'rgb(var(--danger) / <alpha-value>)',
          fg: 'rgb(var(--danger-fg) / <alpha-value>)',
          border: 'rgb(var(--danger-border) / <alpha-value>)',
        },
        info: {
          DEFAULT: 'rgb(var(--info) / <alpha-value>)',
          fg: 'rgb(var(--info-fg) / <alpha-value>)',
          border: 'rgb(var(--info-border) / <alpha-value>)',
        },
        // Categorical accent hues (badge triples). Each hue is a self-contained
        // fill/fg/border set defined per theme in src/index.css.
        'accent-indigo': {
          DEFAULT: 'rgb(var(--accent-indigo) / <alpha-value>)',
          fg: 'rgb(var(--accent-indigo-fg) / <alpha-value>)',
          border: 'rgb(var(--accent-indigo-border) / <alpha-value>)',
        },
        'accent-violet': {
          DEFAULT: 'rgb(var(--accent-violet) / <alpha-value>)',
          fg: 'rgb(var(--accent-violet-fg) / <alpha-value>)',
          border: 'rgb(var(--accent-violet-border) / <alpha-value>)',
        },
        'accent-purple': {
          DEFAULT: 'rgb(var(--accent-purple) / <alpha-value>)',
          fg: 'rgb(var(--accent-purple-fg) / <alpha-value>)',
          border: 'rgb(var(--accent-purple-border) / <alpha-value>)',
        },
        'accent-teal': {
          DEFAULT: 'rgb(var(--accent-teal) / <alpha-value>)',
          fg: 'rgb(var(--accent-teal-fg) / <alpha-value>)',
          border: 'rgb(var(--accent-teal-border) / <alpha-value>)',
        },
        'accent-sky': {
          DEFAULT: 'rgb(var(--accent-sky) / <alpha-value>)',
          fg: 'rgb(var(--accent-sky-fg) / <alpha-value>)',
          border: 'rgb(var(--accent-sky-border) / <alpha-value>)',
        },
        'accent-cyan': {
          DEFAULT: 'rgb(var(--accent-cyan) / <alpha-value>)',
          fg: 'rgb(var(--accent-cyan-fg) / <alpha-value>)',
          border: 'rgb(var(--accent-cyan-border) / <alpha-value>)',
        },
        // Solid status hues (dots, LEDs, progress bars).
        'status-ok': 'rgb(var(--status-ok) / <alpha-value>)',
        'status-warn': 'rgb(var(--status-warn) / <alpha-value>)',
        'status-critical': 'rgb(var(--status-critical) / <alpha-value>)',
        'status-info': 'rgb(var(--status-info) / <alpha-value>)',
        'status-neutral': 'rgb(var(--status-neutral) / <alpha-value>)',
        // Solid action hues (filled buttons with white text).
        'danger-solid': {
          DEFAULT: 'rgb(var(--danger-solid) / <alpha-value>)',
          hover: 'rgb(var(--danger-solid-hover) / <alpha-value>)',
        },
        'success-solid': {
          DEFAULT: 'rgb(var(--success-solid) / <alpha-value>)',
          hover: 'rgb(var(--success-solid-hover) / <alpha-value>)',
        },
        // Interactive accents (focus rings, hover highlights, selected states).
        'focus-ring': 'rgb(var(--focus-ring) / <alpha-value>)',
        'accent-hover': 'rgb(var(--accent-hover) / <alpha-value>)',
        'accent-solid': 'rgb(var(--accent-solid) / <alpha-value>)',
        // Code block surface + text (payload JSON, log excerpts).
        'code-bg': 'rgb(var(--code-bg) / <alpha-value>)',
        'code-fg': 'rgb(var(--code-fg) / <alpha-value>)',
        // Modal/backdrop overlay.
        overlay: 'rgb(var(--overlay) / <alpha-value>)',
        // Console surface + topology canvas palette (fixed dark values, see index.css).
        'console-bg': 'rgb(var(--console-bg) / <alpha-value>)',
        'topo-segment': 'rgb(var(--topo-segment) / <alpha-value>)',
        'topo-host': 'rgb(var(--topo-host) / <alpha-value>)',
        'topo-remote': 'rgb(var(--topo-remote) / <alpha-value>)',
        'topo-unassigned': 'rgb(var(--topo-unassigned) / <alpha-value>)',
        'topo-node': 'rgb(var(--topo-node) / <alpha-value>)',
        'topo-cable': 'rgb(var(--topo-cable) / <alpha-value>)',
        'topo-tunnel': 'rgb(var(--topo-tunnel) / <alpha-value>)',
        'topo-wireless': 'rgb(var(--topo-wireless) / <alpha-value>)',
        'topo-traffic': 'rgb(var(--topo-traffic) / <alpha-value>)',
      },
    },
  },
  plugins: [],
};
