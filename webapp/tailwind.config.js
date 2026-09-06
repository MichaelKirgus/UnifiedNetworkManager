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
      },
    },
  },
  plugins: [],
};
