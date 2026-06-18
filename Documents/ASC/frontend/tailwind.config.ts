import type { Config } from 'tailwindcss'

const config: Config = {
  content: ['./src/**/*.{js,ts,jsx,tsx,mdx}'],
  theme: {
    extend: {
      colors: {
        // ── PremosCorp Corporate Palette ──────────────────────────
        premos: {
          orange:      '#E85D04',
          'orange-dk': '#C44D03',
          'orange-lt': '#FF7A25',
          black:       '#0A0A0A',
          red:         '#8B1E1E',
          'red-lt':    '#B52929',
          neutral:     '#EAEAEA',
          'neutral-dk':'#D0D0D0',
        },
        // ── Surface layers ────────────────────────────────────────
        surface: {
          950: '#070707',
          900: '#0A0A0A',
          850: '#111111',
          800: '#161616',
          750: '#1A1A1A',
          700: '#222222',
          600: '#2A2A2A',
          500: '#333333',
        },
        // ── Threat severity (adapted to Premos colors) ────────────
        threat: {
          critical: '#C0152E',  // vivid red
          high:     '#E85D04',  // Premos Orange — elevated alert
          medium:   '#F2C205',  // amber
          low:      '#2DB863',  // green
          info:     '#4A90D9',  // blue-steel
        },
        // ── Text hierarchy ────────────────────────────────────────
        ink: {
          primary:   '#EAEAEA',
          secondary: '#A0A0A0',
          muted:     '#5A5A5A',
          faint:     '#3A3A3A',
        },
      },
      fontFamily: {
        sans:    ['var(--font-inter)', 'Inter', 'system-ui', 'sans-serif'],
        display: ['var(--font-inter)', 'Inter', 'system-ui', 'sans-serif'],
        mono:    ['var(--font-mono)', 'JetBrains Mono', 'Fira Code', 'monospace'],
      },
      backgroundImage: {
        // Premos mesh — subtle orange + red radials
        'premos-mesh':
          'radial-gradient(ellipse at 15% 40%, rgba(232,93,4,0.06) 0%, transparent 55%), ' +
          'radial-gradient(ellipse at 80% 15%, rgba(139,30,30,0.06) 0%, transparent 55%), ' +
          'radial-gradient(ellipse at 55% 85%, rgba(232,93,4,0.04) 0%, transparent 45%)',
        'gradient-orange':  'linear-gradient(135deg, #C44D03 0%, #E85D04 50%, #FF7A25 100%)',
        'gradient-red':     'linear-gradient(135deg, #6B1212 0%, #8B1E1E 50%, #B52929 100%)',
        'gradient-surface': 'linear-gradient(135deg, rgba(255,255,255,0.04) 0%, rgba(255,255,255,0.01) 100%)',
        'gradient-sidebar': 'linear-gradient(180deg, #0A0A0A 0%, #070707 100%)',
        'gradient-card':    'linear-gradient(135deg, rgba(232,93,4,0.05) 0%, transparent 60%)',
      },
      boxShadow: {
        'orange-glow':    '0 0 20px rgba(232,93,4,0.3), 0 0 40px rgba(232,93,4,0.1)',
        'orange-glow-sm': '0 0 8px rgba(232,93,4,0.35)',
        'red-glow':       '0 0 20px rgba(139,30,30,0.4)',
        'red-glow-sm':    '0 0 8px rgba(192,21,46,0.4)',
        'card':           '0 1px 4px rgba(0,0,0,0.6), inset 0 1px 0 rgba(255,255,255,0.04)',
        'card-hover':     '0 4px 20px rgba(0,0,0,0.6), inset 0 1px 0 rgba(255,255,255,0.06)',
        'card-orange':    '0 1px 4px rgba(0,0,0,0.6), 0 0 0 1px rgba(232,93,4,0.12), inset 0 1px 0 rgba(232,93,4,0.06)',
      },
      borderRadius: {
        'xl':  '12px',
        '2xl': '16px',
        '3xl': '24px',
      },
      animation: {
        'pulse-orange': 'pulseOrange 2.5s ease-in-out infinite',
        'pulse-red':    'pulseRed 1.8s ease-in-out infinite',
        'fade-in':      'fadeIn 0.2s ease-out',
        'slide-in':     'slideIn 0.25s ease-out',
      },
      keyframes: {
        pulseOrange: {
          '0%, 100%': { boxShadow: '0 0 6px rgba(232,93,4,0.2)' },
          '50%':      { boxShadow: '0 0 22px rgba(232,93,4,0.55), 0 0 44px rgba(232,93,4,0.15)' },
        },
        pulseRed: {
          '0%, 100%': { boxShadow: '0 0 8px rgba(192,21,46,0.3)' },
          '50%':      { boxShadow: '0 0 28px rgba(192,21,46,0.7), 0 0 56px rgba(192,21,46,0.2)' },
        },
        fadeIn: {
          from: { opacity: '0', transform: 'translateY(4px)' },
          to:   { opacity: '1', transform: 'translateY(0)' },
        },
        slideIn: {
          from: { opacity: '0', transform: 'translateX(-10px)' },
          to:   { opacity: '1', transform: 'translateX(0)' },
        },
      },
    },
  },
  plugins: [],
}

export default config
