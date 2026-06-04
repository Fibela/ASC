import type { Config } from 'tailwindcss'

const config: Config = {
  content: ['./src/**/*.{js,ts,jsx,tsx,mdx}'],
  theme: {
    extend: {
      colors: {
        navy: {
          900: '#0d1b2a',
          800: '#1a2d42',
          700: '#1e3448',
          600: '#243e58',
        },
        cyan: {
          asc: '#00b4d8',
        },
        threat: {
          critical: '#d92b2b',
          high:     '#e5720d',
          medium:   '#f2c205',
          low:      '#34b85a',
        },
      },
      fontFamily: {
        sans: ['Segoe UI', 'system-ui', 'sans-serif'],
        mono: ['Cascadia Code', 'Fira Code', 'monospace'],
      },
    },
  },
  plugins: [],
}

export default config
