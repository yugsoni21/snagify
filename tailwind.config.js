/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./src/renderer/src/**/*.{js,ts,jsx,tsx}', './src/renderer/index.html'],
  theme: {
    extend: {
      colors: {
        background: '#0a0a0a',
        surface: '#111111',
        'surface-elevated': '#161616',
        border: '#1e1e1e',
        'border-subtle': '#161616',
        accent: '#5e6ad2',
        'accent-hover': '#6b77df',
        text: {
          primary: '#f5f5f5',
          secondary: '#8b8b8b',
          muted: '#4a4a4a'
        }
      },
      fontFamily: {
        sans: [
          'Inter',
          '-apple-system',
          'BlinkMacSystemFont',
          'Segoe UI',
          'sans-serif'
        ]
      },
      animation: {
        'fade-in': 'fadeIn 0.15s ease-out'
      },
      keyframes: {
        fadeIn: {
          from: { opacity: '0', transform: 'translateY(4px)' },
          to: { opacity: '1', transform: 'translateY(0)' }
        }
      }
    }
  },
  plugins: []
}
