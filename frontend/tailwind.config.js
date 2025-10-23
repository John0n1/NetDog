/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        dark: {
          bg: '#0a0a0a',
          surface: '#1a1a1a',
          hover: '#252525',
          border: '#333333',
        },
        blue: {
          accent: '#3b82f6',
          'accent-hover': '#2563eb',
          'accent-dark': '#1d4ed8',
        }
      },
      fontFamily: {
        mono: ['Fira Code', 'Menlo', 'Monaco', 'Courier New', 'monospace'],
      }
    },
  },
  plugins: [],
}
