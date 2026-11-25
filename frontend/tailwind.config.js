/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        dark: {
          800: '#1e293b',
          850: '#162033',
          900: '#0f172a',
          950: '#070b14',
        },
      },
    },
  },
  plugins: [],
}
