/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        'nunito': ['Nunito', 'sans-serif'],
        'lora': ['Lora', 'serif'],
        'satoshi': ['Satoshi', 'sans-serif'],
        'heading': ['Satoshi', 'sans-serif'],
        'body': ['Lora', 'serif'],
        'sans': ['Satoshi', 'ui-sans-serif', 'system-ui'],
      },
      fontWeight: {
        'light': '300',
        'normal': '400',
        'medium': '500',
        'semibold': '600',
        'bold': '700',
        'extrabold': '800',
        'black': '900',
      },
    },
  },
  plugins: [],
}