/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./views/**/*.ejs","./public/**/*.js"],
  theme: { extend: {} },
  plugins: [require("@tailwindcss/typography")],
  corePlugins: { preflight: false }, // ← stäng av resetten
};