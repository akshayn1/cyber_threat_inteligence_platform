/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        ink: {
          950: "#070b14",
          900: "#0b1220",
          800: "#111a2e",
          700: "#1a2540",
          600: "#26345a",
        },
        // Enterprise Slate & Midnight palette
        surface: {
          ground: "var(--color-bg-ground)",
          card: "var(--color-bg-card)",
          hover: "var(--color-bg-hover)",
          subtle: "var(--color-bg-subtle)",
          border: "var(--color-border)",
          borderLight: "var(--color-border-light)",
        },
        sev: {
          critical: "#ef4444",
          high: "#f97316",
          medium: "#eab308",
          low: "#10b981",
        },
      },
      fontFamily: {
        sans: ["Inter", "-apple-system", "BlinkMacSystemFont", "Segoe UI", "Roboto", "sans-serif"],
        mono: ["'JetBrains Mono'", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      boxShadow: {
        card: "0 4px 20px -2px rgba(0, 0, 0, 0.35)",
        "card-glow": "0 0 25px -5px rgba(14, 165, 233, 0.15)",
        "red-glow": "0 0 20px -3px rgba(239, 68, 68, 0.25)",
      },
      keyframes: {
        "pulse-slow": {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.4" },
        },
      },
      animation: {
        "pulse-slow": "pulse-slow 2.5s cubic-bezier(0.4, 0, 0.6, 1) infinite",
      },
    },
  },
  plugins: [],
};

