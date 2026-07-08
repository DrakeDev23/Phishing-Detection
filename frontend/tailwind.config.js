export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            animation: {
                blob: "blob 7s infinite",
                "fade-in": "fadeIn 0.5s ease-in",
                "scale-in": "scaleIn 0.3s ease-out",
            },
            keyframes: {
                blob: {
                    "0%, 100%": {
                        transform: "translate(0, 0) scale(1)",
                    },
                    "33%": {
                        transform: "translate(30px, -50px) scale(1.1)",
                    },
                    "66%": {
                        transform: "translate(-20px, 20px) scale(0.9)",
                    },
                },
                fadeIn: {
                    "0%": { opacity: "0" },
                    "100%": { opacity: "1" },
                },
                scaleIn: {
                    "0%": { opacity: "0", transform: "scale(0.95)" },
                    "100%": { opacity: "1", transform: "scale(1)" },
                },
            },
            colors: {
                "glass-light": "rgba(255, 255, 255, 0.1)",
                "glass-dark": "rgba(15, 23, 42, 0.8)",
            },
            backdropFilter: {
                glass: "blur(10px) saturate(180%)",
            },
        },
    },
    plugins: [],
}