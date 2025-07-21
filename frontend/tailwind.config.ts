import type { Config } from "tailwindcss";
import tailwindcssAnimate from "tailwindcss-animate";

const config = {
	darkMode: ["class"],
	content: [
		"./pages/**/*.{js,ts,jsx,tsx,mdx}",
		"./components/**/*.{js,ts,jsx,tsx,mdx}",
		"./app/**/*.{js,ts,jsx,tsx,mdx}",
	],
	plugins: [
		tailwindcssAnimate,
		// Removed @assistant-ui/react/tailwindcss and @assistant-ui/react-markdown/tailwindcss as they cause errors
	],
} satisfies Config;

export default config;
