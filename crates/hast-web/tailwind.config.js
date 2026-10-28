
const hast = {
	bg: '#090B10', // Void Black: app background
	surface: '#121721', // Graphite: cards, panels, sidebars
	elevated: '#1A202B', // inputs and raised surfaces
	border: '#2B3340',
	primary: '#E3293F', // HAST Crimson: primary actions, active navigation, selection
	'primary-hover': '#C91F34',
	text: '#F3F5F8', // Cold Silver
	secondary: '#A0AABA',
	muted: '#8591A3', // Muted Steel: at least 5:1 on every background (WCAG AA for small text)
	verified: '#45D6A0', // verified signatures, trusted keys
	warning: '#F4B860', // unverified identities, rotations needing attention
	danger: '#FF626F', // failed verification, integrity failures, destructive actions
	link: '#8CB8FF', // links and technical references
};

module.exports = {
	darkMode: ["class"],
	content: [
		"./src/**/*.rs", "./index.html",
	],
	prefix: "",
	theme: {
		container: {
			center: true,
			padding: '2rem',
			screens: {
				'2xl': '1400px'
			}
		},
		extend: {
			colors: {
				// HAST design tokens: the only place the palette's values live (style/input.css exposes them as --hast-*)
				hast,
				// shadcn names used by the shared component classes in src/ui.rs, mapped onto the tokens
				border: hast.border,
				input: hast.border,
				ring: hast.primary,
				background: hast.bg,
				foreground: hast.text,
				primary: { DEFAULT: hast.primary, foreground: '#FFFFFF' },
				secondary: { DEFAULT: hast.elevated, foreground: hast.text },
				destructive: { DEFAULT: hast.danger, foreground: hast.bg },
				muted: { DEFAULT: hast.elevated, foreground: hast.muted },
				accent: { DEFAULT: hast.elevated, foreground: hast.text },
				popover: { DEFAULT: hast.surface, foreground: hast.text },
				card: { DEFAULT: hast.surface, foreground: hast.text },
			},
			borderRadius: {
				lg: 'var(--radius)',
				md: 'calc(var(--radius) - 2px)',
				sm: 'calc(var(--radius) - 4px)'
			},
			keyframes: {
				'accordion-down': {
					from: {
						height: '0'
					},
					to: {
						height: 'var(--radix-accordion-content-height)'
					}
				},
				'accordion-up': {
					from: {
						height: 'var(--radix-accordion-content-height)'
					},
					to: {
						height: '0'
					}
				}
			},
			animation: {
				'accordion-down': 'accordion-down 0.2s ease-out',
				'accordion-up': 'accordion-up 0.2s ease-out',
			},
			fontFamily: {
				sans: ['Inter', 'ui-sans-serif', 'system-ui', 'Segoe UI', 'Roboto', 'sans-serif'],
				mono: ['JetBrains Mono', 'Fira Code', 'ui-monospace', 'Consolas', 'monospace']
			},
			backdropBlur: {
				xs: '2px'
			}
		}
	},
	plugins: [require("tailwindcss-animate")],
};
