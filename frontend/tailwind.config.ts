import type { Config } from 'tailwindcss';
export default { content: ['./app/**/*.{ts,tsx}', './components/**/*.{ts,tsx}'], theme: { extend: { colors: { ink: '#09090d', panel: '#14131a', pink: '#ff4fa3', yellow: '#f9df70' } } }, plugins: [] } satisfies Config;
