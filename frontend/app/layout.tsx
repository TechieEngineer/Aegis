import type { Metadata } from 'next';
import './globals.css';
export const metadata: Metadata = { title: 'Aegis | Security Operations', description: 'Local-first security operations console', robots: { index: false, follow: false } };
export const dynamic = 'force-dynamic';
export default function RootLayout({children}: Readonly<{children: React.ReactNode}>) {return <html lang="en"><body>{children}</body></html>}
