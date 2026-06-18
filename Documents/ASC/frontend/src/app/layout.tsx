import type { Metadata } from 'next'
import { Inter, JetBrains_Mono } from 'next/font/google'
import './globals.css'

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
  display: 'swap',
})

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
  display: 'swap',
})

export const metadata: Metadata = {
  title: 'ASC — Analizador de Seguridad Cibernética | PremosCorp',
  description: 'Plataforma SOC enterprise de detección, análisis y neutralización de amenazas cibernéticas.',
  keywords: ['SOC', 'SIEM', 'cybersecurity', 'threat detection', 'PremosCorp'],
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="es" className={`${inter.variable} ${jetbrainsMono.variable}`}>
      <body>{children}</body>
    </html>
  )
}
