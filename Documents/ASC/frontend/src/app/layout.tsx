import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'ASC PremosCorp — Advanced Security Center',
  description: 'Sistema de detección, análisis y neutralización de amenazas cibernéticas',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="es">
      <body>{children}</body>
    </html>
  )
}
