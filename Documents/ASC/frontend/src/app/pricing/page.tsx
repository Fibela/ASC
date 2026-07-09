'use client'
import { useEffect, useState, useCallback } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import Link from 'next/link'
import {
  Shield, Check, X, Zap, Users, Lock,
  BarChart2, Activity, ArrowRight, Star,
  HelpCircle, ChevronDown, ChevronUp,
} from 'lucide-react'
import {
  getBillingPlans, createCheckoutSession, getBillingSubscription,
  BillingPlan,
} from '@/lib/api'
import { isAuthenticated, getRole, initAuth } from '@/lib/auth'

// ── Design tokens ─────────────────────────────────────────────────────────────

const C = {
  bg:      '#080808',
  bgCard:  '#0f0f0f',
  bgCard2: 'rgba(15,15,15,0.95)',
  border:  'rgba(255,255,255,0.07)',
  orange:  '#E85D04',
  orangeL: 'rgba(232,93,4,0.15)',
  orangeB: 'rgba(232,93,4,0.30)',
  text:    '#e2e8f0',
  muted:   '#64748b',
  green:   '#22c55e',
  greenBg: 'rgba(34,197,94,0.10)',
  red:     '#ef4444',
  redBg:   'rgba(239,68,68,0.08)',
} as const

// ── Annual savings helper ──────────────────────────────────────────────────────

function annualSaving(plan: BillingPlan): number {
  if (!plan.price_usd || !plan.price_usd_annual) return 0
  return (plan.price_usd - plan.price_usd_annual) * 12
}

// ── Badge ─────────────────────────────────────────────────────────────────────

function Badge({ label, variant }: { label: string; variant: 'orange' | 'green' | 'muted' }) {
  const styles = {
    orange: { background: C.orangeL, border: `1px solid ${C.orangeB}`, color: C.orange },
    green:  { background: C.greenBg, border: '1px solid rgba(34,197,94,0.3)', color: C.green },
    muted:  { background: 'rgba(255,255,255,0.04)', border: C.border, color: C.muted },
  }
  return (
    <span
      className="text-xs font-bold uppercase tracking-widest px-3 py-1 rounded-full"
      style={styles[variant]}
    >
      {label}
    </span>
  )
}

// ── Plan Card ─────────────────────────────────────────────────────────────────

interface PlanCardProps {
  plan: BillingPlan
  annual: boolean
  currentPlan?: string
  onSelect: (planId: string) => void
  loading: string | null
}

function PlanCard({ plan, annual, currentPlan, onSelect, loading }: PlanCardProps) {
  const isPopular  = plan.highlight
  const isCurrent  = currentPlan === plan.id
  const isFree     = plan.id === 'free'
  const isEnterprise = plan.id === 'enterprise'

  const displayPrice = annual && plan.price_usd_annual != null
    ? plan.price_usd_annual
    : plan.price_usd

  const saving = annualSaving(plan)

  const cardBorder = isPopular
    ? `1px solid ${C.orangeB}`
    : `1px solid ${C.border}`

  const cardBg = isPopular
    ? `radial-gradient(ellipse at top, rgba(232,93,4,0.08) 0%, ${C.bgCard} 60%)`
    : C.bgCard

  return (
    <div
      className="relative flex flex-col rounded-2xl p-8 transition-shadow duration-300"
      style={{
        background: cardBg,
        border: cardBorder,
        boxShadow: isPopular ? '0 0 40px rgba(232,93,4,0.12)' : 'none',
      }}
    >
      {/* Popular badge */}
      {isPopular && (
        <div
          className="absolute -top-4 left-1/2 -translate-x-1/2 text-xs font-black uppercase tracking-widest px-5 py-1.5 rounded-full whitespace-nowrap"
          style={{ background: C.orange, color: '#fff', boxShadow: `0 4px 20px rgba(232,93,4,0.5)` }}
        >
          ★ Más Popular
        </div>
      )}

      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-3">
          <span className="text-base font-black" style={{ color: C.text }}>
            {plan.name}
          </span>
          {isCurrent && <Badge label="Plan actual" variant="green" />}
        </div>
        <p className="text-sm leading-relaxed" style={{ color: C.muted }}>
          {plan.tagline}
        </p>
      </div>

      {/* Price */}
      <div className="mb-6">
        {isEnterprise ? (
          <div>
            <p className="text-3xl font-black" style={{ color: C.text }}>
              A medida
            </p>
            <p className="text-xs mt-1" style={{ color: C.muted }}>
              Precio según escala y requisitos
            </p>
          </div>
        ) : isFree ? (
          <div>
            <p className="text-3xl font-black" style={{ color: C.text }}>
              $0 <span className="text-base font-normal" style={{ color: C.muted }}>/mes</span>
            </p>
            <p className="text-xs mt-1" style={{ color: C.muted }}>
              Sin tarjeta de crédito
            </p>
          </div>
        ) : (
          <div>
            <p className="text-3xl font-black" style={{ color: C.text }}>
              ${displayPrice}
              <span className="text-base font-normal" style={{ color: C.muted }}> /mes</span>
            </p>
            {annual && saving > 0 && (
              <p className="text-xs mt-1 font-semibold" style={{ color: C.green }}>
                Ahorro de ${saving}/año vs mensual
              </p>
            )}
            {!annual && plan.price_usd_annual && (
              <p className="text-xs mt-1" style={{ color: C.muted }}>
                O ${plan.price_usd_annual}/mes con plan anual
              </p>
            )}
          </div>
        )}
      </div>

      {/* CTA */}
      <button
        onClick={() => onSelect(plan.id)}
        disabled={isCurrent || loading === plan.id}
        className="w-full py-3 rounded-xl font-bold text-sm transition-all duration-200 mb-8 flex items-center justify-center gap-2 group"
        style={
          isPopular
            ? {
                background: `linear-gradient(135deg, ${C.orange} 0%, #c2410c 100%)`,
                color: '#fff',
                boxShadow: `0 4px 20px rgba(232,93,4,0.4)`,
                opacity: isCurrent ? 0.5 : 1,
              }
            : {
                background: 'rgba(255,255,255,0.04)',
                border: C.border,
                color: C.text,
                opacity: isCurrent ? 0.5 : 1,
              }
        }
      >
        {loading === plan.id ? (
          <span className="animate-pulse">Procesando…</span>
        ) : isCurrent ? (
          'Plan actual'
        ) : (
          <>
            {plan.cta}
            <ArrowRight size={14} className="group-hover:translate-x-0.5 transition-transform" />
          </>
        )}
      </button>

      {/* Features */}
      <ul className="space-y-3 flex-1">
        {plan.features_list.map((feat) => (
          <li key={feat} className="flex items-start gap-3 text-sm" style={{ color: C.muted }}>
            <Check
              size={14}
              className="mt-0.5 shrink-0"
              style={{ color: isPopular ? C.orange : C.green }}
            />
            <span>{feat}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

// ── Feature comparison row ────────────────────────────────────────────────────

interface FeatureRowProps {
  label: string
  free: string | boolean | null
  pro:  string | boolean | null
  ent:  string | boolean | null
}

function FeatureRow({ label, free, pro, ent }: FeatureRowProps) {
  const Cell = ({ value }: { value: string | boolean | null }) => {
    if (value === true)  return <Check size={16} style={{ color: C.green }} className="mx-auto" />
    if (value === false) return <X    size={16} style={{ color: C.red }}   className="mx-auto" />
    if (value === null || value === undefined) return (
      <span style={{ color: C.muted }} className="text-xs">—</span>
    )
    return <span className="text-xs font-medium" style={{ color: C.text }}>{value}</span>
  }

  return (
    <tr className="border-b" style={{ borderColor: C.border }}>
      <td className="py-3 pr-4 text-sm" style={{ color: C.muted }}>{label}</td>
      <td className="py-3 text-center w-28"><Cell value={free} /></td>
      <td className="py-3 text-center w-28" style={{ background: 'rgba(232,93,4,0.04)' }}>
        <Cell value={pro} />
      </td>
      <td className="py-3 text-center w-28"><Cell value={ent} /></td>
    </tr>
  )
}

// ── FAQ item ──────────────────────────────────────────────────────────────────

function FAQItem({ q, a }: { q: string; a: string }) {
  const [open, setOpen] = useState(false)
  return (
    <div
      className="rounded-xl overflow-hidden"
      style={{ border: C.border, borderStyle: 'solid', borderWidth: 1 }}
    >
      <button
        className="w-full flex items-center justify-between px-5 py-4 text-sm font-semibold text-left"
        style={{ background: C.bgCard, color: C.text }}
        onClick={() => setOpen((o) => !o)}
      >
        {q}
        {open ? <ChevronUp size={16} style={{ color: C.muted }} /> : <ChevronDown size={16} style={{ color: C.muted }} />}
      </button>
      {open && (
        <div
          className="px-5 pb-4 text-sm leading-relaxed"
          style={{ background: C.bgCard, color: C.muted }}
        >
          {a}
        </div>
      )}
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

const COMPARISON_ROWS: FeatureRowProps[] = [
  { label: 'Usuarios',             free: '5',          pro: '50',            ent: 'Ilimitados'   },
  { label: 'API Keys por usuario', free: '3',          pro: '20',            ent: 'Ilimitadas'   },
  { label: 'Retención de datos',   free: '30 días',    pro: '90 días',       ent: '1 año'        },
  { label: 'SIEM (CrowdStrike, PA, Fortinet)', free: false, pro: true,    ent: true              },
  { label: 'Motor de correlación', free: false,        pro: true,            ent: true            },
  { label: 'Threat Hunting',       free: false,        pro: true,            ent: true            },
  { label: 'SOAR + playbooks',     free: false,        pro: true,            ent: true            },
  { label: 'Reportes ejecutivos',  free: false,        pro: true,            ent: true            },
  { label: 'Honeypots',            free: false,        pro: true,            ent: true            },
  { label: 'Análisis de artefactos', free: '5/mes',   pro: 'Ilimitado',     ent: 'Ilimitado'    },
  { label: 'Audit log completo',   free: true,         pro: true,            ent: true            },
  { label: 'Adaptadores custom',   free: false,        pro: false,           ent: true            },
  { label: 'Analista dedicado',    free: false,        pro: false,           ent: true            },
  { label: 'Compliance (SOC 2, ISO 27001)', free: false, pro: false,      ent: true              },
  { label: 'SLA Uptime',          free: null,          pro: '99.5%',         ent: '99.9%'        },
  { label: 'Soporte',             free: 'Comunidad',   pro: 'Email 24h',     ent: '24/7 dedicado'},
]

const FAQ = [
  {
    q: '¿Puedo cambiar de plan en cualquier momento?',
    a: 'Sí. Los upgrades aplican de inmediato y los downgrades al final del período de facturación. No hay penalización por cambiar.',
  },
  {
    q: '¿El plan Free tiene límite de tiempo?',
    a: 'No. El plan Free es permanente. Puedes usarlo indefinidamente sin tarjeta de crédito.',
  },
  {
    q: '¿Qué incluye el plan anual del Pro?',
    a: 'El plan anual del Pro ($239/mes, facturado $2,868/año) ofrece un 20% de descuento respecto al plan mensual ($299/mes). Incluye exactamente las mismas funciones, sin diferencia en características.',
  },
  {
    q: '¿Hay período de prueba para Pro?',
    a: 'Contáctanos para acceder a un trial de 14 días del plan Pro sin compromiso. Incluye todas las funciones excepto integraciones SIEM productivas.',
  },
  {
    q: '¿Mis datos están seguros?',
    a: 'ASC opera sobre infraestructura cifrada en tránsito y en reposo. Los datos de cada tenant están aislados (Row-Level Security en PostgreSQL). Cumplimos con principios de ISO 27001 y OWASP.',
  },
  {
    q: '¿Puedo cancelar mi suscripción Pro?',
    a: 'Sí, en cualquier momento desde el portal de cliente. Después de cancelar, tu plan pasa a Free al final del período pagado. Tus datos se retienen 30 días adicionales tras la cancelación.',
  },
]

export default function PricingPage() {
  const router       = useRouter()
  const searchParams = useSearchParams()
  const [plans, setPlans]       = useState<BillingPlan[]>([])
  const [annual, setAnnual]     = useState(true)
  const [loading, setLoading]   = useState<string | null>(null)
  const [error, setError]       = useState<string | null>(null)
  const [currentPlan, setCurrentPlan] = useState<string | undefined>()
  const [authed, setAuthed]     = useState(false)

  const successParam  = searchParams?.get('billing') === 'success'
  const cancelledParam = searchParams?.get('billing') === 'cancelled'

  useEffect(() => {
    initAuth()
    const auth = isAuthenticated()
    setAuthed(auth)
    getBillingPlans()
      .then((r) => setPlans(r.plans))
      .catch(() => setError('No se pudo cargar el catálogo de planes.'))
    if (auth) {
      getBillingSubscription()
        .then((s) => setCurrentPlan(s.plan))
        .catch(() => {})
    }
  }, [])

  const handleSelect = useCallback(async (planId: string) => {
    if (planId === 'free') {
      if (!authed) router.push('/login')
      return
    }
    if (planId === 'enterprise') {
      router.push('/contact?subject=enterprise')
      return
    }
    if (!authed) {
      router.push(`/login?return=/pricing`)
      return
    }
    setLoading(planId)
    setError(null)
    try {
      const { checkout_url } = await createCheckoutSession(planId as 'pro' | 'enterprise')
      window.location.href = checkout_url
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'Error al iniciar el pago. Inténtalo de nuevo.')
    } finally {
      setLoading(null)
    }
  }, [authed, router])

  return (
    <div style={{ background: C.bg, minHeight: '100vh', fontFamily: 'var(--font-inter, sans-serif)' }}>

      {/* Nav back */}
      <div className="px-6 py-5 flex items-center gap-3" style={{ borderBottom: `1px solid ${C.border}` }}>
        <Link href="/" className="flex items-center gap-2 text-sm font-medium" style={{ color: C.muted }}>
          <Shield size={16} style={{ color: C.orange }} />
          ASC — Analizador de Seguridad Cibernética
        </Link>
        <span style={{ color: C.border }}>›</span>
        <span className="text-sm" style={{ color: C.text }}>Planes</span>
      </div>

      <div className="max-w-6xl mx-auto px-6 py-16">

        {/* Status banners */}
        {successParam && (
          <div className="mb-8 rounded-xl px-5 py-4 text-sm font-medium flex items-center gap-3"
            style={{ background: C.greenBg, border: '1px solid rgba(34,197,94,0.3)', color: C.green }}>
            <Check size={16} /> ¡Suscripción activada! Tu plan ya está activo.
          </div>
        )}
        {cancelledParam && (
          <div className="mb-8 rounded-xl px-5 py-4 text-sm flex items-center gap-3"
            style={{ background: C.redBg, border: '1px solid rgba(239,68,68,0.25)', color: C.red }}>
            <X size={16} /> Pago cancelado. Puedes intentarlo cuando quieras.
          </div>
        )}
        {error && (
          <div className="mb-8 rounded-xl px-5 py-4 text-sm flex items-center gap-3"
            style={{ background: C.redBg, border: '1px solid rgba(239,68,68,0.25)', color: C.red }}>
            <X size={16} /> {error}
          </div>
        )}

        {/* Hero */}
        <div className="text-center mb-16">
          <div className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-widest mb-5 px-4 py-2 rounded-full"
            style={{ background: C.orangeL, border: `1px solid ${C.orangeB}`, color: C.orange }}>
            <Zap size={12} /> Planes y Precios
          </div>
          <h1 className="text-4xl md:text-5xl font-black mb-5 leading-tight" style={{ color: C.text }}>
            Seguridad real.<br />
            <span style={{ color: C.orange }}>Sin compromisos.</span>
          </h1>
          <p className="text-base max-w-xl mx-auto leading-relaxed" style={{ color: C.muted }}>
            Desde monitoreo básico hasta el SOC enterprise completo. Empieza gratis, escala cuando lo necesites.
          </p>

          {/* Annual / Monthly toggle */}
          <div className="flex items-center justify-center gap-4 mt-8">
            <span className="text-sm font-medium" style={{ color: annual ? C.muted : C.text }}>
              Mensual
            </span>
            <button
              onClick={() => setAnnual((a) => !a)}
              className="relative w-12 h-6 rounded-full transition-colors duration-200 focus:outline-none"
              style={{ background: annual ? C.orange : 'rgba(255,255,255,0.1)' }}
              aria-label="Toggle annual billing"
            >
              <span
                className="absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white transition-transform duration-200"
                style={{ transform: annual ? 'translateX(24px)' : 'translateX(0)' }}
              />
            </button>
            <span className="text-sm font-medium flex items-center gap-2" style={{ color: annual ? C.text : C.muted }}>
              Anual
              <span className="text-xs font-bold px-2 py-0.5 rounded-full"
                style={{ background: C.greenBg, color: C.green, border: '1px solid rgba(34,197,94,0.3)' }}>
                −20%
              </span>
            </span>
          </div>
        </div>

        {/* Plan cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-20">
          {plans.map((plan) => (
            <PlanCard
              key={plan.id}
              plan={plan}
              annual={annual}
              currentPlan={currentPlan}
              onSelect={handleSelect}
              loading={loading}
            />
          ))}
          {plans.length === 0 && (
            /* Loading skeleton */
            [0, 1, 2].map((i) => (
              <div key={i} className="rounded-2xl h-96 animate-pulse" style={{ background: C.bgCard, border: `1px solid ${C.border}` }} />
            ))
          )}
        </div>

        {/* Social proof / trust strip */}
        <div
          className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-20 rounded-2xl p-6"
          style={{ background: C.bgCard, border: `1px solid ${C.border}` }}
        >
          {[
            { icon: <Shield size={20} style={{ color: C.orange }} />, label: 'Arquitectura zero-trust' },
            { icon: <Lock size={20} style={{ color: C.green }} />, label: 'Datos cifrados en reposo y tránsito' },
            { icon: <BarChart2 size={20} style={{ color: C.orange }} />, label: 'RLS — aislamiento por tenant' },
            { icon: <Activity size={20} style={{ color: C.green }} />, label: 'OWASP Top 10 cubierto' },
          ].map(({ icon, label }) => (
            <div key={label} className="flex items-center gap-3">
              {icon}
              <span className="text-xs font-medium leading-tight" style={{ color: C.muted }}>{label}</span>
            </div>
          ))}
        </div>

        {/* Feature comparison table */}
        <div className="mb-20">
          <h2 className="text-2xl font-black mb-8 text-center" style={{ color: C.text }}>
            Comparativa completa de funciones
          </h2>
          <div className="rounded-2xl overflow-hidden" style={{ border: `1px solid ${C.border}` }}>
            <div className="overflow-x-auto">
              <table className="w-full" style={{ background: C.bgCard }}>
                <thead>
                  <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                    <th className="text-left py-4 px-5 text-xs font-semibold uppercase tracking-widest" style={{ color: C.muted }}>
                      Función
                    </th>
                    {['Free', 'Pro', 'Enterprise'].map((name, i) => (
                      <th key={name} className="py-4 px-4 text-center w-28"
                        style={{
                          background: i === 1 ? 'rgba(232,93,4,0.06)' : 'transparent',
                          color: i === 1 ? C.orange : C.text,
                        }}>
                        <span className="text-sm font-black">{name}</span>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {COMPARISON_ROWS.map((row) => (
                    <FeatureRow key={row.label} {...row} />
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* FAQ */}
        <div className="mb-20 max-w-2xl mx-auto">
          <h2 className="text-2xl font-black mb-8 text-center flex items-center justify-center gap-2" style={{ color: C.text }}>
            <HelpCircle size={20} style={{ color: C.orange }} />
            Preguntas frecuentes
          </h2>
          <div className="space-y-3">
            {FAQ.map((item) => (
              <FAQItem key={item.q} q={item.q} a={item.a} />
            ))}
          </div>
        </div>

        {/* Enterprise CTA banner */}
        <div
          className="rounded-2xl p-10 text-center"
          style={{
            background: `radial-gradient(ellipse at center, rgba(232,93,4,0.12) 0%, ${C.bgCard} 70%)`,
            border: `1px solid ${C.orangeB}`,
          }}
        >
          <Users size={32} className="mx-auto mb-4" style={{ color: C.orange }} />
          <h3 className="text-2xl font-black mb-3" style={{ color: C.text }}>
            ¿Tienes requisitos de escala o compliance?
          </h3>
          <p className="text-sm mb-6 max-w-md mx-auto leading-relaxed" style={{ color: C.muted }}>
            Habla con nuestro equipo de seguridad. Diseñamos planes para organizaciones con auditorías ISO, SOC 2, o despliegues on-premise.
          </p>
          <div className="flex items-center justify-center gap-4 flex-wrap">
            <button
              onClick={() => handleSelect('enterprise')}
              className="px-6 py-3 rounded-xl text-sm font-bold flex items-center gap-2 transition-all hover:opacity-90"
              style={{ background: `linear-gradient(135deg, ${C.orange} 0%, #c2410c 100%)`, color: '#fff' }}
            >
              Hablar con ventas <ArrowRight size={14} />
            </button>
            <Link
              href="/"
              className="px-6 py-3 rounded-xl text-sm font-medium transition-all hover:opacity-80"
              style={{ background: 'rgba(255,255,255,0.04)', border: `1px solid ${C.border}`, color: C.text }}
            >
              Volver al panel
            </Link>
          </div>
        </div>

        {/* Footer note */}
        <p className="text-center text-xs mt-10" style={{ color: C.muted }}>
          Precios en USD. Pagos procesados de forma segura por Stripe. Sin costos ocultos.{' '}
          <a href="/legal/privacy" className="underline hover:opacity-80">Política de privacidad</a>
          {' · '}
          <a href="/legal/terms" className="underline hover:opacity-80">Términos de uso</a>
        </p>
      </div>
    </div>
  )
}
