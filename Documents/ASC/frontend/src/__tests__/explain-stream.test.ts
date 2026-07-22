import { parseSSEChunk, ExplainCallbacks } from '@/lib/explainStream'

function collector() {
  const out = { meta: [] as any[], deltas: [] as string[], done: 0, errors: [] as string[] }
  const cb: ExplainCallbacks = {
    onMeta: m => out.meta.push(m),
    onDelta: t => out.deltas.push(t),
    onDone: () => { out.done++ },
    onError: d => out.errors.push(d),
  }
  return { out, cb }
}

describe('parseSSEChunk', () => {
  it('despacha meta + deltas + done y no deja remanente', () => {
    const { out, cb } = collector()
    const buf =
      'event: meta\ndata: {"alert_id":"a1","profile":"hogar"}\n\n' +
      'event: delta\ndata: {"text":"Hola "}\n\n' +
      'event: delta\ndata: {"text":"mundo"}\n\n' +
      'event: done\ndata: {"alert_id":"a1"}\n\n'
    const leftover = parseSSEChunk(buf, cb)
    expect(out.meta[0].profile).toBe('hogar')
    expect(out.deltas.join('')).toBe('Hola mundo')
    expect(out.done).toBe(1)
    expect(leftover).toBe('')
  })

  it('conserva la trama incompleta como remanente', () => {
    const { out, cb } = collector()
    const leftover = parseSSEChunk('event: delta\ndata: {"text":"parcial', cb)
    expect(out.deltas).toHaveLength(0)
    expect(leftover).toContain('parcial')
  })

  it('ignora JSON corrupto sin romper', () => {
    const { out, cb } = collector()
    parseSSEChunk('event: delta\ndata: no-es-json{\n\n', cb)
    expect(out.deltas).toHaveLength(0)
    expect(out.errors).toHaveLength(0)
  })

  it('despacha error', () => {
    const { out, cb } = collector()
    parseSSEChunk('event: error\ndata: {"detail":"upstream"}\n\n', cb)
    expect(out.errors).toEqual(['upstream'])
  })
})
