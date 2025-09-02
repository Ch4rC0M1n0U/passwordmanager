import crypto from 'crypto'

const MAX_PASSWORDS = 500
const CONCURRENCY = 6

async function fetchWithRetries(url, options = {}, attempts = 3) {
  let lastErr
  for (let i = 0; i < attempts; i++) {
    try {
      const controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), 10000)
      const res = await fetch(url, { ...options, signal: controller.signal })
      clearTimeout(timeout)
      if (!res.ok) {
        // On 429, wait and retry
        if (res.status === 429) {
          const wait = Math.pow(2, i) * 500
          await new Promise(r => setTimeout(r, wait))
          continue
        }
        throw new Error(`HTTP ${res.status}`)
      }
      return res
    } catch (err) {
      lastErr = err
      // brief backoff
      await new Promise(r => setTimeout(r, 200 * (i + 1)))
    }
  }
  throw lastErr
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end()

  let passwords = []
  if (Array.isArray(req.body.passwords)) passwords = req.body.passwords
  else if (typeof req.body.password === 'string') passwords = [req.body.password]
  else return res.status(400).json({ error: 'passwords required' })

  if (passwords.length === 0) return res.status(400).json({ error: 'no passwords' })
  if (passwords.length > MAX_PASSWORDS) return res.status(400).json({ error: 'too_many_passwords' })

  try {
    // Calculer tous les SHA1 et regrouper par préfixe
    const entries = passwords.map(pw => {
      const sha1 = crypto.createHash('sha1').update(pw).digest('hex').toUpperCase()
      return { sha1, prefix: sha1.slice(0,5), suffix: sha1.slice(5) }
    })

    const byPrefix = new Map()
    entries.forEach((e, idx) => {
      if (!byPrefix.has(e.prefix)) byPrefix.set(e.prefix, [])
      byPrefix.get(e.prefix).push({ idx, suffix: e.suffix })
    })

    const prefixes = Array.from(byPrefix.keys())
    const results = new Array(entries.length).fill(null)

    // limiter la concurrence
    let i = 0
    async function worker() {
      while (i < prefixes.length) {
        const p = prefixes[i++]
        try {
          const resp = await fetchWithRetries(`https://api.pwnedpasswords.com/range/${p}`)
          const text = await resp.text()
          const lines = text.split('\n')
          const map = new Map()
          for (const line of lines) {
            const [hashSuffix, occ] = line.split(':')
            if (!hashSuffix) continue
            map.set(hashSuffix.trim().toUpperCase(), parseInt((occ||'0').trim(), 10) || 0)
          }
          const list = byPrefix.get(p)
          for (const it of list) {
            results[it.idx] = map.get(it.suffix) || 0
          }
        } catch (err) {
          console.error('prefix fetch error', p, err)
          // en erreur, on met null pour signifier inconnu
          const list = byPrefix.get(p)
          for (const it of list) results[it.idx] = null
        }
      }
    }

    const workers = Array.from({length: Math.min(CONCURRENCY, prefixes.length)}).map(()=>worker())
    await Promise.all(workers)

    // assembler la réponse
    const response = results.map(v => (v === null ? null : v))
    res.status(200).json({ counts: response })
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'internal' })
  }
}
