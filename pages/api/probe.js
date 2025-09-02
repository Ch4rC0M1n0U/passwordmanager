// Serveur: probe une URL avec HEAD puis GET fallback. Retourne JSON { status, httpStatus, timeMs }
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' })
  const { url } = req.body || {}
  if (!url || typeof url !== 'string') return res.status(400).json({ error: 'Missing url' })

  let u = url.trim()
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u

  const TIMEOUT = 8000
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), TIMEOUT)
  // abort if client disconnects
  const onClose = () => {
    try { controller.abort() } catch (e) {}
  }
  req.on && req.on('close', onClose)
  const start = Date.now()
  try {
    // Prefer HEAD first, but many sites block or return misleading statuses for HEAD.
    // We therefore always fall back to GET before concluding the site is dead.
    const headers = {
      'User-Agent': 'Mozilla/5.0 (compatible; PasswordManagerProbe/1.0)',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    }

    // Try HEAD quickly
    let r = null
    try {
      r = await fetch(u, { method: 'HEAD', headers, signal: controller.signal })
    } catch (e) {
      // ignore - will try GET below
    }

    const elapsedHead = Date.now() - start
    if (r && r.ok) {
      clearTimeout(timeout)
      try { req.off && req.off('close', onClose) } catch (e) {}
      return res.status(200).json({ status: 'alive', httpStatus: r.status || null, timeMs: elapsedHead })
    }

    // If HEAD returned non-ok or failed (405, 403, etc), do a GET and inspect body.
    let getRes
    try {
      getRes = await fetch(u, { method: 'GET', headers, signal: controller.signal })
    } catch (e) {
      // network error or aborted
      clearTimeout(timeout)
      try { req.off && req.off('close', onClose) } catch (e) {}
      return res.status(200).json({ status: 'unknown', httpStatus: null, timeMs: null })
    }

    const elapsed = Date.now() - start
    // If GET is a 4xx/5xx, declare dead
    if (getRes.status >= 400) {
      clearTimeout(timeout)
      try { req.off && req.off('close', onClose) } catch (e) {}
      return res.status(200).json({ status: 'dead', httpStatus: getRes.status || null, timeMs: elapsed })
    }

    // If content-type is not HTML (images, binary), and GET succeeded, treat as alive
    const ctype = getRes.headers.get('content-type') || ''
    if (!/text|html|json/i.test(ctype)) {
      clearTimeout(timeout)
      try { req.off && req.off('close', onClose) } catch (e) {}
      return res.status(200).json({ status: 'alive', httpStatus: getRes.status || null, timeMs: elapsed })
    }

    // Read body (limit to first chunk to avoid huge downloads)
    let text = ''
    try {
      text = await getRes.text()
    } catch (e) {
      text = ''
    }
    const sample = (text || '').slice(0, 64 * 1024).toLowerCase()

    // Heuristics to detect custom 404 / not-found pages served with HTTP 200
    const checks = [
      /page not found/,
      /404\s*-?\s*not found/,
      /error\s*404/,
      /<title>\s*404/,
      /we could not find the page/,
      /the page you requested could not be found/,
      /no such page/,
      /not found/,
      /sorry, .* not found/
    ]
    let matchCount = 0
    for (const rx of checks) if (rx.test(sample)) matchCount++

    // require stronger evidence: either title includes 404 or two textual matches
    const title404 = /<title[^>]*>[^<]*404[^<]*<\/title>/.test(sample)
    const likelyNotFound = title404 || matchCount >= 2

    clearTimeout(timeout)
    try { req.off && req.off('close', onClose) } catch (e) {}

    if (likelyNotFound) {
      return res.status(200).json({ status: 'dead', httpStatus: getRes.status || null, timeMs: elapsed })
    }

    // otherwise consider alive
    return res.status(200).json({ status: 'alive', httpStatus: getRes.status || null, timeMs: elapsed })
  } catch (err) {
    clearTimeout(timeout)
    if (err && err.name === 'AbortError') {
      // client aborted or timeout
      try { req.off && req.off('close', onClose) } catch(e){}
      return res.status(200).json({ status: 'unknown', httpStatus: null, timeMs: null })
    }
    // network/other errors -> unknown
    try { req.off && req.off('close', onClose) } catch(e){}
    return res.status(200).json({ status: 'unknown', httpStatus: null, timeMs: null })
  }
}
