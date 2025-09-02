import { useState, useRef } from 'react'
import styles from '../styles/home.module.css'

// Application centrée sur l'import CSV des éléments de gestion de mots de passe
// Fonctionnalités:
// - Import d'un CSV (profile,site,username,password,usage_count)
// - Tri par vulnérabilité (pwnedCount), usage, profil
// - Sélection multiple et suppression
// - Vérification via /api/check-pwned (ne stocke rien)

export default function Home() {
  const [items, setItems] = useState([])
  const [originalHeaders, setOriginalHeaders] = useState(null)
  const [originalColCount, setOriginalColCount] = useState(0)
  const [originalRows, setOriginalRows] = useState([])
  const [originalRawText, setOriginalRawText] = useState(null)
  const [originalUsedQuotes, setOriginalUsedQuotes] = useState(null)
  const [selectedIds, setSelectedIds] = useState(new Set())
  const [checking, setChecking] = useState(false)
  const [filterField, setFilterField] = useState('profile')
  const [filterValue, setFilterValue] = useState('')
  const [siteFilter, setSiteFilter] = useState('all')
  const [checkingSites, setCheckingSites] = useState(false)
  const siteControllersRef = useRef(new Map())
  const [siteCheckProgress, setSiteCheckProgress] = useState({ checked: 0, total: 0 })
  let filteredItems = items.filter(i => {
    if (!filterValue) return true
    const v = (i[filterField] || '').toString().toLowerCase()
    return v.includes(filterValue.toLowerCase())
  })
  if (siteFilter && siteFilter !== 'all') {
    filteredItems = filteredItems.filter(i => i.siteStatus === siteFilter)
  }
  const uniqueValues = Array.from(new Set(items.map(i => (i[filterField]||'').toString().trim()).filter(Boolean))).sort()
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const [pendingDeleteIds, setPendingDeleteIds] = useState(new Set())

  function parseCSV(text) {
    // Parser CSV robuste (gère champs entre guillemets et virgules échappées)
    function parseCSVText(txt) {
      const rows = []
      let i = 0
      let cur = ''
      let row = []
      let inQuotes = false
      while (i < txt.length) {
        const ch = txt[i]
        if (inQuotes) {
          if (ch === '"') {
            if (i + 1 < txt.length && txt[i + 1] === '"') { // double quote => escape
              cur += '"'
              i += 2
              continue
            }
            inQuotes = false
            i++
            continue
          }
          cur += ch
          i++
          continue
        }
        if (ch === '"') {
          inQuotes = true
          i++
          continue
        }
        if (ch === ',') {
          row.push(cur)
          cur = ''
          i++
          continue
        }
        if (ch === '\n' || (ch === '\r' && txt[i+1] === '\n')) {
          // handle CRLF
          if (ch === '\r' && txt[i+1] === '\n') i++
          row.push(cur)
          rows.push(row)
          row = []
          cur = ''
          i++
          continue
        }
        cur += ch
        i++
      }
      // last field
      if (cur !== '' || row.length > 0) {
        row.push(cur)
        rows.push(row)
      }
      return rows
    }

    const allLines = parseCSVText(text).filter(r => r.some(c => (c||'').trim() !== ''))

  // detect header row if first line contains known column names
    const maybeHeader = allLines.length > 0 ? allLines[0].map(c => (c||'').toString().toLowerCase().trim()) : []
    const headerKeywords = ['profile','site','username','user','login','password','pass','usage','count']
    const hasHeader = maybeHeader.some(h => headerKeywords.includes(h))

    const dataLines = hasHeader ? allLines.slice(1) : allLines
    const now = Date.now()

    // store original header and column count
    setOriginalHeaders(hasHeader ? allLines[0] : null)
    setOriginalColCount(dataLines.length > 0 ? Math.max(...dataLines.map(r => r.length)) : (hasHeader ? allLines[0].length : 0))
    setOriginalRows(dataLines.map(r => r.slice()))
    // detect whether original file used quoted fields by inspecting first non-empty raw line
    try {
      const firstRawLine = text.split(/\r?\n/).find(l => (l||'').trim() !== '') || ''
      const quotedFieldPattern = /(^|,)\s*"(?:[^"]|"")*"\s*(?=,|$)/
      setOriginalUsedQuotes(quotedFieldPattern.test(firstRawLine))
    } catch (e) {
      setOriginalUsedQuotes(true)
    }

    const parsed = dataLines.map((parts, idx) => ({
      id: `${now}_${idx}`,
      profile: parts[0] ? parts[0].trim() : '',
      site: parts[1] ? parts[1].trim() : '',
      username: parts[2] ? parts[2].trim() : '',
      password: parts[3] ? parts[3] : '',
      usage: parts[4] ? parseInt(parts[4].trim(), 10) || 0 : 0,
  pwnedCount: null,
  siteStatus: 'unknown',
      originalRowIndex: idx
    }))
  setItems(prev => [...prev, ...parsed])
  }

  function handleFile(e) {
    const f = e.target.files && e.target.files[0]
    if (!f) return
    const reader = new FileReader()
  reader.onload = () => { setOriginalRawText(reader.result); parseCSV(reader.result) }
    reader.readAsText(f)
  }

  function toggleSelect(id) {
    setSelectedIds(prev => {
      const copy = new Set(prev)
      if (copy.has(id)) copy.delete(id)
      else copy.add(id)
      return copy
    })
  }

  function deleteSelected() {
    // ouvrir la modal de confirmation; stocker les ids à supprimer
    if (selectedIds.size === 0) return
    setPendingDeleteIds(new Set(selectedIds))
    setShowDeleteConfirm(true)
  }

  function performDeleteConfirmed() {
    setItems(prev => prev.filter(i => !pendingDeleteIds.has(i.id)))
    setSelectedIds(prev => {
      const copy = new Set(prev)
      for (const id of pendingDeleteIds) copy.delete(id)
      return copy
    })
    setPendingDeleteIds(new Set())
    setShowDeleteConfirm(false)
  }

  function cancelDelete() {
    setPendingDeleteIds(new Set())
    setShowDeleteConfirm(false)
  }

  async function checkPwnedForSelected() {
    setChecking(true)
    try {
      // client-side SHA-1 + k-anonymity to query HIBP directly
      const toCheck = items.filter(i => selectedIds.has(i.id))

      async function sha1Hex(str) {
        const enc = new TextEncoder()
        const data = enc.encode(str)
        const hashBuffer = await crypto.subtle.digest('SHA-1', data)
        const hashArray = Array.from(new Uint8Array(hashBuffer))
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase()
      }

      // compute hashes
      const hashes = await Promise.all(toCheck.map(async t => ({ id: t.id, sha1: await sha1Hex(t.password) })))
      // group by prefix
      const byPrefix = new Map()
      hashes.forEach((h, idx) => {
        const prefix = h.sha1.slice(0,5)
        const suffix = h.sha1.slice(5)
        if (!byPrefix.has(prefix)) byPrefix.set(prefix, [])
        byPrefix.get(prefix).push({ idx, id: h.id, suffix })
      })

      // fetch ranges from HIBP with limited concurrency
      const prefixes = Array.from(byPrefix.keys())
      const resultsMap = new Map()

      const CONC = 6
      let cur = 0
      async function worker() {
        while (cur < prefixes.length) {
          const p = prefixes[cur++]
          try {
            const res = await fetch(`https://api.pwnedpasswords.com/range/${p}`)
            if (!res.ok) throw new Error('HIBP fetch failed')
            const text = await res.text()
            const lines = text.split('\n')
            const map = new Map()
            for (const line of lines) {
              const [hashSuffix, occ] = line.split(':')
              if (!hashSuffix) continue
              map.set(hashSuffix.trim().toUpperCase(), parseInt((occ||'0').trim(), 10) || 0)
            }
            for (const it of byPrefix.get(p)) {
              resultsMap.set(it.id, map.get(it.suffix) || 0)
            }
          } catch (err) {
            console.error('HIBP fetch error', err)
            // fallback: mark as null (unknown) for these ids
            for (const it of byPrefix.get(p)) resultsMap.set(it.id, null)
          }
        }
      }

      await Promise.all(Array.from({length: Math.min(CONC, prefixes.length)}).map(()=>worker()))

  // apply direct HIBP results; note: we DO NOT send les mots de passe au serveur
      const updated = items.map(it => {
        if (!selectedIds.has(it.id)) return it
        const c = resultsMap.get(it.id)
        return { ...it, pwnedCount: c }
      })
      setItems(updated)
    } catch (err) {
      console.error(err)
      alert('Erreur lors de la vérification')
    } finally {
      setChecking(false)
    }
  }

  // vérifie si une URL répond (HEAD then GET fallback). Retourne 'alive'|'dead'|'unknown'
  async function checkUrlAlive(url) {
    if (!url) return 'unknown'
    try {
  // ensure url has protocol
  let u = url.trim()
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u
  // do a HEAD with timeout/abort support (caller should provide AbortController)
  const res = await fetch(u, { method: 'HEAD' })
  if (res && res.ok) return 'alive'
  // if HEAD returns non-ok status, consider dead
  return (res && !res.ok) ? 'dead' : 'unknown'
    } catch (e) {
  // network or CORS issue -> unknown
  return 'unknown'
    }
  }

  // Vérifie les sites pour les éléments sélectionnés via /api/probe
  async function checkSitesForSelected() {
    const toCheck = items.filter(i => selectedIds.has(i.id))
    if (toCheck.length === 0) return
    siteControllersRef.current = new Map()
    setSiteCheckProgress({ checked: 0, total: toCheck.length })
    setCheckingSites(true)
    try {
      const CONC = 6
      let idx = 0
      async function worker() {
        while (idx < toCheck.length) {
          const current = idx++
          const item = toCheck[current]
          if (siteControllersRef.current.stopped) break
          // create a local AbortController for fetch to /api/probe
          const controller = new AbortController()
          siteControllersRef.current.set(item.id, controller)
          // mark as checking so the UI shows a per-row indicator
          setItems(prev => prev.map(it => it.id === item.id ? { ...it, siteStatus: 'checking', httpStatus: null, timeMs: null } : it))
          const timeoutId = setTimeout(() => controller.abort(), 10000)
          try {
            const res = await fetch('/api/probe', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: item.site }), signal: controller.signal })
            if (!res.ok) throw new Error('probe failed')
            const body = await res.json()
            // body: { status, httpStatus, timeMs }
            setItems(prev => prev.map(it => it.id === item.id ? { ...it, siteStatus: body.status, httpStatus: body.httpStatus, timeMs: body.timeMs } : it))
          } catch (err) {
            // mark as unknown
            setItems(prev => prev.map(it => it.id === item.id ? { ...it, siteStatus: 'unknown', httpStatus: null, timeMs: null } : it))
          } finally {
            clearTimeout(timeoutId)
            siteControllersRef.current.delete(item.id)
            setSiteCheckProgress(p => ({ checked: p.checked + 1, total: p.total }))
          }
        }
      }
      await Promise.all(Array.from({ length: Math.min(CONC, toCheck.length) }).map(() => worker()))
    } catch (e) {
      console.error('Site check error', e)
    } finally {
      setCheckingSites(false)
    }
  }

  function stopSiteChecks() {
    // mark stopped and abort all controllers
    siteControllersRef.current.stopped = true
    for (const [, ctrl] of siteControllersRef.current) {
      try { ctrl.abort() } catch (e) {}
    }
    siteControllersRef.current = new Map()
    setCheckingSites(false)
  }

  function deleteDeadSites() {
    // supprimer les éléments visibles ou sélectionnés avec siteStatus === 'dead'
    const toRemove = items.filter(i => selectedIds.has(i.id) && i.siteStatus === 'dead').map(i => i.id)
    if (toRemove.length === 0) {
      alert('Aucun site marqué comme HS dans la sélection.')
      return
    }
    setPendingDeleteIds(new Set(toRemove))
    setShowDeleteConfirm(true)
  }

  // tri simple
  function sortByUsage() {
    setItems(prev => [...prev].sort((a,b) => b.usage - a.usage))
  }

  function sortByProfile() {
    setItems(prev => [...prev].sort((a,b) => (a.profile||'').localeCompare(b.profile||'')))
  }

  function sortByPwned() {
    setItems(prev => [...prev].sort((a,b) => (b.pwnedCount||0) - (a.pwnedCount||0)))
  }

  return (
    <main className={styles.main}>
      <h1 className={styles.title}>Gestionnaire local (import CSV)</h1>

      <section>
        <p className={styles.desc}>Importer un fichier CSV au format: profile,site,username,password,usage_count</p>
        <input className={styles.fileInput} type="file" accept=".csv" onChange={handleFile} />
      </section>

      <section style={{ marginTop: 20 }} className={styles.controls}>
        <button className="btn btnOutline" onClick={sortByPwned}>Trier par vulnérabilité</button>
        <button className="btn ml8" onClick={sortByUsage}>Trier par utilisation</button>
        <button className="btn ml8" onClick={sortByProfile}>Trier par profil</button>
      </section>

  <section style={{ marginTop: 20 }} className={styles.controls}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <label>Filtrer par :</label>
          <select className={styles.textInput} value={filterField} onChange={(e)=>{ setFilterField(e.target.value); setFilterValue('') }}>
            <option value="profile">Profil</option>
            <option value="username">Username</option>
            <option value="site">Site</option>
          </select>
          <input className={styles.textInput} value={filterValue} onChange={(e)=>setFilterValue(e.target.value)} placeholder="Ex: Personal" />
          <select className={styles.textInput} value={filterValue} onChange={(e)=>setFilterValue(e.target.value)}>
            <option value="">(Tous)</option>
            {uniqueValues.map(p => <option key={p} value={p}>{p}</option>)}
          </select>
          <button className="btn" onClick={()=>{
            const ids = filteredItems.map(i=>i.id)
            setSelectedIds(prev => new Set([...prev, ...ids]))
          }}>Sélectionner visibles</button>
          <button className="btn" onClick={()=>{
            const ids = filteredItems.map(i=>i.id)
            setSelectedIds(prev => {
              const copy = new Set(prev)
              for (const id of ids) copy.delete(id)
              return copy
            })
          }}>Désélectionner visibles</button>
        </div>

  <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <input type="checkbox" onChange={(e) => {
            const filteredIds = filteredItems.map(i=>i.id)
            if (e.target.checked) {
              setSelectedIds(prev => new Set([...prev, ...filteredIds]))
            } else {
              setSelectedIds(prev => {
                const copy = new Set(prev)
                for (const id of filteredIds) copy.delete(id)
                return copy
              })
            }
          }} checked={filteredItems.length>0 && filteredItems.every(i=>selectedIds.has(i.id))} />
          Sélectionner tout (visibles)
        </label>

        <button className="btn btnPrimary" onClick={checkPwnedForSelected} disabled={checking || selectedIds.size===0}>
          {checking ? 'Vérification...' : `Vérifier ${selectedIds.size} sélection(s)`}
        </button>

        <button className="btn ml8" onClick={checkSitesForSelected} disabled={checking || selectedIds.size===0}>Vérifier sites</button>

  <select className={styles.textInput} value={siteFilter} onChange={(e)=>setSiteFilter(e.target.value)}>
          <option value="all">Tous sites</option>
          <option value="alive">En ligne</option>
          <option value="dead">HS (dead)</option>
          <option value="unknown">Inconnu</option>
        </select>

  <button className="btn ml8" onClick={stopSiteChecks} disabled={!checkingSites}>Stop vérif.</button>

  <span style={{marginLeft:8}}>{checkingSites ? `Progress: ${siteCheckProgress.checked}/${siteCheckProgress.total}` : ''}</span>

  <button className="btn btnDanger ml8" onClick={deleteDeadSites} disabled={selectedIds.size===0}>Supprimer sites HS (sélection)</button>

        <button className="btn btnDanger ml8" onClick={deleteSelected} disabled={selectedIds.size===0}>Supprimer la sélection</button>

  <button className="btn ml8" onClick={() => exportCSV(filteredItems.length ? filteredItems : items, originalHeaders, originalColCount, originalRows, originalRawText, originalUsedQuotes)} disabled={items.length===0}>Exporter CSV</button>
  <button className="btn ml8" onClick={() => exportProbeResults(filteredItems.length ? filteredItems : items)} disabled={items.length===0}>Exporter résultats probes</button>
      </section>

      <section style={{ marginTop: 20 }} className={styles.tableWrapper}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th></th>
              <th>Profil</th>
              <th>Site</th>
              <th>État du site</th>
              <th>Username</th>
              <th>Usage</th>
              <th>Détails</th>
              <th>Vulnérabilité (pwned)</th>
            </tr>
          </thead>
          <tbody>
            {filteredItems.map(it => (
              <tr key={it.id} className={styles.tableRow + ' ' + ((it.pwnedCount||0)>0 ? styles.rowBad : '')}>
                <td>
                  <input type="checkbox" checked={selectedIds.has(it.id)} onChange={() => toggleSelect(it.id)} />
                </td>
                <td>{it.profile}</td>
                <td>{it.site}</td>
                <td>
                  {it.siteStatus === 'checking' ? (
                    <span><span className={styles.spinner}></span><span className={styles.muted}>Vérif...</span></span>
                  ) : it.siteStatus === 'alive' ? <span className={styles.badge + ' ' + styles.badge_safe}>En ligne</span> : it.siteStatus === 'dead' ? <span className={styles.badge + ' ' + styles.badge_bad}>HS</span> : <span className={styles.muted}>—</span>}
                </td>
                <td>{it.username}</td>
                <td>{it.usage}</td>
                <td>
                  {it.httpStatus ? <span className={styles.muted}>{it.httpStatus} {it.timeMs ? `(${it.timeMs}ms)` : ''}</span> : <span className={styles.muted}>—</span>}
                </td>
                <td>
                  {it.pwnedCount == null ? <span className={styles.muted}>—</span> : it.pwnedCount > 0 ? <span className={styles.badge + ' ' + styles.badge_bad}>{it.pwnedCount} fois</span> : <span className={styles.badge + ' ' + styles.badge_safe}>Non</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      {showDeleteConfirm && (
        <div className={styles.modalOverlay} role="dialog" aria-modal="true">
          <div className={styles.modalDialog}>
            <h3>Confirmer la suppression</h3>
            <p>Voulez-vous vraiment supprimer {pendingDeleteIds.size} élément(s) ? Cette action est irréversible.</p>
            <div className={styles.modalActions}>
              <button className="btn" onClick={cancelDelete}>Annuler</button>
              <button className="btn btnDanger" onClick={performDeleteConfirmed}>Supprimer</button>
            </div>
          </div>
        </div>
      )}
    </main>
  )
}

function exportCSV(items, originalHeaders, originalColCount, originalRows, originalRawText, originalUsedQuotes) {
  // Rebuild using original headers/column count if available to keep identity
  const colCount = originalColCount || 5
  const headerRow = originalHeaders ? originalHeaders.map(h => String(h)) : ['profile','site','username','password','usage']

  const rows = items.map(i => {
    // attempt to preserve original row by index if available
    const original = (originalRows && originalRows[i.originalRowIndex]) || []
    const out = []
    for (let c = 0; c < colCount; c++) {
      // map standard columns to indices 0..4, else preserve original cell if present
      let v = ''
      if (c === 0) v = i.profile
      else if (c === 1) v = i.site
      else if (c === 2) v = i.username
      else if (c === 3) v = i.password
      else if (c === 4) v = i.usage
      // if original had extra columns, prefer original content for those indices
      if ((original[c] || '').toString().trim() !== '') {
        // if original contained a value and we don't have a mapped value, use original
        if (v === '' || (c >= 5)) v = original[c]
      }
  if (originalUsedQuotes) out.push(`"${String(v === null || v === undefined ? '' : v).replace(/"/g,'""')}"`)
  else out.push(String(v === null || v === undefined ? '' : v))
    }
    return out.join(',')
  })

  const csv = (headerRow ? [headerRow.map(h=>`"${String(h).replace(/"/g,'""')}"`).join(',')] : []).concat(rows).join('\n')

  // Compare generated rows to originalRows to check identity
  let identical = false
  try {
    if (originalRows && originalRows.length > 0) {
      // normalize both sides
      const normOrig = originalRows.map(r => r.map(c => (c||'').toString().trim()).join(','))
      const genRows = items.map(i => {
        const original = (originalRows && originalRows[i.originalRowIndex]) || []
        const cells = []
        for (let c=0;c<colCount;c++) {
          let v = c===0?i.profile: c===1?i.site: c===2?i.username: c===3?i.password: c===4?i.usage: ''
          if ((original[c]||'').toString().trim() !== '') {
            if (v === '' || (c>=5)) v = original[c]
          }
          cells.push((v||'').toString().trim())
        }
        return cells.join(',')
      })
      // compare lengths and each normalized row
      if (genRows.length === normOrig.length) {
        identical = genRows.every((r, idx) => r === normOrig[idx])
      }
    }
  } catch (e) {
    console.error('Compare error', e)
  }

  if (identical) {
    // inform user that exported file is identical to source
    alert('L\'export semble identique au fichier source (colonnes et valeurs). Le téléchargement va démarrer.')
  } else {
    // warn user that export differs in structure or values
    const diffMsg = originalRows ? 'Le fichier export diffère de la source (colonnes/valeurs). Le téléchargement va démarrer.' : 'Aucune information d\'origine disponible ; export standard.'
    alert(diffMsg)
  }
  const MAX_BYTES = 150 * 1024 // 150 KB
  const encoder = new TextEncoder()
  const bytes = encoder.encode(csv)
  if (bytes.length <= MAX_BYTES) {
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'export.csv'
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
    return
  }

  // split into multiple files, each with headerRow if available
  const lines = csv.split('\n')
  const headerLine = headerRow ? headerRow.map(h=> originalUsedQuotes ? `"${String(h).replace(/"/g,'""')}"` : String(h)).join(',') : null
  // start from index 0 if no header in originalRows, otherwise lines already include header at 0
  let startIndex = headerLine ? 1 : 0
  let partIdx = 1
  while (startIndex < lines.length) {
    let partLines = headerLine ? [headerLine] : []
    let size = encoder.encode(partLines.join('\n') + '\n').length
    while (startIndex < lines.length) {
      const nextLine = lines[startIndex]
      const nextSize = encoder.encode('\n' + nextLine).length
      if (size + nextSize > MAX_BYTES && partLines.length > (headerLine ? 1 : 0)) break
      partLines.push(nextLine)
      size += nextSize
      startIndex++
    }
    const partCsv = partLines.join('\n')
    const blob = new Blob([partCsv], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `export_part_${partIdx}.csv`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
    partIdx++
  }
}

function exportProbeResults(items) {
  if (!items || items.length === 0) {
    alert('Aucun item à exporter')
    return
  }
  const header = ['profile','site','username','password','usage','siteStatus','httpStatus','timeMs']
  const lines = [header.join(',')]
  for (const it of items) {
    const cells = [it.profile, it.site, it.username, it.password, it.usage || '', it.siteStatus || '', it.httpStatus || '', it.timeMs || '']
    const escaped = cells.map(c => {
      if (c === null || c === undefined) return ''
      const s = String(c)
      if (s.includes(',') || s.includes('"') || s.includes('\n')) return '"' + s.replace(/"/g,'""') + '"'
      return s
    })
    lines.push(escaped.join(','))
  }
  const csv = lines.join('\n')
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'probe_results.csv'
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}
