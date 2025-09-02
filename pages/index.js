import { useState } from 'react'
import styles from '../styles/home.module.css'

// Application centrée sur l'import CSV des éléments de gestion de mots de passe
// Fonctionnalités:
// - Import d'un CSV (profile,site,username,password,usage_count)
// - Tri par vulnérabilité (pwnedCount), usage, profil
// - Sélection multiple et suppression
// - Vérification via /api/check-pwned (ne stocke rien)

export default function Home() {
  const [items, setItems] = useState([])
  const [selectedIds, setSelectedIds] = useState(new Set())
  const [checking, setChecking] = useState(false)

  function parseCSV(text) {
    const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean)
    const parsed = lines.map((line, idx) => {
      const parts = line.split(',')
      return {
        id: `${Date.now()}_${idx}`,
        profile: parts[0] || '',
        site: parts[1] || '',
        username: parts[2] || '',
        password: parts[3] || '',
        usage: parseInt(parts[4], 10) || 0,
        pwnedCount: null
      }
    })
    setItems(prev => [...prev, ...parsed])
  }

  function handleFile(e) {
    const f = e.target.files && e.target.files[0]
    if (!f) return
    const reader = new FileReader()
    reader.onload = () => parseCSV(reader.result)
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
    setItems(prev => prev.filter(i => !selectedIds.has(i.id)))
    setSelectedIds(new Set())
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

      // if all results are null (possible CORS), fallback to server API
      const needFallback = toCheck.some(t => resultsMap.get(t.id) === null)
      if (needFallback) {
        try {
          const passwords = toCheck.map(i=>i.password)
          const resp = await fetch('/api/check-pwned', {
            method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ passwords })
          })
          const j = await resp.json()
          if (Array.isArray(j.counts)) {
            // apply server results
            const updated = items.map(it => {
              if (!selectedIds.has(it.id)) return it
              const idx = toCheck.findIndex(x=>x.id===it.id)
              const c = j.counts[idx]
              return { ...it, pwnedCount: c }
            })
            setItems(updated)
            setChecking(false)
            return
          }
        } catch (err) {
          console.error('Fallback server failed', err)
        }
      }

      // apply direct HIBP results
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
      <h1>Gestionnaire local (import CSV)</h1>

      <section>
        <p>Importer un fichier CSV au format: profile,site,username,password,usage_count</p>
        <input type="file" accept=".csv" onChange={handleFile} />
      </section>

      <section style={{ marginTop: 20 }}>
        <button onClick={sortByPwned}>Trier par vulnérabilité (pwned)</button>
        <button onClick={sortByUsage} style={{ marginLeft: 8 }}>Trier par utilisation</button>
        <button onClick={sortByProfile} style={{ marginLeft: 8 }}>Trier par profil</button>
      </section>

      <section style={{ marginTop: 20 }} className={styles.controls}>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <input type="checkbox" onChange={(e) => {
            if (e.target.checked) setSelectedIds(new Set(items.map(i=>i.id)))
            else setSelectedIds(new Set())
          }} checked={items.length>0 && selectedIds.size===items.length} />
          Sélectionner tout
        </label>

        <button onClick={checkPwnedForSelected} disabled={checking || selectedIds.size===0}>
          {checking ? 'Vérification...' : `Vérifier ${selectedIds.size} sélection(s)`}
        </button>

        <button onClick={deleteSelected} style={{ marginLeft: 8 }} disabled={selectedIds.size===0}>Supprimer la sélection</button>

        <button onClick={() => exportCSV(items)} style={{ marginLeft: 8 }} disabled={items.length===0}>Exporter CSV</button>
      </section>

      <section style={{ marginTop: 20 }} className={styles.tableWrapper}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th></th>
              <th>Profil</th>
              <th>Site</th>
              <th>Username</th>
              <th>Usage</th>
              <th>Vulnérabilité (pwned)</th>
            </tr>
          </thead>
          <tbody>
            {items.map(it => (
              <tr key={it.id} style={{ borderTop: '1px solid #eee', background: it.pwnedCount>0 ? '#fff6f6' : 'transparent' }}>
                <td style={{ padding: 8 }}>
                  <input type="checkbox" checked={selectedIds.has(it.id)} onChange={() => toggleSelect(it.id)} />
                </td>
                <td style={{ padding: 8 }}>{it.profile}</td>
                <td style={{ padding: 8 }}>{it.site}</td>
                <td style={{ padding: 8 }}>{it.username}</td>
                <td style={{ padding: 8 }}>{it.usage}</td>
                <td style={{ padding: 8 }}>
                  {it.pwnedCount == null ? '—' : it.pwnedCount > 0 ? <span className={`${styles.badge} ${styles.badge_bad}`}>{it.pwnedCount} fois</span> : <span className={`${styles.badge} ${styles.badge_safe}`}>Non</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </main>
  )
}

function exportCSV(items) {
  const header = ['profile','site','username','password','usage']
  const rows = items.map(i => [i.profile,i.site,i.username,i.password,i.usage].map(v=>`"${String(v).replace(/"/g,'""')}"`).join(','))
  const csv = [header.join(','), ...rows].join('\n')
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'export.csv'
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}
