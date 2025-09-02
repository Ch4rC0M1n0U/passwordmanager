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
  const [profileFilter, setProfileFilter] = useState('')
  const filteredItems = items.filter(i => {
    if (!profileFilter) return true
    return (i.profile||'').toLowerCase().includes(profileFilter.toLowerCase())
  })
  const uniqueProfiles = Array.from(new Set(items.map(i => (i.profile||'').trim()).filter(Boolean))).sort()
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

    const lines = parseCSVText(text).filter(r => r.some(c => (c||'').trim() !== ''))
    const now = Date.now()
    const parsed = lines.map((parts, idx) => ({
      id: `${now}_${idx}`,
      profile: parts[0] ? parts[0].trim() : '',
      site: parts[1] ? parts[1].trim() : '',
      username: parts[2] ? parts[2].trim() : '',
      password: parts[3] ? parts[3] : '',
      usage: parts[4] ? parseInt(parts[4].trim(), 10) || 0 : 0,
      pwnedCount: null
    }))
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
          <label>Filtrer par profil :</label>
          <input className={styles.textInput} value={profileFilter} onChange={(e)=>setProfileFilter(e.target.value)} placeholder="Ex: Personal" />
          <select className={styles.textInput} value={profileFilter} onChange={(e)=>setProfileFilter(e.target.value)}>
            <option value="">(Tous)</option>
            {uniqueProfiles.map(p => <option key={p} value={p}>{p}</option>)}
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

        <button className="btn btnDanger ml8" onClick={deleteSelected} disabled={selectedIds.size===0}>Supprimer la sélection</button>

        <button className="btn ml8" onClick={() => exportCSV(filteredItems.length ? filteredItems : items)} disabled={items.length===0}>Exporter CSV</button>
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
            {filteredItems.map(it => (
              <tr key={it.id} className={`${styles.tableRow} ${(it.pwnedCount||0)>0 ? styles.rowBad:''}`}>
                <td>
                  <input type="checkbox" checked={selectedIds.has(it.id)} onChange={() => toggleSelect(it.id)} />
                </td>
                <td>{it.profile}</td>
                <td>{it.site}</td>
                <td>{it.username}</td>
                <td>{it.usage}</td>
                <td>
                  {it.pwnedCount == null ? <span className={styles.muted}>—</span> : it.pwnedCount > 0 ? <span className={`${styles.badge} ${styles.badge_bad}`}>{it.pwnedCount} fois</span> : <span className={`${styles.badge} ${styles.badge_safe}`}>Non</span>}
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
