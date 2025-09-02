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
      const updated = await Promise.all(items.map(async it => {
        if (!selectedIds.has(it.id)) return it
        const res = await fetch('/api/check-pwned', {
          method: 'POST',
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify({ password: it.password })
        })
        const j = await res.json()
        return { ...it, pwnedCount: j.pwnedCount }
      }))
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

      <section style={{ marginTop: 20 }}>
        <button onClick={checkPwnedForSelected} disabled={checking || selectedIds.size===0}>
          {checking ? 'Vérification...' : `Vérifier ${selectedIds.size} sélection(s)`}
        </button>
        <button onClick={deleteSelected} style={{ marginLeft: 8 }} disabled={selectedIds.size===0}>Supprimer la sélection</button>
      </section>

      <section style={{ marginTop: 20 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
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
              <tr key={it.id} style={{ borderTop: '1px solid #eee' }}>
                <td style={{ padding: 8 }}>
                  <input type="checkbox" checked={selectedIds.has(it.id)} onChange={() => toggleSelect(it.id)} />
                </td>
                <td style={{ padding: 8 }}>{it.profile}</td>
                <td style={{ padding: 8 }}>{it.site}</td>
                <td style={{ padding: 8 }}>{it.username}</td>
                <td style={{ padding: 8 }}>{it.usage}</td>
                <td style={{ padding: 8 }}>{it.pwnedCount == null ? '—' : it.pwnedCount > 0 ? `${it.pwnedCount} fois` : 'Non'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </main>
  )
}
