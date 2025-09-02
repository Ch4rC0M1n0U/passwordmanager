import crypto from 'crypto'

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end()

  const { password } = req.body
  if (!password) return res.status(400).json({ error: 'password required' })

  try {
    // Calculer SHA1 en majuscules
    const sha1 = crypto.createHash('sha1').update(password).digest('hex').toUpperCase()
    const prefix = sha1.slice(0, 5)
    const suffix = sha1.slice(5)

    const hibpRes = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`)
    const text = await hibpRes.text()

    const lines = text.split('\n')
    let count = 0
    for (const line of lines) {
      const [hashSuffix, occ] = line.split(':')
      if (hashSuffix && hashSuffix.trim() === suffix) {
        count = parseInt(occ, 10) || 0
        break
      }
    }

    // Nous ne stockons rien - renvoyer uniquement le compte
    res.status(200).json({ pwnedCount: count })
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: 'internal' })
  }
}
